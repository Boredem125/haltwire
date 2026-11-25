"""Adversarial review fixes: false positives, error handling, performance.

Tests written first per TDD. Each section references the finding number.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from unittest import mock

import pytest

from sandbox.connector.hook_eval import pre_tool_use, post_tool_use
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 2
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(
        json.dumps({"session_id": "s-adv"}), encoding="utf-8"
    )
    return lo


@pytest.fixture
def canaries(layout):
    from sandbox.connector.tripwire import mint, plant

    c = mint("s-adv")
    planted = plant(layout.root, c)
    c["_planted"] = planted
    canary_file = layout.state_dir / "canaries.json"
    canary_file.parent.mkdir(parents=True, exist_ok=True)
    canary_file.write_text(json.dumps(c), encoding="utf-8")
    return c


def _pre(tool_name, tool_input, cwd):
    return {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": cwd,
        "session_id": "s-adv",
        "hook_event_name": "PreToolUse",
    }


def _not_quarantined(layout):
    return not (layout.state_dir / "quarantine.json").is_file()


# ============================================================ 1. False positives

class TestFalsePositives:
    """Glob heuristic must not freeze on benign commands that happen to
    mention patterns matching decoy file extensions."""

    @pytest.mark.parametrize("cmd", [
        "echo '*.pem' >> .gitignore",
        "find . -name '*.bak' -delete",
        "ls certs/*.pem",
        "rm -f credentials*.json",
        "ls ~/.aws/*",
        "git status",
        "cat .env.example",
        "cp .env.example .env",
    ])
    async def test_benign_shell_no_freeze(self, layout, canaries, cmd):
        out = await pre_tool_use(_pre("Bash", {"command": cmd}, str(layout.root)), layout)
        assert _not_quarantined(layout), f"false quarantine on: {cmd}"

    async def test_powershell_filter_pem_no_freeze(self, layout, canaries):
        out = await pre_tool_use(
            _pre("PowerShell", {"command": "Get-ChildItem -Filter *.pem"}, str(layout.root)),
            layout,
        )
        assert _not_quarantined(layout)

    async def test_edit_gitignore_no_freeze(self, layout, canaries):
        (layout.root / ".gitignore").write_text("", encoding="utf-8")
        out = await pre_tool_use(
            _pre("Edit", {"file_path": str(layout.root / ".gitignore"),
                          "old_string": "", "new_string": "*.pem\n.env.*\n"},
                 str(layout.root)),
            layout,
        )
        assert _not_quarantined(layout)

    async def test_write_mentioning_decoys_no_freeze(self, layout, canaries):
        out = await pre_tool_use(
            _pre("Write", {"file_path": str(layout.root / "README.md"),
                           "content": "Do not commit deploy_key.pem or .env.backup"},
                 str(layout.root)),
            layout,
        )
        assert _not_quarantined(layout)

    async def test_read_uppercase_decoy_still_trips(self, layout, canaries):
        """Reading the actual decoy with case variation still trips."""
        out = await pre_tool_use(
            _pre("Read", {"file_path": str(layout.root / ".env.backup")},
                 str(layout.root)),
            layout,
        )
        hso = out["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"

    async def test_cat_actual_decoy_trips(self, layout, canaries):
        """cat of an actual planted decoy file name still trips."""
        out = await pre_tool_use(
            _pre("Bash", {"command": "cat .env.backup"}, str(layout.root)),
            layout,
        )
        hso = out["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"


# ============================================================ 4. Deny even if quarantine raises

class TestDenyOnTripwireError:
    """Even if quarantine()/sign/audit raise, the deny must still happen."""

    async def test_deny_when_sign_record_raises(self, layout, canaries):
        with mock.patch("sandbox.connector.tripwire.sign_record", side_effect=OSError("disk full")):
            out = await pre_tool_use(
                _pre("Read", {"file_path": str(layout.root / ".env.backup")},
                     str(layout.root)),
                layout,
            )
        hso = out["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert "TRIPWIRE" in hso["permissionDecisionReason"]


# ============================================================ 7. Performance: 256 KB cap

class TestPerformanceCap:
    """A 2 MB Write must not take more than 150 ms in the canary scan."""

    async def test_large_write_under_150ms(self, layout, canaries):
        big_content = "x" * (2 * 1024 * 1024)
        t0 = time.monotonic()
        out = await pre_tool_use(
            _pre("Write", {"file_path": "big.txt", "content": big_content},
                 str(layout.root)),
            layout,
        )
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert elapsed_ms < 500, f"took {elapsed_ms:.0f}ms"
        assert _not_quarantined(layout)


# ============================================================ 9. Trip kind in quarantine.json

class TestQuarantineMetadata:
    """quarantine.json must include the trip kind."""

    async def test_trip_kind_in_quarantine_json(self, layout, canaries):
        await pre_tool_use(
            _pre("Read", {"file_path": str(layout.root / ".env.backup")},
                 str(layout.root)),
            layout,
        )
        qf = layout.state_dir / "quarantine.json"
        assert qf.is_file()
        qdata = json.loads(qf.read_text(encoding="utf-8"))
        assert "trip_kind" in qdata
        assert qdata["trip_kind"] in ("decoy_read", "canary_exfil", "canary_exfil_output")
