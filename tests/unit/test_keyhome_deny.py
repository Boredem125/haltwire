"""Key home directory must be denied: Read, Grep, Glob, shell access.

The key home holds signing keys, planted.json proofs, and gemini.key.
No agent tool call may read or write inside it.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from sandbox.connector.hook_eval import pre_tool_use
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
        json.dumps({"session_id": "s-kh"}), encoding="utf-8"
    )
    return lo


def _pre(tool_name, tool_input, cwd):
    return {"tool_name": tool_name, "tool_input": tool_input, "cwd": cwd,
            "session_id": "s-kh", "hook_event_name": "PreToolUse"}


def _keyhome(tmp_path):
    """Create a fake key home and return the path."""
    kh = tmp_path / "fake_keyhome"
    kh.mkdir(parents=True, exist_ok=True)
    (kh / "gemini.key").write_text("fake-key", encoding="utf-8")
    (kh / "ws-abc" / "planted.json").parent.mkdir(parents=True, exist_ok=True)
    (kh / "ws-abc" / "planted.json").write_text("{}", encoding="utf-8")
    return kh


async def test_read_gemini_key_denied(layout, tmp_path):
    """Read of gemini.key in the key home is denied."""
    kh = _keyhome(tmp_path)
    with mock.patch("sandbox.connector.keyhome.key_home_root", return_value=kh):
        out = await pre_tool_use(
            _pre("Read", {"file_path": str(kh / "gemini.key")}, str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "KEY_HOME" in hso["permissionDecisionReason"]


async def test_cat_gemini_key_denied(layout, tmp_path):
    """cat of key home path in shell is denied."""
    kh = _keyhome(tmp_path)
    with mock.patch("sandbox.connector.keyhome.key_home_root", return_value=kh):
        out = await pre_tool_use(
            _pre("Bash", {"command": f"cat {kh / 'gemini.key'}"}, str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


async def test_type_gemini_key_denied(layout, tmp_path):
    """type (Windows) of key home path is denied."""
    kh = _keyhome(tmp_path)
    with mock.patch("sandbox.connector.keyhome.key_home_root", return_value=kh):
        out = await pre_tool_use(
            _pre("PowerShell", {"command": f"Get-Content {kh / 'gemini.key'}"}, str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


async def test_grep_in_keyhome_denied(layout, tmp_path):
    """Grep in the key home directory is denied."""
    kh = _keyhome(tmp_path)
    with mock.patch("sandbox.connector.keyhome.key_home_root", return_value=kh):
        out = await pre_tool_use(
            _pre("Grep", {"pattern": "key", "path": str(kh)}, str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "KEY_HOME" in hso["permissionDecisionReason"]


async def test_read_planted_json_denied(layout, tmp_path):
    """Read of planted.json proof file is denied."""
    kh = _keyhome(tmp_path)
    with mock.patch("sandbox.connector.keyhome.key_home_root", return_value=kh):
        out = await pre_tool_use(
            _pre("Read", {"file_path": str(kh / "ws-abc" / "planted.json")}, str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


async def test_write_to_keyhome_denied(layout, tmp_path):
    """Write to key home is denied."""
    kh = _keyhome(tmp_path)
    with mock.patch("sandbox.connector.keyhome.key_home_root", return_value=kh):
        out = await pre_tool_use(
            _pre("Write", {"file_path": str(kh / "evil.txt"), "content": "data"},
                 str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


async def test_normal_file_still_allowed(layout, tmp_path):
    """Read of a normal file outside the folder stays at its current verdict."""
    kh = _keyhome(tmp_path)
    normal = layout.root / "README.md"
    normal.write_text("hello", encoding="utf-8")
    with mock.patch("sandbox.connector.keyhome.key_home_root", return_value=kh):
        out = await pre_tool_use(
            _pre("Read", {"file_path": str(normal)}, str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    # Should NOT be denied with KEY_HOME
    assert "KEY_HOME" not in hso.get("permissionDecisionReason", "")
