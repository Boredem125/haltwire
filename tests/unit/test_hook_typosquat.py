"""Tests: typosquat check wired into hook_eval PreToolUse.

Typosquat detection runs in the hook for all agents. Flagged lookalikes
ESCALATE (single human approval), not hard deny. The reason contains
"[TYPOSQUAT]" exactly once.
"""
from __future__ import annotations

import asyncio
import json

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
        json.dumps({"session_id": "s-typo"}), encoding="utf-8"
    )
    return lo


def _pre(tool_name, tool_input, cwd):
    return {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": cwd,
        "session_id": "s-typo",
        "hook_event_name": "PreToolUse",
    }


# ---- typosquat lookalikes escalate (not hard deny) ----

async def test_typosquat_pip_install_escalates(layout):
    """pip install pandaz-csv is a typosquat of pandas and must escalate."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install pandaz-csv"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    # Escalation times out to deny, but the audit has TYPOSQUAT
    assert hso["permissionDecision"] == "deny"
    assert "TYPOSQUAT" in hso["permissionDecisionReason"]
    # "[TYPOSQUAT]" appears exactly once
    assert hso["permissionDecisionReason"].count("[TYPOSQUAT]") == 1


async def test_typosquat_npm_install_escalates(layout):
    """npm install loadsh is a typosquat of lodash."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "npm install loadsh"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "TYPOSQUAT" in hso["permissionDecisionReason"]


async def test_typosquat_uv_add_escalates(layout):
    """uv add numpay is a typosquat of numpy."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "uv add numpay"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "TYPOSQUAT" in hso["permissionDecisionReason"]


async def test_typosquat_reqeusts(layout):
    """pip install reqeusts (typo of requests) escalates."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install reqeusts"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "TYPOSQUAT" in hso["permissionDecisionReason"]


# ---- legitimate packages pass ----

async def test_legit_pip_install_allowed(layout):
    """pip install pandas is not a typosquat."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install pandas"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "TYPOSQUAT" not in hso.get("permissionDecisionReason", "")


@pytest.mark.parametrize("pkg", [
    "vitest", "preact", "psycopg", "psycopg-binary", "dash", "yaml",
    "mysql", "color", "scapy", "cattrs", "arrow", "unicorn", "simpy",
    "boto", "grpc", "jinja",
])
async def test_known_legit_no_flag(layout, pkg):
    """Known-legitimate packages must never be flagged."""
    out = await pre_tool_use(
        _pre("Bash", {"command": f"pip install {pkg}"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "TYPOSQUAT" not in hso.get("permissionDecisionReason", "")


# ---- PowerShell ----

async def test_typosquat_powershell(layout):
    """PowerShell pip install typosquat is also caught."""
    out = await pre_tool_use(
        _pre("PowerShell", {"command": "pip install pandaz-csv"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "TYPOSQUAT" in hso["permissionDecisionReason"]


async def test_powershell_requirements_txt_path(layout):
    """pip install -r .\\requirements.txt must not false-positive."""
    (layout.root / "requirements.txt").write_text("pandas\n", encoding="utf-8")
    out = await pre_tool_use(
        _pre("PowerShell", {"command": r"pip install -r .\requirements.txt"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "TYPOSQUAT" not in hso.get("permissionDecisionReason", "")


# ---- non-shell not checked ----

async def test_non_shell_not_checked(layout):
    """Read tool is not checked for typosquat."""
    out = await pre_tool_use(
        _pre("Read", {"file_path": "pandaz-csv.txt"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "TYPOSQUAT" not in hso.get("permissionDecisionReason", "")
