"""Shell commands that modify hook configs must be HARD DENIED (HOOK_CONFIG).
Reads (cat) stay allowed.
"""
from __future__ import annotations

import json
import pytest

from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    p = default_policy()
    p.escalation_timeout_seconds = 2
    save_policy(p, lo.policy_file)
    lo.session_file.write_text(json.dumps({"session_id": "s-hc"}), encoding="utf-8")
    return lo


def _pre(tool, ti, cwd):
    return {"tool_name": tool, "tool_input": ti, "cwd": cwd,
            "session_id": "s-hc", "hook_event_name": "PreToolUse"}


def _reason(out):
    return out["hookSpecificOutput"].get("permissionDecisionReason", "")


def _decision(out):
    return out["hookSpecificOutput"].get("permissionDecision")


# ---- destructive commands: HARD DENY ----

@pytest.mark.parametrize("cmd", [
    "rm .agents/hooks.json",
    "rm -rf .agents",
    "echo {} > .agents/hooks.json",
    "mv .claude/settings.local.json x.json",
    'python -c "open(\'.agents/hooks.json\',\'w\').write(\'{}\')"',
    "git checkout -- .claude",
    "git restore .claude/settings.local.json",
    "git clean -f .claude",
])
async def test_bash_destructive_denied(layout, cmd):
    out = await pre_tool_use(_pre("Bash", {"command": cmd}, str(layout.root)), layout)
    assert _decision(out) == "deny", f"expected deny for: {cmd}"
    assert "HOOK_CONFIG" in _reason(out), f"expected HOOK_CONFIG for: {cmd}"


@pytest.mark.parametrize("cmd", [
    "Remove-Item .gemini\\settings.json",
    "Set-Content .claude/settings.local.json '{}'",
    "Move-Item .claude/settings.local.json x.json",
])
async def test_powershell_destructive_denied(layout, cmd):
    out = await pre_tool_use(_pre("PowerShell", {"command": cmd}, str(layout.root)), layout)
    assert _decision(out) == "deny", f"expected deny for: {cmd}"
    assert "HOOK_CONFIG" in _reason(out), f"expected HOOK_CONFIG for: {cmd}"


async def test_rm_mcp_json_denied(layout):
    out = await pre_tool_use(
        _pre("Bash", {"command": "rm .mcp.json"}, str(layout.root)), layout)
    assert _decision(out) == "deny"
    assert "HOOK_CONFIG" in _reason(out)


# ---- reads stay allowed ----

async def test_cat_claude_settings_allowed(layout):
    """cat .claude/settings.local.json is harmless and stays allowed."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "cat .claude/settings.local.json"}, str(layout.root)), layout)
    assert "HOOK_CONFIG" not in _reason(out)


async def test_read_tool_claude_settings_allowed(layout):
    """Read tool for .claude/settings.local.json stays at its current verdict."""
    out = await pre_tool_use(
        _pre("Read", {"file_path": ".claude/settings.local.json"}, str(layout.root)), layout)
    assert "HOOK_CONFIG" not in _reason(out)


# ---- normal git commands unaffected ----

async def test_git_status_unaffected(layout):
    out = await pre_tool_use(
        _pre("Bash", {"command": "git status"}, str(layout.root)), layout)
    assert "HOOK_CONFIG" not in _reason(out)


async def test_git_checkout_main_unaffected(layout):
    out = await pre_tool_use(
        _pre("Bash", {"command": "git checkout main"}, str(layout.root)), layout)
    assert "HOOK_CONFIG" not in _reason(out)


async def test_git_diff_unaffected(layout):
    out = await pre_tool_use(
        _pre("Bash", {"command": "git diff .claude/settings.local.json"}, str(layout.root)), layout)
    assert "HOOK_CONFIG" not in _reason(out)
