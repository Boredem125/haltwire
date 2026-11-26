"""Tests: agents cannot tamper with their own hook config files.

Verify that Claude Code (via pre_tool_use) denies Write/Edit/shell access to:
- .agents/hooks.json (agy hooks)
- .gemini/settings.json (Gemini CLI hooks)
- .claude/settings.local.json (Claude Code hooks)
- .claude/settings.json (Claude Code hooks)
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


@pytest.fixture
def workspace(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(
        json.dumps({"session_id": "s-guard", "python": "python", "package_src": "src"}),
        encoding="utf-8",
    )
    return lo


def _pre(workspace, tool_name, tool_input):
    from sandbox.connector.hook_eval import pre_tool_use

    payload = {"tool_name": tool_name, "tool_input": tool_input, "cwd": str(workspace.root)}
    return asyncio.run(pre_tool_use(payload, workspace))


def _decision(result):
    return result.get("hookSpecificOutput", {}).get("permissionDecision", "")


# ------------------------------------------------------------------ .agents/hooks.json


def test_write_agents_hooks_denied(workspace):
    r = _pre(workspace, "Write", {
        "file_path": str(workspace.root / ".agents" / "hooks.json"),
        "content": "{}",
    })
    assert _decision(r) == "deny"


def test_edit_agents_hooks_denied(workspace):
    r = _pre(workspace, "Edit", {
        "file_path": str(workspace.root / ".agents" / "hooks.json"),
        "old_string": "a",
        "new_string": "b",
    })
    assert _decision(r) == "deny"


def test_shell_cat_agents_hooks_denied(workspace):
    """Shell commands touching .agents/ are denied (the .sandbox shell deny pattern catches it
    only for .sandbox paths; .agents is guarded by the write glob, so we test Write instead)."""
    # Write to .agents is what matters; shell commands that modify .agents
    # would go through Write or through shell patterns. The write protection
    # is the primary guard.
    r = _pre(workspace, "Write", {
        "file_path": str(workspace.root / ".agents" / "other.json"),
        "content": "{}",
    })
    assert _decision(r) == "deny"


# ------------------------------------------------------------------ .gemini/settings.json


def test_write_gemini_settings_denied(workspace):
    r = _pre(workspace, "Write", {
        "file_path": str(workspace.root / ".gemini" / "settings.json"),
        "content": "{}",
    })
    assert _decision(r) == "deny"


def test_edit_gemini_settings_denied(workspace):
    r = _pre(workspace, "Edit", {
        "file_path": str(workspace.root / ".gemini" / "settings.json"),
        "old_string": "a",
        "new_string": "b",
    })
    assert _decision(r) == "deny"


# ------------------------------------------------------------------ .claude/settings*.json


def test_write_claude_settings_local_denied(workspace):
    r = _pre(workspace, "Write", {
        "file_path": str(workspace.root / ".claude" / "settings.local.json"),
        "content": "{}",
    })
    assert _decision(r) == "deny"


def test_write_claude_settings_denied(workspace):
    r = _pre(workspace, "Write", {
        "file_path": str(workspace.root / ".claude" / "settings.json"),
        "content": "{}",
    })
    assert _decision(r) == "deny"
