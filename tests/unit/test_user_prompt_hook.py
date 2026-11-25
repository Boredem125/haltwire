"""Tests: UserPromptSubmit hook writes latest user prompt to task.txt.

The hook is installed alongside PreToolUse/PostToolUse in .claude/settings
for Claude Code; uninstall removes it.

Requirements:
- Writes to layout.state_dir / "task.txt" atomically
- Capped at 2000 chars
- Never blocks the prompt (no timeout, no error)
- Fail silently with an audit entry
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_hook_template_exists():
    """The UserPromptSubmit hook template is importable."""
    from sandbox.connector.hook_templates import USERPROMPTSUBMIT_STUB

    assert "UserPromptSubmit" in USERPROMPTSUBMIT_STUB
    assert "task.txt" in USERPROMPTSUBMIT_STUB


def test_install_adds_userpromptsubmit_hook(tmp_path):
    """init_folder installs the UserPromptSubmit hook stub."""
    from sandbox.connector.install import init_folder
    from sandbox.connector.layout import FolderLayout

    init_folder(tmp_path, claude=True, mcp=False)

    lo = FolderLayout(tmp_path)
    stub_path = lo.hooks_dir / "userpromptsubmit.py"
    assert stub_path.is_file(), "UserPromptSubmit stub not written"


def test_install_settings_has_userpromptsubmit(tmp_path):
    """init with claude=True adds a UserPromptSubmit entry to settings."""
    from sandbox.connector.install import init_folder

    init_folder(tmp_path, claude=True, mcp=False)

    # Find the settings file
    for name in (".claude/settings.local.json", ".claude/settings.json"):
        p = tmp_path / name
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            hooks = data.get("hooks", {})
            assert "UserPromptSubmit" in hooks
            entries = hooks["UserPromptSubmit"]
            assert len(entries) > 0
            assert entries[0].get("_sandbox_connector") is True
            return
    pytest.fail("No settings file found with UserPromptSubmit hook")


def test_uninstall_removes_userpromptsubmit(tmp_path):
    """uninstall removes the UserPromptSubmit entry from settings."""
    from sandbox.connector.install import init_folder, uninstall

    init_folder(tmp_path, claude=True, mcp=False)

    result = uninstall(tmp_path)
    assert result["settings_entry_removed"]

    for name in (".claude/settings.local.json", ".claude/settings.json"):
        p = tmp_path / name
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            hooks = data.get("hooks", {})
            entries = hooks.get("UserPromptSubmit", [])
            assert all(not e.get("_sandbox_connector") for e in entries)
