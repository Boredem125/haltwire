"""Tests: `haltwire uninstall` cleans up .mcp.json and empty settings files.

Bug #3 (pilot QA): uninstall leaves the sandbox MCP server entry in .mcp.json
and an empty .claude/settings.local.json.

Covers:
- Uninstall removes our MCP entry from .mcp.json
- If .mcp.json is empty afterwards, it is deleted
- Same for .claude/settings.local.json
- .claude/ dir removed when empty
- Pre-existing user MCP servers and hooks are preserved
- With no user entries, files and dirs are removed; porcelain is clean
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from sandbox.connector.layout import FolderLayout


def _git(args, cwd):
    return subprocess.run(
        ["git"] + args, cwd=str(cwd),
        capture_output=True, text=True, timeout=10,
    )


def _porcelain(cwd):
    return _git(["status", "--porcelain"], cwd).stdout


# ------------------------------------------------------------------ basic
def test_uninstall_removes_mcp_entry(tmp_path):
    """Uninstall removes the sandbox entry from .mcp.json."""
    from sandbox.connector.install import init_folder, uninstall_folder

    init_folder(tmp_path, claude=False, mcp=True, no_canaries=True)
    mcp = tmp_path / ".mcp.json"
    assert mcp.is_file()
    data = json.loads(mcp.read_text(encoding="utf-8"))
    assert "sandbox" in data.get("mcpServers", {})

    uninstall_folder(tmp_path)
    # .mcp.json should be gone (no other servers)
    assert not mcp.is_file(), ".mcp.json should be deleted when empty"


def test_uninstall_removes_empty_settings(tmp_path):
    """Uninstall removes empty .claude/settings.local.json and .claude/ dir."""
    from sandbox.connector.install import init_folder, uninstall_folder

    init_folder(tmp_path, claude=True, mcp=False, no_canaries=True)
    settings = tmp_path / ".claude" / "settings.local.json"
    assert settings.is_file()

    uninstall_folder(tmp_path)
    # With no user hooks, settings file should be gone
    assert not settings.is_file(), "settings.local.json should be deleted when empty"
    # .claude/ dir should be gone too
    assert not (tmp_path / ".claude").is_dir(), ".claude/ should be removed when empty"


def test_uninstall_preserves_user_mcp_server(tmp_path):
    """Uninstall keeps user's own MCP server entries."""
    from sandbox.connector.install import init_folder, uninstall_folder

    # Create a pre-existing .mcp.json with a user server
    mcp = tmp_path / ".mcp.json"
    mcp.write_text(json.dumps({
        "mcpServers": {
            "my-server": {
                "type": "stdio",
                "command": "my-server",
                "args": [],
            }
        }
    }), encoding="utf-8")

    init_folder(tmp_path, claude=False, mcp=True, no_canaries=True)
    data = json.loads(mcp.read_text(encoding="utf-8"))
    assert "sandbox" in data["mcpServers"]
    assert "my-server" in data["mcpServers"]

    uninstall_folder(tmp_path)
    # .mcp.json should still exist with the user's server
    assert mcp.is_file()
    data = json.loads(mcp.read_text(encoding="utf-8"))
    assert "sandbox" not in data.get("mcpServers", {})
    assert "my-server" in data["mcpServers"]


def test_uninstall_preserves_user_hooks(tmp_path):
    """Uninstall keeps user's own hook entries in settings."""
    from sandbox.connector.install import init_folder, uninstall_folder

    # Create a pre-existing settings with a user hook
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = claude_dir / "settings.local.json"
    settings.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "my-hook"}]
            }]
        }
    }), encoding="utf-8")

    init_folder(tmp_path, claude=True, mcp=False, no_canaries=True)
    uninstall_folder(tmp_path)

    # Settings should still have the user hook
    assert settings.is_file()
    data = json.loads(settings.read_text(encoding="utf-8"))
    pre_entries = data.get("hooks", {}).get("PreToolUse", [])
    assert len(pre_entries) == 1
    assert pre_entries[0]["hooks"][0]["command"] == "my-hook"


def test_uninstall_clean_porcelain(tmp_path):
    """After full init+uninstall with no user files, git status is clean."""
    _git(["init", "-q"], tmp_path)
    _git(["config", "user.email", "t@t"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)

    from sandbox.connector.install import init_folder, uninstall_folder

    init_folder(tmp_path, claude=True, mcp=True, no_canaries=True)
    uninstall_folder(tmp_path)

    status = _porcelain(tmp_path)
    # Nothing should be left
    assert status.strip() == "", f"porcelain not clean: {status}"


def test_cli_uninstall_cleanup(tmp_path):
    """CLI uninstall cleans up .mcp.json and empty settings."""
    from sandbox.cli.connector_cmds import init_cmd, uninstall_cmd

    _git(["init", "-q"], tmp_path)

    runner = CliRunner()
    r = runner.invoke(init_cmd, [str(tmp_path), "--no-canaries"])
    assert r.exit_code == 0, f"init failed: {r.output}"

    r = runner.invoke(uninstall_cmd, [str(tmp_path), "--yes"])
    assert r.exit_code == 0, f"uninstall failed: {r.output}"

    # Everything should be gone
    assert not (tmp_path / ".mcp.json").is_file()
    assert not (tmp_path / ".claude").is_dir()
    status = _porcelain(tmp_path)
    assert status.strip() == "", f"porcelain not clean: {status}"
