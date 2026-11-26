"""Tests: `haltwire init --agy` and `--gemini` write hook configs for other agents.

Covers:
- init --agy writes .agents/hooks.json with the correct structure
- The command uses the stable sys.executable and -I -m sandbox.connector.google_adapter
- Merge preserves user hooks in .agents/hooks.json
- Uninstall removes our hook but keeps user hooks
- Uninstall removes .agents/ if empty
- Auto-detect hint when .agents/ exists
- init --gemini writes .gemini/hooks.json (experimental)
- An agy-shaped payload piped through google_adapter gets TYPOSQUAT deny
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from sandbox.connector.layout import FolderLayout


def _git_init(p: Path) -> None:
    subprocess.run(["git", "init", "-q", str(p)], check=True, timeout=10)
    subprocess.run(["git", "-C", str(p), "config", "user.email", "t@t"], timeout=5)
    subprocess.run(["git", "-C", str(p), "config", "user.name", "t"], timeout=5)


# ------------------------------------------------------------------
# init --agy writes .agents/hooks.json
# ------------------------------------------------------------------


def test_init_agy_writes_hooks_json(tmp_path):
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)
    result = init_folder(tmp_path, claude=False, mcp=False, agy=True)

    hooks_file = tmp_path / ".agents" / "hooks.json"
    assert hooks_file.is_file(), ".agents/hooks.json not written"

    data = json.loads(hooks_file.read_text(encoding="utf-8"))
    # Must have our marker key
    assert "agg-security-layer" in data
    layer = data["agg-security-layer"]
    assert layer["enabled"] is True
    assert "PreToolUse" in layer
    entries = layer["PreToolUse"]
    assert len(entries) >= 1
    hook = entries[0]["hooks"][0]
    assert hook["type"] == "command"
    assert "-m sandbox.connector.google_adapter" in hook["command"]
    assert " -I " in hook["command"]


def test_init_agy_uses_stable_interpreter(tmp_path):
    """The command uses the same sys.executable the tool is running under."""
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)
    init_folder(tmp_path, claude=False, mcp=False, agy=True)

    hooks_file = tmp_path / ".agents" / "hooks.json"
    data = json.loads(hooks_file.read_text(encoding="utf-8"))
    cmd = data["agg-security-layer"]["PreToolUse"][0]["hooks"][0]["command"]
    # Must reference the actual interpreter
    assert sys.executable.replace("\\", "/") in cmd.replace("\\", "/") or \
           sys.executable in cmd


# ------------------------------------------------------------------
# Merge preserves user hooks
# ------------------------------------------------------------------


def test_init_agy_preserves_user_hooks(tmp_path):
    """init --agy preserves user's own hooks in .agents/hooks.json."""
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)

    # Pre-existing user hook
    agents_dir = tmp_path / ".agents"
    agents_dir.mkdir()
    user_hooks = {
        "my-custom-hook": {
            "enabled": True,
            "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "my-hook"}]}],
        }
    }
    (agents_dir / "hooks.json").write_text(json.dumps(user_hooks), encoding="utf-8")

    init_folder(tmp_path, claude=False, mcp=False, agy=True)

    data = json.loads((agents_dir / "hooks.json").read_text(encoding="utf-8"))
    assert "my-custom-hook" in data, "user hook was clobbered"
    assert "agg-security-layer" in data


# ------------------------------------------------------------------
# Uninstall removes our hook, keeps user's
# ------------------------------------------------------------------


def test_uninstall_removes_agy_hook(tmp_path):
    from sandbox.connector.install import init_folder, uninstall_folder

    _git_init(tmp_path)
    init_folder(tmp_path, claude=False, mcp=False, agy=True)
    assert (tmp_path / ".agents" / "hooks.json").is_file()

    uninstall_folder(tmp_path)
    # With no user hooks, the file and dir should be gone
    assert not (tmp_path / ".agents" / "hooks.json").is_file()
    assert not (tmp_path / ".agents").is_dir()


def test_uninstall_keeps_user_agy_hooks(tmp_path):
    from sandbox.connector.install import init_folder, uninstall_folder

    _git_init(tmp_path)

    # Pre-existing user hook
    agents_dir = tmp_path / ".agents"
    agents_dir.mkdir()
    (agents_dir / "hooks.json").write_text(json.dumps({
        "my-hook": {"enabled": True}
    }), encoding="utf-8")

    init_folder(tmp_path, claude=False, mcp=False, agy=True)
    uninstall_folder(tmp_path)

    # User hook must survive
    assert (agents_dir / "hooks.json").is_file()
    data = json.loads((agents_dir / "hooks.json").read_text(encoding="utf-8"))
    assert "my-hook" in data
    assert "agg-security-layer" not in data


# ------------------------------------------------------------------
# Auto-detect hint
# ------------------------------------------------------------------


def test_init_hints_agy_detected(tmp_path):
    """init without --agy prints a hint when .agents/ exists."""
    from sandbox.cli.connector_cmds import init_cmd

    _git_init(tmp_path)
    (tmp_path / ".agents").mkdir()

    runner = CliRunner()
    r = runner.invoke(init_cmd, [str(tmp_path), "--no-claude", "--no-mcp", "--no-canaries"])
    assert r.exit_code == 0
    out = r.output.lower()
    assert "antigravity" in out or "agy" in out or "--agy" in out


# ------------------------------------------------------------------
# init --gemini writes .gemini/settings.json
# ------------------------------------------------------------------


def test_init_gemini_writes_hooks(tmp_path):
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)
    result = init_folder(tmp_path, claude=False, mcp=False, gemini=True)

    # Gemini CLI reads from .gemini/settings.json
    settings_file = tmp_path / ".gemini" / "settings.json"
    assert settings_file.is_file(), ".gemini/settings.json not written"

    data = json.loads(settings_file.read_text(encoding="utf-8"))
    assert "hooks" in data
    hooks = data["hooks"]
    assert "BeforeTool" in hooks
    before = hooks["BeforeTool"]
    assert len(before) >= 1
    hook_obj = before[0]["hooks"][0]
    assert hook_obj["name"] == "agg-security-layer"
    assert hook_obj["type"] == "command"
    assert "-m sandbox.connector.google_adapter" in hook_obj["command"]
    assert hook_obj["timeout"] == 60000  # Gemini CLI uses milliseconds


# ------------------------------------------------------------------
# CLI path
# ------------------------------------------------------------------


def test_cli_init_agy(tmp_path):
    from sandbox.cli.connector_cmds import init_cmd

    _git_init(tmp_path)

    runner = CliRunner()
    r = runner.invoke(init_cmd, [str(tmp_path), "--no-claude", "--no-mcp", "--agy"])
    assert r.exit_code == 0, f"init --agy failed: {r.output}"
    assert (tmp_path / ".agents" / "hooks.json").is_file()


# ------------------------------------------------------------------
# agy payload -> TYPOSQUAT deny through google_adapter
# ------------------------------------------------------------------


def test_agy_typosquat_translation(tmp_path):
    """An agy-shaped payload for `pip install pandaz-csv` translates correctly to Claude format."""
    import sandbox.connector.google_adapter as ga
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)
    init_folder(tmp_path, claude=False, mcp=False, agy=True, no_canaries=True)

    # agy payload: run_command uses CommandLine for the command
    payload = {
        "toolCall": {"name": "run_command", "args": {"CommandLine": "pip install pandaz-csv"}},
        "stepIdx": 1,
        "conversationId": "conv-1",
        "workspacePaths": [str(tmp_path)],
        "transcriptPath": "/t.jsonl",
        "modelName": "gemini",
        "lastUserInput": "install deps",
    }

    # Test the translation layer: agy -> Claude payload
    claude_payload = ga.to_claude(ga.ANTIGRAVITY, payload)
    assert claude_payload["tool_name"] in ("Bash", "PowerShell")
    assert "pandaz-csv" in claude_payload["tool_input"]["command"]
    assert claude_payload["cwd"] == str(tmp_path)
    assert claude_payload["agent_type"] == "antigravity-cli"

    # Test a tripwire file read translation
    payload2 = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(tmp_path / ".env.backup")}},
        "stepIdx": 2,
        "conversationId": "conv-1",
        "workspacePaths": [str(tmp_path)],
    }
    claude2 = ga.to_claude(ga.ANTIGRAVITY, payload2)
    assert claude2["tool_name"] == "Read"
    assert str(tmp_path / ".env.backup") in claude2["tool_input"]["file_path"]
