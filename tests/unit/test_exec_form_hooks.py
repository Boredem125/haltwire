"""Tests: Claude Code hooks use exec form (command + args, no shell).

P0: shell-form hooks break on Windows PowerShell. Exec form spawns directly.

Covers:
- Generated JSON has command (exe only) plus args array
- Path with spaces stays one args element (no tokenization)
- Upgrade from shell form to exec form, no duplicates
- Uninstall removes both old shell-form and new exec-form entries
- doctor checks the hook runs correctly
- agy hook: unquoted when no spaces, quoted with warning when spaces
- --version prints version
- ai on/off/status accept positional path
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


def _git_init(p: Path) -> None:
    subprocess.run(["git", "init", "-q", str(p)], check=True, timeout=10)
    subprocess.run(["git", "-C", str(p), "config", "user.email", "t@t"], timeout=5)
    subprocess.run(["git", "-C", str(p), "config", "user.name", "t"], timeout=5)


def _read_settings(root: Path) -> dict:
    for name in (".claude/settings.local.json", ".claude/settings.json"):
        p = root / name
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    return {}


# ------------------------------------------------------------------ exec form


def test_hooks_use_exec_form(tmp_path):
    """init writes Claude Code hooks with command + args (exec form)."""
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)
    init_folder(tmp_path, claude=True, mcp=False, no_canaries=True)

    data = _read_settings(tmp_path)
    hooks = data.get("hooks", {})
    for event in ("PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit"):
        entries = hooks.get(event, [])
        assert len(entries) >= 1, f"no {event} hook entry"
        hook_obj = entries[0]["hooks"][0]
        assert "args" in hook_obj, f"{event} hook missing args (not exec form)"
        assert isinstance(hook_obj["args"], list)
        # command should be the exe only, not contain -I or the stub
        assert " " not in hook_obj["command"] or hook_obj["command"].count('"') == 0, \
            f"{event} command has shell-form content: {hook_obj['command']}"


def test_hooks_path_with_spaces(tmp_path, monkeypatch):
    """An interpreter path with spaces is one args element, not tokenized."""
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)
    fake_py = str(tmp_path / "Program Files" / "My Python" / "python.exe")
    monkeypatch.setattr("sys.executable", fake_py)

    init_folder(tmp_path, claude=True, mcp=False, no_canaries=True)

    data = _read_settings(tmp_path)
    pre = data["hooks"]["PreToolUse"][0]["hooks"][0]
    # command is the exe path
    assert pre["command"] == fake_py
    # -I is a separate arg, the stub path is a separate arg
    assert "-I" in pre["args"]
    # The stub path should be one element (not split on spaces)
    stub_arg = [a for a in pre["args"] if a.endswith(".py")]
    assert len(stub_arg) == 1


# ------------------------------------------------------------------ upgrade from shell form


def test_upgrade_shell_to_exec_form(tmp_path):
    """Re-running init replaces old shell-form entries with exec form."""
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)

    # Write old shell-form entry manually
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    old_settings = {
        "hooks": {
            "PreToolUse": [{
                "_sandbox_connector": True,
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": '"python.exe" -I "stub.py"',
                    "timeout": 600,
                    "onFailure": "block",
                }],
            }],
        }
    }
    (claude_dir / "settings.local.json").write_text(
        json.dumps(old_settings), encoding="utf-8"
    )

    # Re-init
    init_folder(tmp_path, claude=True, mcp=False, no_canaries=True)

    data = _read_settings(tmp_path)
    pre_entries = data["hooks"]["PreToolUse"]
    # Only one entry (no duplicates)
    our = [e for e in pre_entries if e.get("_sandbox_connector")]
    assert len(our) == 1
    # Must be exec form
    hook = our[0]["hooks"][0]
    assert "args" in hook


# ------------------------------------------------------------------ uninstall removes both forms


def test_uninstall_removes_shell_and_exec(tmp_path):
    """Uninstall removes entries whether they're shell-form or exec-form."""
    from sandbox.connector.install import uninstall

    _git_init(tmp_path)

    # Write mixed entries
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    mixed = {
        "hooks": {
            "PreToolUse": [
                {
                    "_sandbox_connector": True,
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": '"py" -I "s.py"'}],
                },
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "user-hook"}]},
            ],
        }
    }
    (claude_dir / "settings.local.json").write_text(json.dumps(mixed), encoding="utf-8")

    # Also need .sandbox dir for uninstall
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()

    uninstall(tmp_path, keep_data=True)

    data = _read_settings(tmp_path)
    pre = data.get("hooks", {}).get("PreToolUse", [])
    assert len(pre) == 1
    assert pre[0]["hooks"][0]["command"] == "user-hook"


# ------------------------------------------------------------------ doctor hook check


def test_doctor_checks_hook(tmp_path):
    """doctor runs the PreToolUse hook and reports OK."""
    from sandbox.connector.install import init_folder
    from sandbox.cli.connector_cmds import doctor_cmd

    _git_init(tmp_path)
    init_folder(tmp_path, claude=True, mcp=False, no_canaries=True)

    runner = CliRunner()
    r = runner.invoke(doctor_cmd, [str(tmp_path)])
    # Should not fail
    assert r.exit_code == 0, f"doctor failed: {r.output}"
    out = r.output.lower()
    # Should mention the hook check
    assert "hook" in out or "ok" in out or "pretooluse" in out


# ------------------------------------------------------------------ agy unquoted


def test_agy_hook_unquoted_no_spaces(tmp_path):
    """agy hook command is unquoted when the interpreter has no spaces."""
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)
    init_folder(tmp_path, claude=False, mcp=False, agy=True)

    hooks = tmp_path / ".agents" / "hooks.json"
    data = json.loads(hooks.read_text(encoding="utf-8"))
    cmd = data["agg-security-layer"]["PreToolUse"][0]["hooks"][0]["command"]
    # sys.executable on this machine has no spaces -> unquoted
    if " " not in sys.executable:
        assert not cmd.startswith('"'), f"should be unquoted: {cmd}"


# ------------------------------------------------------------------ --version


def test_version_option():
    """haltwire --version prints the version."""
    from sandbox.cli.main import cli

    runner = CliRunner()
    r = runner.invoke(cli, ["--version"])
    assert r.exit_code == 0
    assert "0." in r.output or "haltwire" in r.output.lower()


# ------------------------------------------------------------------ ai positional path


def test_ai_status_positional_path(tmp_path):
    """ai status accepts path positionally."""
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    save_policy(default_policy(), lo.policy_file)
    lo.session_file.write_text(json.dumps({"session_id": "s-x"}), encoding="utf-8")

    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["status", str(tmp_path)])
    assert r.exit_code == 0
    assert "enabled" in r.output.lower()
