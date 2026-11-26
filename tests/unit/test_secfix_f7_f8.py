"""Tests for security review findings F7 and F8.

F7: agy/gemini hook commands must quote the interpreter path (spaces in path).
F8: ai status/on must use aikey.key_source() + mask(get_key()), not raw env checks.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


# ------------------------------------------------------------------ F7: quoted interpreter


def test_agy_hook_command_quoted_spaces(tmp_path, monkeypatch):
    """An interpreter path with spaces is quoted in the agy hook command."""
    import subprocess
    from sandbox.connector.install import init_folder

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)

    # Pretend the interpreter has spaces in its path
    fake_python = str(tmp_path / "Program Files" / "Python" / "python.exe")
    monkeypatch.setattr("sys.executable", fake_python)

    init_folder(tmp_path, claude=False, mcp=False, agy=True)

    hooks_file = tmp_path / ".agents" / "hooks.json"
    data = json.loads(hooks_file.read_text(encoding="utf-8"))
    cmd = data["agg-security-layer"]["PreToolUse"][0]["hooks"][0]["command"]
    # The interpreter path must be quoted
    assert cmd.startswith('"'), f"command not quoted: {cmd}"
    assert f'"{fake_python}"' in cmd


def test_gemini_hook_command_quoted_spaces(tmp_path, monkeypatch):
    """An interpreter path with spaces is quoted in the gemini hook command."""
    import subprocess
    from sandbox.connector.install import init_folder

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)

    fake_python = str(tmp_path / "Program Files" / "Python" / "python.exe")
    monkeypatch.setattr("sys.executable", fake_python)

    init_folder(tmp_path, claude=False, mcp=False, gemini=True)

    settings = tmp_path / ".gemini" / "settings.json"
    data = json.loads(settings.read_text(encoding="utf-8"))
    cmd = data["hooks"]["BeforeTool"][0]["hooks"][0]["command"]
    assert cmd.startswith('"'), f"command not quoted: {cmd}"
    assert f'"{fake_python}"' in cmd


# ------------------------------------------------------------------ F8: ai status key source


@pytest.fixture
def versioned_workspace(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(json.dumps({"session_id": "s-f8"}), encoding="utf-8")
    from sandbox.connector.policy_versions import baseline
    baseline(lo, "tester", "initial")
    return lo


def test_ai_status_shows_key_source_env(versioned_workspace, monkeypatch):
    """ai status shows 'env' and masked key when GEMINI_API_KEY is set."""
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyB1234567890abcdefghij")
    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["status", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0
    out = r.output
    assert "env" in out.lower()
    # Must show masked key (first 4 + ... + last 4)
    assert "AIza" in out
    assert "ghij" in out
    # Must NOT show the full key
    assert "AIzaSyB1234567890abcdefghij" not in out


def test_ai_status_shows_not_set(versioned_workspace, monkeypatch):
    """ai status shows 'not set' when no key is available."""
    for k in list(os.environ):
        if k.startswith("GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
    # Also ensure no key file
    monkeypatch.setattr("sandbox.connector.aikey.key_file_path", lambda: None)

    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["status", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0
    out = r.output.lower()
    assert "not set" in out


def test_ai_on_warns_using_aikey(versioned_workspace, monkeypatch):
    """ai on uses aikey module for the key check, not raw env."""
    for k in list(os.environ):
        if k.startswith("GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("sandbox.connector.aikey.key_file_path", lambda: None)

    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["on", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0
    out = r.output.lower()
    # Must warn about no key
    assert "not set" in out or "gemini" in out


def test_ai_on_shows_key_source_when_present(versioned_workspace, monkeypatch):
    """ai on confirms key visibility with source and masked value."""
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyXXXXXXXXXXXXXXXXXXYZ")

    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["on", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0
    out = r.output
    assert "env" in out.lower()
    assert "AIza" in out
    # Full key must not appear
    assert "AIzaSyXXXXXXXXXXXXXXXXXXYZ" not in out
