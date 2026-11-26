"""Tests: `haltwire ai` CLI group (on/off/status).

Covers:
- ai on: sets policy.intent.enabled=True, versioned policy change
- ai on --timeout N: sets timeout_seconds (1..20)
- ai off: refuses without second reviewer (loosening change)
- ai status: shows enabled, timeout, key visibility, google-genai installed
- classify denies `haltwire ai on` as APPROVER_CLI
"""
from __future__ import annotations

import json
import os

import pytest
from click.testing import CliRunner

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, load_policy, save_policy


@pytest.fixture
def workspace(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(
        json.dumps({"session_id": "s-ai"}), encoding="utf-8"
    )
    return lo


@pytest.fixture
def versioned_workspace(workspace):
    """A workspace with an initial policy version (baseline)."""
    from sandbox.connector.policy_versions import baseline
    baseline(workspace, "tester", "initial")
    return workspace


# ------------------------------------------------------------------ ai on


def test_ai_on_enables_intent(versioned_workspace):
    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["on", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0, f"exit {r.exit_code}: {r.output}"

    policy = load_policy(versioned_workspace.policy_file)
    assert policy.intent.enabled is True


def test_ai_on_with_timeout(versioned_workspace):
    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["on", "--timeout", "15", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0, f"exit {r.exit_code}: {r.output}"

    policy = load_policy(versioned_workspace.policy_file)
    assert policy.intent.enabled is True
    assert policy.intent.timeout_seconds == 15


def test_ai_on_warns_no_key(versioned_workspace, monkeypatch):
    """ai on warns when no GEMINI_API_KEY is set."""
    for k in list(os.environ):
        if k.startswith("GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)

    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["on", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0
    out = r.output.lower()
    assert "gemini_api_key" in out or "key" in out


def test_ai_on_survives_load(versioned_workspace):
    """After ai on, the policy round-trips correctly."""
    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    runner.invoke(ai_group, ["on", "--path", str(versioned_workspace.root)])

    # Round-trip
    policy = load_policy(versioned_workspace.policy_file)
    assert policy.intent.enabled is True
    save_policy(policy, versioned_workspace.policy_file)
    policy2 = load_policy(versioned_workspace.policy_file)
    assert policy2.intent.enabled is True


# ------------------------------------------------------------------ ai off


def test_ai_off_refuses_without_second_reviewer(versioned_workspace):
    """ai off is a loosening change and must be refused without the proper flow."""
    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    # First enable
    runner.invoke(ai_group, ["on", "--path", str(versioned_workspace.root)])

    # Then try to disable
    r = runner.invoke(ai_group, ["off", "--path", str(versioned_workspace.root)])
    # Should refuse (exit non-zero or contain a refusal message)
    assert r.exit_code != 0 or "loosen" in r.output.lower() or "two" in r.output.lower() or "propose" in r.output.lower()


# ------------------------------------------------------------------ ai status


def test_ai_status_shows_state(versioned_workspace):
    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["status", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0
    out = r.output.lower()
    assert "enabled" in out
    assert "timeout" in out


def test_ai_status_shows_genai_installed(versioned_workspace):
    from sandbox.cli.ai_cmds import ai_group

    runner = CliRunner()
    r = runner.invoke(ai_group, ["status", "--path", str(versioned_workspace.root)])
    assert r.exit_code == 0
    # Should mention google-genai package status
    assert "google-genai" in r.output.lower() or "genai" in r.output.lower()


# ------------------------------------------------------------------ classify


def test_classify_denies_ai_on(workspace):
    """The agent cannot run `haltwire ai on`."""
    from sandbox.connector.classify import classify

    policy = load_policy(workspace.policy_file)
    result = classify(
        "Bash",
        {"command": "haltwire ai on"},
        policy,
        workspace,
        cwd=str(workspace.root),
    )
    assert result.verdict == "deny"
    assert "APPROVER_CLI" in (result.reason_code or "")


def test_classify_denies_sandbox_ai_status(workspace):
    """The agent cannot run `sandbox ai status`."""
    from sandbox.connector.classify import classify

    policy = load_policy(workspace.policy_file)
    result = classify(
        "Bash",
        {"command": "sandbox ai status"},
        policy,
        workspace,
        cwd=str(workspace.root),
    )
    assert result.verdict == "deny"
    assert "APPROVER_CLI" in (result.reason_code or "")
