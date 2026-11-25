"""Tests: sandbox unfreeze CLI command.

unfreeze requires a pinned reviewer signing key, writes a signed audit record
(signing.sign_record), then clears the quarantine flag. status shows
FROZEN plus the reason.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy
from sandbox.connector.signing import verify_record


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(
        json.dumps({"session_id": "s-uf"}), encoding="utf-8"
    )
    return lo


@pytest.fixture
def frozen_layout(layout):
    """A layout with quarantine flag set."""
    qf = layout.state_dir / "quarantine.json"
    qf.write_text(json.dumps({
        "reason": "tripwire_stop",
        "stopped_at": 1700000000.0,
        "trip_kind": "decoy_read",
    }), encoding="utf-8")
    return layout


def _pin_reviewer(layout, reviewer_id="reviewer-1"):
    """Create and pin a key for a reviewer, returning the pub hex."""
    from sandbox.connector.keyhome import write_pin
    from sandbox.connector.signing import _load_or_create_key

    key = _load_or_create_key(layout, reviewer_id)
    pub_hex = bytes(key.verify_key).hex()
    write_pin(layout, reviewer_id, pub_hex)
    return pub_hex


def test_status_shows_frozen(frozen_layout):
    """sandbox status shows FROZEN when quarantine flag exists."""
    from sandbox.cli.connector_cmds import status_cmd

    runner = CliRunner()
    result = runner.invoke(status_cmd, [str(frozen_layout.root)])
    assert result.exit_code == 0
    assert "FROZEN" in result.output or "frozen" in result.output.lower()


def test_unfreeze_clears_flag(frozen_layout):
    """sandbox unfreeze clears the quarantine flag with a pinned reviewer."""
    from sandbox.cli.connector_cmds import unfreeze_cmd

    _pin_reviewer(frozen_layout, "reviewer-1")

    runner = CliRunner()
    result = runner.invoke(unfreeze_cmd, [
        "--path", str(frozen_layout.root),
        "--reviewer", "reviewer-1",
    ])
    assert result.exit_code == 0
    qf = frozen_layout.state_dir / "quarantine.json"
    assert not qf.exists()


def test_unfreeze_writes_signed_record(frozen_layout):
    """unfreeze writes a signed audit record."""
    from sandbox.cli.connector_cmds import unfreeze_cmd
    from sandbox.connector.audit import FolderAudit

    _pin_reviewer(frozen_layout, "reviewer-1")

    runner = CliRunner()
    result = runner.invoke(unfreeze_cmd, [
        "--path", str(frozen_layout.root),
        "--reviewer", "reviewer-1",
    ])
    assert result.exit_code == 0

    # Check the audit record
    audit = FolderAudit(frozen_layout.audit_dir, "s-uf")
    records = audit.records_file.read_text(encoding="utf-8").strip().splitlines()
    last = json.loads(records[-1])
    assert last.get("event") == "unfreeze"
    assert "signature" in last


def test_unfreeze_fails_unpinned(frozen_layout):
    """unfreeze fails if the reviewer has no pinned key."""
    from sandbox.cli.connector_cmds import unfreeze_cmd

    runner = CliRunner()
    result = runner.invoke(unfreeze_cmd, [
        "--path", str(frozen_layout.root),
        "--reviewer", "nobody",
    ])
    assert result.exit_code != 0
    # Flag must still exist
    qf = frozen_layout.state_dir / "quarantine.json"
    assert qf.is_file()


def test_unfreeze_noop_when_not_frozen(layout):
    """unfreeze on a non-frozen workspace is a no-op."""
    from sandbox.cli.connector_cmds import unfreeze_cmd

    _pin_reviewer(layout, "reviewer-1")

    runner = CliRunner()
    result = runner.invoke(unfreeze_cmd, [
        "--path", str(layout.root),
        "--reviewer", "reviewer-1",
    ])
    # Should succeed but indicate nothing to unfreeze
    assert result.exit_code == 0
    assert "not frozen" in result.output.lower() or "not quarantined" in result.output.lower()


def test_unfreeze_clears_canary_taint_without_freeze(layout):
    """A canary seen in tool output taints the session without freezing it;
    unfreeze (pinned reviewer) clears the taint so network calls work again."""
    from sandbox.cli.connector_cmds import unfreeze_cmd

    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({"event": "canary_taint"}), encoding="utf-8")
    _pin_reviewer(layout, "reviewer-1")

    runner = CliRunner()
    result = runner.invoke(unfreeze_cmd, [
        "--path", str(layout.root),
        "--reviewer", "reviewer-1",
    ])
    assert result.exit_code == 0, result.output
    assert not taint.exists()
    assert not (layout.state_dir / "quarantine.json").exists()


def test_unfreeze_unpinned_keeps_canary_taint(layout):
    """An unpinned reviewer cannot clear canary taint."""
    from sandbox.cli.connector_cmds import unfreeze_cmd

    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({"event": "canary_taint"}), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(unfreeze_cmd, [
        "--path", str(layout.root),
        "--reviewer", "nobody",
    ])
    assert result.exit_code != 0
    assert taint.is_file()
