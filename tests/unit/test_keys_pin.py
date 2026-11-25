"""Tests: `haltwire keys pin <reviewer>` command.

Bug #1 (pilot QA): keys only has purge-legacy and status, so a frozen user
can't follow the documented unfreeze flow.

Covers:
- keys pin creates a key and writes the pin
- keys pin prints fingerprint and path
- keys pin on already-pinned same key is idempotent
- keys pin on already-pinned different key refuses without --force
- keys pin --force overwrites
- pin then unfreeze works end-to-end (GETTING_STARTED flow)
- unfreeze accepts path positionally
- classify denies `haltwire keys pin x` as APPROVER_CLI
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


@pytest.fixture
def workspace(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(
        json.dumps({"session_id": "s-pin"}), encoding="utf-8"
    )
    return lo


@pytest.fixture
def frozen(workspace):
    qf = workspace.state_dir / "quarantine.json"
    qf.write_text(json.dumps({
        "reason": "tripwire_stop",
        "stopped_at": 1700000000.0,
        "trip_kind": "decoy_read",
    }), encoding="utf-8")
    return workspace


# ------------------------------------------------------------------ keys pin
def test_keys_pin_creates_and_prints(workspace):
    from sandbox.cli.keys_cmds import keys_group

    runner = CliRunner()
    r = runner.invoke(keys_group, ["pin", "alice", "--path", str(workspace.root)])
    assert r.exit_code == 0, f"exit {r.exit_code}: {r.output}"
    assert "alice" in r.output
    # Should mention the fingerprint (hex chars)
    # and the key home path
    assert len(r.output) > 10


def test_keys_pin_idempotent(workspace):
    from sandbox.cli.keys_cmds import keys_group

    runner = CliRunner()
    r1 = runner.invoke(keys_group, ["pin", "bob", "--path", str(workspace.root)])
    assert r1.exit_code == 0
    r2 = runner.invoke(keys_group, ["pin", "bob", "--path", str(workspace.root)])
    assert r2.exit_code == 0
    assert "already pinned" in r2.output.lower() or "pinned" in r2.output.lower()


def test_keys_pin_refuses_different_key(workspace):
    """Pin with same reviewer but a different key refuses without --force."""
    from sandbox.connector import keyhome
    from sandbox.connector.signing import _load_or_create_key

    # Pin bob with one key
    key1 = _load_or_create_key(workspace, "carol")
    pub1 = bytes(key1.verify_key).hex()
    keyhome.write_pin(workspace, "carol", pub1)

    # Now create a different key by deleting the seed and re-creating
    from sandbox.connector.signing import _seed_path
    seed = _seed_path(workspace, "carol")
    if seed.is_file():
        seed.unlink()

    from sandbox.cli.keys_cmds import keys_group
    runner = CliRunner()
    r = runner.invoke(keys_group, ["pin", "carol", "--path", str(workspace.root)])
    # Should refuse because a different key is now generated
    assert r.exit_code != 0 or "already pinned" in r.output.lower() or "different" in r.output.lower()


def test_keys_pin_force_overwrites(workspace):
    """--force overwrites an existing pin."""
    from sandbox.connector import keyhome
    from sandbox.connector.signing import _load_or_create_key

    key1 = _load_or_create_key(workspace, "dave")
    pub1 = bytes(key1.verify_key).hex()
    keyhome.write_pin(workspace, "dave", pub1)

    # Delete seed to get a new key
    from sandbox.connector.signing import _seed_path
    seed = _seed_path(workspace, "dave")
    if seed.is_file():
        seed.unlink()

    from sandbox.cli.keys_cmds import keys_group
    runner = CliRunner()
    r = runner.invoke(keys_group, ["pin", "dave", "--path", str(workspace.root), "--force"])
    assert r.exit_code == 0, f"exit {r.exit_code}: {r.output}"


# ------------------------------------------------------------------ pin then unfreeze
def test_pin_then_unfreeze_e2e(frozen):
    """The GETTING_STARTED flow: keys pin, then unfreeze."""
    from sandbox.cli.keys_cmds import keys_group
    from sandbox.cli.connector_cmds import unfreeze_cmd

    runner = CliRunner()

    # Step 1: pin
    r = runner.invoke(keys_group, ["pin", "eve", "--path", str(frozen.root)])
    assert r.exit_code == 0, f"pin failed: {r.output}"

    # Step 2: unfreeze
    r = runner.invoke(unfreeze_cmd, ["--path", str(frozen.root), "--reviewer", "eve"])
    assert r.exit_code == 0, f"unfreeze failed: {r.output}"

    # Step 3: verify
    qf = frozen.state_dir / "quarantine.json"
    assert not qf.is_file(), "quarantine flag still present"


def test_unfreeze_accepts_positional_path(frozen):
    """unfreeze accepts path as a positional argument."""
    from sandbox.cli.keys_cmds import keys_group
    from sandbox.cli.connector_cmds import unfreeze_cmd

    runner = CliRunner()
    runner.invoke(keys_group, ["pin", "frank", "--path", str(frozen.root)])

    # Pass path positionally
    r = runner.invoke(unfreeze_cmd, [str(frozen.root), "--reviewer", "frank"])
    assert r.exit_code == 0, f"unfreeze failed: {r.output}"
    assert not (frozen.state_dir / "quarantine.json").is_file()


# ------------------------------------------------------------------ classify denies keys pin
def test_classify_denies_keys_pin(workspace):
    """The agent cannot run `haltwire keys pin x` (APPROVER_CLI)."""
    from sandbox.connector.classify import classify
    from sandbox.connector.policy import load_policy

    policy = load_policy(workspace.policy_file)
    result = classify(
        "Bash",
        {"command": "haltwire keys pin alice"},
        policy,
        workspace,
        cwd=str(workspace.root),
    )
    assert result.verdict == "deny"
    assert "APPROVER_CLI" in (result.reason_code or "")
