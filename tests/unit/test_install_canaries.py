"""Tests: sandbox init plants canaries, uninstall removes them.

Canaries planted in .sandbox/state/canaries.json, decoy paths added to
.git/info/exclude, and canaries.json + task.txt are unreadable via Read
(added to classify._KEY_SEQS).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(
        json.dumps({"session_id": "s-inst"}), encoding="utf-8"
    )
    return lo


def test_init_plants_canaries(tmp_path):
    """sandbox init creates canary files and stores canaries.json."""
    import subprocess
    from sandbox.connector.install import init_folder
    from sandbox.connector.layout import FolderLayout

    # Use a real git repo
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)

    init_folder(tmp_path)

    lo = FolderLayout(tmp_path)
    canary_file = lo.state_dir / "canaries.json"
    assert canary_file.exists()
    canaries = json.loads(canary_file.read_text(encoding="utf-8"))
    assert "aws_access_key" in canaries
    assert "stripe_key" in canaries

    # Decoy files must exist
    assert (tmp_path / ".env.backup").exists()
    assert (tmp_path / "deploy_key.pem").exists()


def test_init_no_canaries_flag(tmp_path):
    """sandbox init --no-canaries skips planting."""
    from sandbox.connector.install import init_folder

    init_folder(tmp_path, no_canaries=True)

    lo = FolderLayout(tmp_path)
    canary_file = lo.state_dir / "canaries.json"
    assert not canary_file.exists()
    assert not (tmp_path / ".env.backup").exists()


def test_git_exclude_has_decoys(tmp_path):
    """Decoy paths are added to .git/info/exclude."""
    import subprocess
    from sandbox.connector.install import init_folder

    # Use a real git repo so rev-parse can find the exclude file
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)

    init_folder(tmp_path)

    # Find the exclude file via rev-parse (same as production code)
    r = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "--git-path", "info/exclude"],
        capture_output=True, text=True, timeout=5,
    )
    exclude_path = Path(r.stdout.strip())
    if not exclude_path.is_absolute():
        exclude_path = tmp_path / exclude_path
    exclude = exclude_path.read_text(encoding="utf-8")
    assert ".env.backup" in exclude
    assert "deploy_key.pem" in exclude
    assert ".aws/credentials.bak" in exclude


def test_uninstall_removes_decoys(tmp_path):
    """sandbox uninstall removes decoy files."""
    import subprocess
    from sandbox.connector.install import init_folder, uninstall_folder

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)

    init_folder(tmp_path)
    assert (tmp_path / ".env.backup").exists()

    uninstall_folder(tmp_path)
    assert not (tmp_path / ".env.backup").exists()
    assert not (tmp_path / "deploy_key.pem").exists()


def test_classify_denies_canaries_read(layout):
    """classify blocks Read of .sandbox/state/canaries.json."""
    from sandbox.connector.classify import classify
    from sandbox.connector.policy import load_policy

    policy = load_policy(layout.policy_file)
    result = classify(
        "Read",
        {"file_path": str(layout.state_dir / "canaries.json")},
        policy,
        layout,
        cwd=str(layout.root),
    )
    assert result.verdict == "deny"


def test_classify_denies_task_txt_read(layout):
    """classify blocks Read of .sandbox/state/task.txt."""
    from sandbox.connector.classify import classify
    from sandbox.connector.policy import load_policy

    policy = load_policy(layout.policy_file)
    result = classify(
        "Read",
        {"file_path": str(layout.state_dir / "task.txt")},
        policy,
        layout,
        cwd=str(layout.root),
    )
    assert result.verdict == "deny"
