"""Tests: canary / decoy git integration with real git repos.

Covers:
- Root init: decoys and .sandbox/state excluded from git status
- Monorepo subfolder init: exclude is written correctly
- Git worktree (.git is a file): exclude is found via rev-parse
- Non-git folder: no error, .sandbox/state/.gitignore still written
- .sandbox/state/.gitignore contains '*'
- Idempotent re-init: no duplicate exclude lines, no re-plant over existing
- init --no-canaries on already-initialised folder: removes decoys and canaries.json
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git"] + args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=10,
    )


def _porcelain(cwd: Path) -> str:
    r = _git(["status", "--porcelain"], cwd)
    return r.stdout


def _init_git(path: Path) -> None:
    _git(["init", "-q"], path)
    _git(["config", "user.email", "test@test.com"], path)
    _git(["config", "user.name", "test"], path)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def git_root(tmp_path):
    """A fresh git repo in tmp_path."""
    _init_git(tmp_path)
    return tmp_path


# ------------------------------------------------------------------
# 1. Root init: porcelain shows no decoys and no .sandbox/state files
# ------------------------------------------------------------------


def test_root_init_clean_porcelain(git_root):
    from sandbox.connector.install import init_folder

    init_folder(git_root, claude=False, mcp=False)

    status = _porcelain(git_root)
    for decoy in (".env.backup", "deploy_key.pem", ".aws/credentials.bak"):
        assert decoy not in status, f"decoy {decoy} visible in git status"
    assert ".sandbox/state" not in status, ".sandbox/state visible in git status"


def test_root_init_state_gitignore(git_root):
    from sandbox.connector.install import init_folder

    init_folder(git_root, claude=False, mcp=False)

    gi = git_root / ".sandbox" / "state" / ".gitignore"
    assert gi.is_file()
    assert "*" in gi.read_text(encoding="utf-8")


# ------------------------------------------------------------------
# 2. Monorepo subfolder init
# ------------------------------------------------------------------


def test_subfolder_init_clean_porcelain(git_root):
    """init in a subfolder of a git repo: decoys are excluded from the root."""
    from sandbox.connector.install import init_folder

    sub = git_root / "services" / "api"
    sub.mkdir(parents=True)

    init_folder(sub, claude=False, mcp=False)

    status = _porcelain(git_root)
    for decoy in (".env.backup", "deploy_key.pem", ".aws/credentials.bak"):
        assert decoy not in status, f"decoy {decoy} visible in root git status"
    assert ".sandbox/state" not in status


# ------------------------------------------------------------------
# 3. Git worktree (.git is a file)
# ------------------------------------------------------------------


def test_worktree_clean_porcelain(git_root):
    """init in a git worktree: .git is a file, exclude still found."""
    from sandbox.connector.install import init_folder

    # Create an initial commit so we can create a worktree
    dummy = git_root / "README.md"
    dummy.write_text("hi", encoding="utf-8")
    _git(["add", "README.md"], git_root)
    _git(["commit", "-m", "init"], git_root)

    wt = git_root.parent / "wt"
    result = _git(["worktree", "add", str(wt), "-b", "wt-branch"], git_root)
    if result.returncode != 0:
        pytest.skip("git worktree add failed")

    # .git is a file in a worktree
    assert (wt / ".git").is_file(), ".git should be a file in a worktree"

    init_folder(wt, claude=False, mcp=False)

    status = _porcelain(wt)
    for decoy in (".env.backup", "deploy_key.pem", ".aws/credentials.bak"):
        assert decoy not in status, f"decoy {decoy} visible in worktree git status"


# ------------------------------------------------------------------
# 4. Non-git folder: no error
# ------------------------------------------------------------------


def test_non_git_no_error(tmp_path):
    """init in a non-git folder does not raise; state .gitignore still written."""
    from sandbox.connector.install import init_folder

    init_folder(tmp_path, claude=False, mcp=False)

    # Canaries are planted even without git
    from sandbox.connector.layout import FolderLayout
    lo = FolderLayout(tmp_path)
    assert (lo.state_dir / "canaries.json").is_file()
    # .gitignore is written so a later `git init` does not pick up state
    gi = lo.state_dir / ".gitignore"
    assert gi.is_file()
    assert "*" in gi.read_text(encoding="utf-8")


def test_non_git_later_git_init_clean(tmp_path):
    """After init_folder in a non-git dir, a subsequent git init keeps state excluded."""
    from sandbox.connector.install import init_folder

    init_folder(tmp_path, claude=False, mcp=False)
    _init_git(tmp_path)

    status = _porcelain(tmp_path)
    # .sandbox/state files should not appear because of .gitignore
    assert ".sandbox/state/canaries.json" not in status
    assert ".sandbox/state/quarantine.json" not in status


# ------------------------------------------------------------------
# 5. Idempotent re-init
# ------------------------------------------------------------------


def test_reinit_no_duplicate_excludes(git_root):
    """Re-running init does not duplicate exclude lines."""
    from sandbox.connector.install import init_folder

    init_folder(git_root, claude=False, mcp=False)
    init_folder(git_root, claude=False, mcp=False)

    # Find the exclude file
    r = _git(["-C", str(git_root), "rev-parse", "--git-path", "info/exclude"], git_root)
    if r.returncode != 0:
        pytest.skip("cannot find exclude file")
    exclude_path = Path(r.stdout.strip())
    if not exclude_path.is_absolute():
        exclude_path = git_root / exclude_path
    text = exclude_path.read_text(encoding="utf-8")
    # Each decoy path should appear exactly once
    assert text.count(".env.backup") == 1
    assert text.count("deploy_key.pem") == 1


def test_reinit_no_clobber_existing_decoy(git_root):
    """Re-init does not overwrite an existing decoy file (plant skips it)."""
    from sandbox.connector.install import init_folder

    init_folder(git_root, claude=False, mcp=False)

    # Modify a decoy
    decoy = git_root / ".env.backup"
    original = decoy.read_text(encoding="utf-8")
    decoy.write_text("MY_REAL=secret\n", encoding="utf-8")

    # Re-init should not overwrite
    init_folder(git_root, claude=False, mcp=False)
    assert decoy.read_text(encoding="utf-8") == "MY_REAL=secret\n"


# ------------------------------------------------------------------
# 6. init --no-canaries disables existing canaries
# ------------------------------------------------------------------


def test_no_canaries_reinit_removes(git_root):
    """init --no-canaries on an already-initialised folder removes unchanged decoys."""
    from sandbox.connector.install import init_folder
    from sandbox.connector.layout import FolderLayout

    init_folder(git_root, claude=False, mcp=False)
    lo = FolderLayout(git_root)
    assert (lo.state_dir / "canaries.json").is_file()
    assert (git_root / ".env.backup").is_file()

    # Re-init with --no-canaries
    init_folder(git_root, no_canaries=True, claude=False, mcp=False)
    assert not (lo.state_dir / "canaries.json").is_file()
    assert not (git_root / ".env.backup").is_file()


def test_no_canaries_reinit_keeps_modified_decoy(git_root):
    """init --no-canaries keeps a user-modified decoy file."""
    from sandbox.connector.install import init_folder
    from sandbox.connector.layout import FolderLayout

    init_folder(git_root, claude=False, mcp=False)

    # Modify a decoy
    (git_root / ".env.backup").write_text("MY_REAL=secret\n", encoding="utf-8")

    init_folder(git_root, no_canaries=True, claude=False, mcp=False)
    lo = FolderLayout(git_root)
    # canaries.json removed but modified decoy stays
    assert not (lo.state_dir / "canaries.json").is_file()
    assert (git_root / ".env.backup").is_file()
    assert (git_root / ".env.backup").read_text(encoding="utf-8") == "MY_REAL=secret\n"


# ------------------------------------------------------------------
# 7. CLI-level tests via click.testing.CliRunner
# ------------------------------------------------------------------


def test_cli_init_uninstall_roundtrip(git_root):
    """CLI init then uninstall: decoys planted and removed, porcelain clean throughout."""
    from click.testing import CliRunner
    from sandbox.cli.connector_cmds import init_cmd, uninstall_cmd

    runner = CliRunner()

    # Init (--no-claude to avoid touching real claude settings)
    r = runner.invoke(init_cmd, [str(git_root), "--no-claude"])
    assert r.exit_code == 0, f"init failed: {r.output}"

    status = _porcelain(git_root)
    for decoy in (".env.backup", "deploy_key.pem", ".aws/credentials.bak"):
        assert decoy not in status

    # Uninstall
    r = runner.invoke(uninstall_cmd, [str(git_root), "--yes"])
    assert r.exit_code == 0, f"uninstall failed: {r.output}"

    # Decoys removed
    assert not (git_root / ".env.backup").is_file()
    assert not (git_root / "deploy_key.pem").is_file()


def test_cli_init_no_canaries(git_root):
    """CLI init --no-canaries: no decoys, no canaries.json."""
    from click.testing import CliRunner
    from sandbox.cli.connector_cmds import init_cmd

    runner = CliRunner()
    r = runner.invoke(init_cmd, [str(git_root), "--no-claude", "--no-canaries"])
    assert r.exit_code == 0

    from sandbox.connector.layout import FolderLayout
    lo = FolderLayout(git_root)
    assert not (lo.state_dir / "canaries.json").is_file()
    assert not (git_root / ".env.backup").is_file()
