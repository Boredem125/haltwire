"""Tests: planted-proof record in the key home prevents mis-adoption.

The key home record (outside the agent-writable workspace) proves we planted
a decoy. Without it, _readopt_decoys refuses to adopt files that happen to
match our format.

Covers:
1. User's real .env.backup in our format, then init, delete canaries.json,
   init: NOT adopted (no key-home record for it).
2. Uninstall leaves the real file byte-identical.
3. Genuine flow (init, delete canaries.json, init) re-adopts via key-home record.
4. Uninstall removes the key-home planted record.
5. init writes the key-home planted record.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from sandbox.connector.layout import FolderLayout


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True, timeout=10)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@t"], timeout=5)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "t"], timeout=5)


def _load_canaries(layout: FolderLayout) -> dict | None:
    cf = layout.state_dir / "canaries.json"
    if not cf.is_file():
        return None
    return json.loads(cf.read_text(encoding="utf-8"))


def _planted_record_path(layout: FolderLayout) -> Path | None:
    """Find the key-home planted record for this workspace."""
    from sandbox.connector import keyhome
    try:
        ws_id = keyhome.workspace_id(layout, create=False)
        kh = keyhome.key_home_root()
        if kh is None:
            return None
        return kh / ws_id / "planted.json"
    except Exception:
        return None


# ------------------------------------------------------------------
# 1. User's real file not adopted
# ------------------------------------------------------------------


def test_real_env_backup_not_adopted(tmp_path):
    """A user's real .env.backup in our format is NOT adopted after canaries.json deleted."""
    from sandbox.connector.install import init_folder
    from sandbox.connector.tripwire import DECOY_PATHS

    _git_init(tmp_path)

    # Create a real user .env.backup that happens to look like our format
    real_content = "STRIPE_SECRET_KEY=sk_live_REAL_USER_KEY_12345678\nDATABASE_URL=postgres://real:pass@host:5432/db\n"
    (tmp_path / ".env.backup").write_text(real_content, encoding="utf-8")
    real_hash = hashlib.sha256((tmp_path / ".env.backup").read_bytes()).hexdigest()

    # Init - plant() will skip .env.backup (already exists), but plant the others
    init_folder(tmp_path, claude=False, mcp=False)
    lo = FolderLayout(tmp_path)

    # Verify the user's file is untouched
    assert (tmp_path / ".env.backup").read_text(encoding="utf-8") == real_content

    c1 = _load_canaries(lo)
    assert c1 is not None
    # .env.backup should NOT be in _planted_hashes (we didn't plant it)
    assert ".env.backup" not in c1.get("_planted_hashes", {})

    # Delete canaries.json to simulate the bug scenario
    (lo.state_dir / "canaries.json").unlink()

    # Re-init
    init_folder(tmp_path, claude=False, mcp=False)

    c2 = _load_canaries(lo)
    assert c2 is not None
    # .env.backup must NOT be adopted (no key-home proof for the user's file)
    assert ".env.backup" not in c2.get("_planted_hashes", {})

    # The user's file must still be unchanged
    assert (tmp_path / ".env.backup").read_text(encoding="utf-8") == real_content


# ------------------------------------------------------------------
# 2. Uninstall leaves user's real file
# ------------------------------------------------------------------


def test_uninstall_leaves_real_file(tmp_path):
    """Uninstall does not delete a user's real .env.backup even if it looks like ours."""
    from sandbox.connector.install import init_folder, uninstall_folder

    _git_init(tmp_path)

    real_content = "STRIPE_SECRET_KEY=sk_live_REAL_12345\nDATABASE_URL=postgres://r:p@h:5432/d\n"
    (tmp_path / ".env.backup").write_text(real_content, encoding="utf-8")

    init_folder(tmp_path, claude=False, mcp=False)
    uninstall_folder(tmp_path)

    # User's file must survive
    assert (tmp_path / ".env.backup").is_file()
    assert (tmp_path / ".env.backup").read_text(encoding="utf-8") == real_content


# ------------------------------------------------------------------
# 3. Genuine flow re-adopts via key-home record
# ------------------------------------------------------------------


def test_genuine_readopt_via_keyhome(tmp_path):
    """init, delete canaries.json, init: re-adopts our planted decoys via key-home record."""
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)

    init_folder(tmp_path, claude=False, mcp=False)
    lo = FolderLayout(tmp_path)

    c1 = _load_canaries(lo)
    assert c1 is not None
    planted1 = dict(c1["_planted_hashes"])
    assert len(planted1) > 0

    # Verify key-home record exists
    rec = _planted_record_path(lo)
    assert rec is not None and rec.is_file(), "key-home planted record must exist"

    # Delete canaries.json
    (lo.state_dir / "canaries.json").unlink()

    # Re-init: should re-adopt via key-home proof
    init_folder(tmp_path, claude=False, mcp=False)

    c2 = _load_canaries(lo)
    assert c2 is not None
    assert c2["_planted_hashes"] == planted1, "re-adopted hashes must match originals"


# ------------------------------------------------------------------
# 4. Uninstall removes the key-home record
# ------------------------------------------------------------------


def test_uninstall_removes_keyhome_record(tmp_path):
    """Uninstall removes the planted record from the key home."""
    from sandbox.connector.install import init_folder, uninstall_folder

    _git_init(tmp_path)

    init_folder(tmp_path, claude=False, mcp=False)
    lo = FolderLayout(tmp_path)

    rec = _planted_record_path(lo)
    assert rec is not None and rec.is_file()

    uninstall_folder(tmp_path)

    # Record should be gone
    assert not rec.is_file(), "key-home planted record should be removed after uninstall"


# ------------------------------------------------------------------
# 5. init writes the key-home record
# ------------------------------------------------------------------


def test_init_writes_keyhome_record(tmp_path):
    """init writes a planted record to the key home with correct hashes."""
    from sandbox.connector.install import init_folder

    _git_init(tmp_path)

    init_folder(tmp_path, claude=False, mcp=False)
    lo = FolderLayout(tmp_path)

    rec = _planted_record_path(lo)
    assert rec is not None and rec.is_file()

    data = json.loads(rec.read_text(encoding="utf-8"))
    # Must have entries for each planted decoy
    c = _load_canaries(lo)
    for dp, h in c["_planted_hashes"].items():
        assert dp in data, f"{dp} missing from key-home record"
        assert data[dp] == h, f"hash mismatch for {dp} in key-home record"
