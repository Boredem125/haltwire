"""Tests: `haltwire verify` does not crash on cp1252 consoles.

Bug #2 (pilot QA): UnicodeEncodeError for the checkmark/cross characters
when stdout encoding is cp1252.
"""
from __future__ import annotations

import subprocess
import sys

import pytest


def test_verify_no_unicode_crash(tmp_path):
    """haltwire verify exits 0 (or 1 for no chains) without traceback on cp1252."""
    from sandbox.connector.install import init_folder

    init_folder(tmp_path, claude=False, mcp=False, no_canaries=True)

    env = dict(__import__("os").environ)
    env["PYTHONIOENCODING"] = "cp1252"

    result = subprocess.run(
        [sys.executable, "-m", "sandbox.cli.main", "verify", str(tmp_path)],
        capture_output=True, text=True, timeout=30, env=env,
    )
    # Should not have a traceback
    assert "UnicodeEncodeError" not in result.stderr, f"stderr: {result.stderr}"
    assert "Traceback" not in result.stderr, f"stderr: {result.stderr}"
    # Exit 0 (all ok) or exit 1 (no chains / some failed) - but not a crash
    assert result.returncode in (0, 1), f"rc={result.returncode} stderr={result.stderr}"
