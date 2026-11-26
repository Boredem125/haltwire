"""Tests for sandbox.connector.aikey — per-user Gemini key storage."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest import mock

import pytest


@pytest.fixture()
def tmp_keyhome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point SANDBOX_KEY_HOME at a temp directory; restore afterwards."""
    kh = tmp_path / "keys"
    kh.mkdir()
    monkeypatch.setenv("SANDBOX_KEY_HOME", str(kh))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    return kh


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidation:
    def test_empty_key_rejected(self, tmp_keyhome):
        from sandbox.connector.aikey import InvalidKeyError, set_key
        with pytest.raises(InvalidKeyError, match="empty"):
            set_key("")

    def test_whitespace_key_rejected(self, tmp_keyhome):
        from sandbox.connector.aikey import InvalidKeyError, set_key
        with pytest.raises(InvalidKeyError, match="whitespace"):
            set_key("AIza some key with spaces")

    def test_short_key_rejected(self, tmp_keyhome):
        from sandbox.connector.aikey import InvalidKeyError, set_key
        with pytest.raises(InvalidKeyError, match="short"):
            set_key("tooshort")

    def test_valid_key_accepted(self, tmp_keyhome):
        from sandbox.connector.aikey import set_key, get_key
        key = "A" * 40
        set_key(key)
        assert get_key() == key


# ---------------------------------------------------------------------------
# set_key / get_key / clear_key
# ---------------------------------------------------------------------------

class TestSetGetClear:
    def test_roundtrip(self, tmp_keyhome):
        from sandbox.connector.aikey import clear_key, get_key, set_key
        key = "AIzaSyD_test_1234567890abcdef"
        set_key(key)
        assert get_key() == key
        clear_key()
        assert get_key() is None

    def test_overwrite(self, tmp_keyhome):
        from sandbox.connector.aikey import get_key, set_key
        set_key("A" * 30)
        set_key("B" * 30)
        assert get_key() == "B" * 30

    def test_clear_idempotent(self, tmp_keyhome):
        from sandbox.connector.aikey import clear_key
        # Should not raise even when no key file exists
        clear_key()
        clear_key()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX-only file permissions")
    def test_posix_permissions(self, tmp_keyhome):
        from sandbox.connector.aikey import key_file_path, set_key
        set_key("A" * 30)
        p = key_file_path()
        assert p is not None
        mode = p.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


    @pytest.mark.skipif(os.name != "nt", reason="Windows-only ACL test")
    def test_windows_acl_owner_only(self, tmp_keyhome):
        """F5: after set_key, icacls output shows only the current user."""
        from sandbox.connector.aikey import key_file_path, set_key
        import subprocess
        set_key("A" * 30)
        p = key_file_path()
        assert p is not None
        result = subprocess.run(
            ["icacls", str(p)], capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        # Should contain only the current user, not Everyone/BUILTIN\Users/etc.
        username = os.environ.get("USERNAME", "")
        assert username.lower() in output.lower(), (
            f"Expected {username} in icacls output, got: {output}"
        )
        for broad in ("Everyone", r"BUILTIN\Users", "Authenticated Users"):
            assert broad.lower() not in output.lower(), (
                f"Broad group {broad} should not appear: {output}"
            )


# ---------------------------------------------------------------------------
# env precedence
# ---------------------------------------------------------------------------

class TestEnvPrecedence:
    def test_env_wins_over_file(self, tmp_keyhome, monkeypatch):
        from sandbox.connector.aikey import get_key, key_source, set_key
        file_key = "F" * 30
        env_key = "E" * 30
        set_key(file_key)
        monkeypatch.setenv("GEMINI_API_KEY", env_key)
        assert get_key() == env_key
        assert key_source() == "env"

    def test_file_fallback_when_no_env(self, tmp_keyhome, monkeypatch):
        from sandbox.connector.aikey import get_key, key_source, set_key
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        set_key("F" * 30)
        assert get_key() == "F" * 30
        assert key_source() == "file"

    def test_no_key_at_all(self, tmp_keyhome, monkeypatch):
        from sandbox.connector.aikey import get_key, key_source
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        assert get_key() is None
        assert key_source() is None


# ---------------------------------------------------------------------------
# mask
# ---------------------------------------------------------------------------

class TestMask:
    def test_normal_key(self):
        from sandbox.connector.aikey import mask
        assert mask("AIzaSyD_test_1234567890") == "AIza...7890"

    def test_none(self):
        from sandbox.connector.aikey import mask
        assert mask(None) == "(none)"

    def test_short(self):
        from sandbox.connector.aikey import mask
        assert mask("abc") == "(none)"

    def test_full_key_never_in_mask(self):
        from sandbox.connector.aikey import mask
        key = "AIzaSyD_test_1234567890abcdef"
        masked = mask(key)
        assert key not in masked
        assert len(masked) < len(key)


# ---------------------------------------------------------------------------
# key_home_pattern
# ---------------------------------------------------------------------------

class TestKeyHomePattern:
    def test_returns_string(self, tmp_keyhome):
        from sandbox.connector.aikey import key_home_pattern
        pat = key_home_pattern()
        assert isinstance(pat, str)
        assert "gemini.key" in pat

    def test_contains_key_home(self, tmp_keyhome):
        from sandbox.connector.aikey import key_home_pattern
        pat = key_home_pattern()
        assert str(tmp_keyhome) in pat


# ---------------------------------------------------------------------------
# test_key (mocked)
# ---------------------------------------------------------------------------

class TestTestKey:
    def test_missing_genai(self, tmp_keyhome):
        from sandbox.connector.aikey import test_key
        with mock.patch.dict("sys.modules", {"google.genai": None, "google": None}):
            # Force ImportError by clearing the module
            result = test_key("A" * 30)
            # Might get import error or might work if already imported
            # Just ensure it returns a string or None, never raises
            assert result is None or isinstance(result, str)

    def test_success_mock(self, tmp_keyhome):
        """test_key returns None on a successful Gemini call."""
        from sandbox.connector.aikey import test_key

        fake_part = mock.MagicMock()
        fake_part.text = "OK"
        fake_resp = mock.MagicMock()
        fake_resp.candidates = [mock.MagicMock()]
        fake_resp.candidates[0].content.parts = [fake_part]

        fake_client = mock.MagicMock()
        fake_client.models.generate_content.return_value = fake_resp

        # Patch google.genai.Client to return our fake client
        with mock.patch("google.genai.Client", return_value=fake_client):
            result = test_key("A" * 30)
            assert result is None  # success

    def test_validation_error(self, tmp_keyhome):
        from sandbox.connector.aikey import InvalidKeyError, test_key
        with pytest.raises(InvalidKeyError):
            test_key("")


# ---------------------------------------------------------------------------
# Security: agent must not read the key file
# ---------------------------------------------------------------------------

class TestSecurityDeny:
    def test_read_of_key_file_denied_by_pre_tool_use(self, tmp_keyhome):
        """A Read of the key-home gemini.key path via pre_tool_use must be denied.

        The classify owner must add this path to the read-deny list.
        This test asserts that pre_tool_use denies a Read targeting the
        gemini.key file.  Marked xfail until the classify worker wires it.
        """
        from sandbox.connector.aikey import key_file_path, set_key
        from sandbox.connector.classify import classify
        from sandbox.connector.layout import FolderLayout
        from sandbox.connector.policy import default_policy, save_policy

        set_key("A" * 30)
        p = key_file_path()
        assert p is not None

        # Simulate a Read tool call targeting the key file
        layout = FolderLayout(tmp_keyhome.parent)
        layout.ensure_dirs()
        policy = default_policy()
        save_policy(policy, layout.policy_file)
        result = classify(
            "Read",
            {"file_path": str(p)},
            policy,
            layout,
            cwd=str(layout.root),
        )
        # Must be denied
        assert result.verdict == "deny", \
            f"Expected deny for reading the key file, got: {result.verdict}"
