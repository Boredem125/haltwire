"""Per-user Gemini API key storage, outside any repo.

The key lives at ``<key_home_root>/gemini.key`` (the same base dir as
reviewer signing seeds: ``SANDBOX_KEY_HOME`` override, else the platform
default).  It is atomic-written and chmod 600 on POSIX.

API summary (for other workers to call):
    get_key()      -> str | None   (env GEMINI_API_KEY first, then file)
    set_key(key)   -> None         (validates + atomic write)
    clear_key()    -> None
    key_source()   -> "env" | "file" | None
    mask(key)      -> str          ("AIza...abcd")
    test_key(key)  -> str | None   (None = ok, else error message)

SECURITY: the full key is never logged or printed.  ``mask()`` is the
only way it leaves this module in human-readable form.
"""
from __future__ import annotations

import logging
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from sandbox.connector.keyhome import key_home_root

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KEY_FILENAME = "gemini.key"
_MIN_KEY_LEN = 20


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class InvalidKeyError(ValueError):
    """The key does not look like a valid API key."""


def _validate(key: str) -> str:
    """Return the stripped key or raise InvalidKeyError."""
    if not isinstance(key, str):
        raise InvalidKeyError("key must be a string")
    k = key.strip()
    if not k:
        raise InvalidKeyError("key is empty")
    if any(c.isspace() for c in k):
        raise InvalidKeyError("key contains whitespace")
    if len(k) < _MIN_KEY_LEN:
        raise InvalidKeyError(f"key is too short (need at least {_MIN_KEY_LEN} chars)")
    return k


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def key_file_path() -> Path | None:
    """Absolute path to ``gemini.key``, or None when the key home is unusable."""
    root = key_home_root()
    if root is None:
        return None
    return root / _KEY_FILENAME


def key_home_pattern() -> str:
    """The key-home path pattern for the classify read-deny.

    Returns e.g. ``C:\\Users\\Me\\AppData\\Local\\agg\\keys\\gemini.key``
    or ``<SANDBOX_KEY_HOME>/gemini.key``.  Used by other workers to wire
    the deny rule.
    """
    p = key_file_path()
    if p is not None:
        return str(p)
    root = key_home_root()
    if root is not None:
        return str(root / _KEY_FILENAME)
    return "<SANDBOX_KEY_HOME>/gemini.key"


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_key() -> str | None:
    """Return the Gemini API key: env ``GEMINI_API_KEY`` first, then the file.

    Returns None when no key is available (never raises).
    """
    env = os.environ.get("GEMINI_API_KEY", "").strip()
    if env and len(env) >= _MIN_KEY_LEN:
        return env
    p = key_file_path()
    if p is None:
        return None
    try:
        text = p.read_text(encoding="utf-8").strip()
        if text and len(text) >= _MIN_KEY_LEN and not any(c.isspace() for c in text):
            return text
    except (OSError, ValueError):
        pass
    return None


def key_source() -> str | None:
    """Where the key comes from: ``"env"``, ``"file"``, or ``None``."""
    env = os.environ.get("GEMINI_API_KEY", "").strip()
    if env and len(env) >= _MIN_KEY_LEN:
        return "env"
    p = key_file_path()
    if p is None:
        return None
    try:
        text = p.read_text(encoding="utf-8").strip()
        if text and len(text) >= _MIN_KEY_LEN:
            return "file"
    except (OSError, ValueError):
        pass
    return None


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def _secure_windows_acl(path: Path) -> None:
    """Remove ACL inheritance and grant only the current user full control.

    Uses ``icacls.exe`` via subprocess (no shell).  Fails soft: logs a
    warning but never crashes.
    """
    if os.name != "nt":
        return
    try:
        from sandbox.connector.keyhome import _validated_icacls
        icacls = _validated_icacls()
        if icacls is None:
            _log.warning("icacls not found; cannot set owner-only ACL on %s", path.name)
            return
        import getpass
        import re as _re
        username = getpass.getuser()
        if not username:
            _log.warning("cannot determine username; skipping ACL on %s", path.name)
            return
        # Strict validation: Windows usernames may contain letters, digits,
        # dots, hyphens, underscores and spaces; reject anything else to
        # prevent argument injection via a crafted USERNAME env var.
        if not _re.fullmatch(r"[A-Za-z0-9.\-_ ]+", username):
            _log.warning("username %r has unexpected characters; skipping ACL on %s",
                         username, path.name)
            return
        # Remove inheritance, then grant only the current user full control.
        subprocess.run(
            [str(icacls), str(path), "/inheritance:r"],
            capture_output=True, timeout=10, check=False,
        )
        subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args  -- username from getpass.getuser() validated against strict [A-Za-z0-9.\-_ ]+ pattern; icacls is from _validated_icacls()
            [str(icacls), str(path), "/grant:r", f"{username}:(F)"],
            capture_output=True, timeout=10, check=False,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("failed to set owner-only ACL on %s: %s", path.name, exc)


def set_key(key: str) -> None:
    """Validate and atomically write the key to the key home.

    Raises InvalidKeyError on bad input, OSError on write failure.
    On Windows, sets an owner-only ACL on the key file and its parent
    directory (F5).
    """
    k = _validate(key)
    p = key_file_path()
    if p is None:
        raise OSError("key home is not available (set SANDBOX_KEY_HOME)")
    created_parent = not p.parent.exists()
    p.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: write to a temp file in the same directory, then rename.
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".gemini_", suffix=".tmp")
    try:
        os.write(fd, (k + "\n").encode("utf-8"))
        os.close(fd)
        fd = -1
        # POSIX: owner-only
        if os.name != "nt":
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, str(p))
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # Windows: set owner-only ACL (F5, fail soft)
    if os.name == "nt":
        _secure_windows_acl(p)
        if created_parent:
            _secure_windows_acl(p.parent)


def clear_key() -> None:
    """Remove the stored key file (idempotent)."""
    p = key_file_path()
    if p is None:
        return
    try:
        p.unlink()
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------

def mask(key: str | None) -> str:
    """Human-safe representation: first 4 chars + ellipsis + last 4 chars.

    E.g. ``AIza...abcd``.  Returns ``(none)`` for None/empty.
    """
    if not key or len(key) < 8:
        return "(none)"
    return f"{key[:4]}...{key[-4:]}"


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def test_key(key: str) -> str | None:
    """Make a tiny Gemini call to verify the key works.

    Returns None on success, or an error message string.
    Uses the intent module's client factory infrastructure.
    """
    k = _validate(key)  # may raise InvalidKeyError
    try:
        import google.genai as genai
        from google.genai import types as gtypes
    except ImportError:
        return "google-genai is not installed"
    try:
        # Gemini rejects deadlines under 10 s (400 INVALID_ARGUMENT).
        http_opts = gtypes.HttpOptions(timeout=12000)
        client = genai.Client(api_key=k, http_options=http_opts)
    except (ImportError, TypeError):
        try:
            client = genai.Client(api_key=k)
        except Exception as exc:
            return f"client creation failed: {exc}"
    try:
        resp = client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=["Say OK"],
        )
        text = ""
        try:
            parts = resp.candidates[0].content.parts or []
            for part in parts:
                if getattr(part, "text", None):
                    text = part.text
                    break
        except (AttributeError, IndexError, TypeError):
            pass
        if not text:
            return "empty response from Gemini"
        return None  # success
    except Exception as exc:
        detail = str(exc)
        if "401" in detail or "UNAUTHENTICATED" in detail:
            return "invalid API key (401)"
        if "403" in detail or "PERMISSION_DENIED" in detail:
            return "permission denied (403) - check the key"
        if "429" in detail or "RESOURCE_EXHAUSTED" in detail:
            return "rate limited (429) - key is valid but quota exhausted"
        return f"API error: {type(exc).__name__}: {detail[:100]}"
