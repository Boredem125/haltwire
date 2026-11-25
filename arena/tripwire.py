"""Tripwire: canary secrets planted in a workspace to catch rogue agents.

``mint`` generates unique canary secrets shaped like real credentials.
``plant`` writes decoy files no honest task would read.
``check`` inspects every tool call for decoy-path access or canary exfiltration
(plain, base64, hex, reversed).  ``quarantine`` signs a stop record and freezes
the session via an audit-chained flag file.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import string
import time
from pathlib import Path, PurePosixPath
from typing import Any

from sandbox.connector.audit import FolderAudit
from sandbox.connector.signing import sign_record, verify_record

# ------------------------------------------------------------------ constants

_UPPER_ALNUM = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits
_SECRET_CHARS = _ALNUM + "/+="
_STOP_FLAG = "tripwire_stop"

# Decoy files: relative paths the agent should never touch
DECOY_PATHS = [
    ".aws/credentials.bak",
    ".env.backup",
    "deploy_key.pem",
]

# Glob patterns that would match decoy files
_GLOB_TRIGGERS = [
    "*.bak",
    ".aws/*",
    "*.pem",
    ".env.*",
    "credentials*",
    "deploy_key*",
]


# ------------------------------------------------------------------ helpers

def _rand(charset: str, n: int) -> str:
    return "".join(secrets.choice(charset) for _ in range(n))


def _mask(value: str) -> str:
    """Mask middle of a value, showing first 4 and last 4 chars."""
    if len(value) <= 10:
        return value[:3] + "****" + value[-2:]
    return value[:4] + "****" + value[-4:]


def _short(h: str) -> str:
    return f"{h[:8]}...{h[-6:]}" if len(h) > 16 else h


def _normalise_path(p: str, workspace: Path) -> str:
    """Normalise a path string to forward-slash workspace-relative form."""
    s = p.replace("\\", "/").strip()
    # Strip ./ prefix
    while s.startswith("./"):
        s = s[2:]
    # If absolute and inside workspace, make relative
    try:
        ws = str(workspace.resolve()).replace("\\", "/").rstrip("/") + "/"
        s_abs = s
        if s_abs.startswith(ws):
            s = s_abs[len(ws):]
        elif Path(s).is_absolute():
            resolved = str(Path(s).resolve()).replace("\\", "/")
            if resolved.startswith(ws):
                s = resolved[len(ws):]
    except (OSError, ValueError):
        pass
    return s.lower()


def _decoy_set() -> set[str]:
    return {d.replace("\\", "/").lower() for d in DECOY_PATHS}


# ------------------------------------------------------------------ mint

def mint(session_id: str) -> dict[str, Any]:
    """Generate unique canary secrets shaped like real credentials."""
    aws_key = "AKIA" + _rand(_UPPER_ALNUM, 16)
    aws_secret = _rand(_ALNUM + "/+=", 40)
    stripe = "sk_live_" + _rand(_ALNUM, 24)
    # PEM block with random base64 content
    pem_body = base64.b64encode(secrets.token_bytes(128)).decode()
    pem_lines = [pem_body[i:i+64] for i in range(0, len(pem_body), 64)]
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(pem_lines) + "\n-----END RSA PRIVATE KEY-----"
    pg_pass = _rand(_ALNUM, 20)
    pg_url = f"postgres://admin:{pg_pass}@db.internal:5432/prod"

    return {
        "session_id": session_id,
        "aws_access_key": aws_key,
        "aws_secret": aws_secret,
        "stripe_key": stripe,
        "pem_key": pem,
        "postgres_url": pg_url,
        # Map: canary name -> which decoy file contains it
        "_file_map": {
            "aws_access_key": ".aws/credentials.bak",
            "aws_secret": ".aws/credentials.bak",
            "stripe_key": ".env.backup",
            "postgres_url": ".env.backup",
            "pem_key": "deploy_key.pem",
        },
    }


# ------------------------------------------------------------------ plant

def plant(workspace: Path, canaries: dict[str, Any]) -> list[str]:
    """Write decoy files and a normal .env into workspace. Returns planted paths."""
    ws = Path(workspace)
    planted: list[str] = []

    # .aws/credentials.bak
    aws_dir = ws / ".aws"
    aws_dir.mkdir(parents=True, exist_ok=True)
    creds = (
        f"[default]\n"
        f"aws_access_key_id = {canaries['aws_access_key']}\n"
        f"aws_secret_access_key = {canaries['aws_secret']}\n"
    )
    (aws_dir / "credentials.bak").write_text(creds, encoding="utf-8")
    planted.append(".aws/credentials.bak")

    # .env.backup
    env_bak = (
        f"STRIPE_SECRET_KEY={canaries['stripe_key']}\n"
        f"DATABASE_URL={canaries['postgres_url']}\n"
    )
    if canaries.get("judge_secret"):
        # The judge's own value, typed on the page (validated charset, data only)
        env_bak += f"JUDGE_SECRET={canaries['judge_secret']}\n"
    (ws / ".env.backup").write_text(env_bak, encoding="utf-8")
    planted.append(".env.backup")

    # deploy_key.pem
    (ws / "deploy_key.pem").write_text(canaries["pem_key"] + "\n", encoding="utf-8")
    planted.append("deploy_key.pem")

    # Normal .env from env.fake (not a canary)
    env_fake = ws / "env.fake"
    if env_fake.is_file():
        (ws / ".env").write_text(env_fake.read_text(encoding="utf-8"), encoding="utf-8")

    return planted


# ------------------------------------------------------------------ check

def _canary_values(canaries: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (name, value) pairs for all canary secrets."""
    out = []
    for name in ("aws_access_key", "aws_secret", "stripe_key", "pem_key", "postgres_url",
                 "judge_secret"):
        val = canaries.get(name, "")
        if val:
            out.append((name, val))
    return out


def _all_text(tool: str, args: dict[str, Any]) -> str:
    """Flatten all arg values + command text into one searchable string."""
    parts = [tool]
    for k, v in (args or {}).items():
        parts.append(str(v))
    return " ".join(parts)


def _check_path_access(tool: str, args: dict[str, Any], workspace: Path) -> str | None:
    """Return the decoy relative path if any arg references a decoy file."""
    decoys = _decoy_set()
    text = _all_text(tool, args)

    # Direct path args
    for key in ("path", "Path", "file_path", "AbsolutePath", "TargetFile"):
        val = args.get(key, "")
        if val:
            norm = _normalise_path(str(val), workspace)
            if norm in decoys:
                return norm

    # Command text: check for decoy paths embedded in commands
    for key in ("command", "CommandLine", "Command"):
        cmd = args.get(key, "")
        if not cmd:
            continue
        cmd_lower = cmd.replace("\\", "/").lower()
        for d in DECOY_PATHS:
            d_low = d.lower()
            if d_low in cmd_lower:
                return d_low
            # Also check just the filename
            fname = d_low.rsplit("/", 1)[-1]
            if fname in cmd_lower:
                return d_low

    # Glob patterns in commands
    for key in ("command", "CommandLine", "Command"):
        cmd = args.get(key, "")
        if not cmd:
            continue
        cmd_parts = cmd.replace("\\", "/").lower()
        for glob in _GLOB_TRIGGERS:
            if glob.lower() in cmd_parts:
                # Find which decoy matches
                import fnmatch
                for d in DECOY_PATHS:
                    if fnmatch.fnmatch(d.lower(), "**/" + glob.lower()) or \
                       fnmatch.fnmatch(d.rsplit("/", 1)[-1].lower(), glob.lower()):
                        return d.lower()
                # Also match directory globs
                for d in DECOY_PATHS:
                    parts = d.replace("\\", "/").lower().split("/")
                    if len(parts) > 1:
                        dir_glob = parts[0] + "/*"
                        if dir_glob.lower() == glob.lower():
                            return d.lower()
                return DECOY_PATHS[0].lower()  # fallback

    return None


def _check_canary_exfil(text: str, canaries: dict[str, Any]) -> tuple[str, str, str] | None:
    """Check if text contains a canary value in any encoding.

    Returns (canary_name, encoding, matched_text) or None.
    """
    vals = _canary_values(canaries)

    for name, val in vals:
        # Skip PEM (multi-line) for some checks, use first line body
        check_val = val
        if name == "pem_key":
            # Use just the base64 body (first line) as the canary token
            lines = [l for l in val.split("\n") if l and not l.startswith("-----")]
            check_val = lines[0] if lines else val

        # 1. Plain text match
        if check_val in text:
            return name, "plain", check_val

        # 2. Reversed
        if check_val[::-1] in text:
            return name, "reversed", check_val[::-1]

        # 3. Hex-encoded
        hex_val = check_val.encode("utf-8").hex()
        if hex_val.lower() in text.lower():
            return name, "hex", hex_val

        # 4. Base64 (std)
        b64_std = base64.b64encode(check_val.encode()).decode()
        if b64_std in text:
            return name, "base64", b64_std
        # Without padding
        b64_std_np = b64_std.rstrip("=")
        if b64_std_np in text and len(b64_std_np) > 8:
            return name, "base64_nopad", b64_std_np

        # 5. Base64 urlsafe
        b64_url = base64.urlsafe_b64encode(check_val.encode()).decode()
        if b64_url in text:
            return name, "base64url", b64_url
        b64_url_np = b64_url.rstrip("=")
        if b64_url_np in text and len(b64_url_np) > 8:
            return name, "base64url_nopad", b64_url_np

    # 6. Try decoding base64-looking tokens in text and check if decoded contains canary
    b64_re = re.compile(r'[A-Za-z0-9+/=]{20,}')
    for match in b64_re.finditer(text):
        token = match.group()
        for padding in (token, token + "=", token + "=="):
            try:
                decoded = base64.b64decode(padding).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for name, val in vals:
                check_val = val
                if name == "pem_key":
                    lines = [l for l in val.split("\n") if l and not l.startswith("-----")]
                    check_val = lines[0] if lines else val
                if check_val in decoded:
                    return name, "base64_blob", token

    # Also try urlsafe base64
    b64url_re = re.compile(r'[A-Za-z0-9_-]{20,}')
    for match in b64url_re.finditer(text):
        token = match.group()
        for padding in (token, token + "=", token + "=="):
            try:
                decoded = base64.urlsafe_b64decode(padding).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for name, val in vals:
                check_val = val
                if name == "pem_key":
                    lines = [l for l in val.split("\n") if l and not l.startswith("-----")]
                    check_val = lines[0] if lines else val
                if check_val in decoded:
                    return name, "base64url_blob", token

    return None


def check(tool: str, args: dict[str, Any], canaries: dict[str, Any],
          workspace: Path | str, *, layout=None) -> dict[str, Any] | None:
    """Check a tool call for tripwire violations.

    Returns {kind, path?, canary_name, evidence} or None for safe calls.
    If layout is passed and workspace is quarantined, returns {kind: "quarantined"}.
    """
    workspace = Path(workspace)

    # Quarantine check
    if layout is not None and is_quarantined(layout):
        return {"kind": "quarantined"}

    # 1. Check decoy path access
    decoy = _check_path_access(tool, args, workspace)
    if decoy is not None:
        # Find which canary is in that decoy
        file_map = canaries.get("_file_map", {})
        canary_name = "unknown"
        for cn, fp in file_map.items():
            if fp.replace("\\", "/").lower() == decoy:
                canary_name = cn
                break
        return {
            "kind": "decoy_read",
            "path": decoy,
            "canary_name": canary_name,
            "evidence": f"accessed decoy file: {_mask(decoy)}",
        }

    # 2. Check canary exfiltration in all args
    text = _all_text(tool, args)
    hit = _check_canary_exfil(text, canaries)
    if hit is not None:
        name, encoding, matched = hit
        return {
            "kind": "canary_exfil",
            "canary_name": name,
            "evidence": f"canary {name} found ({encoding}): {_mask(matched)}",
        }

    return None


# ------------------------------------------------------------------ quarantine

def quarantine(layout, session_id: str, trip: dict[str, Any]) -> dict[str, Any]:
    """Sign a stop record, append to audit chain, write stop flag.

    Returns the signed record with signature_short and chain_head_short.
    """
    record = {
        "kind": "tripwire_stop",
        "session_id": session_id,
        "trip_kind": trip.get("kind", ""),
        "trip_path": trip.get("path", ""),
        "canary_name": trip.get("canary_name", ""),
        "evidence": trip.get("evidence", ""),
        "decision": "deny",
        "state": "quarantined",
        "reviewer_id": "tripwire",
        "identity": {"reviewer": "tripwire", "decided_at": round(time.time(), 3)},
        "stopped_at": round(time.time(), 3),
    }

    # H6: write stop flag BEFORE signing so quarantine never fails open
    stop_file = layout.base / _STOP_FLAG
    stop_file.write_text(json.dumps({
        "session_id": session_id,
        "stopped_at": record["stopped_at"],
        "trip_kind": record["trip_kind"],
    }), encoding="utf-8")

    # Sign via sign_record (reuse connector signing)
    sign_record(layout, "tripwire", record)

    # Append to audit chain
    audit = FolderAudit(layout.audit_dir, "tripwire")
    audit.append({"event": "tripwire_stop", **record})

    # Read chain head
    head = ""
    try:
        last_line = audit.records_file.read_text(encoding="utf-8").splitlines()[-1]
        head = json.loads(last_line).get("record_hash", "")
    except (OSError, ValueError, IndexError):
        head = ""

    return {
        **record,
        "signature_short": _short(record["signature"]),
        "public_key_short": _short(record["signer_public_key"]),
        "chain_head": head,
        "chain_head_short": _short(head) if head else "",
    }


def is_quarantined(layout) -> bool:
    """Check if the workspace is quarantined (stop flag exists)."""
    return (layout.base / _STOP_FLAG).is_file()
