"""Team approval by QR code.

When the guard-ON agent is frozen, the presenter shows a QR code. Each teammate
scans it, joins with a name and gets a per-device secret. Rules:

- Any one person can sign "keep frozen" (the safe choice).
- "Release" needs two different people; the second approval signs it.

Decisions go through ``Session.decide`` (Ed25519 receipt, audit chain), with
the reviewer recorded as ``team:<name>`` or ``team:<name1>+<name2>``.
State is in memory and expires with the pairing (30 minutes).
"""
from __future__ import annotations

import hmac
import io
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Literal

import segno
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

MAX_PEOPLE = 6
EXPIRY_S = 30 * 60
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{0,15}$")
_RATE_LIMIT = 10           # QR codes per IP per hour
STATIC = Path(__file__).resolve().parent / "static"

_by_code: dict[str, dict[str, Any]] = {}
_by_session: dict[str, str] = {}
_ip_log: dict[str, list[float]] = {}


def _reset() -> None:
    """Clear all state (tests)."""
    _by_code.clear()
    _by_session.clear()
    _ip_log.clear()


def _mgr():
    from arena.server import _mgr as server_mgr
    return server_mgr()


def _client_ip(request: Request) -> str:
    from arena.server import get_client_ip
    return get_client_ip(request)


def _get(code: str) -> dict[str, Any]:
    t = _by_code.get(code)
    if t is None or time.time() > t["expires_at"]:
        raise HTTPException(404, "approval code not found or expired")
    return t


def _state(t: dict[str, Any]) -> dict[str, Any]:
    s = _mgr().get(t["session_id"])
    if s is None:
        raise HTTPException(404, "session not found")
    trip = s.trip or {}
    rc = s.receipt or {}
    return {
        "status": s.status,
        "decided": s.receipt is not None,
        "decision": rc.get("decision"),
        "reviewer": rc.get("reviewer"),
        "people": [p["name"] for p in t["people"].values()],
        "release_votes": list(t["release_votes"]),
        "trip": {"kind": trip.get("kind", ""), "canary_name": trip.get("canary_name", ""),
                 "evidence": str(trip.get("evidence", ""))[:200]},
        "task": s.chip.get("task_prompt", "")[:300],
    }


class JoinIn(BaseModel):
    name: str


class VoteIn(BaseModel):
    vote: Literal["keep_frozen", "release"]


router = APIRouter()


@router.post("/api/session/{session_id}/approvers")
def create_team_code(session_id: str, request: Request) -> dict[str, Any]:
    """Presenter: create (or return) the QR join code for a frozen guard-ON session."""
    s = _mgr().get(session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    token = request.headers.get("x-session-token", "")
    if not token or not s.check_token(token):
        raise HTTPException(403, "invalid session token")
    if not s.guard:
        raise HTTPException(400, "team approval is only for guard-ON sessions")
    if session_id in _by_session and _by_session[session_id] in _by_code:
        return _public(_by_code[_by_session[session_id]], request)
    ip = _client_ip(request)
    now = time.time()
    log = [t for t in _ip_log.get(ip, []) if now - t < 3600]
    if len(log) >= _RATE_LIMIT:
        raise HTTPException(429, "too many approval codes from this address")
    log.append(now)
    _ip_log[ip] = log
    code = secrets.token_urlsafe(12)
    t = {"code": code, "session_id": session_id, "people": {}, "release_votes": [],
         "created_at": now, "expires_at": now + EXPIRY_S}
    _by_code[code] = t
    _by_session[session_id] = code
    return _public(t, request)


def ensure_code(session_id: str) -> str:
    """Server-side: the live team-approval code for a frozen session, made on
    first use.  Used for the Google Chat alert's Decide link.  No token or
    per-IP limit (only the server calls it, once per trip); the same rules
    apply as for the QR: one person keeps it frozen, release needs two."""
    existing = _by_session.get(session_id)
    if existing and existing in _by_code and time.time() <= _by_code[existing]["expires_at"]:
        return existing
    now = time.time()
    code = secrets.token_urlsafe(12)
    _by_code[code] = {"code": code, "session_id": session_id, "people": {}, "release_votes": [],
                      "created_at": now, "expires_at": now + EXPIRY_S}
    _by_session[session_id] = code
    return code


def _public(t: dict[str, Any], request: Request) -> dict[str, Any]:
    base = os.environ.get("ARENA_PUBLIC_URL", "").rstrip("/") or str(request.base_url).rstrip("/")
    return {"code": t["code"], "url": f"{base}/approve/{t['code']}",
            "qr_svg_url": f"/api/approvers/{t['code']}/qr.svg", "expires_at": t["expires_at"]}


@router.get("/api/approvers/{code}/qr.svg")
def qr_svg(code: str, request: Request) -> Response:
    t = _get(code)
    buf = io.BytesIO()
    segno.make(_public(t, request)["url"], error="m").save(
        buf, kind="svg", scale=8, border=2, dark="#3a2c21", light="#fffdf8")
    return Response(buf.getvalue(), media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store"})


@router.get("/approve/{code}")
def approve_page(code: str) -> FileResponse:
    _get(code)
    return FileResponse(STATIC / "approve.html", headers={"Cache-Control": "no-store"})


@router.get("/api/approvers/{code}")
def team_state(code: str) -> dict[str, Any]:
    return _state(_get(code))


@router.post("/api/approvers/{code}/join")
def join(code: str, body: JoinIn) -> dict[str, Any]:
    t = _get(code)
    name = body.name.strip()
    if not _NAME_RE.fullmatch(name):
        raise HTTPException(400, "name: 1-16 letters, spaces, . ' or -")
    if len(t["people"]) >= MAX_PEOPLE:
        raise HTTPException(409, "this team is full")
    if any(p["name"].lower() == name.lower() for p in t["people"].values()):
        raise HTTPException(409, "that name is already taken on this team")
    secret = secrets.token_urlsafe(24)
    t["people"][secret] = {"name": name, "joined_at": time.time()}
    return {"secret": secret, "name": name, **_state(t)}


@router.post("/api/approvers/{code}/vote")
def vote(code: str, body: VoteIn,
         x_approver_secret: str = Header(default="")) -> dict[str, Any]:
    t = _get(code)
    person = None
    for sec, p in t["people"].items():
        if x_approver_secret and hmac.compare_digest(sec, x_approver_secret):
            person = p
            break
    if person is None:
        raise HTTPException(403, "join the team first")
    s = _mgr().get(t["session_id"])
    if s is None:
        raise HTTPException(404, "session not found")
    if s.receipt is not None or s.status != "awaiting_decision":
        raise HTTPException(409, "already decided")
    from arena.session import AlreadyDecidedError
    try:
        if body.vote == "keep_frozen":
            s.decide("keep_frozen", f"team:{person['name']}", _internal=True)
            s._add_event({"kind": "info", "text": f"Team decision: keep frozen ({person['name']})"})
        else:
            if person["name"] not in t["release_votes"]:
                t["release_votes"].append(person["name"])
                s._add_event({"kind": "info", "text": f"Release approval {len(t['release_votes'])} of 2: "
                                                     f"{person['name']}"})
            if len(t["release_votes"]) >= 2:
                a, b = t["release_votes"][:2]
                s.decide("release", f"team:{a}+{b}", _internal=True)
                s._add_event({"kind": "info", "text": f"Team decision: release (two approvals: {a}, {b})"})
    except AlreadyDecidedError:
        raise HTTPException(409, "already decided")
    return _state(t)
