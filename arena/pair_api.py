"""Pair-your-phone API: QR code pairing, phone claim, voice bridge, decision.

Mounted as an APIRouter and included in arena.server via
``app.include_router(make_pair_router(lambda: _mgr()))``.

All pairing state is in-memory (resets on restart).  No personal data stored.
"""
from __future__ import annotations

import hmac
import io
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException, Query, Request, WebSocket
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

import segno

# ---------------------------------------------------------------------------
# In-memory state  (module-level so tests can inspect/patch)
# ---------------------------------------------------------------------------

# session_id -> pairing dict
_pairings: dict[str, dict[str, Any]] = {}
# code -> session_id  (reverse lookup)
_code_to_session: dict[str, str] = {}

# Per-IP rate limit for pair creation: 10/hour
_PAIR_IP_LIMIT = 10
_PAIR_IP_WINDOW = 3600  # 1 hour
_pair_ip_log: dict[str, list[float]] = {}

PAIR_EXPIRY_S = 30 * 60  # 30 minutes

STATIC = Path(__file__).resolve().parent / "static"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_client_ip(request: Request) -> str:
    """Extract client IP, trusting X-Forwarded-For only from localhost."""
    peer = request.client.host if request.client else ""
    if peer in ("127.0.0.1", "::1", "localhost"):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[-1].strip()
    return peer


def _check_pair_rate(client_ip: str) -> None:
    """Enforce per-IP rate limit on pair creation."""
    if not client_ip:
        return
    now = time.time()
    cutoff = now - _PAIR_IP_WINDOW
    times = _pair_ip_log.get(client_ip, [])
    times = [t for t in times if t > cutoff]
    _pair_ip_log[client_ip] = times
    if len(times) >= _PAIR_IP_LIMIT:
        raise HTTPException(429, "pair creation rate limit (10/hour) exceeded")
    times.append(now)


def _pairing_state(p: dict[str, Any], session: Any) -> str:
    """Compute the current pairing state from session status."""
    if time.time() > p["expires_at"]:
        return "expired"
    if session is None:
        return "expired"
    if session.status == "decided" or session.receipt is not None:
        return "decided"
    if session.status in ("awaiting_decision", "tripped"):
        if p.get("in_call"):
            return "in_call"
        return "ringing"
    return "waiting"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class PhoneDecisionIn(BaseModel):
    decision: str  # keep_frozen | release


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------

def make_pair_router(get_manager: Callable) -> APIRouter:
    """Build and return the APIRouter for phone-pairing endpoints.

    Parameters
    ----------
    get_manager : callable
        Returns the SessionManager instance.
    """
    router = APIRouter()

    # ------------------------------------------------------------------
    # POST /api/session/{session_id}/pair
    # ------------------------------------------------------------------
    @router.post("/api/session/{session_id}/pair")
    def create_pair(session_id: str, request: Request) -> dict[str, Any]:
        mgr = get_manager()
        s = mgr.get(session_id)
        if s is None:
            raise HTTPException(404, "session not found")

        # Auth
        token = request.headers.get("x-session-token", "")
        if not token or not s.check_token(token):
            raise HTTPException(403, "invalid session token")

        # Only guard-ON sessions
        if not s.guard:
            raise HTTPException(400, "pairing only available for guard-ON sessions")

        # Idempotent: return existing pairing
        if session_id in _pairings:
            p = _pairings[session_id]
            return {
                "code": p["code"],
                "url": p["url"],
                "qr_svg_url": p["qr_svg_url"],
                "expires_at": p["expires_at"],
            }

        # Rate limit
        client_ip = _get_client_ip(request)
        _check_pair_rate(client_ip)

        # Create pairing
        code = secrets.token_urlsafe(16)
        public_base = os.environ.get("ARENA_PUBLIC_URL", "").rstrip("/")
        if not public_base:
            public_base = str(request.base_url).rstrip("/")
        url = f"{public_base}/call/{code}"

        now = time.time()
        p = {
            "code": code,
            "session_id": session_id,
            "url": url,
            "qr_svg_url": f"/api/pair/{code}/qr.svg",
            "expires_at": now + PAIR_EXPIRY_S,
            "created_at": now,
            "phone_secret": None,  # set on first claim
            "claimed": False,
            "in_call": False,
        }
        _pairings[session_id] = p
        _code_to_session[code] = session_id

        return {
            "code": code,
            "url": url,
            "qr_svg_url": p["qr_svg_url"],
            "expires_at": p["expires_at"],
        }

    # ------------------------------------------------------------------
    # GET /api/pair/{code}/qr.svg
    # ------------------------------------------------------------------
    @router.get("/api/pair/{code}/qr.svg")
    def get_qr_svg(code: str) -> Response:
        sid = _code_to_session.get(code)
        if sid is None or sid not in _pairings:
            raise HTTPException(404, "pairing not found")
        p = _pairings[sid]

        buf = io.BytesIO()
        qr = segno.make(p["url"], error="m")
        qr.save(buf, kind="svg", scale=6, border=2)
        return Response(
            content=buf.getvalue(),
            media_type="image/svg+xml",
            headers={"Cache-Control": "no-store"},
        )

    # ------------------------------------------------------------------
    # GET /call/{code}  -- serves the phone page
    # ------------------------------------------------------------------
    @router.get("/call/{code}")
    def call_page(code: str) -> Response:
        sid = _code_to_session.get(code)
        if sid is None or sid not in _pairings:
            raise HTTPException(404, "pairing not found")

        oncall_html = STATIC / "oncall.html"
        if oncall_html.is_file():
            content = oncall_html.read_text(encoding="utf-8")
            return HTMLResponse(content)
        # Placeholder
        return HTMLResponse(
            "<html><body><h1>Phone page not built yet</h1>"
            "<p>The phone call page is under construction.</p>"
            "</body></html>"
        )

    # ------------------------------------------------------------------
    # GET /api/pair/{code}  -- pair state, first-claim with phone_secret
    # ------------------------------------------------------------------
    @router.get("/api/pair/{code}")
    def get_pair(code: str, request: Request) -> dict[str, Any]:
        sid = _code_to_session.get(code)
        if sid is None or sid not in _pairings:
            raise HTTPException(404, "pairing not found")
        p = _pairings[sid]
        mgr = get_manager()
        s = mgr.get(sid)

        state = _pairing_state(p, s)

        # First GET claims the pairing
        if not p["claimed"]:
            phone_secret = secrets.token_urlsafe(24)
            p["phone_secret"] = phone_secret
            p["claimed"] = True
            trip_data = None
            if s and s.trip:
                trip_data = {
                    "kind": s.trip.get("kind"),
                    "target_or_path": s.trip.get("target_or_path", s.trip.get("path", "")),
                    "evidence": s.trip.get("evidence", ""),
                    "signature_short": s.trip.get("signature_short", ""),
                    "chain_head_short": s.trip.get("chain_head_short", ""),
                }
            return {
                "state": state,
                "task_title": s.chip.get("title", "") if s else "",
                "trip": trip_data,
                "receipt": s.receipt if s else None,
                "phone_secret": phone_secret,
            }

        # Already claimed -- require X-Phone-Secret
        provided = request.headers.get("x-phone-secret", "")
        if not provided or not hmac.compare_digest(p["phone_secret"], provided):
            raise HTTPException(409, "already paired to another phone")

        trip_data = None
        if s and s.trip:
            trip_data = {
                "kind": s.trip.get("kind"),
                "target_or_path": s.trip.get("target_or_path", s.trip.get("path", "")),
                "evidence": s.trip.get("evidence", ""),
                "signature_short": s.trip.get("signature_short", ""),
                "chain_head_short": s.trip.get("chain_head_short", ""),
            }
        return {
            "state": state,
            "task_title": s.chip.get("title", "") if s else "",
            "trip": trip_data,
            "receipt": s.receipt if s else None,
        }

    # ------------------------------------------------------------------
    # WS /ws/oncall/{code}  -- voice bridge via phone
    # ------------------------------------------------------------------
    @router.websocket("/ws/oncall/{code}")
    async def ws_oncall(websocket: WebSocket, code: str,
                        lang: str = Query(default="en"),
                        phone: str = Query(default="")):
        sid = _code_to_session.get(code)
        if sid is None or sid not in _pairings:
            await websocket.close(code=4003, reason="pairing not found")
            return
        p = _pairings[sid]
        mgr = get_manager()
        s = mgr.get(sid)

        # Must be ringing or in_call
        state = _pairing_state(p, s)
        if state not in ("ringing", "in_call"):
            await websocket.close(code=4003, reason="session not ringing")
            return

        # Verify phone_secret (compare_digest)
        if not p["claimed"] or not p["phone_secret"]:
            await websocket.close(code=4003, reason="pairing not claimed")
            return
        if not phone or not hmac.compare_digest(p["phone_secret"], phone):
            await websocket.close(code=4003, reason="invalid phone secret")
            return

        if lang not in ("en", "hi", "te"):
            lang = "en"

        await websocket.accept()
        p["in_call"] = True

        async def on_decision(decision_val: str) -> dict[str, Any]:
            from arena.session import AlreadyDecidedError
            reviewer = "phone (paired)"
            try:
                result = s.decide(decision_val, reviewer)
                return result.get("receipt", {})
            except AlreadyDecidedError:
                return {"error": "already decided"}
            except Exception:
                return {"error": "decision failed"}

        try:
            from arena.voice import handle_call
            trip = s.trip or {}
            await handle_call(websocket, trip, lang, on_decision)
        except Exception:
            pass
        finally:
            p["in_call"] = False
            try:
                await websocket.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # POST /api/pair/{code}/decision  -- fallback button decision
    # ------------------------------------------------------------------
    @router.post("/api/pair/{code}/decision")
    def phone_decision(code: str, body: PhoneDecisionIn,
                       request: Request) -> dict[str, Any]:
        sid = _code_to_session.get(code)
        if sid is None or sid not in _pairings:
            raise HTTPException(404, "pairing not found")
        p = _pairings[sid]
        mgr = get_manager()
        s = mgr.get(sid)
        if s is None:
            raise HTTPException(404, "session not found")

        # Verify phone_secret
        if not p["claimed"] or not p["phone_secret"]:
            raise HTTPException(403, "pairing not claimed")
        provided = request.headers.get("x-phone-secret", "")
        if not provided or not hmac.compare_digest(p["phone_secret"], provided):
            raise HTTPException(403, "invalid phone secret")

        # Validate decision value
        if body.decision not in ("keep_frozen", "release"):
            raise HTTPException(400, "decision must be keep_frozen or release")

        # Decide using the same path as the buttons
        from arena.session import AlreadyDecidedError
        try:
            result = s.decide(body.decision, "phone (paired)")
        except AlreadyDecidedError:
            raise HTTPException(409, "already decided")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

        return result

    # ------------------------------------------------------------------
    # GET /api/session/{session_id}/pair-status
    # ------------------------------------------------------------------
    @router.get("/api/session/{session_id}/pair-status")
    def pair_status(session_id: str, request: Request) -> dict[str, Any]:
        mgr = get_manager()
        s = mgr.get(session_id)
        if s is None:
            raise HTTPException(404, "session not found")

        # Auth
        token = request.headers.get("x-session-token", "")
        if not token or not s.check_token(token):
            raise HTTPException(403, "invalid session token")

        p = _pairings.get(session_id)
        if p is None:
            return {"paired": False, "state": "none"}

        state = _pairing_state(p, s)
        return {"paired": True, "state": state}

    return router
