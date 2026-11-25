"""Attack Arena + Tripwire web server.

    python -m arena.server            # http://127.0.0.1:8088

Tripwire endpoints (new):
GET  /             tripwire page
GET  /arena        old red-team page
GET  /api/tasks    scenario chips
POST /api/session  create a session
GET  /api/session/{id}?since=N  poll events
POST /api/session/{id}/decision  human decision
POST /api/session/{id}/phone    phone call via Bolna
GET  /api/receipt/{id}/verify[?tamper=1]  verify receipt
GET  /api/stats    scoreboard
WS   /ws/call/{id}?lang=en|hi|te  voice call
GET  /api/replays  list recorded sessions

Existing (arena):
GET  /api/state    latest run + judge attacks
POST /api/judge    one attack written by a person (one at a time)
POST /api/run      start a Gemini run (needs ARENA_ADMIN_TOKEN)
"""
from __future__ import annotations

import sys

# `python -m arena.server` runs this file as __main__.  Without this alias,
# `from arena.server import _mgr` (in duel_api) loads a second copy of the
# module with its own SessionManager, and duel sessions are invisible to the
# /api/session routes (decision, phone, voice, verify all 404).
if __name__ == "__main__":
    sys.modules.setdefault("arena.server", sys.modules[__name__])

import asyncio
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from arena import core, scenarios_tw, duel, phone
from arena.arena import Arena
from arena.runner import package_exists, redact
from arena.session import (
    SessionManager, TooManySessionsError, RateLimitError, AlreadyDecidedError,
)

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Tripwire", docs_url=None, redoc_url=None, openapi_url=None)


def _allowed_hosts() -> list[str]:
    """L6: Host header allow-list, which blocks DNS rebinding against the
    localhost server.  ``testserver`` is the test client's host name.
    ``ARENA_PUBLIC_HOST`` (comma list) adds the deployed domain."""
    hosts = ["localhost", "127.0.0.1", "[::1]", "testserver"]
    extra = os.environ.get("ARENA_PUBLIC_HOST", "")
    hosts += [h.strip() for h in extra.split(",") if h.strip()]
    return hosts


from starlette.middleware.trustedhost import TrustedHostMiddleware  # noqa: E402

app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts())

# --- Arena (old) state ---
_arena: Arena | None = None
_judge_lock = asyncio.Lock()
_run_task: asyncio.Task | None = None
_tasks: set[asyncio.Task] = set()

# --- Tripwire state ---
_tw_manager: SessionManager | None = None

# --- Phone call state (in-memory, resets on restart) ---
_phone_sessions: set[str] = set()       # session ids that have had a call placed
import contextvars as _cv  # noqa: E402
_call_slot: _cv.ContextVar[str] = _cv.ContextVar("_call_slot", default="")  # auto-call slot


def _phone_key(session_id: str) -> str:
    """Once-per-session key: manual calls use the session id; each auto-call
    number gets its own slot so the presenters can be called in parallel."""
    return session_id + _call_slot.get()
_phone_daily_count: int = 0             # calls placed today
_phone_daily_reset: float = 0.0         # epoch when the daily count resets
_phone_ip_calls: dict[str, list[float]] = {}  # ip -> [timestamps] for per-IP cap
_phone_number_hashes: dict[str, list[float]] = {}  # M2: hashed number -> [timestamps]

# H3: voice call caps
MAX_VOICE_PER_SESSION = 2   # max total calls per session
MAX_VOICE_CONCURRENT = 2    # global concurrent voice calls
_voice_sessions: dict[str, int] = {}   # session_id -> call count
_voice_active: int = 0                 # current active voice calls


def _mgr() -> SessionManager:
    global _tw_manager
    if _tw_manager is None:
        _tw_manager = SessionManager()
    return _tw_manager


# M1: shared helper for extracting real client IP behind a trusted proxy
def get_client_ip(request: Request) -> str:
    """Extract the real client IP, using X-Forwarded-For only from a trusted proxy."""
    peer = request.client.host if request.client else ""
    trusted_proxies = set(
        p.strip() for p in
        os.environ.get("ARENA_TRUSTED_PROXY", "").split(",")
        if p.strip()
    )
    # Also trust localhost (for local dev without Caddy)
    trusted_proxies.update(("127.0.0.1", "::1", "localhost"))
    if peer in trusted_proxies:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # M1: use the LAST X-Forwarded-For entry
            # (the rightmost entry is what the trusted proxy appended)
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if parts:
                # The last entry is the one the trusted proxy added -- the real client
                return parts[-1]
    return peer


def arena() -> Arena:
    global _arena
    if _arena is None:
        _arena = Arena.load_latest() or Arena()
    return _arena


# ============================================================================
# Pydantic models
# ============================================================================

class JudgeIn(BaseModel):
    readme: str = Field(min_length=1, max_length=core.MAX_FILE_CHARS)
    prompt: str = Field(min_length=1, max_length=core.MAX_PROMPT_CHARS)


class RunIn(BaseModel):
    rounds: int = Field(default=3, ge=1, le=5)
    n: int = Field(default=4, ge=1, le=8)
    parallel: int = Field(default=2, ge=1, le=3)


class SessionIn(BaseModel):
    task_id: str | None = None
    task: str | None = None
    guard: bool = True
    ai: bool = False
    feature: str | None = None  # preset feature id (csv-export, currency, top-n)


class DecisionIn(BaseModel):
    decision: str
    reviewer: str = Field(min_length=1, max_length=40)


class PhoneIn(BaseModel):
    number: str = Field(min_length=10, max_length=16)
    lang: str = Field(default="en", max_length=5)


# ============================================================================
# Page routes
# ============================================================================

@app.get("/")
def index() -> FileResponse:
    """Tripwire page (new default). Falls back to index.html if tripwire.html missing."""
    st = STATIC / "story.html"
    if st.is_file():
        return FileResponse(st, headers={"Cache-Control": "no-store"})
    tw = STATIC / "tripwire.html"
    if tw.is_file():
        return FileResponse(tw, headers={"Cache-Control": "no-store"})
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})


def _token_from_first_message(msg: str) -> str:
    """The voice page sends {"token": "..."} as its first WS message; older
    clients sent the bare token.  Accept both."""
    text = (msg or "").strip()
    if text.startswith("{"):
        try:
            import json as _json
            val = _json.loads(text).get("token", "")
            return val.strip() if isinstance(val, str) else ""
        except ValueError:
            return text
    return text


@app.get("/story.html")
def story_page() -> FileResponse:
    """Story-mode page (About, repo, live analysis, decision, agents)."""
    st = STATIC / "story.html"
    if not st.is_file():
        raise HTTPException(404, "story page not built")
    return FileResponse(st, headers={"Cache-Control": "no-store"})


@app.get("/classic")
def classic_page() -> FileResponse:
    """The single-screen duel page."""
    return FileResponse(STATIC / "tripwire.html", headers={"Cache-Control": "no-store"})


@app.get("/arena")
def arena_page() -> FileResponse:
    """Old red-team page."""
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})


# ============================================================================
# Tripwire API
# ============================================================================

@app.get("/api/tasks")
def get_tasks() -> list[dict[str, Any]]:
    """Return scenario chips for the UI."""
    chips = scenarios_tw.all_chips()
    return [{"id": c["id"], "title": c["title"], "task": c["task_prompt"]} for c in chips]


@app.post("/api/session", status_code=202)
async def create_session(body: SessionIn, request: Request) -> dict[str, Any]:
    """Create a new tripwire session."""
    mgr = _mgr()
    client_ip = get_client_ip(request)

    # -- resolve feature preset --
    feature_obj: dict[str, Any] | None = None
    if body.feature is not None:
        if body.task_id != "setup":
            raise HTTPException(400, "feature is only valid with task_id 'setup'")
        feature_obj = scenarios_tw.get_feature(body.feature)
        if feature_obj is None:
            raise HTTPException(400, f"unknown feature: {body.feature}")

    try:
        if body.task_id:
            s = mgr.create(body.task_id, body.guard, client_ip=client_ip, ai=body.ai)
        elif body.task:
            # H5: custom task requires ARENA_ALLOW_CUSTOM=1
            if os.environ.get("ARENA_ALLOW_CUSTOM") != "1":
                raise HTTPException(403, "custom tasks disabled")
            if len(body.task) > 300:
                raise HTTPException(400, "task must be at most 300 chars")
            s = mgr.create_custom(body.task, body.guard, client_ip=client_ip, ai=body.ai)
        else:
            raise HTTPException(400, "task_id or task required")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except TooManySessionsError:
        raise HTTPException(429, "max 2 concurrent sessions")
    except RateLimitError:
        raise HTTPException(429, "rate limit: 6 sessions per 10 minutes")

    # -- apply feature override --
    if feature_obj is not None:
        s.chip = {**s.chip, "task_prompt": feature_obj["task_prompt"]}
        s.feature = feature_obj
    else:
        s.feature = None

    # Launch the agent session as a background task
    task = asyncio.create_task(mgr.run_session_async(s))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)

    return {"session_id": s.id, "token": s.token}


@app.get("/api/session/{session_id}")
def get_session(session_id: str, since: int = Query(default=0)) -> dict[str, Any]:
    """Poll session state and events."""
    mgr = _mgr()
    s = mgr.get(session_id)
    if s is not None:
        return s.to_dict(since)
    # Try replay
    replay = mgr.load_replay(session_id)
    if replay is not None:
        return replay
    raise HTTPException(404, "session not found")


@app.post("/api/session/{session_id}/decision")
def post_decision(session_id: str, body: DecisionIn,
                  request: Request) -> dict[str, Any]:
    """Record a human decision on a tripped session."""
    mgr = _mgr()
    s = mgr.get(session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    # Auth: require session token
    token = request.headers.get("x-session-token", "")
    if not token or not s.check_token(token):
        raise HTTPException(403, "invalid session token")
    if s.status not in ("tripped", "awaiting_decision", "decided"):
        raise HTTPException(400, f"session not awaiting decision (status={s.status})")

    try:
        result = s.decide(body.decision, body.reviewer)
    except AlreadyDecidedError:
        raise HTTPException(409, "already decided")
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return result


@app.get("/api/receipt/{session_id}/verify")
def verify_receipt(session_id: str, tamper: int = Query(default=0)) -> dict[str, Any]:
    """Verify (or tamper-test) a session's receipt."""
    mgr = _mgr()
    s = mgr.get(session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    if s.receipt is None:
        raise HTTPException(404, "no receipt")

    if tamper:
        # Copy receipt, flip decision, verify -> should be false
        tampered = dict(s.receipt)
        old = tampered.get("decision", "")
        tampered["decision"] = "approve" if old == "deny" else "deny"
        valid = duel.verify_receipt(tampered)
        return {"valid": valid, "detail": "tampered copy verified" if valid else "signature mismatch: receipt was tampered"}
    else:
        valid = s.verify_receipt()
        return {"valid": valid, "detail": "Ed25519 signature verified against chain" if valid else "signature verification failed"}


@app.get("/api/hook-demo")
def hook_demo_replay() -> JSONResponse:
    """Recorded real run: Antigravity CLI governed by the same layer.
    The audit chain is re-verified on every request; 404 if none recorded."""
    import json as _json
    from arena import hook_demo as _hd

    path = Path(__file__).resolve().parent / "recordings" / "hook_demo.json"
    if not path.is_file():
        raise HTTPException(404, "no hook demo recorded")
    replay = _json.loads(path.read_text(encoding="utf-8"))
    replay.setdefault("audit", {})["chain_ok"] = bool(_hd.verify(replay))
    return JSONResponse(replay, headers={"Cache-Control": "no-store"})


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    """Return scoreboard stats (including benign fields from another worker)."""
    mgr = _mgr()
    stats = mgr.stats()
    from arena.duel_api import benign_stats
    stats.update(benign_stats(mgr.runs_dir))
    return stats


@app.get("/api/replays")
def get_replays() -> list[dict[str, Any]]:
    """List recorded replay sessions."""
    return _mgr().list_replays()


# ============================================================================
# Phone call (Bolna)
# ============================================================================

def _get_client_ip(request: Request) -> str:
    """Extract client IP -- delegates to shared get_client_ip (M1)."""
    return get_client_ip(request)


def _check_phone_caps(client_ip: str) -> None:
    """Check daily cap and per-IP cap for phone calls. Raises HTTPException."""
    global _phone_daily_count, _phone_daily_reset

    now = time.time()

    # Reset daily counter at midnight (or if never set)
    if _phone_daily_reset == 0.0 or now - _phone_daily_reset > 86400:
        _phone_daily_count = 0
        _phone_daily_reset = now

    daily_cap = int(os.environ.get("PHONE_DAILY_CAP", "30"))
    if _phone_daily_count >= daily_cap:
        raise HTTPException(429, f"daily phone call cap ({daily_cap}) reached")

    # Per-IP cap: 3 calls per day
    per_ip_cap = 3
    ip_times = _phone_ip_calls.get(client_ip, [])
    day_start = now - 86400
    ip_times = [t for t in ip_times if t > day_start]
    _phone_ip_calls[client_ip] = ip_times
    if len(ip_times) >= per_ip_cap:
        raise HTTPException(429, f"per-IP phone cap ({per_ip_cap}/day) reached")


@app.get("/api/autocall")
def autocall_config() -> dict[str, Any]:
    """Whether the server auto-calls the presenter when an agent freezes.
    The number lives only in the server env (ARENA_AUTOCALL_NUMBER); the page
    gets the last 3 digits for display, never the number."""
    nums = _autocall_numbers()
    if not nums:
        return {"enabled": False}
    return {"enabled": True, "ends_with": ", ".join(n[-3:] for n in nums)}


def _autocall_numbers() -> list[str]:
    raw = os.environ.get("ARENA_AUTOCALL_NUMBER", "")
    return [n.strip() for n in raw.split(",") if n.strip()][:3]


@app.post("/api/session/{session_id}/autocall", status_code=202)
async def post_autocall(session_id: str, request: Request,
                        lang: str = Query(default="en")) -> dict[str, Any]:
    """Call the presenter's server-side number for this frozen session."""
    nums = _autocall_numbers()
    if not nums:
        raise HTTPException(404, "auto-call is not configured")
    s = _mgr().get(session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    token = request.headers.get("x-session-token", "")
    if not token or not s.check_token(token):
        raise HTTPException(403, "invalid session token")
    fn = globals()["post_phone"]   # looked up at call time (patched in tests)

    async def one(i: int, num: str) -> dict[str, Any]:
        _call_slot.set(f"#auto{i}")   # each number its own once-per-session slot
        try:
            out = await fn(session_id, PhoneIn(number=num, lang=lang), request)
            return {"ok": True, "masked": (out or {}).get("masked", "")}
        except HTTPException as exc:
            return {"ok": False, "detail": exc.detail}

    results = await asyncio.gather(*(one(i, n) for i, n in enumerate(nums)))
    placed = [r for r in results if r["ok"]]
    if not placed:
        raise HTTPException(502, results[0].get("detail", "auto-call failed"))
    return {"calls": len(placed), "masked": ", ".join(r["masked"] for r in placed if r["masked"])}


@app.post("/api/session/{session_id}/phone", status_code=202)
async def post_phone(session_id: str, body: PhoneIn,
                     request: Request) -> dict[str, Any]:
    """Place a Bolna phone call for a tripped session.

    Requires X-Session-Token. Only when status is awaiting_decision.
    One call per session (409 after). Global daily cap and per-IP cap.
    ARENA_PHONE=0 disables the endpoint (404).
    """
    # Check if phone feature is disabled
    if os.environ.get("ARENA_PHONE", "1") == "0":
        raise HTTPException(404, "phone calling is disabled")

    mgr = _mgr()
    s = mgr.get(session_id)
    if s is None:
        raise HTTPException(404, "session not found")

    # Auth: require session token
    token = request.headers.get("x-session-token", "")
    if not token or not s.check_token(token):
        raise HTTPException(403, "invalid session token")

    # Must be awaiting_decision
    if s.status != "awaiting_decision":
        raise HTTPException(409, f"session not awaiting decision (status={s.status})")

    # Validate number
    if not phone.validate_number(body.number):
        raise HTTPException(400, f"Invalid phone number (must be +91 India mobile)")

    # Once per session
    if _phone_key(session_id) in _phone_sessions:
        raise HTTPException(409, "phone call already placed for this session")

    # Check caps
    client_ip = _get_client_ip(request)
    _check_phone_caps(client_ip)

    # M2: cap per hashed number to 2 calls per day
    import hashlib as _hl
    num_hash = _hl.sha256(body.number.encode()).hexdigest()
    now_m2 = time.time()
    day_start_m2 = now_m2 - 86400
    num_times = _phone_number_hashes.get(num_hash, [])
    num_times = [t for t in num_times if t > day_start_m2]
    _phone_number_hashes[num_hash] = num_times
    cap = int(os.environ.get("PHONE_PER_NUMBER_CAP", "2"))  # 0 = no per-number limit
    if cap > 0 and len(num_times) >= cap:
        raise HTTPException(429, "this number has reached the daily call limit")

    # Place the call
    masked = phone.mask_number(body.number)
    try:
        result = await asyncio.to_thread(
            phone.place_call, s, body.number, body.lang)  # L4: async
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except RuntimeError as exc:
        # Bolna API error -> emit event and return 502
        s._add_event({"seq": 0, "kind": "info",
                       "text": "Phone call failed: could not reach calling service"})
        raise HTTPException(502, "phone call failed: could not reach calling service")

    # Mark this session as having a call and update caps
    global _phone_daily_count
    _phone_sessions.add(_phone_key(session_id))
    _phone_daily_count += 1
    ip_times = _phone_ip_calls.get(client_ip, [])
    ip_times.append(time.time())
    _phone_ip_calls[client_ip] = ip_times
    # M2: record the hashed number call
    num_times.append(time.time())
    _phone_number_hashes[num_hash] = num_times

    # Emit event (use masked number, never the real one)
    s._add_event({"seq": 0, "kind": "info",
                   "text": f"Calling {masked}"})

    # Start background poll task
    execution_id = result["execution_id"]
    # Keep the real number ONLY in memory for the duration of the poll
    _number_ref = body.number  # local variable, not stored on session or disk

    async def _poll_bolna():
        """Poll Bolna every 3s up to 4 min; on confirmed decision -> decide."""
        max_polls = 80  # 80 * 3s = 240s = 4 min
        for i in range(max_polls):
            await asyncio.sleep(3)
            try:
                poll_result = phone.poll(execution_id)
            except Exception:
                s._add_event({"seq": 0, "kind": "info",
                               "text": "Phone call: polling error"})
                break

            status = poll_result.get("status", "")

            # Emit ringing/answered events once
            if i == 0 and status not in ("completed", "error"):
                pass  # Already emitted "Calling" event

            if status == "completed" or status == "call-disconnected":
                decision = poll_result.get("decision")
                confirmed = poll_result.get("confirmed", False)

                if decision in ("keep_frozen", "release") and confirmed:
                    # H1 founder ruling: phone can only auto-sign deny
                    if decision == "release" and phone.VOICE_DENY_ONLY:
                        s._add_event({
                            "seq": 0, "kind": "info",
                            "text": "Release requested by phone, confirm with button"
                        })
                    else:
                        reviewer = f"phone:{masked}"
                        try:
                            s.decide(decision, reviewer, _internal=True)
                            s._add_event({
                                "seq": 0, "kind": "info",
                                "text": f"Decision by phone: {decision}"
                            })
                        except AlreadyDecidedError:
                            pass
                else:
                    s._add_event({
                        "seq": 0, "kind": "info",
                        "text": "Phone call ended without a confirmed decision"
                    })
                break

            if status in ("failed", "error", "no-answer"):
                s._add_event({
                    "seq": 0, "kind": "info",
                    "text": "Phone call ended without a confirmed decision"
                })
                break
        else:
            # Timeout
            s._add_event({
                "seq": 0, "kind": "info",
                "text": "Phone call ended without a confirmed decision"
            })

    task = asyncio.create_task(_poll_bolna())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)

    return {"call_id": execution_id, "masked": masked}


# ============================================================================
# WebSocket: voice call
# ============================================================================

@app.websocket("/ws/call/{session_id}")
async def ws_call(websocket: WebSocket, session_id: str,
                  lang: str = Query(default="en"),
                  token: str = Query(default="")):
    """Voice call bridge. Only accepts tripped, undecided sessions."""
    global _voice_active
    mgr = _mgr()
    s = mgr.get(session_id)
    if s is None or s.status not in ("tripped", "awaiting_decision"):
        await websocket.close(code=4000, reason="session not tripped or not found")
        return

    # L3: accept token as first WS message if not in query
    # (keep query form working for current frontend)
    if not token or not s.check_token(token):
        # Try accepting and reading the first message as a token
        if not token:
            await websocket.accept()
            try:
                first_msg = await asyncio.wait_for(websocket.receive_text(), 5.0)
                token = _token_from_first_message(first_msg)
            except Exception:
                await websocket.close(code=4003, reason="invalid session token")
                return
            if not s.check_token(token):
                await websocket.close(code=4003, reason="invalid session token")
                return
        else:
            await websocket.close(code=4003, reason="invalid session token")
            return
    else:
        await websocket.accept()

    if lang not in ("en", "hi", "te"):
        lang = "en"

    # H3: one active call per session, max 2 total calls, global cap
    session_calls = _voice_sessions.get(session_id, 0)
    if session_calls >= MAX_VOICE_PER_SESSION:
        await websocket.close(code=4008, reason="max calls per session reached")
        return
    if _voice_active >= MAX_VOICE_CONCURRENT:
        await websocket.close(code=4009, reason="max concurrent voice calls reached")
        return
    _voice_sessions[session_id] = session_calls + 1
    _voice_active += 1

    async def on_decision(decision_val: str) -> dict[str, Any]:
        """Called by voice.handle_call when Gemini confirms decision."""
        from arena.voice import VOICE_DENY_ONLY
        # H1 founder ruling: voice can only auto-sign deny
        if decision_val == "release" and VOICE_DENY_ONLY:
            s._add_event({"seq": 0, "kind": "info",
                          "text": "Release requested by voice, confirm with button"})
            return {"pending": True, "decision": "release",
                    "message": "Release requested, confirm with button"}
        reviewer = f"voice:{lang}"
        try:
            result = s.decide(decision_val, reviewer, _internal=True)
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
        _voice_active = max(0, _voice_active - 1)
        try:
            await websocket.close()
        except Exception:
            pass


# ============================================================================
# Arena (old) endpoints
# ============================================================================

def _refresh() -> None:
    global _arena
    if (_run_task and not _run_task.done()) or _judge_lock.locked():
        return
    latest = Arena.load_latest(mark_stopped=False)
    if latest is not None:
        if _arena is not None and latest.run_id == _arena.run_id:
            latest.state["judge"] = latest.state.get("judge") or _arena.state.get("judge", [])
        _arena = latest


def _is_public() -> bool:
    return os.environ.get("ARENA_PUBLIC", "") == "1"


@app.get("/api/state")
def state() -> JSONResponse:
    _refresh()
    st = dict(arena().state)
    st["judge_busy"] = _judge_lock.locked()
    return JSONResponse(st, headers={"Cache-Control": "no-store"})


@app.post("/api/judge", status_code=202)
async def judge(body: JudgeIn) -> dict[str, Any]:
    if _is_public():
        raise HTTPException(404, "not available in public mode")
    if _judge_lock.locked():
        raise HTTPException(409, "busy")
    probe = core.judge_attack(body.readme, body.prompt, "probe")
    errs = await asyncio.to_thread(core.validate, probe, package_exists=package_exists)
    if errs:
        raise HTTPException(400, "; ".join(errs[:3]))
    if _judge_lock.locked():
        raise HTTPException(409, "busy")
    await _judge_lock.acquire()
    a = arena()
    attack_id = f"judge-{len(a.state['judge']) + 1}"

    async def go() -> None:
        try:
            await a.judge(body.readme, body.prompt)
        finally:
            _judge_lock.release()

    t = asyncio.create_task(go())
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return {"id": attack_id}


@app.post("/api/run", status_code=202)
async def run(body: RunIn, x_arena_token: str = Header(default="")) -> dict[str, Any]:
    if _is_public():
        raise HTTPException(404, "not available in public mode")
    global _arena, _run_task
    token = os.environ.get("ARENA_ADMIN_TOKEN", "")
    if not token or not hmac.compare_digest(token, x_arena_token):
        raise HTTPException(403, "forbidden")
    if _run_task and not _run_task.done():
        raise HTTPException(409, "a run is already in progress")
    _arena = Arena()
    _run_task = asyncio.create_task(_arena.run(body.rounds, body.n, body.parallel))
    return {"run_id": _arena.run_id}


# ============================================================================
# Attack recording / replay (single unguarded run for the opening scene)
# ============================================================================

_FEATURE_ID_RE = __import__("re").compile(r"^[a-z0-9-]{1,40}$")


class RecordAttackIn(BaseModel):
    feature: str


@app.post("/api/session/record")
async def record_attack(body: RecordAttackIn, request: Request,
                        x_arena_token: str = Header(default="")) -> dict[str, Any]:
    """Record a real guard-OFF session for a feature preset.  Admin only.

    Runs the session, waits for completion, and saves the recording if the
    verdict is ``compromised`` (canary really reached the attacker).
    """
    if _is_public():
        admin_token = os.environ.get("ARENA_ADMIN_TOKEN", "")
        if not admin_token or not hmac.compare_digest(admin_token, x_arena_token):
            raise HTTPException(404, "not available")
    else:
        admin_token = os.environ.get("ARENA_ADMIN_TOKEN", "")
        if not admin_token or not hmac.compare_digest(admin_token, x_arena_token):
            raise HTTPException(403, "forbidden")

    feature_obj = scenarios_tw.get_feature(body.feature)
    if feature_obj is None:
        raise HTTPException(400, f"unknown feature: {body.feature}")

    mgr = _mgr()
    chip = scenarios_tw.get_chip("setup")
    if chip is None:
        raise HTTPException(500, "setup chip missing")
    chip = {**chip, "task_prompt": feature_obj["task_prompt"]}

    # Create a guard-OFF session (bypass caps for admin)
    s = mgr._setup_session(chip, guard=False, client_ip="", replay=False)
    s.feature = feature_obj

    # Run synchronously (admin endpoint, not async for the caller)
    await mgr.run_session_async(s)

    # Detect model from events
    model_name = "unknown"
    for ev in s.events:
        text = ev.get("text") or ""
        if ev.get("kind") == "info" and "model=" in text:
            model_name = text.split("model=", 1)[1].split()[0]
            break

    # Find leak_ts: ts of the first attacker canary_hit event
    leak_ts = None
    for ev in s.events:
        if ev.get("kind") == "attacker" and ev.get("extra", {}).get("canary_hit"):
            leak_ts = ev.get("ts")
            break

    if s.verdict != "compromised":
        return {"verdict": s.verdict, "error_reason": s.error_reason or None,
                "saved": False}

    recording = {
        "feature": dict(feature_obj),
        "task_prompt": chip["task_prompt"],
        "model": model_name,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "events": redact(s.events),
        "loot": s.loot,
        "verdict": s.verdict,
        "leak_ts": leak_ts,
        "duration": round(s.events[-1]["ts"], 1) if s.events else 0,
    }

    recordings_dir = mgr.runs_dir / "recordings"
    recordings_dir.mkdir(parents=True, exist_ok=True)
    rec_path = recordings_dir / f"attack-{body.feature}.json"
    rec_path.write_text(json.dumps(recording, indent=2), encoding="utf-8")
    # Never write into arena/recordings/ here: those are the shipped real runs,
    # copied there by hand after a check. (Tests once overwrote them with fakes.)

    return {"verdict": s.verdict, "saved": True, "leak_ts": leak_ts,
            "duration": recording["duration"], "model": model_name,
            "session_id": s.id}


@app.get("/api/attack/replay")
def attack_replay(feature: str = Query(default="")) -> dict[str, Any]:
    """Return a recorded attack for the given feature."""
    if not feature or not _FEATURE_ID_RE.match(feature):
        raise HTTPException(400, "invalid feature id")
    if scenarios_tw.get_feature(feature) is None:
        raise HTTPException(400, f"unknown feature: {feature}")

    # Prefer the shipped recording (repo), then the runs dir
    repo_path = Path(__file__).resolve().parent / "recordings" / f"attack-{feature}.json"
    runs_path = _mgr().runs_dir / "recordings" / f"attack-{feature}.json"

    rec_path = None
    if repo_path.is_file():
        rec_path = repo_path
    elif runs_path.is_file():
        rec_path = runs_path

    if rec_path is None:
        raise HTTPException(404, f"no recording for feature {feature}")

    try:
        return json.loads(rec_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(500, "recording corrupted")


# ============================================================================
# Duel API (split-screen guard OFF vs ON)
# ============================================================================

from arena.duel_api import duel_router  # noqa: E402
app.include_router(duel_router)
from arena.approvers import router as approvers_router  # noqa: E402
app.include_router(approvers_router)

# L5: pair_api dropped. Keep the file, do not mount.
# from arena.pair_api import make_pair_router
# app.include_router(make_pair_router(lambda: _mgr()))

from arena.hook_live import hook_live_router  # noqa: E402
app.include_router(hook_live_router)

from arena.gchat import make_gchat_router  # noqa: E402
app.include_router(make_gchat_router(lambda: _mgr()))


# ============================================================================
# Entry point
# ============================================================================

def main() -> None:
    import uvicorn

    kw: dict[str, Any] = {"host": os.environ.get("ARENA_HOST", "127.0.0.1"),
                          "port": int(os.environ.get("ARENA_PORT", "8088"))}
    # Optional local HTTPS: Google Chat opens every button link as https, so a
    # laptop demo needs TLS.  Both files or neither (GCP terminates TLS in Caddy).
    cert, key = os.environ.get("ARENA_SSL_CERT", ""), os.environ.get("ARENA_SSL_KEY", "")
    if cert and key:
        kw.update(ssl_certfile=cert, ssl_keyfile=key)
    uvicorn.run(app, **kw)


if __name__ == "__main__":
    main()
