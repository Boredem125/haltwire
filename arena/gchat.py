"""Google Chat alerts when the guard freezes a coding agent.

Two parts:

1. Incoming-webhook alerts (one-way).  ``notify_trip`` posts a cardsV2
   message "Agent frozen" with a link to the story page where a human
   decides.  ``notify_decision`` posts the follow-up (decision, reviewer,
   short receipt signature) in the same thread.  The webhook URL comes from
   env ``GCHAT_WEBHOOK_URL`` only; unset means no-op.  The URL is a secret:
   it is never logged.  Every POST runs on a daemon thread with a 5 s
   timeout, and nothing here ever raises to the caller.

2. Chat app (interactive), off unless ``GCHAT_APP_ENABLED=1``.
   ``make_gchat_router`` returns an APIRouter with ``POST /api/gchat/event``
   for "Keep frozen" / "Release" button clicks.  Each request must carry a
   Google-signed bearer token (issuer ``chat@system.gserviceaccount.com``,
   audience env ``GCHAT_AUDIENCE``).  Without google-auth, every request is
   rejected.  Note: incoming-webhook messages cannot carry working action
   buttons; ``decision_buttons`` is for messages the Chat app itself posts.

Every value shown in a card passes through ``mask_text``: planted canary
values are masked (``arena.egress._mask_preview`` plus a full-value pass),
then known env secrets and Google API keys are redacted
(``arena.runner.redact``).
"""
from __future__ import annotations

import html
import importlib
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from arena.egress import _mask_preview
from arena.runner import redact

log = logging.getLogger(__name__)

TIMEOUT_S = 5
MAX_FIELD = 500
CHAT_ISSUER = "chat@system.gserviceaccount.com"
CHAT_CERTS_URL = ("https://www.googleapis.com/service_accounts/v1/metadata/x509/"
                  "chat@system.gserviceaccount.com")
_MAX_TOKEN_LEN = 8192
_REPLY_OPTION = "messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"

PROOF_BASIS = "PROOF: planted secret left the box"

# H1: Chat clicks can only auto-sign deny (same as phone/voice).
# A release click emits "Release requested via Chat, confirm with button".
CHAT_DENY_ONLY: bool = True

# Chat button function name -> Session.decide() value
_ACTIONS = {"keep_frozen": "keep_frozen", "release": "release"}
_DECISION_LABEL = {"keep_frozen": "Kept frozen", "deny": "Kept frozen", "denied": "Kept frozen",
                   "release": "Released", "approve": "Released", "approved": "Released"}


# ---------------------------------------------------------------------------
# Masking

def mask_text(value: Any, canaries: Mapping[str, Any] | None) -> str:
    """Return *value* as text with every canary and known secret hidden."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    try:
        if isinstance(canaries, Mapping) and canaries:
            text = _mask_preview(text, dict(canaries), max_len=len(text))
            # Second pass: full raw values (whole PEM block, names the
            # scanner does not list).
            for name, val in canaries.items():
                if isinstance(val, str) and len(val) >= 6 and val in text:
                    text = text.replace(val, f"[CANARY:{name}]")
        out = redact(text)
        return out if isinstance(out, str) else "[hidden]"
    except Exception:  # noqa: BLE001 -- never leak on a masking failure
        return "[hidden]"


def _field(value: Any, canaries: Mapping[str, Any] | None) -> str:
    text = mask_text(value, canaries).strip()
    if len(text) > MAX_FIELD:
        text = text[:MAX_FIELD] + "…"
    return text


def _short(h: str) -> str:
    return f"{h[:8]}...{h[-6:]}" if len(h) > 16 else h


# ---------------------------------------------------------------------------
# Payload building (pure)

def _as_dict(d: Any) -> dict[str, Any]:
    return d if isinstance(d, dict) else {}


def _session_id(sd: dict[str, Any]) -> str:
    return str(sd.get("id") or sd.get("session_id") or "")


def _canaries(sd: dict[str, Any]) -> Mapping[str, Any] | None:
    c = sd.get("canaries")
    return c if isinstance(c, Mapping) else None


def _fmt_time(ts: Any) -> str:
    try:
        t = float(ts)
    except (TypeError, ValueError):
        t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t))


def _decorated(label: str, text: str) -> dict[str, Any]:
    return {"decoratedText": {"topLabel": label,
                              "text": html.escape(text, quote=False) or "-",
                              "wrapText": True}}


def _card(card_id: str, title: str, subtitle: str,
          sections: list[dict[str, Any]], fallback: str, thread_key: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "text": fallback,
        "cardsV2": [{"cardId": card_id,
                     "card": {"header": {"title": title, "subtitle": subtitle},
                              "sections": sections}}],
    }
    if thread_key:
        payload["thread"] = {"threadKey": thread_key}
    return payload


def build_trip_card(session_dict: dict[str, Any], base_url: str) -> dict[str, Any]:
    """cardsV2 payload for a freeze.  Pure; all text masked."""
    sd = _as_dict(session_dict)
    trip = _as_dict(sd.get("trip"))
    canaries = _canaries(sd)
    sid = _session_id(sd)

    task = _field(sd.get("task") or trip.get("agent_task") or "", canaries)
    if trip.get("basis") == "ai_judgment":
        basis = _field(f"AI JUDGMENT: {trip.get('reason') or 'flagged'}", canaries)
    elif trip.get("basis") == "rule":
        basis = _field(f"RULE: {trip.get('reason') or 'blocked by default deny'}", canaries)
    else:
        basis = PROOF_BASIS
    kind = _field(trip.get("kind") or trip.get("trip_kind") or "unknown", canaries)
    when = _fmt_time(trip.get("stopped_at"))

    sections: list[dict[str, Any]] = [{"widgets": [
        _decorated("Task", task),
        _decorated("Basis", basis),
        _decorated("Trip kind", kind),
        _decorated("Time", when),
    ]}]
    base = (base_url or "").rstrip("/")
    code = str(sd.get("approve_code") or "")
    if base.startswith(("https://", "http://")) and code:
        # The team-approval page: anyone in the Chat space can keep it frozen;
        # release needs two different people (arena/approvers.py).
        link = f"{base}/approve/{urllib.parse.quote(code, safe='')}"
        sections.append({"widgets": [{"buttonList": {"buttons": [
            {"text": "Decide", "onClick": {"openLink": {"url": link}}}]}}]})
    return _card(f"trip-{sid}", "Agent frozen", "Tripwire guard",
                 sections, f"Agent frozen: {kind}. A human decision is needed.",
                 f"tw-{sid}" if sid else "")


def build_decision_card(session_dict: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    """cardsV2 follow-up: decision, reviewer, short signature.  Pure; masked."""
    sd = _as_dict(session_dict)
    rc = _as_dict(receipt)
    canaries = _canaries(sd)
    sid = _session_id(sd)

    raw = str(rc.get("decision") or rc.get("state") or "")
    decision = _DECISION_LABEL.get(raw) or _DECISION_LABEL.get(str(rc.get("state") or "")) \
        or _field(raw or "unknown", canaries)
    reviewer = _field(rc.get("reviewer") or rc.get("reviewer_id") or "unknown", canaries)
    sig = rc.get("signature_short") or (
        _short(rc["signature"]) if isinstance(rc.get("signature"), str) and rc["signature"] else "")
    sig = _field(sig, canaries) if sig else "(unsigned)"

    sections = [{"widgets": [
        _decorated("Decision", decision),
        _decorated("Reviewer", reviewer),
        _decorated("Signature", sig),
    ]}]
    return _card(f"decision-{sid}", "Decision recorded", "Tripwire guard",
                 sections, f"Decision: {decision} by {reviewer}.",
                 f"tw-{sid}" if sid else "")


def decision_buttons(session_id: str) -> dict[str, Any]:
    """buttonList widget for Chat-app-posted cards (not usable via webhook)."""
    params = [{"key": "session_id", "value": session_id}]
    return {"buttonList": {"buttons": [
        {"text": "Keep frozen", "onClick": {"action": {"function": "keep_frozen",
                                                       "parameters": params}}},
        {"text": "Release", "onClick": {"action": {"function": "release",
                                                   "parameters": params}}},
    ]}}


def session_payload(s: Any) -> dict[str, Any]:
    """Build the dict notify_* expects from a Session object (read only)."""
    try:
        chip = getattr(s, "chip", None)
        chip = chip if isinstance(chip, dict) else {}
        approve_code = None
        if getattr(s, "guard", False) and getattr(s, "id", ""):
            try:
                from arena import approvers
                approve_code = approvers.ensure_code(str(s.id))
            except Exception:  # noqa: BLE001
                approve_code = None
        return {
            "approve_code": approve_code,
            "id": str(getattr(s, "id", "") or ""),
            "task": chip.get("task_prompt") or chip.get("task") or "",
            "trip": getattr(s, "trip", None),
            "receipt": getattr(s, "receipt", None),
            "canaries": getattr(s, "_canaries", None),
        }
    except Exception:  # noqa: BLE001
        return {"id": "", "task": "", "trip": None, "receipt": None, "canaries": None}


# ---------------------------------------------------------------------------
# Sending

def _webhook_url() -> str | None:
    url = os.environ.get("GCHAT_WEBHOOK_URL", "").strip()
    if not url:
        return None
    if not url.startswith("https://"):
        log.warning("gchat: GCHAT_WEBHOOK_URL is not https; not sending")
        return None
    return url


def _threaded(url: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{_REPLY_OPTION}"


def _post_json(url: str, payload: dict[str, Any]) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json; charset=UTF-8"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # noqa: S310 -- https only
        resp.read()


OnResult = Callable[[bool, str], None]


def _report(on_result: "OnResult | None", ok: bool, detail: str) -> None:
    if on_result is None:
        return
    try:
        on_result(ok, detail)
    except Exception:  # noqa: BLE001
        pass


_RETRY_DELAY = 2.0  # seconds before a retry (doubled for each further 429 retry)
_MIN_GAP = 1.1      # seconds between two posts to the space (Chat rate-limits bursts)
_SEND_LOCK = threading.Lock()
_last_post = [0.0]


def _is_transient(exc: BaseException) -> bool:
    """True for errors worth retrying: URLError, timeout, HTTP 5xx."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    if isinstance(exc, urllib.error.URLError):
        return True
    if isinstance(exc, (TimeoutError, OSError)):
        return True
    name = type(exc).__name__.lower()
    return "timeout" in name


def _post_spaced(url: str, payload: dict[str, Any]) -> None:
    """One post at a time, at least _MIN_GAP apart, so a task card and a decision
    card fired at the same instant do not both hit Chat's rate limit (HTTP 429)."""
    with _SEND_LOCK:
        wait = _last_post[0] + _MIN_GAP - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            _post_json(url, payload)
        finally:
            _last_post[0] = time.monotonic()


def _send(url: str, payload: dict[str, Any], what: str,
          on_result: "OnResult | None" = None) -> None:
    """POST and swallow every error.  Transient errors (URLError, timeout,
    HTTP 5xx) get ONE retry after ~2 s.  HTTP 429 (rate limit) gets up to two
    retries with back-off (2 s, 4 s).  Other 4xx are never retried.
    Logs and results never include the URL.  on_result reports the final
    outcome only."""
    attempt = 0
    while True:
        try:
            _post_spaced(url, payload)
            _report(on_result, True, "sent")
            return
        except urllib.error.HTTPError as exc:
            retry = (exc.code == 429 and attempt < 2) or (attempt == 0 and _is_transient(exc))
            if retry:
                log.warning("gchat: %s post failed: HTTP %s (retrying)", what, exc.code)
                time.sleep(_RETRY_DELAY * (2 ** attempt if exc.code == 429 else 1))
                attempt += 1
                continue
            log.warning("gchat: %s post failed: HTTP %s", what, exc.code)
            _report(on_result, False, f"HTTP {exc.code}")
            return
        except Exception as exc:  # noqa: BLE001
            if attempt == 0 and _is_transient(exc):
                log.warning("gchat: %s post failed: %s (retrying)", what, type(exc).__name__)
                time.sleep(_RETRY_DELAY)
                attempt += 1
                continue
            log.warning("gchat: %s post failed: %s", what, type(exc).__name__)
            _report(on_result, False, type(exc).__name__)
            return


def _spawn(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True, name="gchat-notify").start()


def _dispatch(payload_fn: Callable[[], dict[str, Any]], what: str,
              on_result: "OnResult | None" = None) -> None:
    try:
        url = _webhook_url()
        if url is None:
            _report(on_result, False, "Google Chat is not configured")
            return
        payload = payload_fn()
        target = _threaded(url)
        _spawn(lambda: _send(target, payload, what, on_result))
    except Exception as exc:  # noqa: BLE001
        log.warning("gchat: %s not sent: %s", what, type(exc).__name__)


def notify_trip(session_dict: dict[str, Any], base_url: str,
                on_result: "OnResult | None" = None) -> None:
    """Post "Agent frozen" to the Chat webhook.  No-op without GCHAT_WEBHOOK_URL."""
    _dispatch(lambda: build_trip_card(session_dict, base_url), "trip", on_result)


def build_ai_card(session_dict: dict[str, Any], info: dict[str, Any]) -> dict[str, Any]:
    """Follow-up in the trip's thread: the AI judge's view of the freeze.  Masked."""
    sd = _as_dict(session_dict)
    ai = _as_dict(info)
    canaries = _canaries(sd)
    sid = _session_id(sd)
    conf = f"{float(ai.get('confidence') or 0):.0%}"
    if ai.get("error"):
        view = f"AI judge unavailable ({ai.get('error')}): the rule freeze stands"
    elif ai.get("flag"):
        view = f"Does not fit the task ({conf}): {ai.get('reason') or ''}"
    else:
        view = f"Fits the task ({conf}): {ai.get('reason') or ''}"
    sections = [{"widgets": [_decorated("AI view", _field(view, canaries))]}]
    return _card(f"ai-{sid}", "AI analysis", "Gemini intent judge",
                 sections, "AI analysis of the frozen agent", f"tw-{sid}" if sid else "")


def notify_ai_analysis(session_dict: dict[str, Any], info: dict[str, Any],
                       on_result: "OnResult | None" = None) -> None:
    """Post the AI judge's view in the trip's thread.  Never raises."""
    _dispatch(lambda: build_ai_card(session_dict, info), "ai", on_result)


def notify_decision(session_dict: dict[str, Any], receipt: dict[str, Any],
                    on_result: "OnResult | None" = None) -> None:
    """Post the decision follow-up in the trip's thread.  Never raises."""
    _dispatch(lambda: build_decision_card(session_dict, receipt), "decision", on_result)


def build_task_card(feature: dict[str, Any], on_session_id: str) -> dict[str, Any]:
    """cardsV2 payload for a 'Task assigned' notification.  Pure; no secrets."""
    ask = str(feature.get("ask") or feature.get("title") or "")
    title_text = str(feature.get("title") or feature.get("id") or "feature")
    sections: list[dict[str, Any]] = [{"widgets": [
        _decorated("Feature", title_text),
        _decorated("Request", ask),
        _decorated("Status", "Handed to coding agent"),
    ]}]
    thread_key = f"tw-{on_session_id}" if on_session_id else ""
    return _card(f"task-{on_session_id}", "Task assigned", "Product lead",
                 sections, f"Task assigned: {title_text}",
                 thread_key)


def notify_task(feature: dict[str, Any], on_session_id: str,
                on_result: "OnResult | None" = None) -> None:
    """Post 'Task assigned' card in the ON session's Chat thread.  Never raises."""
    _dispatch(lambda: build_task_card(feature, on_session_id), "task", on_result)


# ---------------------------------------------------------------------------
# Chat app: token verification + router (GCHAT_APP_ENABLED=1)

def app_enabled() -> bool:
    return os.environ.get("GCHAT_APP_ENABLED", "") == "1"


def _google_request() -> Any:
    tr = importlib.import_module("google.auth.transport.requests")
    return tr.Request()


def verify_chat_token(token: str) -> dict[str, Any] | None:
    """Verify a Google Chat bearer token.  Returns claims, or None to reject.

    Rejects when GCHAT_AUDIENCE is unset, google-auth is missing, the
    signature/audience/expiry fail, or the issuer is not Chat.
    """
    audience = os.environ.get("GCHAT_AUDIENCE", "").strip()
    if not audience or not token or len(token) > _MAX_TOKEN_LEN:
        return None
    try:
        id_token = importlib.import_module("google.oauth2.id_token")
        request = _google_request()
    except Exception:  # noqa: BLE001 -- ImportError or missing transport
        log.warning("gchat: google-auth not available; rejecting Chat event")
        return None
    try:
        claims = id_token.verify_token(token, request, audience=audience,
                                       certs_url=CHAT_CERTS_URL)
    except Exception as exc:  # noqa: BLE001
        log.info("gchat: token rejected: %s", type(exc).__name__)
        return None
    if not isinstance(claims, dict) or claims.get("iss") != CHAT_ISSUER:
        log.info("gchat: token rejected: wrong issuer")
        return None
    return claims


def _event_action(ev: dict[str, Any]) -> tuple[str, dict[str, str]]:
    """(function name, parameters) from either Chat event shape."""
    common = _as_dict(ev.get("common"))
    action = _as_dict(ev.get("action"))
    name = str(common.get("invokedFunction") or action.get("actionMethodName") or "")
    params: dict[str, str] = {}
    cp = common.get("parameters")
    if isinstance(cp, dict):
        params.update({str(k): str(v) for k, v in cp.items()})
    ap = action.get("parameters")
    if isinstance(ap, list):
        for p in ap:
            if isinstance(p, dict) and "key" in p:
                params.setdefault(str(p["key"]), str(p.get("value", "")))
    return name, params


def _reply(text: str) -> dict[str, Any]:
    return {"text": text}


def make_gchat_router(get_manager: Callable[[], Any]) -> APIRouter:
    """APIRouter with POST /api/gchat/event.  404 unless GCHAT_APP_ENABLED=1."""
    router = APIRouter()

    @router.get("/api/gchat/status")
    async def gchat_status() -> dict[str, bool]:
        # Booleans only: the webhook URL is a secret and never leaves the server.
        return {"webhook": _webhook_url() is not None, "app": app_enabled()}

    @router.post("/api/gchat/event")
    async def gchat_event(request: Request) -> dict[str, Any]:
        if not app_enabled():
            raise HTTPException(status_code=404, detail="Not Found")

        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="unauthorized")
        claims = await run_in_threadpool(verify_chat_token, token)
        if claims is None:
            raise HTTPException(status_code=401, detail="unauthorized")

        try:
            ev = json.loads(await request.body())
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(status_code=400, detail="bad json") from None
        if not isinstance(ev, dict):
            raise HTTPException(status_code=400, detail="bad event")
        if ev.get("type") != "CARD_CLICKED":
            return {}

        name, params = _event_action(ev)
        decision = _ACTIONS.get(name)
        if decision is None:
            return _reply("Unknown action.")
        email = str(_as_dict(ev.get("user")).get("email") or "").strip()
        if "@" not in email or any(ord(c) < 32 or ord(c) == 127 for c in email):
            return _reply("No reviewer email in the event; decision not recorded.")

        sid = params.get("session_id", "")
        try:
            sess = get_manager().get(sid) if sid else None
        except Exception:  # noqa: BLE001
            sess = None
        if sess is None:
            return _reply("Session not found.")
        if getattr(sess, "status", "") != "awaiting_decision":
            return _reply("Nothing to decide for this session.")

        # H1: Chat clicks are deny-only (same rule as phone/voice).
        # A release click does NOT auto-sign: the human must confirm via
        # the story page button or two-person team approval.
        if decision == "release" and CHAT_DENY_ONLY:
            try:  # tell the page (no email: the feed may be public)
                sess._add_event({"seq": 0, "kind": "info",
                                 "text": "Release requested via Google Chat, confirm with button"})
            except Exception:  # noqa: BLE001
                log.warning("gchat: could not add release-request event")
            return _reply("Release requested via Chat. Confirm with the story page button.")

        from arena.session import AlreadyDecidedError  # lazy: heavy module
        try:
            result = await run_in_threadpool(sess.decide, decision, reviewer=email,
                                             _internal=False)
        except AlreadyDecidedError:
            return _reply("Already decided.")
        except ValueError as exc:
            return _reply(f"Decision not accepted: {exc}")
        except Exception as exc:  # noqa: BLE001
            log.warning("gchat: decide failed: %s", type(exc).__name__)
            return _reply(f"Decision not signed: {type(exc).__name__}. Try again.")

        receipt = _as_dict(_as_dict(result).get("receipt"))
        sig = receipt.get("signature_short") or "(unsigned)"
        return _reply(f"{_DECISION_LABEL[decision]} by {email}. Receipt {sig}.")

    return router
