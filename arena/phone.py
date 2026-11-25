"""Bolna phone call integration: place a call, poll for decision.

When a tripwire fires and the judge wants a phone call, we call the
Bolna API to place an outbound call with the "Tripwire security caller"
agent.  The agent explains the incident, asks keep frozen or release,
confirms, and hangs up.  We poll for the transcript and extraction.

Public API
----------
- ``validate_number(number)``  -- E.164 India mobile only
- ``mask_number(number)``      -- +91 98***389
- ``place_call(session, number, lang, http_client=None)`` -- {execution_id}
- ``poll(execution_id, http_client=None)`` -- {status, decision, confirmed, transcript_excerpt}
- ``build_call_message(trip, lang)`` -- build the user_data.message from trip record
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Protocol

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_E164_INDIA_MOBILE = re.compile(r"\+91[6-9]\d{9}\Z")  # \Z not $ (M2: fullmatch semantics)

BOLNA_CALL_URL = "https://api.bolna.ai/call"
BOLNA_EXEC_URL = "https://api.bolna.ai/executions"

# The agent id is loaded from phone_agent.json (no secrets in it)
_AGENT_ID: str | None = None
_AGENT_JSON = Path(__file__).resolve().parent / "phone_agent.json"
_AGENT_EXAMPLE = Path(__file__).resolve().parent / "phone_agent.example.json"


def _load_agent_id() -> str:
    """Load the Bolna agent id from phone_agent.json.

    Falls back to phone_agent.example.json when the real file is absent.
    Returns "" (empty string) when neither file exists or the agent_id is blank,
    so callers can check before placing a call.
    """
    global _AGENT_ID
    if _AGENT_ID is not None:
        return _AGENT_ID
    for path in (_AGENT_JSON, _AGENT_EXAMPLE):
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            aid = data.get("agent_id", "")
            if aid:
                _AGENT_ID = aid
                return _AGENT_ID
    # Return empty instead of crashing -- callers should guard on non-empty.
    return ""


def _load_bolna_key() -> str:
    """Load the Bolna API key from env or key file. Never log it."""
    key = os.environ.get("BOLNA_API_KEY", "")
    if key:
        return key
    key_file = os.environ.get("BOLNA_KEY_FILE", "")
    if key_file:
        return Path(key_file).read_text(encoding="utf-8").strip()
    raise RuntimeError("BOLNA_API_KEY or BOLNA_KEY_FILE must be set")


# ---------------------------------------------------------------------------
# Validation and masking
# ---------------------------------------------------------------------------

def validate_number(number: str) -> bool:
    """Return True if number is a valid E.164 India mobile number."""
    return bool(re.fullmatch(r"\+91[6-9][0-9]{9}", number))


def mask_number(number: str) -> str:
    """Mask an Indian mobile number for display: +91 98*****389."""
    if not number or len(number) < 13:
        return "***"
    # +91 XX XXXXX XXX -> show first 2 digits and last 3 digits of the 10-digit part
    # +91 9 8 _ _ _ _ _ 3 8 9
    local = number[3:]  # 10 digits after +91
    return f"+91 {local[:2]}{chr(0x2022) * 5}{local[-3:]}"


# ---------------------------------------------------------------------------
# HTTP client protocol (for injection in tests)
# ---------------------------------------------------------------------------

class HTTPClient(Protocol):
    """Minimal HTTP client interface for Bolna API calls."""

    def post(self, url: str, *, headers: dict[str, str],
             json_body: dict[str, Any]) -> dict[str, Any]: ...

    def get(self, url: str, *, headers: dict[str, str]) -> dict[str, Any]: ...


class _DefaultHTTPClient:
    """Real HTTP client using urllib (no extra deps)."""

    def post(self, url: str, *, headers: dict[str, str],
             json_body: dict[str, Any]) -> dict[str, Any]:
        import urllib.request
        data = json.dumps(json_body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def get(self, url: str, *, headers: dict[str, str]) -> dict[str, Any]:
        import urllib.request
        req = urllib.request.Request(url, method="GET", headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Build the call message from a trip record
# ---------------------------------------------------------------------------

def build_call_message(trip: dict[str, Any], lang: str = "en") -> str:
    """Build the user_data.message string from the real trip record.

    Contains: what was touched, by which tool, that the agent is frozen
    and the stop is signed.  No secrets or full paths.
    """
    kind = trip.get("kind", "unknown")
    path = trip.get("path", "unknown")
    tool = trip.get("tool", "unknown")
    evidence = trip.get("evidence", "")
    agent_task = trip.get("agent_task", "")
    sig_short = trip.get("signature_short", "")

    # Mask the path to hide full filesystem paths
    if "/" in path or "\\" in path:
        # Keep only the filename
        path = path.replace("\\", "/").split("/")[-1]

    if kind == "egress_blocked":
        host = str(trip.get("host", "") or "an unknown host")
        action = f"tried to send data to an unknown website {host}; the request was blocked"
    elif "decoy" in kind:
        action = f"opened a decoy secret file ({path})"
    elif "canary" in kind or "exfil" in kind:
        action = f"tried to exfiltrate data from {path}"
    else:
        action = f"triggered a tripwire at {path}"

    parts = [
        f"An AI coding agent {action} using {tool}.",
        "The agent has been frozen and cannot take any more actions.",
    ]
    if sig_short:
        parts.append(f"The stop is signed (signature: {sig_short}).")
    # M2: never put agent_task or other user text into the Bolna message.
    # Use only fixed incident description from the trip record.
    if evidence:
        parts.append(f"Evidence: {evidence}")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Place call
# ---------------------------------------------------------------------------

def place_call(
    session: Any,
    number: str,
    lang: str = "en",
    *,
    http_client: HTTPClient | None = None,
) -> dict[str, Any]:
    """Place a Bolna outbound call for a tripped session.

    Returns {"execution_id": "..."}.
    Raises ValueError for bad numbers, RuntimeError for API errors.
    """
    if not validate_number(number):
        raise ValueError(f"Invalid phone number (must be E.164 India mobile): {mask_number(number)}")

    if lang not in ("en", "hi", "te"):
        lang = "en"

    trip = session.trip or {}
    message = build_call_message(trip, lang)

    agent_id = _load_agent_id()
    if not agent_id:
        raise RuntimeError(
            "phone_agent.json not found or agent_id is blank -- "
            "copy phone_agent.example.json to phone_agent.json and fill in your Bolna agent details"
        )
    key = _load_bolna_key()
    client = http_client or _DefaultHTTPClient()

    lang_names = {"en": "English", "hi": "Hindi", "te": "Telugu"}

    body = {
        "agent_id": agent_id,
        "recipient_phone_number": number,
        "user_data": {
            "message": message,
            "lang": lang_names.get(lang, "English"),
        },
    }

    headers = {"Authorization": f"Bearer {key}"}

    try:
        resp = client.post(BOLNA_CALL_URL, headers=headers, json_body=body)
    except Exception as exc:
        raise RuntimeError(f"Bolna API error: {type(exc).__name__}") from exc

    execution_id = resp.get("execution_id", "")
    if not execution_id:
        raise RuntimeError("Bolna API returned no execution_id")

    return {"execution_id": execution_id}


# ---------------------------------------------------------------------------
# Poll for result
# ---------------------------------------------------------------------------

def poll(
    execution_id: str,
    *,
    http_client: HTTPClient | None = None,
) -> dict[str, Any]:
    """Poll a Bolna execution for status, decision, and transcript.

    Returns {status, decision, confirmed, transcript_excerpt}.
    """
    key = _load_bolna_key()
    client = http_client or _DefaultHTTPClient()

    url = f"{BOLNA_EXEC_URL}/{execution_id}"
    headers = {"Authorization": f"Bearer {key}"}

    try:
        resp = client.get(url, headers=headers)
    except Exception as exc:
        return {
            "status": "error",
            "decision": None,
            "confirmed": False,
            "transcript_excerpt": f"API error: {type(exc).__name__}",
        }

    status = resp.get("status", "unknown")
    transcript = resp.get("transcript", "")

    # Extract decision from extracted_data if available
    decision, confirmed = _extract_decision(resp, transcript)

    # Build a short transcript excerpt (last 200 chars, no secrets)
    excerpt = ""
    if isinstance(transcript, str) and transcript:
        excerpt = transcript[-200:] if len(transcript) > 200 else transcript
    elif isinstance(transcript, list):
        # Sometimes transcript is a list of utterances
        texts = [u.get("text", "") for u in transcript if isinstance(u, dict)]
        combined = " ".join(texts)
        excerpt = combined[-200:] if len(combined) > 200 else combined

    return {
        "status": status,
        "decision": decision,
        "confirmed": confirmed,
        "transcript_excerpt": excerpt,
    }


def _extract_decision(resp: dict[str, Any], transcript: Any) -> tuple[str | None, bool]:
    """Extract decision and confirmation from Bolna response.

    Checks extracted_data first (preferred, structured), then falls back
    to transcript parsing.  The transcript fallback parses ONLY user/caller
    turns (never the agent's), requires the agent to have read back a
    decision AND a caller confirmation word after it.  Any conflict or
    missing confirmation -> ("unclear", False) -> NO decide.

    Returns (decision, confirmed).  "unclear" is mapped to None so the
    caller never signs a guessed decision.
    """
    # ----- 1. Structured extraction (preferred) -----
    decision_ext, confirmed_ext = _try_structured_extraction(resp)
    if decision_ext in ("keep_frozen", "release"):
        return decision_ext, confirmed_ext
    # If extraction says "unclear" or is absent, fall through to transcript

    # ----- 2. Transcript fallback: structured transcript with turns -----
    # H1: requires agent readback between decision turn and confirmation turn
    return _parse_transcript_with_readback(transcript)


def _try_structured_extraction(resp: dict[str, Any]) -> tuple[str | None, bool]:
    """Read the Bolna extracted_data fields (dispositions)."""
    extracted = resp.get("extracted_data", {})
    if not isinstance(extracted, dict) or not extracted:
        return None, False

    decision_val = None
    confirmed_val = False

    for category in extracted.values():
        if not isinstance(category, dict):
            continue
        for field_name, val in category.items():
            obj_val = ""
            if isinstance(val, dict):
                obj_val = str(val.get("objective", "")).strip().lower()
            else:
                obj_val = str(val).strip().lower()

            fname = field_name.lower()

            if "decision" in fname:
                if obj_val in ("keep_frozen", "keep frozen"):
                    decision_val = "keep_frozen"
                elif obj_val == "release":
                    decision_val = "release"
                elif obj_val == "unclear":
                    decision_val = None  # treat as no decision
                else:
                    decision_val = None

            if "confirmed" in fname or "confirm" in fname:
                confirmed_val = obj_val in ("true", "yes", "confirmed")

    return decision_val, confirmed_val


def _get_user_turns(transcript: Any) -> list[str]:
    """Extract only the user/caller turns from the transcript.

    Bolna transcripts come in two formats:
    - str: "role: text\\nrole: text" with "user:" and "assistant:" prefixes
    - list[dict]: [{role, text}, ...]
    """
    user_turns: list[str] = []

    if isinstance(transcript, list):
        for u in transcript:
            if isinstance(u, dict):
                role = str(u.get("role", "")).lower()
                text = str(u.get("text", "")).strip()
                if role in ("user", "human", "caller") and text:
                    user_turns.append(text.lower())
        return user_turns

    if isinstance(transcript, str) and transcript.strip():
        # Try to split by role prefixes
        lines = transcript.split("\n")
        in_user_block = False
        current = []
        for line in lines:
            stripped = line.strip().lower()
            if stripped.startswith("user:") or stripped.startswith("human:") or stripped.startswith("caller:"):
                if current and in_user_block:
                    user_turns.append(" ".join(current))
                    current = []
                in_user_block = True
                # Remove the prefix
                for prefix in ("user:", "human:", "caller:"):
                    if stripped.startswith(prefix):
                        stripped = stripped[len(prefix):].strip()
                        break
                if stripped:
                    current.append(stripped)
            elif stripped.startswith("assistant:") or stripped.startswith("agent:") or stripped.startswith("bot:"):
                if current and in_user_block:
                    user_turns.append(" ".join(current))
                    current = []
                in_user_block = False
            elif in_user_block and stripped:
                current.append(stripped)
        if current and in_user_block:
            user_turns.append(" ".join(current))

        # If we got role-based turns, return them
        if user_turns:
            return user_turns

        # Last resort: cannot distinguish roles in flat text -> return empty
        # (do NOT parse agent text as user text; that caused the live bug)
        return []

    return []


def _parse_transcript_with_readback(transcript: Any) -> tuple[str | None, bool]:
    """Parse a transcript requiring agent readback between decision and confirm.

    H1: confirmation must be a separate, later caller turn that comes AFTER
    an agent turn which repeated the decision back.
    """
    # Build turn list with roles: list of (role, text)
    turns: list[tuple[str, str]] = []
    if isinstance(transcript, list):
        for u in transcript:
            if isinstance(u, dict):
                role = str(u.get("role", "")).lower()
                text = str(u.get("text", "")).strip()
                if text:
                    turns.append((role, text.lower()))
    elif isinstance(transcript, str) and transcript.strip():
        lines = transcript.split("\n")
        in_role = ""
        current: list[str] = []
        for line in lines:
            stripped = line.strip().lower()
            if stripped.startswith(("user:", "human:", "caller:")):
                if current and in_role:
                    turns.append((in_role, " ".join(current)))
                in_role = "user"
                current = []
                for prefix in ("user:", "human:", "caller:"):
                    if stripped.startswith(prefix):
                        rest = stripped[len(prefix):].strip()
                        if rest:
                            current.append(rest)
                        break
            elif stripped.startswith(("assistant:", "agent:", "bot:")):
                if current and in_role:
                    turns.append((in_role, " ".join(current)))
                in_role = "assistant"
                current = []
                for prefix in ("assistant:", "agent:", "bot:"):
                    if stripped.startswith(prefix):
                        rest = stripped[len(prefix):].strip()
                        if rest:
                            current.append(rest)
                        break
            elif stripped and in_role:
                current.append(stripped)
        if current and in_role:
            turns.append((in_role, " ".join(current)))
        if not turns:
            return None, False

    if not turns:
        return None, False

    # Extract only user turns for decision parsing
    user_turns = [text for role, text in turns if role in ("user", "human", "caller")]
    if not user_turns:
        return None, False

    # Find the decision using the standard parser
    decision, _ = _parse_user_turns(user_turns)
    if decision is None:
        return None, False

    # Now check for readback: an agent turn must exist between the decision
    # turn and a user confirmation turn.
    # Find the last decision turn index in the full turn list
    last_decision_full_idx = -1
    for idx, (role, text) in enumerate(turns):
        if role not in ("user", "human", "caller"):
            continue
        f_hit = _mentions(text, _FREEZE_PHRASES)
        r_hit = _mentions(text, _RELEASE_PHRASES)
        if f_hit and not _turn_has_negation(text) and not _turn_is_question(text):
            if decision == "keep_frozen":
                last_decision_full_idx = idx
        if r_hit and not _turn_has_negation(text) and not _turn_is_question(text):
            if decision == "release":
                last_decision_full_idx = idx

    if last_decision_full_idx < 0:
        return decision, False

    # Look for an agent turn after the decision turn, then a user confirm after that
    agent_readback_idx = -1
    for idx in range(last_decision_full_idx + 1, len(turns)):
        role, text = turns[idx]
        if role in ("assistant", "agent", "bot"):
            agent_readback_idx = idx
            break

    if agent_readback_idx < 0:
        return decision, False

    # Look for a user confirmation turn after the agent readback
    confirmed = False
    for idx in range(agent_readback_idx + 1, len(turns)):
        role, text = turns[idx]
        if role not in ("user", "human", "caller"):
            continue
        if any(_phrase_re(w).search(text) for w in _CONFIRM_WORDS):
            confirmed = True
            break

    return decision, confirmed


# Confirmation words across supported languages
_CONFIRM_WORDS = frozenset({
    # English
    "yes", "correct", "confirmed", "confirm", "that's correct",
    "that is correct", "right", "yep", "yeah", "affirmative",
    # Hindi
    "haan", "ha", "haa", "ji", "ji haan", "sahi hai", "theek hai",
    # Telugu
    "avunu", "avu", "avnu", "correct", "sare",
})

_FREEZE_PHRASES = [
    "keep frozen", "remain frozen", "stay frozen", "confirm frozen",
    "freeze it", "keep it frozen", "yes frozen", "frozen please",
    "frozen", "keep freeze", "freeze",
]

_RELEASE_PHRASES = [
    "release it", "release the agent", "let it go", "release please",
    "unfreeze", "yes release", "release",
]


# H1: negation words -- ANY negation word ANYWHERE in the same turn as a
# decision phrase makes the turn unclear. Covers English, Hindi, Telugu.
_NEGATION_WORDS = frozenset({
    # English -- "don't", "not", "never", "no" (not bare "do"/"does" to avoid false positives)
    "don't", "dont", "not", "never", "no",
    # Hindi
    "mat", "nahi", "nahin", "na",
    # Telugu
    "vaddu", "ledu",
})
# Telugu suffix: -kandi (e.g. cheyyakandi)
_KANDI_SUFFIX_RE = re.compile(r"\w+kandi\b", re.IGNORECASE)

# H1 founder ruling: phone/voice can auto-sign deny only.
# A spoken "release" becomes a pending request requiring the button.
VOICE_DENY_ONLY: bool = True


def _phrase_re(phrase: str) -> "re.Pattern[str]":
    words = r"\s+".join(re.escape(w) for w in phrase.split())
    return re.compile(r"(?<![\w'])" + words + r"(?![\w'])", re.IGNORECASE)


def _turn_has_negation(turn: str) -> bool:
    """True if any negation word appears anywhere in the turn."""
    words = re.findall(r"[a-zA-Z'ऀ-ॿఀ-౿]+", turn.lower())
    if _KANDI_SUFFIX_RE.search(turn):
        return True
    return bool(_NEGATION_WORDS & set(words))


def _turn_is_question(turn: str) -> bool:
    """True if the turn contains a question mark or 'should i'."""
    if "?" in turn:
        return True
    if re.search(r"\bshould\s+i\b", turn, re.IGNORECASE):
        return True
    return False


def _mentions(turn: str, phrases) -> bool:
    """True if any phrase appears as whole words in the turn."""
    return any(_phrase_re(p).search(turn) for p in phrases)


def _parse_user_turns(user_turns: list[str]) -> tuple[str | None, bool]:
    """Parse the CALLER's turns for a decision + confirmation (fail closed).

    - Whole-word matching only ("ha" never matches inside "that").
    - Any negation word ANYWHERE in a turn that contains a decision phrase
      makes that turn unclear (H1). Covers English, Hindi, Telugu.
    - A question mark or "should i" in a decision turn makes it unclear (H1).
    - The last clear decision wins; both decisions in one turn = unclear.
    - A confirmation word must appear in a LATER caller turn (not same turn
      as decision) -- i.e., the user confirms in a separate turn (H1).
    """
    last_decision = None
    last_decision_idx = -1

    for idx, turn in enumerate(user_turns):
        f_hit = _mentions(turn, _FREEZE_PHRASES)
        r_hit = _mentions(turn, _RELEASE_PHRASES)
        # "unfreeze" is a release word: drop the freeze hit it would cause
        if r_hit and f_hit and not _phrase_re("freeze").search(turn.replace("unfreeze", "")) \
                and not any(_phrase_re(p).search(turn) for p in _FREEZE_PHRASES if p != "freeze"):
            f_hit = False

        has_decision = f_hit or r_hit
        has_neg = _turn_has_negation(turn) if has_decision else False
        is_question = _turn_is_question(turn) if has_decision else False

        if has_neg or is_question or (f_hit and r_hit):
            last_decision, last_decision_idx = "conflict", idx
        elif f_hit:
            last_decision, last_decision_idx = "keep_frozen", idx
        elif r_hit:
            last_decision, last_decision_idx = "release", idx

    if last_decision is None or last_decision == "conflict":
        return None, False

    # H1: confirmation must be in a LATER turn (not same as decision turn)
    confirmed = any(_phrase_re(w).search(user_turns[i])
                    for i in range(last_decision_idx + 1, len(user_turns))
                    for w in _CONFIRM_WORDS)
    return last_decision, confirmed
