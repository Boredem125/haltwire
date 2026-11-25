"""Gemini Live voice bridge: the AI security officer calls the human judge.

When an AI coding agent touches a honeypot secret, it is frozen.  Gemini Live
then "calls" the judge in the browser, explains what happened, asks whether to
keep the agent frozen or release it, reads the decision back, and only after
explicit confirmation calls the ``record_decision`` tool.  Our server (not
Gemini) signs the decision with Ed25519 via ``arena.duel``.

Public API
----------
- ``build_system_prompt(trip, lang)`` -- build the voice system instruction
- ``bridge(ws_recv, ws_send_bytes, ws_send_json, trip, lang, on_decision, ...)``
  -- run the full voice session over an injected WebSocket transport
- ``handle_call(websocket, trip, lang, on_decision)``
  -- convenience wrapper for a Starlette/FastAPI WebSocket
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Callable, Awaitable

from google.genai import types

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_DECISIONS = frozenset({"keep_frozen", "release"})

# H1 founder ruling: voice can auto-sign deny only.
# A spoken "release" emits an event but stays awaiting_decision for the button.
VOICE_DENY_ONLY: bool = True

DEFAULT_MODEL = "gemini-3.1-flash-live-preview"
TIME_CAP_S = 90.0
MAX_INBOUND_BYTES = 2 * 1024 * 1024  # 2 MB

AUDIO_MIME = "audio/pcm;rate=16000"

_LANG_NAMES = {"en": "English", "hi": "Hindi", "te": "Telugu"}

# Scrub patterns: strip anything that looks like a secret key from error msgs
_SECRET_RE = re.compile(
    r"(sk_live_|sk_test_|AKIA|AIza|SECRET_?KEY|PASSWORD|TOKEN|API_KEY|"
    r"postgres://|GEMINI_API_KEY)\S*",
    re.I,
)


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

def build_system_prompt(trip: dict, lang: str) -> str:
    """Build the voice system instruction from a real trip record.

    Parameters
    ----------
    trip : dict
        Must have keys: kind, path, tool, evidence, agent_task.
    lang : str
        One of "en", "hi", "te".  Unknown languages fall back to English.

    Returns a short, calm prompt that:
    - describes the incident using only the record fields
    - instructs the model to never claim facts not in the record
    - asks the judge: keep frozen or release?
    - read the decision back and call record_decision only after confirmation
    - if unclear, ask again
    """
    lang_name = _LANG_NAMES.get(lang, _LANG_NAMES["en"])

    kind = trip.get("kind", "unknown")
    path = trip.get("path", "unknown path")
    tool = trip.get("tool", "unknown tool")
    evidence = trip.get("evidence", "")
    agent_task = trip.get("agent_task", "")

    if kind == "egress_blocked":
        host = str(trip.get("host", "") or "an unknown host")
        action_desc = f"tried to send data to an unknown website {host}; the request was blocked"
    elif "decoy" in kind:
        action_desc = f"opened a decoy secret file at {path} using {tool}"
    elif "canary" in kind or "exfil" in kind:
        action_desc = f"attempted to exfiltrate data from {path} using {tool}"
    else:
        action_desc = f"triggered a tripwire at {path} using {tool}"

    prompt = (
        f"You are a calm security officer making a voice call to a developer. "
        f"Speak in {lang_name}.\n\n"
        f"INCIDENT RECORD (these are the only facts you may state):\n"
        f"- Kind: {kind}\n"
        f"- Path: {path}\n"
        f"- Tool: {tool}\n"
        f"- Evidence: {evidence}\n"
        f"- Agent task: {agent_task}\n\n"
        f"The developer's AI coding agent {action_desc} and has been frozen.\n\n"
        f"INSTRUCTIONS:\n"
        f"1. Explain the incident in two short sentences, then ask: "
        f"keep the agent frozen, or release it?\n"
        f"2. Do not claim any facts not in the record above.\n"
        f"3. When the human answers, read their decision back to them clearly.\n"
        f"4. Call record_decision ONLY after the human explicitly confirms "
        f"the read-back is correct.\n"
        f"5. If their answer is unclear, ask again for clarification.\n"
        f"6. You may answer 'what happened?' questions using only the record above."
    )
    return prompt


# ---------------------------------------------------------------------------
# Bridge: the core voice loop
# ---------------------------------------------------------------------------

async def bridge(
    ws_recv: Callable[[], Awaitable[bytes | str]],
    ws_send_bytes: Callable[[bytes], Awaitable[None]],
    ws_send_json: Callable[[dict], Awaitable[None]],
    trip: dict,
    lang: str,
    on_decision: Callable[[str], Awaitable[dict]],
    *,
    connect: Callable | None = None,
    model: str = DEFAULT_MODEL,
    time_cap: float = TIME_CAP_S,
) -> None:
    """Run a Gemini Live voice session bridged to a WebSocket client.

    Parameters
    ----------
    ws_recv :
        Awaitable that returns bytes (PCM16 audio) or str (JSON text frame).
        Raise ``StopAsyncIteration`` or return ``None`` on client disconnect.
    ws_send_bytes :
        Send raw bytes (audio) to the client.
    ws_send_json :
        Send a JSON dict to the client.
    trip : dict
        The tripwire record (kind, path, tool, evidence, agent_task).
    lang : str
        Language code (en, hi, te).
    on_decision :
        Called once with the decision string ("keep_frozen" or "release").
        Must return a receipt dict.
    connect :
        Injectable session factory for tests.  Signature:
        ``async def connect(model, config) -> session``.
    model :
        Gemini model name.
    time_cap :
        Maximum call duration in seconds.
    """
    session = None
    _ctx = None  # keep context manager alive to prevent GC closing the ws
    decided = False

    try:
        # Build config
        sys_prompt = build_system_prompt(trip, lang)
        tool_decl = types.Tool(function_declarations=[
            types.FunctionDeclaration(
                name="record_decision",
                description="Record the human's confirmed decision.",
                parameters=types.Schema(
                    type="OBJECT",
                    properties={
                        "decision": types.Schema(
                            type="STRING",
                            enum=["keep_frozen", "release"],
                        ),
                    },
                    required=["decision"],
                ),
            ),
        ])

        cfg = types.LiveConnectConfig(
            response_modalities=["AUDIO"],
            system_instruction=sys_prompt,
            tools=[tool_decl],
            output_audio_transcription=types.AudioTranscriptionConfig(),
            input_audio_transcription=types.AudioTranscriptionConfig(),
        )

        # Open session
        if connect is not None:
            session = await connect(model, cfg)
        else:
            from google import genai
            from arena.agent import _load_keys

            # Primary key first; if the connect is refused (429 rate limit or
            # quota), open the session with the fallback key instead.
            keys = _load_keys()
            last_exc: Exception | None = None
            session = None
            for i, key in enumerate(keys):
                client = genai.Client(api_key=key, http_options={"api_version": "v1beta"})
                _ctx = client.aio.live.connect(model=model, config=cfg)
                try:
                    session = await _ctx.__aenter__()
                    break
                except Exception as exc:  # noqa: BLE001 - try the next key
                    last_exc = exc
                    if i == len(keys) - 1:
                        raise
            if session is None and last_exc is not None:
                raise last_exc

        # Send initial text so Gemini speaks first
        await session.send_client_content(
            turns=types.Content(
                role="user",
                parts=[types.Part(text="The developer picked up the phone.")],
            ),
            turn_complete=True,
        )

        # Run receive loop and client forward loop concurrently with a time cap
        inbound_bytes = 0
        done_event = asyncio.Event()

        async def _process_msg(msg):
            """Process one Gemini server message."""
            nonlocal decided

            # Audio data -> binary frame to client
            if msg.data:
                await ws_send_bytes(msg.data)

            # Transcripts
            sc = msg.server_content
            if sc:
                if sc.output_transcription and sc.output_transcription.text:
                    await ws_send_json({
                        "type": "transcript",
                        "who": "agent",
                        "text": sc.output_transcription.text,
                    })
                if sc.input_transcription and sc.input_transcription.text:
                    await ws_send_json({
                        "type": "transcript",
                        "who": "you",
                        "text": sc.input_transcription.text,
                    })

            # Tool call
            if msg.tool_call:
                for fc in msg.tool_call.function_calls:
                    if fc.name == "record_decision":
                        decision_val = (fc.args or {}).get("decision", "")
                        if decision_val not in VALID_DECISIONS:
                            await session.send_tool_response(
                                function_responses=[
                                    types.FunctionResponse(
                                        id=fc.id,
                                        name=fc.name,
                                        response={
                                            "error": "Invalid. Must be keep_frozen or release."
                                        },
                                    )
                                ]
                            )
                            return

                        if not decided:
                            decided = True
                            receipt = await on_decision(decision_val)
                            await ws_send_json({
                                "type": "decision",
                                "decision": decision_val,
                                "receipt": receipt,
                            })
                            await session.send_tool_response(
                                function_responses=[
                                    types.FunctionResponse(
                                        id=fc.id,
                                        name=fc.name,
                                        response={"ok": True, "decision": decision_val},
                                    )
                                ]
                            )
                        else:
                            await session.send_tool_response(
                                function_responses=[
                                    types.FunctionResponse(
                                        id=fc.id,
                                        name=fc.name,
                                        response={"ok": True, "already_decided": True},
                                    )
                                ]
                            )

        async def _recv_gemini():
            """Receive from Gemini, forward audio and transcripts to client.

            The SDK's ``session.receive()`` yields messages until the model
            turn is complete, then stops.  We loop and call it again for
            each successive turn until the session ends or we are done.
            """
            MAX_TURNS = 20  # safety valve
            for turn_i in range(MAX_TURNS):
                if done_event.is_set():
                    return
                try:
                    async for msg in session.receive():
                        await _process_msg(msg)
                except asyncio.CancelledError:
                    return
                except Exception:
                    return  # session closed or network error

                # After a decided + closing turn, stop
                if decided:
                    done_event.set()
                    return

        async def _recv_client():
            """Receive from the WebSocket client, forward to Gemini."""
            nonlocal inbound_bytes
            while not done_event.is_set():
                try:
                    frame = await ws_recv()
                except (StopAsyncIteration, StopIteration):
                    return
                if frame is None:
                    return

                if isinstance(frame, bytes):
                    # PCM16 audio from client
                    if inbound_bytes + len(frame) > MAX_INBOUND_BYTES:
                        continue
                    inbound_bytes += len(frame)
                    try:
                        await session.send_realtime_input(
                            audio=types.Blob(data=frame, mime_type=AUDIO_MIME),
                        )
                    except Exception:
                        return
                elif isinstance(frame, str):
                    try:
                        obj = json.loads(frame)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if obj.get("type") == "text" and obj.get("text"):
                        try:
                            await session.send_client_content(
                                turns=types.Content(
                                    role="user",
                                    parts=[types.Part(text=obj["text"])],
                                ),
                                turn_complete=True,
                            )
                        except Exception:
                            return

        try:
            results = await asyncio.wait_for(
                asyncio.gather(_recv_gemini(), _recv_client(), return_exceptions=True),
                timeout=time_cap,
            )
            # Log any unexpected exceptions (for debugging, not sent to client)
            for r in (results or []):
                if isinstance(r, BaseException) and not isinstance(
                    r, (StopAsyncIteration, StopIteration, asyncio.CancelledError)
                ):
                    # Unexpected error in one of the tasks -- ignore silently
                    pass
        except asyncio.TimeoutError:
            pass

    except Exception as exc:
        # Send error frame to client -- scrub secrets and stack traces
        err_msg = str(exc)
        err_msg = _SECRET_RE.sub("[REDACTED]", err_msg)
        # Keep it short
        if len(err_msg) > 200:
            err_msg = err_msg[:200]
        await ws_send_json({"type": "error", "message": err_msg})
    finally:
        if _ctx is not None:
            try:
                await _ctx.__aexit__(None, None, None)
            except Exception:
                pass
        elif session is not None:
            try:
                await session.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# handle_call: Starlette / FastAPI WebSocket adapter
# ---------------------------------------------------------------------------

async def handle_call(
    websocket,
    trip: dict,
    lang: str,
    on_decision: Callable[[str], Awaitable[dict]],
) -> None:
    """Mount-ready handler for a Starlette/FastAPI WebSocket.

    Usage in a FastAPI route::

        @app.websocket("/ws/call/{call_id}")
        async def ws_call(websocket: WebSocket, call_id: str):
            await websocket.accept()
            trip = get_trip(call_id)
            await handle_call(websocket, trip, "en", my_on_decision)

    Parameters
    ----------
    websocket :
        A Starlette WebSocket (accepted).
    trip : dict
        The tripwire record.
    lang : str
        Language code.
    on_decision :
        Callback; receives the decision string, returns a receipt dict.
    """

    async def ws_recv():
        try:
            msg = await websocket.receive()
        except Exception:
            raise StopAsyncIteration
        if msg.get("type") == "websocket.disconnect":
            raise StopAsyncIteration
        if "bytes" in msg and msg["bytes"]:
            return msg["bytes"]
        if "text" in msg and msg["text"]:
            return msg["text"]
        raise StopAsyncIteration

    async def ws_send_bytes(data: bytes):
        try:
            await websocket.send_bytes(data)
        except Exception:
            pass

    async def ws_send_json(obj: dict):
        try:
            await websocket.send_json(obj)
        except Exception:
            pass

    await bridge(ws_recv, ws_send_bytes, ws_send_json, trip, lang, on_decision)
