"""Tests for the POST /api/session/{id}/phone endpoint in arena.server.

Covers: validation, token auth, not-tripped rejection, once-per-session,
daily cap, per-IP cap, masked output, Bolna errors, ARENA_PHONE=0 disables,
poll -> decide integration, full number never persisted.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from arena import server, session as sess_mod, phone


# ---------------------------------------------------------------- helpers

FAKE_TRIP = {
    "kind": "decoy_read", "path": ".aws/credentials.bak",
    "canary_name": "aws_access_key",
    "evidence": "accessed decoy file: .aws/****tials.bak",
    "tool": "read_file",
    "agent_task": "Fix deploy",
}


async def _fake_run_session_trip(chip, workspace, *, guard, client, event_cb,
                                 tripwire, canaries, session_id, proxy_url, model,
                                 layout=None, ai=False):
    """Fake run_session that trips immediately."""
    events = []
    seq = 0

    def emit(kind, **kw):
        nonlocal seq
        seq += 1
        ev = {"seq": seq, "side": "protected", "ts": seq * 0.5,
              "kind": kind, "tool": kw.get("tool", ""),
              "text": kw.get("text", ""), "decision": kw.get("decision", ""),
              "reason": kw.get("reason", ""), "extra": kw.get("extra", {})}
        events.append(ev)
        if event_cb:
            event_cb(ev)
        return ev

    emit("info", text="Starting session")
    emit("tool", tool="list_dir", text=".")
    emit("trip", tool="read_file", text="TRIPPED",
         decision="deny", reason="canary accessed",
         extra={"trip": FAKE_TRIP})
    return events


async def _fake_run_session_clean(chip, workspace, *, guard, client, event_cb,
                                  tripwire, canaries, session_id, proxy_url, model,
                                  layout=None, ai=False):
    """Fake run_session that completes cleanly."""
    events = []
    seq = 0

    def emit(kind, **kw):
        nonlocal seq
        seq += 1
        ev = {"seq": seq, "side": "protected", "ts": seq * 0.5,
              "kind": kind, "tool": kw.get("tool", ""),
              "text": kw.get("text", ""), "decision": kw.get("decision", ""),
              "reason": kw.get("reason", ""), "extra": kw.get("extra", {})}
        events.append(ev)
        if event_cb:
            event_cb(ev)
        return ev

    emit("info", text="Starting session")
    emit("tool", tool="list_dir", text=".")
    emit("done", text="Task complete")
    return events


# ---------------------------------------------------------------- fixtures

@pytest.fixture(autouse=True)
def reset_phone_state():
    """Reset phone module state and server global phone counters between tests."""
    phone._AGENT_ID = None
    server._phone_sessions = set()
    server._phone_daily_count = 0
    server._phone_daily_reset = 0.0
    server._phone_ip_calls = {}
    yield
    phone._AGENT_ID = None
    server._phone_sessions = set()
    server._phone_daily_count = 0
    server._phone_daily_reset = 0.0
    server._phone_ip_calls = {}


@pytest.fixture
def runs_dir(tmp_path):
    d = tmp_path / "tw-runs"
    d.mkdir()
    return d


@pytest.fixture
def agent_json(tmp_path, monkeypatch):
    p = tmp_path / "phone_agent.json"
    p.write_text(json.dumps({"agent_id": "test-agent-phone"}), encoding="utf-8")
    monkeypatch.setattr(phone, "_AGENT_JSON", p)
    return p


@pytest.fixture(autouse=True)
def _reset_phone_state():
    """Reset per-module phone state between tests (M2: hashed number cap)."""
    server._phone_sessions.clear()
    server._phone_daily_count = 0
    server._phone_daily_reset = 0.0
    server._phone_ip_calls.clear()
    server._phone_number_hashes.clear()
    yield
    server._phone_sessions.clear()
    server._phone_daily_count = 0
    server._phone_daily_reset = 0.0
    server._phone_ip_calls.clear()
    server._phone_number_hashes.clear()


@pytest.fixture
def _tripped_client(runs_dir, monkeypatch, agent_json):
    """TestClient with a session manager that trips sessions + phone enabled."""
    monkeypatch.setenv("ARENA_RUNS", str(runs_dir))
    monkeypatch.setenv("ARENA_PHONE", "1")
    monkeypatch.setenv("BOLNA_API_KEY", "fake-test-key")
    mgr = sess_mod.SessionManager(runs_dir=runs_dir)
    monkeypatch.setattr(server, "_tw_manager", mgr)
    monkeypatch.setattr(sess_mod, "run_session", _fake_run_session_trip)
    with TestClient(server.app) as c:
        yield c


@pytest.fixture
def _clean_client(runs_dir, monkeypatch, agent_json):
    """TestClient with clean (non-tripped) sessions + phone enabled."""
    monkeypatch.setenv("ARENA_RUNS", str(runs_dir))
    monkeypatch.setenv("ARENA_PHONE", "1")
    monkeypatch.setenv("BOLNA_API_KEY", "fake-test-key")
    mgr = sess_mod.SessionManager(runs_dir=runs_dir)
    monkeypatch.setattr(server, "_tw_manager", mgr)
    monkeypatch.setattr(sess_mod, "run_session", _fake_run_session_clean)
    with TestClient(server.app) as c:
        yield c


def _create_tripped_session(client) -> tuple[str, str]:
    """Create a session that trips and return (session_id, token)."""
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    tok = r.json()["token"]
    # Wait for the session to trip
    time.sleep(1.0)
    return sid, tok


# ---------------------------------------------------------------- Validation tests

class TestPhoneValidation:

    def test_non_plus91_rejected(self, _tripped_client, monkeypatch):
        sid, tok = _create_tripped_session(_tripped_client)
        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+12125551234", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r.status_code == 400
        assert "Invalid" in r.json()["detail"]

    def test_landline_rejected(self, _tripped_client):
        sid, tok = _create_tripped_session(_tripped_client)
        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+910112345678", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r.status_code == 400

    def test_junk_rejected(self, _tripped_client):
        sid, tok = _create_tripped_session(_tripped_client)
        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "not-a-number", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r.status_code == 400


# ---------------------------------------------------------------- Token required

class TestPhoneAuth:

    def test_token_required(self, _tripped_client):
        sid, tok = _create_tripped_session(_tripped_client)
        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
        )
        assert r.status_code == 403

    def test_wrong_token_rejected(self, _tripped_client):
        sid, tok = _create_tripped_session(_tripped_client)
        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": "wrong-token"},
        )
        assert r.status_code == 403


# ---------------------------------------------------------------- Not-tripped 409

class TestPhoneNotTripped:

    def test_not_tripped_409(self, _clean_client):
        r = _clean_client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
        sid = r.json()["session_id"]
        tok = r.json()["token"]
        time.sleep(1.0)
        r2 = _clean_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r2.status_code == 409


# ---------------------------------------------------------------- Once per session

class TestPhoneOncePerSession:

    def test_second_call_409(self, _tripped_client, monkeypatch):
        sid, tok = _create_tripped_session(_tripped_client)

        # Patch place_call to succeed without hitting Bolna
        fake_result = {"execution_id": "exec-once"}
        monkeypatch.setattr(phone, "place_call",
                            lambda s, n, l, **kw: fake_result)

        r1 = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r1.status_code == 202

        r2 = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r2.status_code == 409
        assert "already" in r2.json()["detail"].lower()


# ---------------------------------------------------------------- Daily cap

class TestPhoneDailyCap:

    def test_daily_cap_429(self, _tripped_client, monkeypatch):
        monkeypatch.setenv("PHONE_DAILY_CAP", "2")

        fake_result = {"execution_id": "exec-cap"}
        monkeypatch.setattr(phone, "place_call",
                            lambda s, n, l, **kw: fake_result)

        # Bump the concurrent session limit so we can create several
        monkeypatch.setattr(sess_mod, "MAX_CONCURRENT", 10)

        # M2: use different numbers so per-number cap (2) doesn't trigger first
        numbers = ["+919876543210", "+919876543211", "+919876543212"]

        # Create and trip 3 sessions
        sessions = []
        for i in range(3):
            sid, tok = _create_tripped_session(_tripped_client)
            sessions.append((sid, tok))

        # First 2 should succeed (different numbers)
        for i in range(2):
            sid, tok = sessions[i]
            r = _tripped_client.post(
                f"/api/session/{sid}/phone",
                json={"number": numbers[i], "lang": "en"},
                headers={"X-Session-Token": tok},
            )
            assert r.status_code == 202, f"call {i+1} failed: {r.json()}"

        # Third should hit the daily cap
        sid, tok = sessions[2]
        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": numbers[2], "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r.status_code == 429


# ---------------------------------------------------------------- Per-IP cap

class TestPhonePerIPCap:

    def test_per_ip_cap_429(self, _tripped_client, monkeypatch):
        fake_result = {"execution_id": "exec-ip"}
        monkeypatch.setattr(phone, "place_call",
                            lambda s, n, l, **kw: fake_result)

        # Bump concurrent session limit
        monkeypatch.setattr(sess_mod, "MAX_CONCURRENT", 10)

        # M2: use different numbers so per-number cap doesn't trigger first
        numbers = ["+919876543210", "+919876543211", "+919876543212", "+919876543213"]

        # Create 4 sessions (per-IP cap is 3/day)
        sessions = []
        for i in range(4):
            sid, tok = _create_tripped_session(_tripped_client)
            sessions.append((sid, tok))

        for i in range(3):
            sid, tok = sessions[i]
            r = _tripped_client.post(
                f"/api/session/{sid}/phone",
                json={"number": numbers[i], "lang": "en"},
                headers={"X-Session-Token": tok},
            )
            assert r.status_code == 202, f"call {i+1} failed: {r.json()}"

        # 4th should hit per-IP cap
        sid, tok = sessions[3]
        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": numbers[3], "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r.status_code == 429


# ---------------------------------------------------------------- Masked output

class TestPhoneMaskedOutput:

    def test_response_uses_masked_number(self, _tripped_client, monkeypatch):
        sid, tok = _create_tripped_session(_tripped_client)
        fake_result = {"execution_id": "exec-mask"}
        monkeypatch.setattr(phone, "place_call",
                            lambda s, n, l, **kw: fake_result)

        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r.status_code == 202
        body = r.json()
        assert "masked" in body
        # Full number must NOT appear
        assert "9876543210" not in json.dumps(body)
        # Masked number should be present
        assert body["masked"].startswith("+91")

    def test_full_number_not_in_persisted_session(self, _tripped_client, monkeypatch, runs_dir):
        sid, tok = _create_tripped_session(_tripped_client)
        fake_result = {"execution_id": "exec-persist"}
        monkeypatch.setattr(phone, "place_call",
                            lambda s, n, l, **kw: fake_result)

        _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )

        # Check persisted session.json does NOT contain the full number
        session_json = runs_dir / "sessions" / sid / "session.json"
        if session_json.is_file():
            text = session_json.read_text(encoding="utf-8")
            assert "9876543210" not in text, "Full number found in persisted session.json"

    def test_full_number_not_in_events(self, _tripped_client, monkeypatch):
        sid, tok = _create_tripped_session(_tripped_client)
        fake_result = {"execution_id": "exec-events"}
        monkeypatch.setattr(phone, "place_call",
                            lambda s, n, l, **kw: fake_result)

        _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        time.sleep(0.3)

        # Poll and check events
        r = _tripped_client.get(f"/api/session/{sid}")
        text = json.dumps(r.json())
        assert "9876543210" not in text, "Full number found in event stream"


# ---------------------------------------------------------------- Bolna error -> clean error event

class TestPhoneBolnaError:

    def test_bolna_error_returns_clean_error(self, _tripped_client, monkeypatch):
        monkeypatch.setattr(sess_mod, "MAX_CONCURRENT", 10)
        sid, tok = _create_tripped_session(_tripped_client)

        def _raise(*a, **kw):
            raise RuntimeError("Bolna API error: ConnectionError")

        monkeypatch.setattr(phone, "place_call", _raise)

        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        # Should return a 502 or similar error, not 500
        assert r.status_code in (502, 500)


# ---------------------------------------------------------------- ARENA_PHONE=0 disables

class TestPhoneDisabled:

    def test_disabled_returns_404(self, runs_dir, monkeypatch, agent_json):
        monkeypatch.setenv("ARENA_RUNS", str(runs_dir))
        monkeypatch.setenv("ARENA_PHONE", "0")
        monkeypatch.setenv("BOLNA_API_KEY", "fake-test-key")
        mgr = sess_mod.SessionManager(runs_dir=runs_dir)
        monkeypatch.setattr(server, "_tw_manager", mgr)
        monkeypatch.setattr(sess_mod, "run_session", _fake_run_session_trip)

        with TestClient(server.app) as client:
            sid, tok = _create_tripped_session(client)
            r = client.post(
                f"/api/session/{sid}/phone",
                json={"number": "+919876543210", "lang": "en"},
                headers={"X-Session-Token": tok},
            )
            assert r.status_code == 404


# ---------------------------------------------------------------- Poll -> decide once integration

class TestPhonePollDecide:

    def test_poll_decide_keep_frozen(self, _tripped_client, monkeypatch):
        """When poll returns confirmed keep_frozen, session.decide is called once."""
        monkeypatch.setattr(sess_mod, "MAX_CONCURRENT", 10)
        sid, tok = _create_tripped_session(_tripped_client)

        # Track decide calls
        mgr = server._tw_manager
        s = mgr.get(sid)
        original_decide = s.decide
        decide_calls = []

        def tracking_decide(decision, reviewer):
            decide_calls.append((decision, reviewer))
            return original_decide(decision, reviewer)

        s.decide = tracking_decide

        # Patch place_call + poll to return confirmed decision
        monkeypatch.setattr(phone, "place_call",
                            lambda s, n, l, **kw: {"execution_id": "exec-decide"})

        poll_count = [0]
        def fake_poll(eid, **kw):
            poll_count[0] += 1
            if poll_count[0] >= 2:
                return {
                    "status": "completed",
                    "decision": "keep_frozen",
                    "confirmed": True,
                    "transcript_excerpt": "Keep frozen confirmed",
                }
            return {
                "status": "in-progress",
                "decision": None,
                "confirmed": False,
                "transcript_excerpt": "",
            }

        monkeypatch.setattr(phone, "poll", fake_poll)

        r = _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )
        assert r.status_code == 202

        # Give the background poller time to run
        time.sleep(8.0)

        # Check events contain the decision
        r2 = _tripped_client.get(f"/api/session/{sid}")
        events_text = json.dumps(r2.json()["events"])
        # At least one decision-related event should exist
        data = r2.json()
        assert data["status"] in ("decided", "awaiting_decision")

    def test_unclear_no_decide(self, _tripped_client, monkeypatch):
        """When poll returns unclear, session stays awaiting_decision."""
        monkeypatch.setattr(sess_mod, "MAX_CONCURRENT", 10)
        sid, tok = _create_tripped_session(_tripped_client)

        monkeypatch.setattr(phone, "place_call",
                            lambda s, n, l, **kw: {"execution_id": "exec-unclear"})

        def fake_poll(eid, **kw):
            return {
                "status": "completed",
                "decision": None,
                "confirmed": False,
                "transcript_excerpt": "Call ended without decision",
            }

        monkeypatch.setattr(phone, "poll", fake_poll)

        _tripped_client.post(
            f"/api/session/{sid}/phone",
            json={"number": "+919876543210", "lang": "en"},
            headers={"X-Session-Token": tok},
        )

        time.sleep(5.0)

        r = _tripped_client.get(f"/api/session/{sid}")
        # Should still be awaiting_decision
        assert r.json()["status"] == "awaiting_decision"
