"""Tests for the phone-pairing API (arena.pair_api).

Covers: pairing creation, QR SVG, claim/secret, state machine,
ringing after trip, WS auth, phone decision, expiry, pair-status.
"""
from __future__ import annotations

import hmac
import time
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from arena.pair_api import make_pair_router


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeSession:
    """Minimal stand-in for arena.session.Session."""

    def __init__(self, sid: str, guard: bool, status: str = "running"):
        self.id = sid
        self.guard = guard
        self.status = status
        self.token = "tok_" + sid
        self.trip = None
        self.receipt = None
        self.call_state = "none"
        self.chip = {"title": "Test chip", "task_prompt": "do stuff"}
        self._decided = False
        self._lock = threading.Lock()

    def check_token(self, t: str) -> bool:
        return hmac.compare_digest(self.token, t)

    def decide(self, decision: str, reviewer: str) -> dict[str, Any]:
        from arena.session import AlreadyDecidedError
        with self._lock:
            if self._decided:
                raise AlreadyDecidedError(self.id)
            self._decided = True
        self.status = "decided"
        self.call_state = "ended"
        self.receipt = {
            "decision": "deny" if decision == "keep_frozen" else "approve",
            "reviewer_id": reviewer,
            "reviewer": reviewer,
            "signature_short": "abc123",
            "chain_head_short": "def456",
        }
        return {"ok": True, "receipt": self.receipt}


class FakeManager:
    """Minimal stand-in for arena.session.SessionManager."""

    def __init__(self):
        self._sessions: dict[str, FakeSession] = {}

    def get(self, sid: str):
        return self._sessions.get(sid)

    def add(self, s: FakeSession):
        self._sessions[s.id] = s


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_pair_state():
    """Reset module-level pairing state between tests."""
    from arena import pair_api
    pair_api._pairings.clear()
    pair_api._code_to_session.clear()
    pair_api._pair_ip_log.clear()
    yield
    pair_api._pairings.clear()
    pair_api._code_to_session.clear()
    pair_api._pair_ip_log.clear()


@pytest.fixture()
def manager():
    return FakeManager()


@pytest.fixture()
def app(manager):
    _app = FastAPI()
    router = make_pair_router(lambda: manager)
    _app.include_router(router)
    return _app


@pytest.fixture()
def client(app):
    return TestClient(app)


@pytest.fixture()
def guard_on_session(manager):
    s = FakeSession("sess01", guard=True, status="running")
    manager.add(s)
    return s


@pytest.fixture()
def guard_off_session(manager):
    s = FakeSession("sess02", guard=False, status="running")
    manager.add(s)
    return s


@pytest.fixture()
def tripped_session(manager):
    s = FakeSession("sess03", guard=True, status="awaiting_decision")
    s.trip = {
        "kind": "canary_exfil",
        "target_or_path": "/secrets/.env",
        "evidence": "canary ***MASKED*** exfiltrated",
        "signature_short": "sig12345",
        "chain_head_short": "ch12345",
    }
    s.call_state = "ringing"
    manager.add(s)
    return s


# ---------------------------------------------------------------------------
# POST /api/session/{session_id}/pair  -- create pairing
# ---------------------------------------------------------------------------

class TestCreatePair:
    def test_requires_token(self, client, guard_on_session):
        r = client.post(f"/api/session/{guard_on_session.id}/pair")
        assert r.status_code == 403

    def test_wrong_token_rejected(self, client, guard_on_session):
        r = client.post(
            f"/api/session/{guard_on_session.id}/pair",
            headers={"X-Session-Token": "wrong"},
        )
        assert r.status_code == 403

    def test_guard_off_rejected(self, client, guard_off_session):
        r = client.post(
            f"/api/session/{guard_off_session.id}/pair",
            headers={"X-Session-Token": guard_off_session.token},
        )
        assert r.status_code == 400

    def test_creates_pair(self, client, guard_on_session):
        r = client.post(
            f"/api/session/{guard_on_session.id}/pair",
            headers={"X-Session-Token": guard_on_session.token},
        )
        assert r.status_code == 200
        body = r.json()
        assert "code" in body
        assert "url" in body
        assert "qr_svg_url" in body
        assert "expires_at" in body
        assert body["code"] in body["url"]

    def test_repeat_returns_same_code(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        r1 = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        r2 = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        assert r1.json()["code"] == r2.json()["code"]

    def test_session_not_found(self, client):
        r = client.post(
            "/api/session/nonexistent/pair",
            headers={"X-Session-Token": "whatever"},
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/pair/{code}/qr.svg  -- QR SVG
# ---------------------------------------------------------------------------

class TestQrSvg:
    def test_returns_valid_svg(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        r = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        code = r.json()["code"]
        r2 = client.get(f"/api/pair/{code}/qr.svg")
        assert r2.status_code == 200
        assert r2.headers["content-type"].startswith("image/svg+xml")
        assert "<svg" in r2.text

    def test_unknown_code_404(self, client):
        r = client.get("/api/pair/BADCODE/qr.svg")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# GET /call/{code}  -- serves the phone page
# ---------------------------------------------------------------------------

class TestCallPage:
    def test_unknown_code_404(self, client):
        r = client.get("/call/BADCODE")
        assert r.status_code == 404

    def test_valid_code_returns_html(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        r = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        code = r.json()["code"]
        r2 = client.get(f"/call/{code}")
        assert r2.status_code == 200
        # Should be HTML regardless (placeholder or real)
        assert "html" in r2.headers.get("content-type", "").lower() or "text" in r2.headers.get("content-type", "").lower()


# ---------------------------------------------------------------------------
# GET /api/pair/{code}  -- pair status (claim and secret)
# ---------------------------------------------------------------------------

class TestPairStatus:
    def test_first_get_claims_and_gets_secret(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        r = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        code = r.json()["code"]

        r2 = client.get(f"/api/pair/{code}")
        assert r2.status_code == 200
        body = r2.json()
        assert body["state"] == "waiting"
        assert "phone_secret" in body
        assert len(body["phone_secret"]) > 10

    def test_second_device_without_secret_409(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        r = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        code = r.json()["code"]

        # First device claims
        r2 = client.get(f"/api/pair/{code}")
        secret = r2.json()["phone_secret"]

        # Second device without secret -> 409
        r3 = client.get(f"/api/pair/{code}")
        assert r3.status_code == 409

    def test_claimed_device_with_secret_ok(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        r = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        code = r.json()["code"]

        r2 = client.get(f"/api/pair/{code}")
        secret = r2.json()["phone_secret"]

        # Same device with the right secret -> ok
        r3 = client.get(f"/api/pair/{code}", headers={"X-Phone-Secret": secret})
        assert r3.status_code == 200

    def test_state_ringing_after_trip(self, client, tripped_session):
        h = {"X-Session-Token": tripped_session.token}
        r = client.post(f"/api/session/{tripped_session.id}/pair", headers=h)
        code = r.json()["code"]

        r2 = client.get(f"/api/pair/{code}")
        assert r2.json()["state"] == "ringing"
        assert r2.json()["trip"] is not None

    def test_task_title_in_pair(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        r = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        code = r.json()["code"]
        r2 = client.get(f"/api/pair/{code}")
        assert "task_title" in r2.json()

    def test_unknown_code_404(self, client):
        r = client.get("/api/pair/BADCODE")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# WS /ws/oncall/{code}  -- refuses wrong secret or untripped
# ---------------------------------------------------------------------------

class TestWsOnCall:
    def test_wrong_secret_closes_4003(self, client, tripped_session):
        from starlette.websockets import WebSocketDisconnect

        h = {"X-Session-Token": tripped_session.token}
        r = client.post(f"/api/session/{tripped_session.id}/pair", headers=h)
        code = r.json()["code"]

        # Claim
        r2 = client.get(f"/api/pair/{code}")
        secret = r2.json()["phone_secret"]

        # Server should reject before handshake completes -> WebSocketDisconnect
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(
                f"/ws/oncall/{code}?lang=en&phone=WRONG"
            ):
                pass
        assert exc_info.value.code == 4003

    def test_untripped_session_closes(self, client, guard_on_session):
        """WS should refuse if the session is not in ringing/in_call state."""
        from starlette.websockets import WebSocketDisconnect

        h = {"X-Session-Token": guard_on_session.token}
        r = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        code = r.json()["code"]

        # Claim
        r2 = client.get(f"/api/pair/{code}")
        secret = r2.json()["phone_secret"]

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(
                f"/ws/oncall/{code}?lang=en&phone={secret}"
            ):
                pass
        assert exc_info.value.code == 4003


# ---------------------------------------------------------------------------
# POST /api/pair/{code}/decision  -- phone decision
# ---------------------------------------------------------------------------

class TestPhoneDecision:
    def test_decision_via_phone(self, client, tripped_session):
        h = {"X-Session-Token": tripped_session.token}
        r = client.post(f"/api/session/{tripped_session.id}/pair", headers=h)
        code = r.json()["code"]

        # Claim
        r2 = client.get(f"/api/pair/{code}")
        secret = r2.json()["phone_secret"]

        # Decide
        r3 = client.post(
            f"/api/pair/{code}/decision",
            headers={"X-Phone-Secret": secret},
            json={"decision": "keep_frozen"},
        )
        assert r3.status_code == 200
        body = r3.json()
        assert body["ok"] is True
        assert "receipt" in body

    def test_second_decision_409(self, client, tripped_session):
        h = {"X-Session-Token": tripped_session.token}
        r = client.post(f"/api/session/{tripped_session.id}/pair", headers=h)
        code = r.json()["code"]

        r2 = client.get(f"/api/pair/{code}")
        secret = r2.json()["phone_secret"]

        # First decision
        client.post(
            f"/api/pair/{code}/decision",
            headers={"X-Phone-Secret": secret},
            json={"decision": "keep_frozen"},
        )

        # Second decision -> 409
        r4 = client.post(
            f"/api/pair/{code}/decision",
            headers={"X-Phone-Secret": secret},
            json={"decision": "release"},
        )
        assert r4.status_code == 409

    def test_decision_wrong_secret_403(self, client, tripped_session):
        h = {"X-Session-Token": tripped_session.token}
        r = client.post(f"/api/session/{tripped_session.id}/pair", headers=h)
        code = r.json()["code"]

        # Claim
        r2 = client.get(f"/api/pair/{code}")
        _ = r2.json()["phone_secret"]

        r3 = client.post(
            f"/api/pair/{code}/decision",
            headers={"X-Phone-Secret": "wrong_secret"},
            json={"decision": "keep_frozen"},
        )
        assert r3.status_code == 403

    def test_decision_unclaimed_403(self, client, tripped_session):
        """Decision without claiming first should fail."""
        h = {"X-Session-Token": tripped_session.token}
        r = client.post(f"/api/session/{tripped_session.id}/pair", headers=h)
        code = r.json()["code"]

        # Don't claim, just try to decide
        r3 = client.post(
            f"/api/pair/{code}/decision",
            headers={"X-Phone-Secret": "whatever"},
            json={"decision": "keep_frozen"},
        )
        assert r3.status_code == 403

    def test_decision_bad_value_400(self, client, tripped_session):
        h = {"X-Session-Token": tripped_session.token}
        r = client.post(f"/api/session/{tripped_session.id}/pair", headers=h)
        code = r.json()["code"]

        r2 = client.get(f"/api/pair/{code}")
        secret = r2.json()["phone_secret"]

        r3 = client.post(
            f"/api/pair/{code}/decision",
            headers={"X-Phone-Secret": secret},
            json={"decision": "invalid"},
        )
        assert r3.status_code == 400


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_expired_pair_state(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        r = client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)
        code = r.json()["code"]

        # Monkey-patch the expiry time to the past
        from arena import pair_api
        for p in pair_api._pairings.values():
            if p["code"] == code:
                p["expires_at"] = time.time() - 10
                break

        r2 = client.get(f"/api/pair/{code}")
        assert r2.json()["state"] == "expired"


# ---------------------------------------------------------------------------
# GET /api/session/{session_id}/pair-status
# ---------------------------------------------------------------------------

class TestPairStatusEndpoint:
    def test_unpaired_session(self, client, guard_on_session):
        r = client.get(
            f"/api/session/{guard_on_session.id}/pair-status",
            headers={"X-Session-Token": guard_on_session.token},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["paired"] is False

    def test_paired_session(self, client, guard_on_session):
        h = {"X-Session-Token": guard_on_session.token}
        client.post(f"/api/session/{guard_on_session.id}/pair", headers=h)

        r = client.get(
            f"/api/session/{guard_on_session.id}/pair-status",
            headers={"X-Session-Token": guard_on_session.token},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["paired"] is True
        assert "state" in body

    def test_requires_token(self, client, guard_on_session):
        r = client.get(f"/api/session/{guard_on_session.id}/pair-status")
        assert r.status_code == 403

    def test_session_not_found(self, client):
        r = client.get(
            "/api/session/nonexistent/pair-status",
            headers={"X-Session-Token": "whatever"},
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# IP rate limit on pair creation
# ---------------------------------------------------------------------------

class TestRateLimit:
    def test_ip_rate_limit(self, client, manager):
        """Creating >10 pairings from the same IP within 1 hour should fail."""
        for i in range(11):
            s = FakeSession(f"rl_{i:02d}", guard=True)
            manager.add(s)

        for i in range(10):
            sid = f"rl_{i:02d}"
            s = manager.get(sid)
            r = client.post(
                f"/api/session/{sid}/pair",
                headers={"X-Session-Token": s.token},
            )
            assert r.status_code == 200, f"Pair {i} should succeed"

        # 11th should be rate-limited
        s = manager.get("rl_10")
        r = client.post(
            f"/api/session/rl_10/pair",
            headers={"X-Session-Token": s.token},
        )
        assert r.status_code == 429
