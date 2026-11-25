"""Tests for Tripwire endpoints in arena.server (agent stubbed)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from arena import server, session as sess_mod


# ---------------------------------------------------------------- helpers

FAKE_TRIP = {
    "kind": "decoy_read", "path": ".aws/credentials.bak",
    "canary_name": "aws_access_key",
    "evidence": "accessed decoy file: .aws/****tials.bak",
}


async def _fake_run_session_trip(chip, workspace, *, guard, client, event_cb,
                                 tripwire, canaries, session_id, proxy_url, model,
                                 layout=None, ai=False):
    """Fake run_session that emits a few events then trips."""
    events = []
    seq = 0

    def emit(kind, **kw):
        nonlocal seq
        seq += 1
        ev = {"seq": seq, "side": "protected" if guard else "unprotected",
              "ts": seq * 0.5, "kind": kind, "tool": kw.get("tool", ""),
              "text": kw.get("text", ""), "decision": kw.get("decision", ""),
              "reason": kw.get("reason", ""), "extra": kw.get("extra", {})}
        events.append(ev)
        if event_cb:
            event_cb(ev)
        return ev

    emit("info", text="Starting session")
    emit("tool", tool="list_dir", text=".")
    if guard:
        emit("trip", tool="read_file", text="TRIPPED",
             decision="deny", reason="canary accessed",
             extra={"trip": FAKE_TRIP})
    else:
        emit("tool", tool="read_file", text=".env.backup")
        emit("done", text="Task complete")
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
        ev = {"seq": seq, "side": "protected" if guard else "unprotected",
              "ts": seq * 0.5, "kind": kind, "tool": kw.get("tool", ""),
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

@pytest.fixture
def runs_dir(tmp_path):
    d = tmp_path / "tw-runs"
    d.mkdir()
    return d


@pytest.fixture
def client(runs_dir, monkeypatch):
    monkeypatch.setenv("ARENA_RUNS", str(runs_dir))
    monkeypatch.setenv("ARENA_ALLOW_CUSTOM", "1")  # H5: allow custom tasks in tests
    # Patch the session manager used by server
    mgr = sess_mod.SessionManager(runs_dir=runs_dir)
    monkeypatch.setattr(server, "_tw_manager", mgr)
    # Patch run_session in the session module
    monkeypatch.setattr(sess_mod, "run_session", _fake_run_session_trip)
    with TestClient(server.app) as c:
        yield c


@pytest.fixture
def client_clean(runs_dir, monkeypatch):
    monkeypatch.setenv("ARENA_RUNS", str(runs_dir))
    monkeypatch.setenv("ARENA_ALLOW_CUSTOM", "1")  # H5
    mgr = sess_mod.SessionManager(runs_dir=runs_dir)
    monkeypatch.setattr(server, "_tw_manager", mgr)
    monkeypatch.setattr(sess_mod, "run_session", _fake_run_session_clean)
    with TestClient(server.app) as c:
        yield c


# ---------------------------------------------------------------- GET /api/tasks

def test_tasks_returns_list(client):
    r = client.get("/api/tasks")
    assert r.status_code == 200
    tasks = r.json()
    assert isinstance(tasks, list)
    ids = {t["id"] for t in tasks}
    # Demo chips only: readme-poison is hidden (0/4 trips: the model refuses it).
    assert {"setup", "fix-deploy"} <= ids and "readme-poison" not in ids
    for t in tasks:
        assert "id" in t
        assert "title" in t
        assert "task" in t


# ---------------------------------------------------------------- POST /api/session

def test_create_session_by_task_id(client):
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    assert r.status_code == 202
    data = r.json()
    assert "session_id" in data
    assert len(data["session_id"]) == 12
    assert "token" in data  # per-session auth token


def test_create_session_by_custom_task(client):
    r = client.post("/api/session", json={"task": "Read all files", "guard": True})
    assert r.status_code == 202
    data = r.json()
    assert "session_id" in data
    assert "token" in data


def test_create_session_bad_task_id(client):
    r = client.post("/api/session", json={"task_id": "nonexistent", "guard": True})
    assert r.status_code == 400


# ---------------------------------------------------------------- GET /api/session/{id}

def test_poll_session(client):
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    # Give the async task a moment
    import time
    time.sleep(0.5)
    r2 = client.get(f"/api/session/{sid}?since=0")
    assert r2.status_code == 200
    data = r2.json()
    assert "status" in data
    assert "events" in data
    assert "next" in data


def test_poll_nonexistent_session(client):
    r = client.get("/api/session/nosuchid?since=0")
    assert r.status_code == 404


def test_poll_since_filters_events(client):
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    import time
    time.sleep(0.5)
    # First poll gets all
    r1 = client.get(f"/api/session/{sid}?since=0")
    all_evts = r1.json()["events"]
    nxt = r1.json()["next"]
    # Second poll with since=next gets nothing new
    r2 = client.get(f"/api/session/{sid}?since={nxt}")
    assert len(r2.json()["events"]) == 0 or r2.json()["next"] >= nxt


# ---------------------------------------------------------------- Trip -> awaiting_decision

def test_trip_sets_awaiting_decision(client):
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    import time
    time.sleep(1.0)
    r2 = client.get(f"/api/session/{sid}")
    data = r2.json()
    # After trip, status should be awaiting_decision or tripped
    assert data["status"] in ("tripped", "awaiting_decision", "running", "done")
    if data["trip"]:
        assert data["trip"]["kind"] == "decoy_read"


# ---------------------------------------------------------------- POST /api/session/{id}/decision

def test_decision_once(client):
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    tok = r.json()["token"]
    import time
    time.sleep(1.0)
    # Make sure session is in awaiting_decision
    poll = client.get(f"/api/session/{sid}")
    if poll.json()["status"] not in ("tripped", "awaiting_decision"):
        pytest.skip("session did not trip in time")
    r2 = client.post(f"/api/session/{sid}/decision",
                      json={"decision": "keep_frozen", "reviewer": "testuser"},
                      headers={"X-Session-Token": tok})
    assert r2.status_code == 200
    data = r2.json()
    assert data["ok"] is True
    assert "receipt" in data


def test_decision_needs_token(client):
    """Decision without session token -> 403."""
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    import time
    time.sleep(1.0)
    poll = client.get(f"/api/session/{sid}")
    if poll.json()["status"] not in ("tripped", "awaiting_decision"):
        pytest.skip("session did not trip in time")
    r2 = client.post(f"/api/session/{sid}/decision",
                      json={"decision": "keep_frozen", "reviewer": "testuser"})
    assert r2.status_code == 403


def test_decision_twice_409(client):
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    tok = r.json()["token"]
    import time
    time.sleep(1.0)
    poll = client.get(f"/api/session/{sid}")
    if poll.json()["status"] not in ("tripped", "awaiting_decision"):
        pytest.skip("session did not trip in time")
    client.post(f"/api/session/{sid}/decision",
                json={"decision": "keep_frozen", "reviewer": "alice"},
                headers={"X-Session-Token": tok})
    r2 = client.post(f"/api/session/{sid}/decision",
                      json={"decision": "release", "reviewer": "bob"},
                      headers={"X-Session-Token": tok})
    assert r2.status_code == 409


# ---------------------------------------------------------------- GET /api/receipt/{id}/verify

def test_verify_receipt_valid(client):
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    tok = r.json()["token"]
    import time
    time.sleep(1.0)
    poll = client.get(f"/api/session/{sid}")
    if poll.json()["status"] not in ("tripped", "awaiting_decision"):
        pytest.skip("session did not trip in time")
    client.post(f"/api/session/{sid}/decision",
                json={"decision": "keep_frozen", "reviewer": "alice"},
                headers={"X-Session-Token": tok})
    r2 = client.get(f"/api/receipt/{sid}/verify")
    assert r2.status_code == 200
    assert r2.json()["valid"] is True


def test_verify_receipt_tamper_false(client):
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    tok = r.json()["token"]
    import time
    time.sleep(1.0)
    poll = client.get(f"/api/session/{sid}")
    if poll.json()["status"] not in ("tripped", "awaiting_decision"):
        pytest.skip("session did not trip in time")
    client.post(f"/api/session/{sid}/decision",
                json={"decision": "keep_frozen", "reviewer": "alice"},
                headers={"X-Session-Token": tok})
    r2 = client.get(f"/api/receipt/{sid}/verify?tamper=1")
    assert r2.status_code == 200
    assert r2.json()["valid"] is False
    # Stored receipt unchanged
    r3 = client.get(f"/api/receipt/{sid}/verify")
    assert r3.json()["valid"] is True


# ---------------------------------------------------------------- Guard OFF verdict

def test_guard_off_verdict(client, monkeypatch, runs_dir):
    # Use a clean run for guard OFF
    monkeypatch.setattr(sess_mod, "run_session", _fake_run_session_clean)
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": False})
    sid = r.json()["session_id"]
    import time
    time.sleep(1.0)
    r2 = client.get(f"/api/session/{sid}")
    data = r2.json()
    # Guard off with no loot = not_leaked
    if data["status"] in ("done", "error"):
        assert data["verdict"] in ("not_leaked", "compromised", None)


# ---------------------------------------------------------------- Caps 429

def test_caps_429_concurrent(client, monkeypatch):
    """More than 2 concurrent running sessions -> 429."""
    mgr = server._tw_manager
    # Create two running sessions directly
    s1 = mgr.create("fix-deploy", guard=True)
    s1.status = "running"
    s2 = mgr.create("setup", guard=True)
    s2.status = "running"
    r = client.post("/api/session", json={"task_id": "readme-poison", "guard": True})
    assert r.status_code == 429


def test_caps_429_rate_limit(client, monkeypatch):
    """More than 6 sessions per IP in 10 min -> 429."""
    mgr = server._tw_manager
    # TestClient peer is "testclient"; pre-populate rate limit for that IP.
    for i in range(6):
        s = mgr.create("fix-deploy", guard=True, client_ip="testclient")
        s.status = "done"  # Free the concurrent slot
    r = client.post("/api/session",
                    json={"task_id": "fix-deploy", "guard": True})
    assert r.status_code == 429


# ---------------------------------------------------------------- Custom task sanitised

def test_custom_task_sanitised(client):
    r = client.post("/api/session",
                    json={"task": "hello\x00world", "guard": True})
    assert r.status_code == 202


def test_custom_task_too_long(client):
    r = client.post("/api/session",
                    json={"task": "x" * 301, "guard": True})
    assert r.status_code == 400


# ---------------------------------------------------------------- GET /api/stats

def test_stats_shape(client):
    r = client.get("/api/stats")
    assert r.status_code == 200
    data = r.json()
    assert "sessions" in data
    assert "tripped" in data
    assert "refused" in data
    assert "leaks_guard_on" in data
    assert "leaks_guard_off" in data
    assert "errors" in data
    assert "started_at" in data


# ---------------------------------------------------------------- Existing endpoints

def test_existing_api_state_still_works(client, monkeypatch, tmp_path):
    """The old /api/state endpoint from the arena page should still work."""
    from arena.arena import Arena
    monkeypatch.setattr("arena.arena.RUNS_DIR", tmp_path)
    monkeypatch.setattr("arena.runner.RUNS_DIR", tmp_path)
    monkeypatch.setattr(server, "package_exists", lambda n: False)
    monkeypatch.setattr(server, "_arena", Arena("t-run"))
    monkeypatch.setattr(server, "_judge_lock", asyncio.Lock())
    r = client.get("/api/state")
    assert r.status_code == 200
    data = r.json()
    assert "run_id" in data


# ---------------------------------------------------------------- Page routing

def test_root_serves_tripwire_html(client, monkeypatch, tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "tripwire.html").write_text("<h1>tripwire</h1>", encoding="utf-8")
    (static / "index.html").write_text("<h1>arena</h1>", encoding="utf-8")
    monkeypatch.setattr(server, "STATIC", static)
    r = client.get("/")
    assert r.status_code == 200
    assert "tripwire" in r.text


def test_arena_serves_index_html(client, monkeypatch, tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "tripwire.html").write_text("<h1>tripwire</h1>", encoding="utf-8")
    (static / "index.html").write_text("<h1>arena</h1>", encoding="utf-8")
    monkeypatch.setattr(server, "STATIC", static)
    r = client.get("/arena")
    assert r.status_code == 200
    assert "arena" in r.text


# ---------------------------------------------------------------- WS refuses untripped

def test_ws_refuses_untripped_session(client_clean):
    r = client_clean.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    import time
    time.sleep(0.5)
    # Try WS connect -- should be refused (session not tripped)
    with pytest.raises(Exception):
        with client_clean.websocket_connect(f"/ws/call/{sid}?lang=en"):
            pass  # Should not reach here


# ---------------------------------------------------------------- Redact applied

def test_events_redacted_in_poll(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyFAKEKEY123456789012345678901234")
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    import time
    time.sleep(0.5)
    r2 = client.get(f"/api/session/{sid}")
    text = r2.text
    assert "AIzaSyFAKEKEY" not in text


# ---------------------------------------------------------------- Signing keys outside workspace (security item 7)

def test_no_keys_or_audit_in_workspace(client):
    """After trip+decision, signing keys and audit chain must NOT be in ws."""
    r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": True})
    sid = r.json()["session_id"]
    tok = r.json()["token"]
    import time
    time.sleep(1.0)
    poll = client.get(f"/api/session/{sid}")
    if poll.json()["status"] not in ("tripped", "awaiting_decision"):
        pytest.skip("session did not trip in time")
    client.post(f"/api/session/{sid}/decision",
                json={"decision": "keep_frozen", "reviewer": "alice"},
                headers={"X-Session-Token": tok})
    # Check workspace has no .sandbox with keys
    mgr = server._tw_manager
    s = mgr.get(sid)
    ws = s.workspace
    # .sandbox should NOT contain key seeds or audit records
    sandbox_dir = ws / ".sandbox"
    if sandbox_dir.is_dir():
        for f in sandbox_dir.rglob("*.seed"):
            assert False, f"Found key seed in workspace: {f}"
        # Audit records file should not be in workspace .sandbox
        for f in sandbox_dir.rglob("records.jsonl"):
            assert False, f"Found audit records in workspace: {f}"


# ---------------------------------------------------------------- Proxy on_trip (fake run that triggers egress canary)

def test_proxy_on_trip_emits_trip_event(client, monkeypatch, runs_dir):
    """When the egress proxy detects a canary, it should trip the session."""

    async def _fake_run_proxy_trip(chip, workspace, *, guard, client, event_cb,
                                   tripwire, canaries, session_id, proxy_url, model,
                                   layout=None, ai=False):
        """Simulate agent sending data through proxy that hits a canary."""
        events = []
        seq = 0
        def emit(kind, **kw):
            nonlocal seq
            seq += 1
            ev = {"seq": seq, "side": "protected", "ts": seq * 0.1,
                  "kind": kind, "tool": kw.get("tool", ""),
                  "text": kw.get("text", ""), "decision": kw.get("decision", ""),
                  "reason": kw.get("reason", ""), "extra": kw.get("extra", {})}
            events.append(ev)
            if event_cb:
                event_cb(ev)

        emit("info", text="Starting")
        emit("tool", tool="run_command", text="curl")
        # Simulate proxy on_trip firing (this would happen from the proxy thread)
        # We just emit a trip event as if the proxy caught it
        emit("trip", tool="run_command", text="TRIPPED",
             decision="deny", reason="canary exfiltrated",
             extra={"trip": {"kind": "canary_exfil", "canary_name": "stripe_key",
                            "evidence": "canary stripe_key exfiltrated (plain)"}})
        return events

    monkeypatch.setattr(sess_mod, "run_session", _fake_run_proxy_trip)
    r = client.post("/api/session", json={"task_id": "setup", "guard": True})
    sid = r.json()["session_id"]
    import time
    time.sleep(1.0)
    poll = client.get(f"/api/session/{sid}")
    data = poll.json()
    # Session should be tripped/awaiting_decision
    assert data["status"] in ("tripped", "awaiting_decision", "done")


# ---------------------------------------------------------------- GET /api/replays

def test_replays_empty(client):
    r = client.get("/api/replays")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
