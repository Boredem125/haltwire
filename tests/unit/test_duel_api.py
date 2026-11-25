"""Tests for arena.duel_api -- duel endpoints (split-screen: guard OFF + guard ON)."""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from arena import server, session as sess_mod


# ---------------------------------------------------------------- fake run_session

FAKE_TRIP = {
    "kind": "decoy_read", "path": ".aws/credentials.bak",
    "canary_name": "aws_access_key",
    "evidence": "accessed decoy file: .aws/****tials.bak",
}


async def _fake_run(chip, workspace, *, guard, client, event_cb,
                    tripwire, canaries, session_id, proxy_url, model,
                    layout=None, ai=False):
    """Fake run_session: guard ON trips, guard OFF completes with a tool call."""
    seq = [0]

    def emit(kind, **kw):
        seq[0] += 1
        ev = {"seq": seq[0], "side": "protected" if guard else "unprotected",
              "ts": seq[0] * 0.5, "kind": kind, "tool": kw.get("tool", ""),
              "text": kw.get("text", ""), "decision": kw.get("decision", ""),
              "reason": kw.get("reason", ""), "extra": kw.get("extra", {})}
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
    return []


# ---------------------------------------------------------------- fixtures

@pytest.fixture
def runs_dir(tmp_path):
    d = tmp_path / "tw-runs"
    d.mkdir()
    return d


@pytest.fixture
def client(runs_dir, monkeypatch):
    monkeypatch.setenv("ARENA_RUNS", str(runs_dir))
    mgr = sess_mod.SessionManager(runs_dir=runs_dir)
    monkeypatch.setattr(server, "_tw_manager", mgr)
    monkeypatch.setattr(sess_mod, "run_session", _fake_run)
    # Import duel_api and make sure its router is included
    from arena import duel_api
    monkeypatch.setattr(duel_api, "_mgr", lambda: mgr)
    with TestClient(server.app) as c:
        yield c


# ---------------------------------------------------------------- POST /api/duel

class TestCreateDuel:

    def test_creates_two_sessions(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup"})
        assert r.status_code == 202
        d = r.json()
        assert "duel_id" in d
        assert "off" in d and "on" in d
        assert "session_id" in d["off"] and "token" in d["off"]
        assert "session_id" in d["on"] and "token" in d["on"]
        assert d["off"]["session_id"] != d["on"]["session_id"]

    def test_tokens_differ(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup"})
        d = r.json()
        assert d["off"]["token"] != d["on"]["token"]

    def test_default_chip_is_setup(self, client):
        r = client.post("/api/duel", json={})
        assert r.status_code == 202

    def test_bad_chip_400(self, client):
        r = client.post("/api/duel", json={"chip_id": "no-such-chip"})
        assert r.status_code == 400

    def test_duel_counts_as_one_ip_slot(self, client, monkeypatch, runs_dir):
        """A duel counts as 1 toward the per-IP cap, not 2."""
        mgr = server._tw_manager
        # Make 5 duels (= 10 sessions) but each duel = 1 IP slot.
        # Mark sessions done + sleep briefly so the async tasks finish
        # before we check concurrent caps for the next duel.
        for i in range(5):
            r = client.post("/api/duel", json={"chip_id": "setup"})
            assert r.status_code == 202, f"duel {i} failed: {r.text}"
            d = r.json()
            time.sleep(0.5)  # let fake run complete
            s_off = mgr.get(d["off"]["session_id"])
            s_on = mgr.get(d["on"]["session_id"])
            if s_off:
                s_off.status = "done"
            if s_on:
                s_on.status = "done"
        # 6th should still work (5 < 6)
        r = client.post("/api/duel", json={"chip_id": "setup"})
        assert r.status_code == 202
        d = r.json()
        time.sleep(0.5)
        s_off = mgr.get(d["off"]["session_id"])
        s_on = mgr.get(d["on"]["session_id"])
        if s_off:
            s_off.status = "done"
        if s_on:
            s_on.status = "done"
        # 7th should hit rate limit (6 >= 6)
        r = client.post("/api/duel", json={"chip_id": "setup"})
        assert r.status_code == 429


# ---------------------------------------------------------------- GET /api/duel/{id}

class TestPollDuel:

    def test_poll_returns_both_sides(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup"})
        d = r.json()
        time.sleep(1.0)
        r2 = client.get(f"/api/duel/{d['duel_id']}?since_off=0&since_on=0")
        assert r2.status_code == 200
        body = r2.json()
        assert body["duel_id"] == d["duel_id"]
        assert body["chip_id"] == "setup"
        assert "off" in body and "on" in body
        assert "events" in body["off"] and "events" in body["on"]
        assert body["replay"] is False

    def test_poll_nonexistent_404(self, client):
        r = client.get("/api/duel/nonexistent")
        assert r.status_code == 404


# ---------------------------------------------------------------- GET /api/duel/replay

class TestReplay:

    def test_replay_404_when_none(self, client):
        # Use a chip_id that has no recording anywhere
        r = client.get("/api/duel/replay?chip_id=no-such-chip")
        assert r.status_code == 404

    def test_replay_has_verifiable_receipt(self, client, runs_dir):
        """Record a duel, then replay it; receipt should verify."""
        # Create a duel, trip the ON side, decide, persist as recording
        r = client.post("/api/duel", json={"chip_id": "fix-deploy"})
        d = r.json()
        time.sleep(1.5)
        # Decide the ON side
        on_sid = d["on"]["session_id"]
        on_tok = d["on"]["token"]
        poll = client.get(f"/api/session/{on_sid}")
        if poll.json()["status"] in ("tripped", "awaiting_decision"):
            client.post(f"/api/session/{on_sid}/decision",
                        json={"decision": "keep_frozen", "reviewer": "test"},
                        headers={"X-Session-Token": on_tok})
        time.sleep(0.5)
        # Manually save as recording
        mgr = server._tw_manager
        from arena import duel_api
        duel_api._save_recording(d["duel_id"], "fix-deploy", mgr, runs_dir)
        # Now fetch replay
        r2 = client.get("/api/duel/replay?chip_id=fix-deploy")
        assert r2.status_code == 200
        body = r2.json()
        assert body["replay"] is True
        assert body["chip_id"] == "fix-deploy"
        # Verify the ON side receipt if present
        on_data = body.get("on", {})
        if on_data.get("receipt"):
            rv = client.get(f"/api/receipt/{on_data['session_id']}/verify")
            assert rv.status_code == 200
            assert rv.json()["valid"] is True


# ---------------------------------------------------------------- POST /api/duel/record

class TestRecord:

    def test_record_needs_admin_token(self, client, monkeypatch):
        monkeypatch.setenv("ARENA_ADMIN_TOKEN", "s3cret")
        r = client.post("/api/duel/record", json={"chip_id": "setup"})
        assert r.status_code == 403
        r2 = client.post("/api/duel/record", json={"chip_id": "setup"},
                         headers={"X-Arena-Token": "wrong"})
        assert r2.status_code == 403

    def test_record_404_in_public_no_token(self, client, monkeypatch):
        monkeypatch.setenv("ARENA_PUBLIC", "1")
        monkeypatch.delenv("ARENA_ADMIN_TOKEN", raising=False)
        r = client.post("/api/duel/record", json={"chip_id": "setup"})
        assert r.status_code == 404


# ---------------------------------------------------------------- GET /api/stats (benign fields)

class TestStatsBenign:

    def test_stats_has_benign_fields(self, client):
        r = client.get("/api/stats")
        data = r.json()
        assert "benign_runs" in data
        assert "benign_false_trips" in data


# ---------------------------------------------------------------- mode duel: Rules only vs Rules + AI

class TestAiCompareDuel:
    """compare="ai": both sides guarded, left rules only, right rules + AI."""

    _XOR = {"encoding": "xor", "channel": "body", "host": "cmp"}

    def test_both_sides_guarded_ai_only_on_right(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup", "variant": self._XOR, "compare": "ai"})
        assert r.status_code == 202, r.text
        d = r.json()
        mgr = server._tw_manager
        left, right = mgr.get(d["off"]["session_id"]), mgr.get(d["on"]["session_id"])
        assert left.guard is True and left.ai is False
        assert right.guard is True and right.ai is True
        assert d["mode"] == "ai_compare"
        assert d["sides"] == {"off": {"guard": True, "ai": False, "label": "Rules only"},
                              "on": {"guard": True, "ai": True, "label": "Rules + AI"}}

    def test_compare_ignores_body_ai_flag(self, client):
        d = client.post("/api/duel", json={"variant": self._XOR, "compare": "ai", "ai": False}).json()
        assert server._tw_manager.get(d["on"]["session_id"]).ai is True

    def test_default_mode_unchanged(self, client):
        d = client.post("/api/duel", json={"chip_id": "setup", "ai": True}).json()
        mgr = server._tw_manager
        assert mgr.get(d["off"]["session_id"]).guard is False
        assert d["mode"] == "guard"
        assert d["sides"]["off"] == {"guard": False, "ai": False, "label": "Guard off"}
        assert d["sides"]["on"] == {"guard": True, "ai": True, "label": "Guard on, Rules + AI"}

    def test_poll_carries_mode_and_sides(self, client):
        d = client.post("/api/duel", json={"variant": self._XOR, "compare": "ai"}).json()
        p = client.get(f"/api/duel/{d['duel_id']}").json()
        assert p["mode"] == "ai_compare" and p["sides"]["off"]["label"] == "Rules only"

    def test_bad_compare_value_rejected(self, client):
        r = client.post("/api/duel", json={"compare": "everything"})
        assert r.status_code == 422
