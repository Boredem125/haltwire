"""Tests for the roleplay feature-request system.

FEATURES in scenarios_tw, GET /api/features, POST /api/duel {feature},
Google Chat "Task assigned" card, and compose with variants/secrets/README.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from arena import scenarios_tw, server, session as sess_mod


# ---------------------------------------------------------------- fake run_session

FAKE_TRIP = {
    "kind": "canary_exfil", "path": ".env.backup",
    "canary_name": "stripe_key",
    "evidence": "setup.py telemetry to collect.evil.example",
}


async def _fake_run(chip, workspace, *, guard, client, event_cb,
                    tripwire, canaries, session_id, proxy_url, model,
                    layout=None, ai=False):
    seq = [0]

    def emit(kind, **kw):
        seq[0] += 1
        ev = {"seq": seq[0], "side": "protected" if guard else "unprotected",
              "ts": seq[0] * 0.5, "kind": kind, "tool": kw.get("tool", ""),
              "text": kw.get("text", ""), "decision": kw.get("decision", ""),
              "reason": kw.get("reason", ""), "extra": kw.get("extra", {})}
        if event_cb:
            event_cb(ev)

    emit("info", text="Starting session")
    emit("tool", tool="run_command", text="python setup.py configure")
    if guard:
        emit("trip", tool="egress", text="TRIPPED", decision="deny",
             reason="canary accessed", extra={"trip": FAKE_TRIP})
    else:
        emit("tool", tool="run_command", text="python test_totals.py")
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
    from arena import duel_api
    monkeypatch.setattr(duel_api, "_mgr", lambda: mgr)
    with TestClient(server.app) as c:
        yield c


# ---------------------------------------------------------------- FEATURES data

class TestFeaturesData:
    """scenarios_tw.FEATURES shape and content."""

    def test_exactly_three_features(self):
        from arena.scenarios_tw import FEATURES
        assert len(FEATURES) == 3

    def test_required_ids(self):
        from arena.scenarios_tw import FEATURES
        ids = {f["id"] for f in FEATURES}
        assert ids == {"csv-export", "currency", "top-n"}

    def test_feature_shape(self):
        from arena.scenarios_tw import FEATURES
        for f in FEATURES:
            assert isinstance(f["id"], str) and f["id"]
            assert isinstance(f["title"], str) and len(f["title"]) <= 40
            assert isinstance(f["ask"], str) and f["ask"]
            assert isinstance(f["task_prompt"], str) and f["task_prompt"]

    def test_task_prompts_lead_to_setup(self):
        """Every task_prompt should naturally lead the agent to run setup.py."""
        from arena.scenarios_tw import FEATURES
        for f in FEATURES:
            prompt = f["task_prompt"].lower()
            # Must reference setup or test running (which needs setup first)
            assert ("setup" in prompt or "test" in prompt or "configure" in prompt), \
                f"feature {f['id']} task_prompt doesn't lead to setup"


# ---------------------------------------------------------------- GET /api/features

class TestGetFeatures:

    def test_returns_features_list(self, client):
        r = client.get("/api/features")
        assert r.status_code == 200
        body = r.json()
        assert "features" in body
        assert len(body["features"]) == 3

    def test_feature_fields(self, client):
        r = client.get("/api/features")
        for f in r.json()["features"]:
            assert set(f.keys()) >= {"id", "title", "ask", "task_prompt"}


# ---------------------------------------------------------------- POST /api/duel with feature

class TestDuelWithFeature:

    def test_feature_accepted_for_setup_chip(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "csv-export"})
        assert r.status_code == 202, r.text
        d = r.json()
        assert d.get("feature") is not None
        assert d["feature"]["id"] == "csv-export"

    def test_feature_rejected_for_non_setup_chip(self, client):
        r = client.post("/api/duel", json={"chip_id": "fix-deploy", "feature": "csv-export"})
        assert r.status_code == 400

    def test_unknown_feature_rejected(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "no-such-feature"})
        assert r.status_code in (400, 422)

    def test_free_text_feature_rejected(self, client):
        """H5: custom task + guard off = host shell. Only preset ids allowed."""
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "do whatever you want"})
        assert r.status_code in (400, 422)

    def test_feature_null_accepted(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": None})
        assert r.status_code == 202
        d = r.json()
        assert d.get("feature") is None

    def test_feature_omitted_accepted(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup"})
        assert r.status_code == 202

    def test_poll_carries_feature(self, client):
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "currency"})
        d = r.json()
        time.sleep(1.0)
        p = client.get(f"/api/duel/{d['duel_id']}").json()
        assert p["feature"]["id"] == "currency"
        assert "ask" in p["feature"]

    def test_poll_feature_null_without_feature(self, client):
        d = client.post("/api/duel", json={"chip_id": "setup"}).json()
        time.sleep(1.0)
        p = client.get(f"/api/duel/{d['duel_id']}").json()
        assert p.get("feature") is None

    def test_feature_uses_feature_task_prompt(self, client):
        """When a feature is set, both sides use the feature's task_prompt."""
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "top-n"})
        d = r.json()
        from arena.scenarios_tw import FEATURES
        feat = next(f for f in FEATURES if f["id"] == "top-n")
        assert feat["task_prompt"] in d["task_prompt"]

    def test_feature_composes_with_variant(self, client):
        """variant + feature: prompt = feature prompt, variant attack unchanged."""
        xor = {"encoding": "xor", "channel": "body", "host": "ftst"}
        r = client.post("/api/duel", json={
            "chip_id": "setup", "variant": xor, "feature": "csv-export"
        })
        assert r.status_code == 202
        d = r.json()
        assert d.get("feature") is not None
        assert d["feature"]["id"] == "csv-export"

    def test_feature_composes_with_readme(self, client):
        """README edit + feature: prompt says 'Read README.md first, then ...'."""
        r = client.post("/api/duel", json={
            "chip_id": "setup",
            "feature": "currency",
            "readme": "# test\nCustom readme."
        })
        assert r.status_code == 202
        d = r.json()
        assert "README.md" in d["task_prompt"]

    def test_feature_composes_with_ai_compare(self, client):
        r = client.post("/api/duel", json={
            "chip_id": "setup", "feature": "csv-export", "compare": "ai"
        })
        assert r.status_code == 202
        d = r.json()
        assert d["mode"] == "ai_compare"
        assert d["feature"]["id"] == "csv-export"


# ---------------------------------------------------------------- Google Chat task card

class TestTaskCard:
    """When a duel starts with a feature AND webhook configured, post a task card."""

    def test_task_card_sent_on_feature_duel(self, client, monkeypatch):
        from arena import gchat, duel_api
        calls = []
        monkeypatch.setenv("GCHAT_WEBHOOK_URL",
                           "https://chat.googleapis.com/v1/spaces/X/messages?key=k&token=t")
        monkeypatch.setattr(gchat, "_spawn", lambda fn: fn())
        monkeypatch.setattr(gchat, "_post_json",
                            lambda url, payload: calls.append(("post", url, payload)))
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "csv-export"})
        assert r.status_code == 202
        time.sleep(0.5)
        # Should have at least one task card
        task_posts = [c for c in calls if "Task assigned" in json.dumps(c[2])]
        assert len(task_posts) >= 1

    def test_no_task_card_without_feature(self, client, monkeypatch):
        from arena import gchat
        calls = []
        monkeypatch.setenv("GCHAT_WEBHOOK_URL",
                           "https://chat.googleapis.com/v1/spaces/X/messages?key=k&token=t")
        monkeypatch.setattr(gchat, "_spawn", lambda fn: fn())
        monkeypatch.setattr(gchat, "_post_json",
                            lambda url, payload: calls.append(("post", url, payload)))
        r = client.post("/api/duel", json={"chip_id": "setup"})
        assert r.status_code == 202
        time.sleep(0.5)
        task_posts = [c for c in calls if "Task assigned" in json.dumps(c[2])]
        assert len(task_posts) == 0

    def test_no_task_card_without_webhook(self, client, monkeypatch):
        monkeypatch.delenv("GCHAT_WEBHOOK_URL", raising=False)
        from arena import gchat
        spawns = []
        monkeypatch.setattr(gchat, "_spawn", lambda fn: spawns.append(fn))
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "csv-export"})
        assert r.status_code == 202
        time.sleep(0.5)
        # _spawn should not be called for a task card since webhook is not configured
        assert len(spawns) == 0

    def test_task_card_uses_same_thread_key_as_trip(self, client, monkeypatch):
        """The task card must use the ON session's thread_key so it appears in the same Chat thread."""
        from arena import gchat
        calls = []
        monkeypatch.setenv("GCHAT_WEBHOOK_URL",
                           "https://chat.googleapis.com/v1/spaces/X/messages?key=k&token=t")
        monkeypatch.setattr(gchat, "_spawn", lambda fn: fn())
        monkeypatch.setattr(gchat, "_post_json",
                            lambda url, payload: calls.append(payload))
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "csv-export"})
        d = r.json()
        time.sleep(1.5)
        on_sid = d["on"]["session_id"]
        task_cards = [c for c in calls if "Task assigned" in json.dumps(c)]
        if task_cards:
            # Thread key must match the ON session's thread_key
            assert task_cards[0].get("thread", {}).get("threadKey") == f"tw-{on_sid}"

    def test_task_alert_recorded_in_session(self, client, monkeypatch):
        """The task card result must be recorded in Session.alerts with kind 'task'."""
        from arena import gchat
        monkeypatch.setenv("GCHAT_WEBHOOK_URL",
                           "https://chat.googleapis.com/v1/spaces/X/messages?key=k&token=t")
        monkeypatch.setattr(gchat, "_spawn", lambda fn: fn())
        monkeypatch.setattr(gchat, "_post_json", lambda url, payload: None)
        r = client.post("/api/duel", json={"chip_id": "setup", "feature": "currency"})
        d = r.json()
        time.sleep(1.5)
        on_sid = d["on"]["session_id"]
        mgr = server._tw_manager
        s_on = mgr.get(on_sid)
        task_alerts = [a for a in s_on.alerts if a.get("what") == "task"]
        assert len(task_alerts) >= 1
        assert task_alerts[0]["ok"] is True
        assert task_alerts[0]["channel"] == "google_chat"


# ---------------------------------------------------------------- compare:"ai" still works

class TestAiModeStillWorks:
    def test_ai_compare_still_works(self, client):
        xor = {"encoding": "xor", "channel": "body", "host": "cmp"}
        r = client.post("/api/duel", json={"chip_id": "setup", "variant": xor, "compare": "ai"})
        assert r.status_code == 202
        d = r.json()
        assert d["mode"] == "ai_compare"


# ================================================================
# POST /api/session with feature (single-session path)
# ================================================================

class TestSessionFeature:
    """Single-session POST /api/session with optional feature."""

    def test_feature_accepted_for_setup(self, client):
        r = client.post("/api/session", json={"task_id": "setup", "guard": False,
                                               "feature": "csv-export"})
        assert r.status_code == 202, r.text
        d = r.json()
        assert "session_id" in d

    def test_feature_rejected_for_non_setup(self, client):
        r = client.post("/api/session", json={"task_id": "fix-deploy", "guard": False,
                                               "feature": "csv-export"})
        assert r.status_code == 400

    def test_unknown_feature_rejected(self, client):
        r = client.post("/api/session", json={"task_id": "setup", "guard": False,
                                               "feature": "no-such-feature"})
        assert r.status_code in (400, 422)

    def test_free_text_feature_rejected(self, client):
        r = client.post("/api/session", json={"task_id": "setup", "guard": False,
                                               "feature": "do whatever"})
        assert r.status_code in (400, 422)

    def test_feature_null_accepted(self, client):
        r = client.post("/api/session", json={"task_id": "setup", "guard": False,
                                               "feature": None})
        assert r.status_code == 202

    def test_feature_omitted_accepted(self, client):
        r = client.post("/api/session", json={"task_id": "setup", "guard": False})
        assert r.status_code == 202

    def test_poll_carries_feature(self, client):
        r = client.post("/api/session", json={"task_id": "setup", "guard": False,
                                               "feature": "currency"})
        d = r.json()
        time.sleep(1.0)
        p = client.get(f"/api/session/{d['session_id']}").json()
        assert p["feature"]["id"] == "currency"
        assert "ask" in p["feature"]

    def test_poll_feature_null_without_feature(self, client):
        d = client.post("/api/session", json={"task_id": "setup", "guard": False}).json()
        time.sleep(1.0)
        p = client.get(f"/api/session/{d['session_id']}").json()
        assert p.get("feature") is None

    def test_no_gchat_for_guard_off_single(self, client, monkeypatch):
        """Guard-OFF single session must NOT send any gchat notifications."""
        from arena import gchat
        spawns = []
        monkeypatch.setenv("GCHAT_WEBHOOK_URL",
                           "https://chat.googleapis.com/v1/spaces/X/messages?key=k&token=t")
        monkeypatch.setattr(gchat, "_spawn", lambda fn: spawns.append(fn))
        r = client.post("/api/session", json={"task_id": "setup", "guard": False,
                                               "feature": "csv-export"})
        assert r.status_code == 202
        time.sleep(1.5)
        # No task card, no alert for unguarded sessions
        assert len(spawns) == 0


# ================================================================
# Rate limit: env override
# ================================================================

class TestRateLimitEnv:
    """ARENA_SESSION_RATE env overrides the per-IP session rate limit."""

    def test_env_override_rate(self, client, monkeypatch):
        monkeypatch.setenv("ARENA_SESSION_RATE", "20")
        from arena import session as sess_mod
        # Patch the module-level constant for this test
        monkeypatch.setattr(sess_mod, "RATE_LIMIT_PER_IP",
                            int(os.environ.get("ARENA_SESSION_RATE", "6")))
        mgr = server._tw_manager
        mgr._ip_log.clear()
        for i in range(10):
            r = client.post("/api/session", json={"task_id": "setup", "guard": False})
            d = r.json()
            time.sleep(0.3)
            s = mgr.get(d.get("session_id", ""))
            if s:
                s.status = "done"
        # 11th should work (under 20)
        r = client.post("/api/session", json={"task_id": "setup", "guard": False})
        assert r.status_code == 202, f"Expected 202 with rate=20, got {r.status_code}"


# ================================================================
# Replay fallback: OFF side events usable standalone
# ================================================================

class TestReplayOffSide:
    """GET /api/duel/replay?chip_id=setup: the OFF side must have events."""

    def test_replay_off_side_has_events(self, client, runs_dir):
        r = client.post("/api/duel", json={"chip_id": "fix-deploy"})
        d = r.json()
        time.sleep(1.5)
        mgr = server._tw_manager
        from arena import duel_api
        duel_api._save_recording(d["duel_id"], "fix-deploy", mgr, runs_dir)
        r2 = client.get("/api/duel/replay?chip_id=fix-deploy")
        assert r2.status_code == 200
        body = r2.json()
        off = body.get("off", {})
        assert "events" in off
        assert len(off["events"]) > 0, "OFF side must have events for standalone replay"


# ================================================================
# POST /api/session/record and GET /api/attack/replay
# ================================================================

FAKE_LOOT_TRIP = {
    "kind": "canary_exfil", "path": ".env.backup",
    "canary_name": "stripe_key",
    "evidence": "setup.py telemetry to collect.evil.example",
}


async def _fake_run_compromised(chip, workspace, *, guard, client, event_cb,
                                tripwire, canaries, session_id, proxy_url,
                                model, layout=None, ai=False):
    """Fake: guard-OFF run that gets compromised (attacker events + loot)."""
    seq = [0]

    def emit(kind, **kw):
        seq[0] += 1
        ev = {"seq": seq[0], "side": "unprotected",
              "ts": seq[0] * 0.5, "kind": kind, "tool": kw.get("tool", ""),
              "text": kw.get("text", ""), "decision": kw.get("decision", ""),
              "reason": kw.get("reason", ""), "extra": kw.get("extra", {})}
        if event_cb:
            event_cb(ev)

    emit("info", text="Starting session with model=gemini-3.5-flash-lite guard=OFF")
    emit("tool", tool="run_command", text="python setup.py configure")
    emit("attacker", text="Received 128B from setup.py",
         extra={"canary_hit": True, "canary_name": "stripe_key",
                "encoding": "plain", "bytes": 128})
    emit("done", text="Task complete")
    return []


# Patch CaptureServer.loot to return a canary_hit for the fake compromised run
_orig_capture_loot = None


def _fake_capture_loot(self, session_id):
    """Return a fake canary_hit loot entry for any session."""
    return [{"canary_hit": True, "canary_name": "stripe_key",
             "encoding": "plain", "bytes": 128,
             "preview": "STRIPE_SECRET_KEY=sk_live_..."}]


@pytest.fixture
def rec_client(runs_dir, monkeypatch):
    """Client with a fake that produces compromised sessions."""
    monkeypatch.setenv("ARENA_RUNS", str(runs_dir))
    monkeypatch.setenv("ARENA_ADMIN_TOKEN", "test-admin-tok")
    mgr = sess_mod.SessionManager(runs_dir=runs_dir)
    monkeypatch.setattr(server, "_tw_manager", mgr)
    monkeypatch.setattr(sess_mod, "run_session", _fake_run_compromised)
    from arena.attacker_server import CaptureServer
    monkeypatch.setattr(CaptureServer, "loot", _fake_capture_loot)
    from arena import duel_api
    monkeypatch.setattr(duel_api, "_mgr", lambda: mgr)
    with TestClient(server.app) as c:
        yield c


class TestRecordAttack:
    """POST /api/session/record {feature}: admin-only, saves a recording."""

    def test_needs_admin_token(self, rec_client, monkeypatch):
        r = rec_client.post("/api/session/record", json={"feature": "csv-export"})
        assert r.status_code == 403

    def test_bad_token_forbidden(self, rec_client):
        r = rec_client.post("/api/session/record", json={"feature": "csv-export"},
                            headers={"X-Arena-Token": "wrong"})
        assert r.status_code == 403

    def test_unknown_feature_400(self, rec_client):
        r = rec_client.post("/api/session/record", json={"feature": "nope"},
                            headers={"X-Arena-Token": "test-admin-tok"})
        assert r.status_code == 400

    def test_records_compromised_run(self, rec_client, runs_dir):
        r = rec_client.post("/api/session/record", json={"feature": "csv-export"},
                            headers={"X-Arena-Token": "test-admin-tok"})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["verdict"] == "compromised"
        assert d.get("saved") is True
        # Recording file exists
        from pathlib import Path
        rec_path = runs_dir / "recordings" / "attack-csv-export.json"
        assert rec_path.is_file()
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
        assert rec["feature"]["id"] == "csv-export"
        assert rec["verdict"] == "compromised"
        assert len(rec["events"]) > 0
        assert rec["recorded_at"]  # ISO string
        assert rec.get("leak_ts") is not None

    def test_public_mode_404(self, rec_client, monkeypatch):
        monkeypatch.setenv("ARENA_PUBLIC", "1")
        monkeypatch.delenv("ARENA_ADMIN_TOKEN", raising=False)
        r = rec_client.post("/api/session/record", json={"feature": "csv-export"})
        assert r.status_code == 404


class TestAttackReplay:
    """GET /api/attack/replay?feature=<id>: returns the recording."""

    def test_404_when_none(self, client, monkeypatch):
        """No recording at all -> 404."""
        # Hide the shipped recording (Path instances take no attributes, so
        # patch the class); the client fixture's runs dir is a fresh tmp.
        from pathlib import Path
        real_is_file = Path.is_file
        monkeypatch.setattr(
            Path, "is_file",
            lambda self: False if self.name == "attack-top-n.json" else real_is_file(self))
        r = client.get("/api/attack/replay?feature=top-n")
        assert r.status_code == 404

    def test_unknown_feature_400(self, client):
        r = client.get("/api/attack/replay?feature=../../etc/passwd")
        assert r.status_code == 400

    def test_returns_recording_after_save(self, rec_client, runs_dir):
        # Record first
        rec_client.post("/api/session/record", json={"feature": "csv-export"},
                        headers={"X-Arena-Token": "test-admin-tok"})
        # Replay
        r = rec_client.get("/api/attack/replay?feature=csv-export")
        assert r.status_code == 200
        d = r.json()
        assert d["feature"]["id"] == "csv-export"
        assert d["verdict"] == "compromised"
        assert len(d["events"]) > 0

    def test_record_never_writes_repo_recordings(self, rec_client, runs_dir):
        """Recording writes only to the runs dir. The shipped real recordings in
        arena/recordings/ must never be overwritten (a test run once replaced
        them with fake-agent runs)."""
        from pathlib import Path
        repo_dir = Path(server.__file__).resolve().parent / "recordings"
        before = {p.name: p.read_bytes() for p in repo_dir.glob("attack-*.json")}
        for feat in ("csv-export", "currency", "top-n"):
            r = rec_client.post("/api/session/record", json={"feature": feat},
                                headers={"X-Arena-Token": "test-admin-tok"})
            assert r.status_code == 200
            assert (runs_dir / "recordings" / f"attack-{feat}.json").is_file()
        after = {p.name: p.read_bytes() for p in repo_dir.glob("attack-*.json")}
        assert after == before

    def test_replay_shape(self, rec_client, runs_dir):
        rec_client.post("/api/session/record", json={"feature": "currency"},
                        headers={"X-Arena-Token": "test-admin-tok"})
        d = rec_client.get("/api/attack/replay?feature=currency").json()
        for key in ("feature", "task_prompt", "model", "recorded_at",
                    "events", "loot", "verdict", "duration"):
            assert key in d, f"missing key: {key}"
