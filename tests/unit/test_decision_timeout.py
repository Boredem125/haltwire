"""H2 decision deadline and the decide() double-sign race."""
from __future__ import annotations

import threading
import time

import pytest

from arena import duel, scenarios_tw, session as session_mod
from arena.session import AlreadyDecidedError


def _tripped(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_RUNS", str(tmp_path))
    mgr = session_mod.SessionManager(runs_dir=tmp_path)
    s = mgr._setup_session(scenarios_tw.get_chip("setup"), guard=True, client_ip="")
    s.handle_trip({"kind": "canary_exfil", "path": "stripe_key",
                   "canary_name": "stripe_key", "evidence": "test"})
    return mgr, s


def test_get_auto_keeps_frozen_after_deadline(tmp_path, monkeypatch):
    mgr, s = _tripped(tmp_path, monkeypatch)
    s._tripped_at = time.time() - session_mod.DECISION_TIMEOUT_S - 1
    got = mgr.get(s.id)
    assert got.status == "decided"
    assert got.receipt["decision"] == "deny"
    assert got.receipt["reviewer"] == "timeout"
    texts = [e.get("text", "") for e in got.events]
    assert any(t.startswith("No decision in") and "kept frozen (auto)" in t for t in texts)


def test_get_before_deadline_still_awaiting(tmp_path, monkeypatch):
    mgr, s = _tripped(tmp_path, monkeypatch)
    assert mgr.get(s.id).status == "awaiting_decision"
    assert s.receipt is None


def test_timeout_does_not_override_human_decision(tmp_path, monkeypatch):
    mgr, s = _tripped(tmp_path, monkeypatch)
    s.decide("keep_frozen", "Judge")
    s._tripped_at = time.time() - session_mod.DECISION_TIMEOUT_S - 1
    got = mgr.get(s.id)
    assert got.receipt["reviewer"] == "Judge"
    assert not any("kept frozen (auto)" in e.get("text", "") for e in got.events)


def test_timeout_signing_failure_tried_once(tmp_path, monkeypatch):
    mgr, s = _tripped(tmp_path, monkeypatch)
    s._tripped_at = time.time() - session_mod.DECISION_TIMEOUT_S - 1

    def boom(*a, **k):
        raise OSError("disk")
    monkeypatch.setattr(duel, "sign_decision", boom)
    for _ in range(5):
        mgr.get(s.id)
    fails = [e for e in s.events if e.get("text", "").startswith("decision not signed")]
    assert len(fails) == 1
    assert s.status == "awaiting_decision"


def test_concurrent_decides_sign_once(tmp_path, monkeypatch):
    mgr, s = _tripped(tmp_path, monkeypatch)
    real = duel.sign_decision

    def slow(*a, **k):
        time.sleep(0.3)
        return real(*a, **k)
    monkeypatch.setattr(duel, "sign_decision", slow)

    results = []

    def go(dec, who):
        try:
            s.decide(dec, who, _internal=True)
            results.append(("ok", who))
        except AlreadyDecidedError:
            results.append(("already", who))

    t1 = threading.Thread(target=go, args=("keep_frozen", "Judge"))
    t2 = threading.Thread(target=go, args=("release", "phone:x"))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert sorted(r[0] for r in results) == ["already", "ok"]


def test_failed_sign_allows_retry(tmp_path, monkeypatch):
    mgr, s = _tripped(tmp_path, monkeypatch)
    real = duel.sign_decision
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk")
        return real(*a, **k)
    monkeypatch.setattr(duel, "sign_decision", flaky)
    with pytest.raises(OSError):
        s.decide("keep_frozen", "Judge")
    assert s.decide("keep_frozen", "Judge")["ok"] is True


# ---------------------------------------------------------------- L6 Host check (DNS rebinding)

def test_foreign_host_header_rejected():
    from fastapi.testclient import TestClient
    from arena import server
    c = TestClient(server.app)
    assert c.get("/api/variants", headers={"Host": "evil.example"}).status_code == 400
    assert c.get("/api/variants", headers={"Host": "127.0.0.1:8088"}).status_code == 200
    assert c.get("/api/variants", headers={"Host": "localhost:8088"}).status_code == 200


def test_public_host_env_allowed(monkeypatch):
    from arena import server
    monkeypatch.setenv("ARENA_PUBLIC_HOST", "1-2-3-4.sslip.io")
    assert "1-2-3-4.sslip.io" in server._allowed_hosts()


# ---------------------------------------------------------------- shipped data wins over the runs dir

def test_benign_stats_prefers_shipped_file(tmp_path):
    import json
    from arena import duel_api
    (tmp_path / "benign_stats.json").write_text(
        json.dumps({"benign_runs": 999, "benign_false_trips": 0}), encoding="utf-8")
    assert duel_api.benign_stats(tmp_path)["benign_runs"] != 999


def test_replay_prefers_shipped_recording(tmp_path, monkeypatch):
    import json
    from fastapi.testclient import TestClient
    from arena import duel_api, server
    mgr = session_mod.SessionManager(runs_dir=tmp_path)
    monkeypatch.setattr(duel_api, "_mgr", lambda: mgr)
    planted = tmp_path / "recordings"
    planted.mkdir()
    (planted / "setup.json").write_text(json.dumps({"planted": True, "off": {}, "on": {}}),
                                        encoding="utf-8")
    r = TestClient(server.app).get("/api/duel/replay?chip_id=setup")
    assert r.status_code == 200
    assert "planted" not in r.json()


def test_compose_runs_root_not_agent_writable():
    from pathlib import Path
    text = Path("deploy/docker-compose.yml").read_text(encoding="utf-8")
    assert "mode=2750" in text and "mode=2770" not in text


# ---------------------------------------------------------------- deploy wiring (found in a local compose run)

def test_entrypoint_runs_given_command():
    import subprocess, shutil
    from pathlib import Path
    text = Path("deploy/entrypoint.sh").read_text(encoding="utf-8")
    assert 'exec "$@"' in text
    # The runner service passes its command; it must not fall through to the web server
    assert text.index('exec "$@"') < text.index("exec python -m arena.server")


def test_compose_healthchecks_match_bind_and_host_check():
    from pathlib import Path
    text = Path("deploy/docker-compose.yml").read_text(encoding="utf-8")
    assert "172.30.0.10:8088" in text.split("healthcheck:")[1]
    assert "'Host': 'localhost'" in text
    assert "test -S /sock/exec.sock" in text or '"-S", "/sock/exec.sock"' in text


# ---------------------------------------------------------------- honest verdicts when the sandbox is down

def test_runner_failure_is_error_not_not_leaked(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_RUNS", str(tmp_path))
    mgr = session_mod.SessionManager(runs_dir=tmp_path)
    s = mgr._setup_session(scenarios_tw.get_chip("setup"), guard=False, client_ip="")
    s._add_event({"kind": "tool", "tool": "run_command", "text": "python setup.py configure"})
    s._add_event({"kind": "result", "tool": "run_command",
                  "text": "Error: runner socket failed: [Errno 2] No such file or directory"})
    s._add_event({"kind": "done", "text": "Session ended"})
    s.loot = []
    s._compute_verdict()
    assert s.verdict == "error"
    assert s.error_reason == "sandbox unavailable"


def test_agent_session_error_text_is_categorised():
    from arena import agent
    assert agent._error_category(RuntimeError("429 RESOURCE_EXHAUSTED key AQ.secret")) == "model quota exhausted (429)"
    assert agent._error_category(RuntimeError("503 Service Unavailable")) == "model unavailable (503)"
    assert agent._error_category(KeyError("/data/keys/x")) == "run failed"


def test_runner_exec_error_is_error_verdict(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_RUNS", str(tmp_path))
    mgr = session_mod.SessionManager(runs_dir=tmp_path)
    s = mgr._setup_session(scenarios_tw.get_chip("setup"), guard=False, client_ip="")
    s._add_event({"kind": "tool", "tool": "run_command", "text": "python setup.py configure"})
    s._add_event({"kind": "result", "tool": "run_command",
                  "text": "exec error: [Errno 13] Permission denied: '/runs/sessions/x/ws'"})
    s._add_event({"kind": "done", "text": "Session ended"})
    s.loot = []
    s._compute_verdict()
    assert s.verdict == "error" and s.error_reason == "sandbox unavailable"


def test_compose_runner_in_agent_group():
    """Popen chdirs into the workspace BEFORE dropping to uid 10001, while the
    runner is still root without DAC capabilities, so it needs group 10001."""
    from pathlib import Path
    text = Path("deploy/docker-compose.yml").read_text(encoding="utf-8")
    runner = text.split("  runner:")[1]
    assert 'group_add:' in runner.split("networks:")[0]
    assert '"10001"' in runner.split("networks:")[0]


@pytest.mark.parametrize("chip", ["setup", "fix-deploy"])
def test_shipped_replay_receipt_verifies_on_fresh_host(chip, tmp_path, monkeypatch):
    """Fresh deploy: runs dir empty, only the shipped recording exists.
    Verify must return valid=True and tamper valid=False (not 404)."""
    from fastapi.testclient import TestClient
    from arena import duel_api, server
    mgr = session_mod.SessionManager(runs_dir=tmp_path)
    monkeypatch.setattr(duel_api, "_mgr", lambda: mgr)
    monkeypatch.setattr(server, "_tw_manager", mgr)
    c = TestClient(server.app)
    body = c.get(f"/api/duel/replay?chip_id={chip}").json()
    sid = body["on"]["session_id"]
    assert body["on"].get("receipt")
    rv = c.get(f"/api/receipt/{sid}/verify")
    assert rv.status_code == 200 and rv.json()["valid"] is True
    rt = c.get(f"/api/receipt/{sid}/verify?tamper=1")
    assert rt.status_code == 200 and rt.json()["valid"] is False


# ---------------------------------------------------------------- one SessionManager under `python -m arena.server`

def test_single_session_manager_when_run_as_main():
    """`python -m arena.server` runs the module as __main__; duel_api's
    `from arena.server import _mgr` must not load a second copy with its own
    SessionManager (duel sessions were invisible to /api/session routes)."""
    import subprocess, sys
    code = (
        "import runpy, uvicorn\n"
        "uvicorn.run = lambda *a, **k: None\n"
        "g = runpy.run_module('arena.server', run_name='__main__', alter_sys=True)\n"
        "from arena import duel_api\n"
        "print(duel_api._mgr() is g['_mgr']())\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         timeout=60, cwd=str(__import__('pathlib').Path(__file__).resolve().parents[2]))
    assert out.stdout.strip().endswith("True"), out.stdout + out.stderr
