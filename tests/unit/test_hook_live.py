"""Tests for arena.hook_live -- live agy run with our security hook.

Uses a FAKE agy (a small Python script) that writes hook-log and
stream-json lines with controlled delays, via env AGY path override.
All polling tests are async so the background task shares the event loop.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI


# ---------------------------------------------------------------------------
# Fake agy scripts (embedded as string constants)
# ---------------------------------------------------------------------------

_FAKE_AGY_NORMAL = textwrap.dedent(r'''
    import json, os, sys, time, re

    if "--version" in sys.argv:
        print("1.5.99-fake")
        sys.exit(0)
    if "models" in sys.argv:
        print("gemini-3.8-flash-low\tFake Low")
        sys.exit(0)

    delay = float(os.environ.get("FAKE_AGY_DELAY", "0.05"))

    ws = os.getcwd()
    hooks_file = os.path.join(ws, ".agents", "hooks.json")
    log_path = os.environ.get("FAKE_AGY_HOOK_LOG", "")
    if not log_path and os.path.exists(hooks_file):
        text = open(hooks_file, encoding="utf-8").read()
        m = re.search(r"--log\s+(\S+)", text)
        if m:
            log_path = m.group(1).strip('"').strip("'")

    ts = time.time()
    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "in": json.dumps({"toolCall": {"name": "read_file",
                                               "args": {"Path": "README.md"}},
                                  "modelName": "gemini-3.8-flash-low"}),
                "out": {"decision": "allow", "reason": ""},
                "ts": ts,
            }) + "\n")
            f.flush()
        time.sleep(delay)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "in": json.dumps({"toolCall": {"name": "run_command",
                                               "args": {"CommandLine":
                                                        "pip install -r requirements.txt"}}}),
                "out": {"decision": "deny",
                        "reason": ("SANDBOX DENIED [TYPOSQUAT]: requirements.txt "
                                   "installs 'pandaz-csv', 1 letter(s) away from "
                                   "the popular package 'pandas'. "
                                   "This is a common supply-chain attack.")},
                "ts": ts + 1,
            }) + "\n")
            f.flush()

    time.sleep(delay)
    print(json.dumps({
        "event": "step_update",
        "step_update": {"step_type": "tool", "state": "ACTIVE",
                        "tool_name": "run_command",
                        "tool_info": {"parameters":
                                      {"CommandLine":
                                       "pip install -r requirements.txt"}}},
    }), flush=True)
    time.sleep(delay)
    print(json.dumps({
        "event": "result",
        "result": {"status": "SUCCESS",
                   "response": "The install was denied."},
    }), flush=True)
''').lstrip()

_FAKE_AGY_STREAMING = textwrap.dedent(r'''
    import json, os, sys, time, re

    if "--version" in sys.argv:
        print("1.5.99-fake")
        sys.exit(0)
    if "models" in sys.argv:
        print("gemini-3.8-flash-low\tFake Low")
        sys.exit(0)

    ws = os.getcwd()
    hooks_file = os.path.join(ws, ".agents", "hooks.json")
    log_path = ""
    if os.path.exists(hooks_file):
        text = open(hooks_file, encoding="utf-8").read()
        m = re.search(r"--log\s+(\S+)", text)
        if m:
            log_path = m.group(1).strip('"').strip("'")

    # Write a hook log entry immediately
    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "in": json.dumps({"toolCall": {"name": "read_file",
                                               "args": {"Path": "README.md"}},
                                  "modelName": "gemini-3.8-flash-low"}),
                "out": {"decision": "allow", "reason": ""},
                "ts": time.time(),
            }) + "\n")
            f.flush()

    # Print a stream-json event EARLY (think delta), then wait
    print(json.dumps({
        "event": "step_update",
        "step_update": {"step_type": "agent_response",
                        "text_delta": "Looking at the project..."},
    }), flush=True)

    # Signal that the first event is out: write a marker file
    marker = os.path.join(ws, ".stream_started")
    with open(marker, "w") as f:
        f.write("1")

    # Wait so the test can poll BEFORE we exit
    time.sleep(3.0)

    print(json.dumps({
        "event": "step_update",
        "step_update": {"step_type": "tool", "state": "ACTIVE",
                        "tool_name": "run_command",
                        "tool_info": {"parameters":
                                      {"CommandLine": "pip install -r requirements.txt"}}},
    }), flush=True)
    time.sleep(0.1)
    print(json.dumps({
        "event": "result",
        "result": {"status": "SUCCESS",
                   "response": "Task complete."},
    }), flush=True)
''').lstrip()


_FAKE_AGY_SLOW = textwrap.dedent(r'''
    import sys, time
    if "--version" in sys.argv:
        print("1.5.99-fake")
        sys.exit(0)
    time.sleep(30)
''').lstrip()

_FAKE_AGY_TIMEOUT = textwrap.dedent(r'''
    import json, os, sys, time, re

    if "--version" in sys.argv:
        print("1.5.99-fake")
        sys.exit(0)

    ws = os.getcwd()
    hooks_file = os.path.join(ws, ".agents", "hooks.json")
    log_path = ""
    if os.path.exists(hooks_file):
        text = open(hooks_file, encoding="utf-8").read()
        m = re.search(r"--log\s+(\S+)", text)
        if m:
            log_path = m.group(1).strip('"').strip("'")

    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "in": json.dumps({"toolCall": {"name": "read_file",
                                               "args": {"Path": "README.md"}}}),
                "out": {"decision": "allow", "reason": ""},
                "ts": time.time(),
            }) + "\n")
            f.flush()

    time.sleep(600)
''').lstrip()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def fake_agy_script(tmp_path: Path) -> Path:
    script = tmp_path / "fake_agy.py"
    script.write_text(_FAKE_AGY_NORMAL, encoding="utf-8")
    return script


@pytest.fixture()
def slow_agy_script(tmp_path: Path) -> Path:
    script = tmp_path / "slow_agy.py"
    script.write_text(_FAKE_AGY_SLOW, encoding="utf-8")
    return script


@pytest.fixture()
def timeout_agy_script(tmp_path: Path) -> Path:
    script = tmp_path / "timeout_agy.py"
    script.write_text(_FAKE_AGY_TIMEOUT, encoding="utf-8")
    return script


def _setup_app(monkeypatch, agy_path: Path | None, tmp_path: Path,
               timeout: int | None = None) -> FastAPI:
    """Build a patched FastAPI app with hook_live_router."""
    if agy_path is not None:
        monkeypatch.setenv("AGY", str(agy_path))
    else:
        monkeypatch.setenv("AGY", str(tmp_path / "nonexistent_agy"))

    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("ARENA_RUNS", str(runs_dir))

    # Mock _sandbox to avoid needing real sandbox binary
    def fake_sandbox(*args, cwd):
        cwd = Path(cwd)
        sb = cwd / ".sandbox"
        sb.mkdir(parents=True, exist_ok=True)
        (sb / "policy.json").write_text(
            json.dumps({"shell": {"allow_patterns": []},
                        "escalation_timeout_seconds": 3}),
            encoding="utf-8",
        )
        (sb / "audit").mkdir(exist_ok=True)

    monkeypatch.setattr("arena.hook_demo._sandbox", fake_sandbox)

    # Reset module state
    import arena.hook_live as hl
    hl._active_run_id = None
    hl._runs.clear()
    hl._ip_log.clear()
    hl.RUNS_BASE = runs_dir
    if timeout is not None:
        hl.HARD_TIMEOUT = timeout

    app = FastAPI()
    app.include_router(hl.hook_live_router)
    return app


async def _poll_done(client: httpx.AsyncClient, run_id: str,
                     deadline_s: float = 30) -> dict[str, Any]:
    """Poll GET until status is done or error."""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        r = await client.get(f"/api/hook-live/{run_id}")
        assert r.status_code == 200, f"GET {r.status_code}: {r.text}"
        data = r.json()
        if data["status"] in ("done", "error"):
            return data
        await asyncio.sleep(0.3)
    raise AssertionError(f"run {run_id} did not finish within {deadline_s}s")


# ---------------------------------------------------------------------------
# Tests: POST basics (sync TestClient is fine here)
# ---------------------------------------------------------------------------

def test_post_returns_202_and_run_id(monkeypatch, fake_agy_script, tmp_path):
    from fastapi.testclient import TestClient
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    client = TestClient(app)
    resp = client.post("/api/hook-live")
    assert resp.status_code == 202
    body = resp.json()
    assert "run_id" in body
    assert isinstance(body["run_id"], str)
    assert len(body["run_id"]) >= 8


# ---------------------------------------------------------------------------
# Tests: 503 when binary missing (sync)
# ---------------------------------------------------------------------------

def test_503_when_agy_missing(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    app = _setup_app(monkeypatch, agy_path=None, tmp_path=tmp_path)
    client = TestClient(app)
    resp = client.post("/api/hook-live")
    assert resp.status_code == 503
    assert "not available" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Tests: rate limit (sync)
# ---------------------------------------------------------------------------

def test_rate_limit_per_ip(monkeypatch, fake_agy_script, tmp_path):
    from fastapi.testclient import TestClient
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    import arena.hook_live as hl
    hl._ip_log["testclient"] = [time.time()] * 3
    client = TestClient(app)
    resp = client.post("/api/hook-live")
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Tests: 404 for unknown run_id (sync)
# ---------------------------------------------------------------------------

def test_get_unknown_run_returns_404(monkeypatch, fake_agy_script, tmp_path):
    from fastapi.testclient import TestClient
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    client = TestClient(app)
    resp = client.get("/api/hook-live/nonexistent")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: status flow  running -> blocked -> done  (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_status_flow_running_blocked_done(monkeypatch, fake_agy_script, tmp_path):
    """POST starts a run; poll until done; must see block + done."""
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        assert resp.status_code == 202
        run_id = resp.json()["run_id"]

        final = await _poll_done(client, run_id)
        assert final["status"] == "done"
        assert final["block"] is not None, "block must be set after TYPOSQUAT deny"
        assert final["block"]["package"] == "pandaz-csv"
        assert final["block"]["looks_like"] == "pandas"
        assert final["block"]["reason"] == "TYPOSQUAT"
        assert isinstance(final["block"]["seconds"], (int, float))


@pytest.mark.asyncio
async def test_events_have_increasing_seq(monkeypatch, fake_agy_script, tmp_path):
    """Events must have strictly increasing seq numbers."""
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        final = await _poll_done(client, run_id)
        events = final["events"]
        assert len(events) > 0
        seqs = [e["seq"] for e in events]
        for i in range(1, len(seqs)):
            assert seqs[i] > seqs[i - 1], f"seq not increasing: {seqs}"


@pytest.mark.asyncio
async def test_events_since_filter(monkeypatch, fake_agy_script, tmp_path):
    """GET with since=N returns only events with seq > N."""
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        await _poll_done(client, run_id)

        all_data = (await client.get(f"/api/hook-live/{run_id}?since=0")).json()
        all_events = all_data["events"]
        if len(all_events) >= 2:
            cutoff = all_events[0]["seq"]
            filtered = (await client.get(f"/api/hook-live/{run_id}?since={cutoff}")).json()
            for e in filtered["events"]:
                assert e["seq"] > cutoff


@pytest.mark.asyncio
async def test_response_has_agent_and_model(monkeypatch, fake_agy_script, tmp_path):
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        final = await _poll_done(client, run_id)
        assert isinstance(final["agent"], str) and final["agent"]
        assert isinstance(final["model"], str) and final["model"]


# ---------------------------------------------------------------------------
# Tests: busy 409 (async -- slow script keeps the run alive)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_busy_returns_409(monkeypatch, slow_agy_script, tmp_path):
    """Second POST while a run is active returns 409."""
    app = _setup_app(monkeypatch, slow_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp1 = await client.post("/api/hook-live")
        assert resp1.status_code == 202

        # Let the task start (the subprocess needs a moment to launch)
        await asyncio.sleep(0.5)

        resp2 = await client.post("/api/hook-live")
        assert resp2.status_code == 409
        assert "already" in resp2.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Tests: timeout -> error (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_timeout_returns_error(monkeypatch, timeout_agy_script, tmp_path):
    """Hard timeout triggers error status."""
    app = _setup_app(monkeypatch, timeout_agy_script, tmp_path, timeout=3)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        assert resp.status_code == 202
        run_id = resp.json()["run_id"]
        final = await _poll_done(client, run_id, deadline_s=15)
        assert final["status"] == "error"


# ---------------------------------------------------------------------------
# Tests: redact applied (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_redact_removes_secrets(monkeypatch, fake_agy_script, tmp_path):
    fake_key = "AIzaSyFAKE_KEY_1234567890123456789012345"
    monkeypatch.setenv("GEMINI_API_KEY", fake_key)
    monkeypatch.setenv("ARENA_AGENT_KEY", fake_key)

    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        final = await _poll_done(client, run_id)
        text = json.dumps(final)
        assert fake_key not in text, "secret value leaked through redact"


# ---------------------------------------------------------------------------
# Tests: response shape (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_response_shape_complete(monkeypatch, fake_agy_script, tmp_path):
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        final = await _poll_done(client, run_id)
        for key in ("status", "events", "next", "block", "audit", "agent", "model"):
            assert key in final, f"missing key: {key}"


# ---------------------------------------------------------------------------
# Tests: agy stream events appear BEFORE process exits (async)
# ---------------------------------------------------------------------------

@pytest.fixture()
def streaming_agy_script(tmp_path: Path) -> Path:
    script = tmp_path / "streaming_agy.py"
    script.write_text(_FAKE_AGY_STREAMING, encoding="utf-8")
    return script


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_agy_events_appear_before_exit(monkeypatch, streaming_agy_script, tmp_path):
    """An agy stream-json event must appear in run.events BEFORE the process exits."""
    app = _setup_app(monkeypatch, streaming_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        assert resp.status_code == 202
        run_id = resp.json()["run_id"]

        # Poll until we see at least one agy-stream event (think or tool)
        # while the process is still running (status == "running")
        deadline = time.time() + 15
        saw_agy_event_while_running = False
        while time.time() < deadline:
            r = await client.get(f"/api/hook-live/{run_id}")
            data = r.json()
            agy_events = [e for e in data["events"]
                          if e.get("kind") in ("think", "tool", "done")]
            if agy_events and data["status"] == "running":
                saw_agy_event_while_running = True
                break
            await asyncio.sleep(0.3)

        assert saw_agy_event_while_running, \
            "agy stream events must appear BEFORE the process exits"


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_no_duplicate_events_at_end(monkeypatch, streaming_agy_script, tmp_path):
    """After the process exits, there must be no duplicate events."""
    app = _setup_app(monkeypatch, streaming_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        final = await _poll_done(client, run_id)
        events = final["events"]
        # No duplicate seq numbers
        seqs = [e["seq"] for e in events]
        assert len(seqs) == len(set(seqs)), f"duplicate seq numbers: {seqs}"

        # No duplicate tool events with the same text
        tool_events = [(e["kind"], e.get("tool", ""), e.get("text", ""))
                       for e in events if e["kind"] == "tool"]
        assert len(tool_events) == len(set(tool_events)), \
            f"duplicate tool events: {tool_events}"


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_seq_monotonic_with_streaming(monkeypatch, streaming_agy_script, tmp_path):
    """Events must have strictly increasing seq numbers including streamed agy events."""
    app = _setup_app(monkeypatch, streaming_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        final = await _poll_done(client, run_id)
        events = final["events"]
        assert len(events) > 0
        seqs = [e["seq"] for e in events]
        for i in range(1, len(seqs)):
            assert seqs[i] > seqs[i - 1], f"seq not monotonic: {seqs}"


# ---------------------------------------------------------------------------
# Tests: parse_agy_line unit tests (duel.py refactor)
# ---------------------------------------------------------------------------

def test_parse_agy_line_tool():
    """parse_agy_line returns a tool event for an ACTIVE tool step."""
    from arena.duel import parse_agy_line
    line = json.dumps({
        "event": "step_update",
        "step_update": {"step_type": "tool", "state": "ACTIVE",
                        "tool_name": "run_command",
                        "tool_info": {"parameters": {"CommandLine": "ls"}}},
    })
    ev = parse_agy_line(line, "protected", ts=1.5, seq=10)
    assert ev is not None
    assert ev["kind"] == "tool"
    assert ev["tool"] == "run_command"
    assert ev["seq"] == 11


def test_parse_agy_line_think():
    from arena.duel import parse_agy_line
    line = json.dumps({
        "event": "step_update",
        "step_update": {"step_type": "agent_response",
                        "text_delta": "Thinking..."},
    })
    ev = parse_agy_line(line, "protected", ts=2.0, seq=5)
    assert ev is not None
    assert ev["kind"] == "think"
    assert ev["text"] == "Thinking..."
    assert ev["seq"] == 6


def test_parse_agy_line_result():
    from arena.duel import parse_agy_line
    line = json.dumps({
        "event": "result",
        "result": {"status": "SUCCESS", "response": "done"},
    })
    ev = parse_agy_line(line, "unprotected", ts=3.0, seq=20)
    assert ev is not None
    assert ev["kind"] == "done"
    assert ev["seq"] == 21


def test_parse_agy_line_bad_json():
    from arena.duel import parse_agy_line
    ev = parse_agy_line("not json", "protected", ts=0, seq=0)
    assert ev is None


def test_parse_agy_line_irrelevant():
    from arena.duel import parse_agy_line
    line = json.dumps({"event": "something_else"})
    ev = parse_agy_line(line, "protected", ts=0, seq=0)
    assert ev is None


# ---------------------------------------------------------------------------
# Tests: run-dir files (proc.json, agy_stdout.jsonl, done.json)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_run_dir_files_written(monkeypatch, fake_agy_script, tmp_path):
    """After a run, proc.json + agy_stdout.jsonl + done.json exist."""
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        await _poll_done(client, run_id)

    run_dir = tmp_path / "runs" / "hook-live" / run_id
    # proc.json
    proc_path = run_dir / "proc.json"
    assert proc_path.is_file(), "proc.json must exist"
    proc_data = json.loads(proc_path.read_text(encoding="utf-8"))
    assert proc_data["run_id"] == run_id
    assert isinstance(proc_data["pid"], int) and proc_data["pid"] > 0
    assert proc_data["agent"]  # non-empty
    assert proc_data["started_at"]  # ISO timestamp
    assert proc_data["cwd"]  # workspace path

    # agy_stdout.jsonl
    stdout_path = run_dir / "agy_stdout.jsonl"
    assert stdout_path.is_file(), "agy_stdout.jsonl must exist"
    lines = stdout_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1  # at least one agy output line

    # done.json
    done_path = run_dir / "done.json"
    assert done_path.is_file(), "done.json must exist"
    done_data = json.loads(done_path.read_text(encoding="utf-8"))
    assert done_data["status"] in ("done", "blocked", "error")
    assert isinstance(done_data["seconds"], (int, float))


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_run_dir_no_env_secrets(monkeypatch, fake_agy_script, tmp_path):
    """No env values or API keys in the run-dir files."""
    fake_key = "AIzaSyFAKE_KEY_1234567890123456789012345"
    monkeypatch.setenv("GEMINI_API_KEY", fake_key)
    monkeypatch.setenv("ARENA_AGENT_KEY", fake_key)
    app = _setup_app(monkeypatch, fake_agy_script, tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/hook-live")
        run_id = resp.json()["run_id"]
        await _poll_done(client, run_id)

    run_dir = tmp_path / "runs" / "hook-live" / run_id
    for fname in ("proc.json", "agy_stdout.jsonl", "done.json"):
        fpath = run_dir / fname
        if fpath.is_file():
            text = fpath.read_text(encoding="utf-8")
            assert fake_key not in text, f"secret leaked in {fname}"


# ---------------------------------------------------------------------------
# Tests: watch_agy formatting functions
# ---------------------------------------------------------------------------

def test_format_tool_line():
    from arena.watch_agy import format_agy_event
    ev = {"kind": "tool", "tool": "run_command", "text": "pip install -r requirements.txt"}
    line = format_agy_event(ev)
    assert "run_command" in line
    assert "pip install" in line


def test_format_think_line():
    from arena.watch_agy import format_agy_event
    ev = {"kind": "think", "text": "Looking at the project..."}
    line = format_agy_event(ev)
    assert "Looking at" in line


def test_format_done_line():
    from arena.watch_agy import format_agy_event
    ev = {"kind": "done", "text": "Task complete."}
    line = format_agy_event(ev)
    assert "done" in line.lower() or "complete" in line.lower()


def test_format_hook_allow():
    from arena.watch_agy import format_hook_entry
    entry = {"in": json.dumps({"toolCall": {"name": "read_file",
                                            "args": {"Path": "README.md"}}}),
             "out": {"decision": "allow"}}
    line = format_hook_entry(entry)
    assert "allow" in line.lower()
    assert "read_file" in line


def test_format_hook_deny():
    from arena.watch_agy import format_hook_entry
    entry = {"in": json.dumps({"toolCall": {"name": "run_command",
                                            "args": {"CommandLine": "pip install x"}}}),
             "out": {"decision": "deny",
                     "reason": "SANDBOX DENIED [TYPOSQUAT]: installs 'pandaz-csv'"}}
    line = format_hook_entry(entry)
    assert "DENY" in line or "deny" in line
    assert "TYPOSQUAT" in line


def test_format_block_banner():
    from arena.watch_agy import format_block_banner
    block = {"package": "pandaz-csv", "looks_like": "pandas",
             "reason": "TYPOSQUAT", "seconds": 3.2}
    banner = format_block_banner(block)
    assert "pandaz-csv" in banner
    assert "pandas" in banner
    assert "3.2" in banner


# ---------------------------------------------------------------------------
# Tests: events_from_agy_stream backward compat
# ---------------------------------------------------------------------------

def test_events_from_agy_stream_still_works():
    """The refactored events_from_agy_stream must behave the same."""
    from arena.duel import events_from_agy_stream
    stream = "\n".join([
        json.dumps({"event": "step_update", "step_update": {
            "step_type": "tool", "state": "ACTIVE",
            "tool_name": "run_command",
            "tool_info": {"parameters": {"CommandLine": "pip install x"}}}}),
        json.dumps({"event": "step_update", "step_update": {
            "step_type": "agent_response", "text_delta": "Installing."}}),
        json.dumps({"event": "result", "result": {
            "status": "SUCCESS", "response": "done"}}),
    ])
    events = events_from_agy_stream(stream, "unprotected", start=0.0)
    kinds = [e["kind"] for e in events]
    assert kinds == ["tool", "think", "done"]
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_hook_live_rate_off_with_env_zero(monkeypatch):
    from arena import hook_live
    monkeypatch.setenv("ARENA_HOOK_LIVE_RATE", "0")
    monkeypatch.setattr(hook_live, "_ip_log", {})
    for _ in range(10):
        hook_live._check_ip_rate("10.0.0.9")   # never raises


def test_hook_live_rate_env_value(monkeypatch):
    from fastapi import HTTPException
    from arena import hook_live
    monkeypatch.setenv("ARENA_HOOK_LIVE_RATE", "2")
    monkeypatch.setattr(hook_live, "_ip_log", {})
    hook_live._check_ip_rate("10.0.0.8")
    hook_live._check_ip_rate("10.0.0.8")
    with pytest.raises(HTTPException) as e:
        hook_live._check_ip_rate("10.0.0.8")
    assert e.value.status_code == 429 and "2 runs per hour" in e.value.detail


def test_hook_live_rate_default_unchanged(monkeypatch):
    from fastapi import HTTPException
    from arena import hook_live
    monkeypatch.delenv("ARENA_HOOK_LIVE_RATE", raising=False)
    monkeypatch.setattr(hook_live, "_ip_log", {})
    for _ in range(3):
        hook_live._check_ip_rate("10.0.0.7")
    with pytest.raises(HTTPException):
        hook_live._check_ip_rate("10.0.0.7")


class TestAutoOpenWatcher:
    """ARENA_AGY_WATCH=1 opens the live-process console once (laptop only)."""

    def _fake_popen(self, calls):
        class P:
            def __init__(self, cmd, **kw):
                calls.append((cmd, kw)); self._alive = True
            def poll(self):
                return None if self._alive else 0
        return P

    def test_off_by_default(self, monkeypatch):
        from arena import hook_live
        calls = []
        monkeypatch.delenv("ARENA_AGY_WATCH", raising=False)
        monkeypatch.setattr(hook_live.subprocess, "Popen", self._fake_popen(calls))
        monkeypatch.setattr(hook_live, "_watch_proc", None)
        hook_live._ensure_watch_window()
        assert calls == []

    def test_opens_once_when_on(self, monkeypatch):
        from arena import hook_live
        calls = []
        monkeypatch.setenv("ARENA_AGY_WATCH", "1")
        monkeypatch.setattr(hook_live.subprocess, "Popen", self._fake_popen(calls))
        monkeypatch.setattr(hook_live, "_watch_proc", None)
        monkeypatch.setattr(hook_live, "_watcher_running_elsewhere", lambda: False)
        hook_live._ensure_watch_window()
        hook_live._ensure_watch_window()
        assert len(calls) == 1
        cmd, kw = calls[0]
        assert "arena.watch_agy" in cmd
        assert "GEMINI" not in " ".join(f"{k}={v}" for k, v in (kw.get("env") or {}).items()
                                        if k.startswith("GEMINI"))

    def test_skips_when_a_watcher_is_already_open(self, monkeypatch):
        from arena import hook_live
        calls = []
        monkeypatch.setenv("ARENA_AGY_WATCH", "1")
        monkeypatch.setattr(hook_live.subprocess, "Popen", self._fake_popen(calls))
        monkeypatch.setattr(hook_live, "_watch_proc", None)
        monkeypatch.setattr(hook_live, "_watcher_running_elsewhere", lambda: True)
        hook_live._ensure_watch_window()
        assert calls == []

    def test_failure_never_breaks_the_run(self, monkeypatch):
        from arena import hook_live
        def boom(*a, **k):
            raise OSError("no console")
        monkeypatch.setenv("ARENA_AGY_WATCH", "1")
        monkeypatch.setattr(hook_live.subprocess, "Popen", boom)
        monkeypatch.setattr(hook_live, "_watch_proc", None)
        monkeypatch.setattr(hook_live, "_watcher_running_elsewhere", lambda: False)
        hook_live._ensure_watch_window()   # no raise
