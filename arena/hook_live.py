"""Live hook demo: start a real agy run with our security hook and stream events.

POST /api/hook-live -> 202 {run_id}
  One run at a time (409 if busy). Per-IP 3/hour.
  If agy not installed: 503.

GET /api/hook-live/{run_id}?since=N -> {status, events, next, block, audit, agent, model}
  status: running | blocked | done | error
  block:  null | {package, looks_like, reason, seconds}
  audit:  null | {chain_ok, head_hash_short, record_hash_short}
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from arena import duel
from arena.runner import (
    AGY as _DEFAULT_AGY,
    AGENT_TIMEOUT_S,
    PYTHON,
    agent_env,
    read_log,
    redact,
)
from arena.hook_demo import (
    PROMPT,
    _prepare_workspace,
    _read_chain,
    _find_block,
    _find_deny_record,
    _model_from_hook_log,
)

RUNS_BASE = Path(os.environ.get("ARENA_RUNS", str(Path(tempfile.gettempdir()) / "haltwire-runs")))
HARD_TIMEOUT = 150        # seconds
POLL_INTERVAL = 0.3       # seconds
IP_LIMIT = 3              # per IP per hour
MODEL = "gemini-3.8-flash-low"  # fastest model that still triggers the install

hook_live_router = APIRouter()

# ---- module-level mutable state (reset in tests) ----
_runs: dict[str, "LiveRun"] = {}       # run_id -> LiveRun (kept after completion)
_active_run_id: str | None = None      # set while a run is in progress
_ip_log: dict[str, list[float]] = {}   # ip -> [epoch timestamps]


# ---- agy helpers ----

def _agy_path() -> Path:
    """Resolve the agy binary path, respecting the AGY env override."""
    return Path(os.environ.get("AGY", str(_DEFAULT_AGY)))


def _agy_available() -> bool:
    agy = _agy_path()
    if agy.suffix == ".py":
        return agy.is_file()
    return agy.is_file() or shutil.which(str(agy)) is not None


def _agy_cmd() -> list[str]:
    """Command list to invoke agy.  Supports .py scripts for testing."""
    agy = _agy_path()
    if agy.suffix == ".py":
        return [sys.executable, "-I", str(agy)]
    return [str(agy)]


def _agy_version() -> str:
    try:
        result = subprocess.run(
            _agy_cmd() + ["--version"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


# ---- rate limiting ----

def _get_client_ip(request: Request) -> str:
    """M1: delegates to the shared get_client_ip helper."""
    from arena.server import get_client_ip
    return get_client_ip(request)


def _ip_limit() -> int:
    """Runs per IP per hour: env ARENA_HOOK_LIVE_RATE (0 = no limit, for the
    presenter's laptop), else IP_LIMIT."""
    raw = os.environ.get("ARENA_HOOK_LIVE_RATE", "").strip()
    try:
        return int(raw) if raw else IP_LIMIT
    except ValueError:
        return IP_LIMIT


def _check_ip_rate(client_ip: str) -> None:
    limit = _ip_limit()
    if not client_ip or limit <= 0:
        return
    now = time.time()
    cutoff = now - 3600
    times = _ip_log.get(client_ip, [])
    times = [t for t in times if t > cutoff]
    _ip_log[client_ip] = times
    if len(times) >= limit:
        raise HTTPException(429, f"rate limit: {limit} runs per hour")
    times.append(now)


# ---- LiveRun state ----

class LiveRun:
    """Tracks one background agy run."""

    def __init__(self, run_id: str, model: str) -> None:
        self.run_id = run_id
        self.model = model
        self.status: str = "running"      # running | blocked | done | error
        self.events: list[dict[str, Any]] = []
        self.block: dict[str, Any] | None = None
        self.audit: dict[str, Any] | None = None
        self.agent: str = ""
        self.error_reason: str = ""
        self.error: str | None = None   # public category only
        self.started_at: float = time.time()
        self._seq: int = 0
        self._last_hook_lines: int = 0
        self._ws: Path | None = None
        self._log_path: Path | None = None

    def to_dict(self, since: int = 0) -> dict[str, Any]:
        evts = [e for e in self.events if e.get("seq", 0) > since]
        next_val = self.events[-1]["seq"] if self.events else 0
        return redact({
            "status": self.status,
            "events": evts,
            "next": next_val,
            "block": self.block,
            "audit": self.audit,
            "agent": self.agent,
            "model": self.model,
            "error": getattr(self, "error", None),
        })


# ---- block detection ----

def _has_typosquat_block(events: list[dict[str, Any]]) -> bool:
    """True if any event is a block with TYPOSQUAT in the reason."""
    return any(
        e.get("kind") == "block" and "TYPOSQUAT" in (e.get("reason") or "")
        for e in events
    )


# ---- background runner ----

def _poll_hook_log_sync(run: LiveRun) -> None:
    """Read new entries from the hook log and append events (sync)."""
    log_path = run._log_path
    if not log_path or not log_path.is_file():
        return
    hook_entries = read_log(log_path)
    new_entries = hook_entries[run._last_hook_lines:]
    if not new_entries:
        return
    new_events = duel.events_from_hook_log(
        new_entries, "protected", start=run.started_at, seq0=run._seq,
    )
    # The hook log carries no timestamps, so stamp each event with the moment
    # we first read it (polled about every 0.7 s), relative to the run start.
    seen = round(time.time() - run.started_at, 2)
    for ev in new_events:
        if not ev.get("ts"):
            ev["ts"] = seen
        run.events.append(ev)
        run._seq = ev["seq"]
    run._last_hook_lines = len(hook_entries)

    # Check for TYPOSQUAT deny
    if run.block is None and _has_typosquat_block(run.events):
        block_info = _find_block(run.events)
        run.block = {
            **block_info,
            "seconds": round(time.time() - run.started_at, 1),
        }
        run.status = "blocked"
        _fill_audit(run)


def _fill_audit(run: LiveRun) -> None:
    """Read and verify the workspace audit chain."""
    ws = run._ws
    if ws is None:
        return
    try:
        chain_bytes, chain_result = _read_chain(ws, "")
        deny_rec = _find_deny_record(chain_bytes) if chain_bytes else {}
        run.audit = {
            "chain_ok": chain_result.get("ok", False),
            "head_hash_short": chain_result.get("head_hash", "")[:8],
            "record_hash_short": (deny_rec.get("record_hash", "") or "")[:8],
        }
    except Exception:
        run.audit = {"chain_ok": False, "head_hash_short": "", "record_hash_short": ""}


def _agy_error(stream: str, stderr: str) -> str | None:
    """Public category for an agy run that ended in error, else None."""
    status, msg = None, ""
    for line in stream.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("event") == "result":
            res = ev.get("result") or {}
            status, msg = res.get("status"), str(res.get("error") or "")
    if status != "ERROR":
        return None
    text = f"{msg} {stderr}"
    if "429" in text or "quota" in text.lower() or "RESOURCE_EXHAUSTED" in text:
        return "model quota reached (429)"
    return "run failed"


_watch_proc: Any = None   # the console this server opened, if any


def _watcher_running_elsewhere() -> bool:
    """True when some arena.watch_agy console is already running (e.g. opened
    by hand with watch_agy.cmd), so we never stack a second window."""
    if os.name != "nt":
        return False
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             # Only python processes: this query's own command line also
             # contains the module name and must not count as a watcher.
             "(Get-CimInstance Win32_Process | Where-Object { $_.Name -like "
             "'python*' -and $_.CommandLine -like '*arena.watch_agy*' } "
             "| Measure-Object).Count"],
            capture_output=True, text=True, timeout=8)
        return int((out.stdout or "0").strip() or 0) > 0
    except Exception:  # noqa: BLE001 - unknown: assume none, open one
        return False


def _ensure_watch_window() -> None:
    """ARENA_AGY_WATCH=1 (presenter laptop only): open the live-process
    console (python -m arena.watch_agy) in its own window, once.  It reads
    only the run files; no secrets go to it (agent_env strips keys).
    Never raises: the run must not depend on a window opening."""
    global _watch_proc
    if os.environ.get("ARENA_AGY_WATCH") != "1":
        return
    try:
        if _watch_proc is not None and _watch_proc.poll() is None:
            return
        if _watcher_running_elsewhere():
            return
        env = agent_env()
        env["ARENA_RUNS"] = str(RUNS_BASE)
        flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
        _watch_proc = subprocess.Popen(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args  -- all args are hardcoded (sys.executable, module name, RUNS_BASE constant set at import time); env is the server operator's own os.environ filtered through agent_env(); no web request input reaches this call; guarded by ARENA_AGY_WATCH=1 (presenter-only)
            [sys.executable, "-m", "arena.watch_agy", str(RUNS_BASE)],
            cwd=str(Path(__file__).resolve().parent.parent),
            env=env, creationflags=flags)
    except Exception:  # noqa: BLE001 - a missing window never breaks the run
        _watch_proc = None


async def _run_live(run: LiveRun, dest_dir: Path, model: str) -> None:
    """Background task: prepare workspace, start agy, poll events."""
    global _active_run_id
    proc = None
    try:
        # Prepare workspace (blocking I/O, offload to thread)
        ws, log_path = await asyncio.to_thread(_prepare_workspace, dest_dir)
        run._ws = ws
        run._log_path = log_path

        # Agent version
        run.agent = f"Antigravity CLI {_agy_version()}"

        # Ensure run dir exists for sidecar files
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Build agy command
        cmd = _agy_cmd() + [
            "-p", PROMPT,
            "--output-format", "stream-json",
            "--print-timeout", f"{AGENT_TIMEOUT_S}s",
        ]
        if model:
            cmd.extend(["--model", model])

        # Laptop demo: make sure the live-process console is open beside
        # the browser before agy starts, so it shows the run from the start.
        _ensure_watch_window()

        # Start agy subprocess
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(ws),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=agent_env(),
        )

        raw_lines: list[str] = []

        # Write proc.json (never breaks the run on failure)
        try:
            proc_info = {
                "run_id": run.run_id,
                "pid": proc.pid,
                "agent": run.agent,
                "model": model,
                "prompt": PROMPT,
                "cwd": str(ws),
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            (dest_dir / "proc.json").write_text(
                json.dumps(proc_info, indent=2), encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

        # Open agy_stdout.jsonl for streaming writes
        _stdout_file = None
        try:
            _stdout_file = open(dest_dir / "agy_stdout.jsonl", "a",
                                encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

        # Poll loop: read stdout lines and poll the hook log file.
        # On Windows proc.returncode stays None until proc.wait() is
        # called, so we detect exit via readline() returning b"" (EOF).
        #
        # Each agy stdout line is parsed immediately via parse_agy_line
        # so events appear in run.events BEFORE the process exits.
        while True:
            elapsed = time.time() - run.started_at
            if elapsed > HARD_TIMEOUT:
                proc.kill()
                await proc.wait()
                run.status = "error"
                run.error_reason = f"hard timeout ({HARD_TIMEOUT}s)"
                run.error = "timed out"
                break

            # Try to read one line from stdout
            try:
                line_bytes = await asyncio.wait_for(
                    proc.stdout.readline(), POLL_INTERVAL,
                )
            except asyncio.TimeoutError:
                # No data yet -- poll hook log and loop
                _poll_hook_log_sync(run)
                continue

            if line_bytes:
                line_str = line_bytes.decode("utf-8", errors="replace").rstrip()
                raw_lines.append(line_str)
                # Append to agy_stdout.jsonl (flush each line)
                if _stdout_file is not None:
                    try:
                        _stdout_file.write(line_str + "\n")
                        _stdout_file.flush()
                    except Exception:  # noqa: BLE001
                        pass
                # Parse and append immediately (real-time streaming)
                ts = round(time.time() - run.started_at, 2)
                ev = duel.parse_agy_line(line_str, "protected", ts, run._seq)
                if ev is not None:
                    run.events.append(ev)
                    run._seq = ev["seq"]
                _poll_hook_log_sync(run)
                continue

            # readline returned b"" => EOF on stdout.  The subprocess
            # has closed its pipe; wait for it to exit fully.
            try:
                await asyncio.wait_for(proc.wait(), 5.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
            break

        # Final poll of hook log
        _poll_hook_log_sync(run)

        # No post-exit re-parse: events were already appended in real time.
        # raw_lines kept only for _agy_error detection below.
        raw_text = "\n".join(raw_lines)

        # Detect model from hook log
        if run._log_path:
            hook_entries = read_log(run._log_path)
            detected_model = _model_from_hook_log(hook_entries)
            if detected_model:
                run.model = detected_model

        # An agy run that reported ERROR is an error, never "done"
        stderr_text = ""
        try:
            stderr_text = (await asyncio.wait_for(proc.stderr.read(), 2.0)).decode(
                "utf-8", errors="replace")[-2000:]
        except Exception:  # noqa: BLE001 - stderr is best-effort context
            pass
        agy_err = _agy_error(raw_text, stderr_text)
        if agy_err and run.block is None:
            run.status = "error"
            run.error = agy_err
            run.error_reason = agy_err

        # Set final status (if not already error)
        if run.status not in ("error",):
            run.status = "done"

        # If we never found a block, try one more time with final events
        if run.block is None and _has_typosquat_block(run.events):
            block_info = _find_block(run.events)
            run.block = {
                **block_info,
                "seconds": round(time.time() - run.started_at, 1),
            }
            _fill_audit(run)

        # Write done.json
        try:
            done_info = {
                "status": run.status,
                "error": run.error,
                "block": run.block,
                "audit": run.audit,
                "seconds": round(time.time() - run.started_at, 1),
            }
            (dest_dir / "done.json").write_text(
                json.dumps(done_info, indent=2), encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

    except Exception as exc:
        run.status = "error"
        run.error_reason = str(exc)
        run.error = "run failed"
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        # Write done.json even on exception
        try:
            done_info = {
                "status": run.status,
                "error": run.error,
                "block": None,
                "audit": None,
                "seconds": round(time.time() - run.started_at, 1),
            }
            (dest_dir / "done.json").write_text(
                json.dumps(done_info, indent=2), encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass
    finally:
        _active_run_id = None
        if _stdout_file is not None:
            try:
                _stdout_file.close()
            except Exception:  # noqa: BLE001
                pass


# ---- API endpoints ----

@hook_live_router.post("/api/hook-live", status_code=202)
async def start_hook_live(request: Request) -> dict[str, Any]:
    """Start a live agy run with the security hook.

    Returns 202 {run_id} on success.
    Returns 409 if a run is already in progress.
    Returns 429 if per-IP rate limit exceeded.
    Returns 503 if agy binary is not installed.
    """
    global _active_run_id

    if not _agy_available():
        raise HTTPException(503, detail="Antigravity CLI not available on this host")

    if _active_run_id is not None:
        raise HTTPException(409, detail="a live run is already in progress")

    client_ip = _get_client_ip(request)
    _check_ip_rate(client_ip)

    run_id = uuid.uuid4().hex[:12]
    run = LiveRun(run_id, MODEL)
    dest_dir = RUNS_BASE / "hook-live" / run_id

    _active_run_id = run_id
    _runs[run_id] = run

    task = asyncio.create_task(_run_live(run, dest_dir, MODEL))
    # Store task reference but it is not needed for GET
    run._task = task  # type: ignore[attr-defined]

    return {"run_id": run_id}


@hook_live_router.get("/api/hook-live/{run_id}")
def get_hook_live(run_id: str, since: int = Query(default=0)) -> dict[str, Any]:
    """Poll the live run status and events.

    Returns events with seq > since.
    """
    run = _runs.get(run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    return run.to_dict(since)
