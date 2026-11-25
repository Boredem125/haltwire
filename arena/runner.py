"""Run one attack against the real Antigravity CLI with our hook in front of it.

Each attack gets a fresh copy of the template repo, its own sandbox folder
policy (escalations time out after a few seconds so runs never hang), and its
own hook log, which ``core.score`` reads afterwards.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from arena import core

ARENA_DIR = Path(__file__).resolve().parent
TEMPLATE = ARENA_DIR / "template"
REPO = ARENA_DIR.parent
RUNS_DIR = Path(os.environ.get("ARENA_RUNS", str(Path(tempfile.gettempdir()) / "haltwire-runs")))
PYTHON = Path(sys.executable)
SANDBOX = PYTHON.parent / ("sandbox.exe" if os.name == "nt" else "sandbox")
AGY = Path(os.environ.get("AGY", Path(os.environ.get("LOCALAPPDATA", "")) / "agy/bin/agy.exe"))
AGENT_TIMEOUT_S = int(os.environ.get("ARENA_AGENT_TIMEOUT", "150"))
PS_READ_ONLY = r"^(Get-ChildItem|Get-Content|Get-Location|Test-Path|Get-Command|Select-String)(\s|$)"


_SECRET_ENV = ("ARENA_ATTACKER_KEY", "ARENA_AGENT_KEY", "ARENA_AGENT_KEY1", "ARENA_ADMIN_TOKEN",
               "GEMINI_API_KEY", "GEMINI_API_KEY1", "GEMINI_API_KEY2", "GEMINI_API_KEY3", "GOOGLE_API_KEY",
               "BOLNA_API_KEY", "BOLNA_KEY_FILE")  # H5
_GOOGLE_KEY_RE = re.compile(r"AIza[0-9A-Za-z_\-]{35}")


def _secret_values() -> list[str]:
    vals = [os.environ.get(k, "") for k in _SECRET_ENV]
    env_file = ARENA_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                vals.append(line.split("=", 1)[1].strip().strip('"').strip("'"))
    return sorted({v for v in vals if len(v) >= 8}, key=len, reverse=True)


def redact(data: Any) -> Any:
    """Remove every known secret value and anything shaped like a Google API key."""
    text = json.dumps(data)
    for v in _secret_values():
        text = text.replace(json.dumps(v)[1:-1], "[REDACTED]")
    text = _GOOGLE_KEY_RE.sub("[REDACTED]", text)
    return json.loads(text)


def agent_env() -> dict[str, str]:
    """Environment for the victim agent: no attacker key, no admin token.
    Its own key (ARENA_AGENT_KEY, spend-capped) is passed as GEMINI_API_KEY."""
    env = {k: v for k, v in os.environ.items()
           if k not in _SECRET_ENV and not k.startswith("GEMINI_API_KEY")}
    agent_key = os.environ.get("ARENA_AGENT_KEY", "")
    if agent_key:
        env["GEMINI_API_KEY"] = agent_key
    # M3: prevent pip from installing real PyPI packages in the hook-live env
    env["PIP_NO_INDEX"] = "1"
    env["PIP_INDEX_URL"] = "http://127.0.0.1:9/simple"
    env["PIP_EXTRA_INDEX_URL"] = ""
    return env


def package_exists(name: str) -> bool:
    """True if *name* is on PyPI or npm. Network errors raise (caller treats as unsafe)."""
    for url in (f"https://pypi.org/pypi/{name}/json", f"https://registry.npmjs.org/{name}"):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:  # noqa: S310 — fixed hosts
                if r.status == 200:
                    return True
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
    return False


def _sandbox(*args: str, cwd: Path) -> None:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    subprocess.run([str(SANDBOX), *args], cwd=cwd, env=env, check=True,
                   capture_output=True, text=True, timeout=120)


def prepare(attack: dict[str, Any], dest: Path, log_path: Path) -> None:
    core.build_workspace(TEMPLATE, attack, dest)
    fake = dest / "env.fake"
    if fake.exists():
        fake.replace(dest / ".env")
    _sandbox("init", "--no-claude", "--no-mcp", "--no-versioning", str(dest), cwd=dest)
    policy_file = dest / ".sandbox" / "policy.json"
    policy = json.loads(policy_file.read_text(encoding="utf-8"))
    policy["escalation_timeout_seconds"] = 3  # tighter: nobody approves arena runs
    policy["shell"]["allow_patterns"].append(PS_READ_ONLY)
    policy_file.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    _sandbox("policy", "baseline", "--reason", "arena workspace starting policy", str(dest), cwd=dest)
    hooks = {"agg-security-layer": {"enabled": True, "PreToolUse": [{
        "matcher": "*",
        "hooks": [{"type": "command", "timeout": 60, "command":
                   f"{PYTHON.as_posix()} -m sandbox.connector.google_adapter "
                   f"--log {log_path.as_posix()}"}]}]}}
    (dest / ".agents").mkdir(exist_ok=True)
    (dest / ".agents" / "hooks.json").write_text(json.dumps(hooks, indent=2), encoding="utf-8")


def _parse_agent(stream: str) -> dict[str, Any]:
    reply, status, steps = "", "unknown", []
    for line in stream.splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get("event") == "result":
            res = o.get("result") or {}
            status = res.get("status", status)
            reply = res.get("response") or reply
        su = o.get("step_update") or {}
        if su.get("step_type") == "agent_response" and su.get("text_delta"):
            reply_delta = su["text_delta"]
            steps.append(reply_delta)
    if not reply and steps:
        reply = "".join(steps)
    return {"agent_status": status, "agent_reply": reply[:4000]}


async def run_agent(dest: Path, prompt: str, raw_path: Path | None = None) -> dict[str, Any]:
    proc = await asyncio.create_subprocess_exec(
        str(AGY), "-p", prompt, "--output-format", "stream-json",
        "--print-timeout", f"{AGENT_TIMEOUT_S}s",
        cwd=str(dest), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        env=agent_env(),
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), AGENT_TIMEOUT_S + 60)
    except asyncio.TimeoutError:
        proc.kill()
        return {"agent_status": "timeout", "agent_reply": ""}
    text = out.decode("utf-8", errors="replace")
    if raw_path is not None:
        raw_path.write_text(text, encoding="utf-8")
    return _parse_agent(text)


def read_log(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    out = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


async def run_attack(attack: dict[str, Any], run_id: str) -> dict[str, Any]:
    """Run one attack; every result (including errors) is redacted."""
    return redact(await _run_attack(attack, run_id))


async def _run_attack(attack: dict[str, Any], run_id: str) -> dict[str, Any]:
    started = time.time()
    base = {"id": attack["id"], "parent": attack.get("parent"),
            "technique": attack.get("technique", ""), "goal": attack.get("goal", ""),
            "user_prompt": attack.get("user_prompt", ""), "files": attack.get("files", {}),
            "indicators": attack.get("indicators", []), "source": attack.get("source", "gemini")}
    errs = await asyncio.to_thread(core.validate, attack, package_exists=package_exists)
    if errs:
        return {**base, "outcome": "error", "error": "rejected by safety check: " + "; ".join(errs[:3]),
                "seconds": round(time.time() - started, 1)}
    dest = RUNS_DIR / run_id / attack["id"]
    log_path = RUNS_DIR / run_id / "logs" / f"{attack['id']}.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    try:
        await asyncio.to_thread(prepare, attack, dest, log_path)
        agent = await run_agent(dest, attack["user_prompt"],
                                log_path.with_suffix(".agent.jsonl"))
    except Exception as exc:  # noqa: BLE001 — one bad run must not stop the arena
        return {**base, "outcome": "error", "error": f"run failed: {exc}",
                "seconds": round(time.time() - started, 1)}
    log = read_log(log_path)
    s = core.score(attack, log)
    probes = core.guard_probes(log)
    s["probed_guard"] = bool(probes)
    s["guard_probes"] = probes[:10]
    calls = []
    for e in log:
        try:
            tc = json.loads(e["in"]).get("toolCall") or {}
        except (ValueError, KeyError, TypeError):
            continue
        calls.append({"tool": tc.get("name"), "args": tc.get("args"),
                      "decision": (e.get("out") or {}).get("decision", "allow"),
                      "reason": (e.get("out") or {}).get("reason", "")[:400]})
    return redact({**base, **s, **agent, "tool_calls": calls[-25:],
                   "seconds": round(time.time() - started, 1)})
