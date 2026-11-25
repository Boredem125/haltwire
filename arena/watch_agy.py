"""Console watcher for Antigravity CLI live runs.

Usage:
    python -m arena.watch_agy              # follows ARENA_RUNS
    python -m arena.watch_agy <runs-dir>/<session>

Shows the real OS process, streams agy steps human-readable, and prints
hook decisions and block/audit results.  ANSI colours for large-font
terminals.  Never prints secrets.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from arena.runner import read_log, redact

# ---------------------------------------------------------------------------
# ANSI helpers (enable VT mode on Windows)

try:
    os.system("")  # enables VT processing on Windows 10+
    if os.name == "nt":
        os.system("title Antigravity CLI - live process")
except Exception:
    pass

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"


# ---------------------------------------------------------------------------
# Formatting functions (unit-tested)

def format_agy_event(ev: dict[str, Any]) -> str:
    """Format one parsed agy event for the console."""
    kind = ev.get("kind", "")
    if kind == "tool":
        tool = ev.get("tool", "?")
        text = ev.get("text", "")[:120]
        return f"  {CYAN}\u25b8 {tool}{RESET} {text}"
    if kind == "think":
        text = ev.get("text", "")[:200]
        return f"  {DIM}{text}{RESET}"
    if kind == "done":
        text = ev.get("text", "")[:200]
        return f"  {GREEN}done{RESET} {text}"
    return f"  {kind}: {ev.get('text', '')[:120]}"


def format_hook_entry(entry: dict[str, Any]) -> str:
    """Format one hook log entry for the console."""
    try:
        tc = json.loads(entry.get("in") or "{}").get("toolCall") or {}
    except (ValueError, TypeError):
        tc = {}
    out = entry.get("out") or {}
    name = tc.get("name", "?")
    decision = out.get("decision", "?")
    reason = out.get("reason", "")
    if decision == "allow":
        return f"  {GREEN}hook: allow{RESET} {name}"
    elif decision == "deny":
        short = reason[:100] if reason else "denied"
        return f"  {RED}hook: DENY{RESET} {name} {YELLOW}{short}{RESET}"
    return f"  hook: {decision} {name}"


def format_block_banner(block: dict[str, Any]) -> str:
    """Format the BLOCKED banner for the console."""
    pkg = block.get("package", "?")
    looks = block.get("looks_like", "?")
    reason = block.get("reason", "BLOCKED")
    secs = block.get("seconds", "?")
    return (
        f"\n{RED}{BOLD}"
        f"  BLOCKED [{reason}] {pkg} looks like {looks} \u00b7 {secs} s"
        f"{RESET}\n"
    )


def format_audit(audit: dict[str, Any] | None) -> str:
    """Format audit chain verification."""
    if not audit:
        return ""
    ok = audit.get("chain_ok", False)
    h = audit.get("head_hash_short", "")
    status = f"{GREEN}verified{RESET}" if ok else f"{RED}FAILED{RESET}"
    return f"  audit chain {status} \u00b7 {h}"


# ---------------------------------------------------------------------------
# Process info (Windows)

def _get_process_info(pid: int) -> dict[str, Any]:
    """Get process info from Windows WMI.  Returns {} on failure."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\" | "
             "Select-Object Name,CommandLine,ParentProcessId | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(r.stdout)
        if isinstance(data, list):
            data = data[0] if data else {}
        # Truncate CommandLine (contains the prompt, never env)
        cl = str(data.get("CommandLine") or "")
        if len(cl) > 200:
            cl = cl[:200] + "..."
        # Redact any secrets that might leak through CommandLine
        cl = redact(cl) if isinstance(redact(cl), str) else cl
        ppid = data.get("ParentProcessId")
        parent_name = ""
        if ppid:
            try:
                r2 = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-CimInstance Win32_Process -Filter \"ProcessId={ppid}\").Name"],
                    capture_output=True, text=True, timeout=5,
                )
                parent_name = r2.stdout.strip()
            except Exception:
                pass
        return {
            "name": data.get("Name", ""),
            "command_line": cl,
            "ppid": ppid,
            "parent_name": parent_name,
        }
    except Exception:
        return {}


def _is_process_running(pid: int) -> bool:
    """Check if a PID is still running."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Select-Object Id"],
            capture_output=True, text=True, timeout=5,
        )
        return str(pid) in r.stdout
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main watcher

def _find_latest_run(base: Path) -> Path | None:
    """Find the most recently modified run dir under base/hook-live/."""
    hl = base / "hook-live"
    if not hl.is_dir():
        return None
    dirs = sorted(hl.iterdir(), key=lambda d: d.stat().st_mtime if d.is_dir() else 0,
                  reverse=True)
    return dirs[0] if dirs else None


def _wait_for_run(base: Path, seen: set[str]) -> Path:
    """Block until a new run dir appears."""
    while True:
        hl = base / "hook-live"
        if hl.is_dir():
            for d in sorted(hl.iterdir(),
                            key=lambda d: d.stat().st_mtime if d.is_dir() else 0,
                            reverse=True):
                if d.is_dir() and d.name not in seen:
                    return d
        time.sleep(0.5)


def watch(base: Path) -> None:
    """Main watch loop: follows new runs automatically."""
    print(f"{BOLD}Antigravity CLI watcher{RESET}")
    print(f"Watching: {base / 'hook-live'}")
    print(f"Waiting for a run...\n")

    seen: set[str] = set()
    # Mark existing runs as seen (only follow NEW runs)
    hl = base / "hook-live"
    if hl.is_dir():
        for d in hl.iterdir():
            if d.is_dir():
                seen.add(d.name)

    while True:
        run_dir = _wait_for_run(base, seen)
        seen.add(run_dir.name)
        _watch_one_run(run_dir)
        print(f"\n{DIM}--- waiting for next run ---{RESET}\n")


def _watch_one_run(run_dir: Path) -> None:
    """Watch a single run from start to finish."""
    run_id = run_dir.name
    print(f"\n{BOLD}=== Run {run_id} ==={RESET}")

    # Wait for proc.json (the subprocess may not have started yet)
    proc_path = run_dir / "proc.json"
    deadline = time.time() + 30
    while not proc_path.is_file() and time.time() < deadline:
        time.sleep(0.3)
    if not proc_path.is_file():
        print(f"  {RED}proc.json not found after 30 s{RESET}")
        return

    proc_data = json.loads(proc_path.read_text(encoding="utf-8"))
    pid = proc_data.get("pid", 0)
    print(f"  {BOLD}Antigravity CLI{RESET} \u00b7 PID {CYAN}{pid}{RESET}"
          f" \u00b7 started {proc_data.get('started_at', '?')}")
    print(f"  Prompt: {DIM}{proc_data.get('prompt', '?')[:120]}{RESET}")
    print(f"  Workspace: {DIM}{proc_data.get('cwd', '?')}{RESET}")

    # Windows process info
    pinfo = _get_process_info(pid)
    if pinfo:
        print(f"  Process: {pinfo.get('name', '?')}"
              f"  Parent: {pinfo.get('parent_name', '?')} (PID {pinfo.get('ppid', '?')})")
        print(f"  Cmd: {DIM}{pinfo.get('command_line', '?')}{RESET}")
    print()

    # Stream agy_stdout.jsonl and hook log
    stdout_path = run_dir / "agy_stdout.jsonl"
    done_path = run_dir / "done.json"
    stdout_pos = 0
    in_think = False
    hook_log_lines = 0

    # Find the hook log in the workspace
    ws = Path(proc_data.get("cwd", ""))
    hook_log_path = None
    if ws.is_dir():
        # Look for the hook log path in .agents/hooks.json
        hooks_file = ws / ".agents" / "hooks.json"
        if hooks_file.is_file():
            import re
            text = hooks_file.read_text(encoding="utf-8")
            m = re.search(r"--log\s+(\S+)", text)
            if m:
                hook_log_path = Path(m.group(1).strip('"').strip("'"))

    while True:
        # Check process status
        running = _is_process_running(pid) if pid else False

        # Read new stdout lines
        if stdout_path.is_file():
            try:
                with open(stdout_path, "rb") as f:
                    f.seek(stdout_pos)
                    chunk = f.read()
                # Only consume complete lines: a half-written last line is
                # read again on the next poll instead of being lost.
                cut = chunk.rfind(b"\n") + 1
                stdout_pos += cut
                for raw in chunk[:cut].decode("utf-8", errors="replace").splitlines():
                    line = raw.strip()
                    if not line:
                        continue
                    from arena.duel import parse_agy_line
                    ev = parse_agy_line(line, "protected", 0, 0)
                    if not ev:
                        continue
                    if ev.get("kind") == "think":
                        # Text arrives in small fragments: print them as one
                        # flowing paragraph, not one fragment per line.
                        if not in_think:
                            print("  ", end="")
                            in_think = True
                        print(f"{DIM}{ev.get('text', '')}{RESET}", end="", flush=True)
                        continue
                    if in_think:
                        print()
                        in_think = False
                    print(format_agy_event(ev))
            except Exception:
                pass

        # Read new hook log entries
        if hook_log_path and hook_log_path.is_file():
            try:
                entries = read_log(hook_log_path)
                new_entries = entries[hook_log_lines:]
                hook_log_lines = len(entries)
                for entry in new_entries:
                    if in_think:
                        print()
                        in_think = False
                    print(format_hook_entry(entry))
            except Exception:
                pass

        # Check for done.json
        if done_path.is_file():
            try:
                done_data = json.loads(done_path.read_text(encoding="utf-8"))
                if in_think:
                    print()
                    in_think = False
                block = done_data.get("block")
                if block:
                    print(format_block_banner(block))
                audit = done_data.get("audit")
                if audit:
                    print(format_audit(audit))
                status = done_data.get("status", "?")
                secs = done_data.get("seconds", "?")
                error = done_data.get("error")
                if error:
                    print(f"  {RED}Error: {error}{RESET}")
                print(f"\n  {BOLD}Status: {status}{RESET} ({secs} s)")
                if not running:
                    print(f"  Process: {DIM}exited{RESET}")
            except Exception:
                pass
            break

        if not running and not done_path.is_file():
            # Process exited but no done.json yet, wait a bit
            time.sleep(1.0)
            if done_path.is_file():
                continue
            print(f"  {YELLOW}Process exited without done.json{RESET}")
            break

        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Entry point

def main() -> None:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        os.environ.get("ARENA_RUNS", str(Path(tempfile.gettempdir()) / "haltwire-runs")))
    watch(base)


if __name__ == "__main__":
    main()
