"""Privileged runner daemon -- executes agent commands as uid 10001.

Listens on a Unix domain socket (ARENA_RUNNER_SOCK, default /sock/exec.sock).
Protocol: one JSON line in -> one JSON line out per connection.

Request:  {"cwd": "...", "cmd": "...", "proxy": "..."}
Response: {"out": "...", "rc": <int>, "timed_out": <bool>}

Runs only on Linux inside the runner container (root with CAP_SETUID/SETGID).
On non-Linux the module still imports; OS-specific calls are guarded.
"""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
from pathlib import PurePosixPath

# ---------------------------------------------------------------------------
# Configuration (all overridable via environment for testing)
# ---------------------------------------------------------------------------

SOCK_PATH = os.environ.get("ARENA_RUNNER_SOCK", "/sock/exec.sock")
RUNS_ROOT = os.environ.get("ARENA_RUNS", "/runs")
PROXY_PATTERN = re.compile(
    os.environ.get("ARENA_PROXY_RE", r"^http://172\.31\.0\.10:\d+$")
)
CWD_PATTERN_TEMPLATE = r"^{root}/sessions/[A-Za-z0-9_-]+/ws(/.*)?$"
MAX_CMD = 4096
MAX_OUTPUT = 8192
TIMEOUT_S = 20
MAX_CONCURRENT = 4
EXEC_UID = 10001
EXEC_GID = 10001

_IS_LINUX = sys.platform.startswith("linux")
_sem = threading.Semaphore(MAX_CONCURRENT)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _cwd_re(runs_root: str) -> re.Pattern[str]:
    return re.compile(CWD_PATTERN_TEMPLATE.format(root=re.escape(runs_root)))


def validate_request(data: dict, runs_root: str | None = None) -> str | None:
    """Return an error string, or None if valid."""
    root = runs_root or RUNS_ROOT
    cwd = data.get("cwd", "")
    cmd = data.get("cmd", "")
    proxy = data.get("proxy", "")

    if not isinstance(cwd, str) or not isinstance(cmd, str) or not isinstance(proxy, str):
        return "invalid types"
    if not cmd or len(cmd) > MAX_CMD:
        return "cmd empty or too long"

    # Resolve path and check against pattern (use PurePosixPath on all OS)
    # On Linux we can os.path.realpath; on Windows for tests we use the raw value
    if _IS_LINUX:
        resolved = os.path.realpath(cwd)
    else:
        # For test validation on Windows, normalise forward slashes
        resolved = cwd.replace("\\", "/")

    if not _cwd_re(root).match(resolved):
        return "cwd rejected"

    if proxy and not PROXY_PATTERN.match(proxy):
        return "proxy rejected"

    return None


# ---------------------------------------------------------------------------
# Executor (Linux-only real path; injectable for tests)
# ---------------------------------------------------------------------------

def _default_executor(cwd: str, cmd: str, proxy: str) -> dict:
    """Run cmd under prlimit as uid 10001. Linux only."""
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": cwd,
        "LANG": "C.UTF-8",
    }
    if proxy:
        env.update({
            "HTTP_PROXY": proxy, "http_proxy": proxy,
            "HTTPS_PROXY": proxy, "https_proxy": proxy,
            "NO_PROXY": "",
        })

    full_cmd = [
        "prlimit",
        "--as=1073741824", "--nproc=64", "--cpu=20",
        "--fsize=67108864", "--nofile=256",
        "--", "bash", "-c", cmd,
    ]

    timed_out = False
    try:
        proc = subprocess.Popen(
            full_cmd, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            user=EXEC_UID, group=EXEC_GID, extra_groups=[],
            umask=0o007, start_new_session=True,
            env=env,
        )
        try:
            out_bytes, _ = proc.communicate(timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired:
            timed_out = True
            out_bytes = b""
        finally:
            # Always kill the process group
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            proc.wait(timeout=5)
    except Exception as exc:
        return {"out": f"exec error: {exc}", "rc": -1, "timed_out": False}

    out = out_bytes[:MAX_OUTPUT].decode("utf-8", errors="replace") if out_bytes else ""
    return {"out": out, "rc": proc.returncode if not timed_out else -1, "timed_out": timed_out}


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def _handle_conn(conn: socket.socket, executor=None) -> None:
    """Handle one client connection. One JSON line in, one JSON line out."""
    if executor is None:
        executor = _default_executor
    try:
        conn.settimeout(30)
        buf = b""
        while b"\n" not in buf and len(buf) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk

        data = json.loads(buf.decode("utf-8"))
        err = validate_request(data)
        if err:
            resp = {"out": f"rejected: {err}", "rc": -1, "timed_out": False}
        else:
            resp = executor(data["cwd"], data["cmd"], data.get("proxy", ""))

        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
    except Exception:
        try:
            conn.sendall(json.dumps(
                {"out": "internal error", "rc": -1, "timed_out": False}
            ).encode("utf-8") + b"\n")
        except Exception:
            pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Server loop
# ---------------------------------------------------------------------------

def serve(sock_path: str | None = None, executor=None) -> None:
    """Blocking server loop. Normally called as __main__."""
    path = sock_path or SOCK_PATH
    # Remove stale socket
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    if _IS_LINUX:
        # Only the server's group may connect; the agent uid (10001) may not
        # even enter the socket directory.
        server_gid = int(os.environ.get("ARENA_SERVER_GID", "999"))
        sock_dir = os.path.dirname(path) or "."
        os.chown(sock_dir, 0, server_gid)
        os.chmod(sock_dir, 0o750)
        os.chown(path, 0, server_gid)
        os.chmod(path, 0o660)
    srv.listen(8)
    print(f"[runner] listening on {path}", flush=True)

    while True:
        conn, _ = srv.accept()
        if not _sem.acquire(blocking=False):
            # At capacity -- reject
            try:
                conn.sendall(json.dumps(
                    {"out": "rejected: at capacity", "rc": -1, "timed_out": False}
                ).encode("utf-8") + b"\n")
            except Exception:
                pass
            conn.close()
            continue
        t = threading.Thread(target=_threaded_handle, args=(conn, executor), daemon=True)
        t.start()


def _threaded_handle(conn: socket.socket, executor) -> None:
    try:
        _handle_conn(conn, executor)
    finally:
        _sem.release()


if __name__ == "__main__":
    serve()
