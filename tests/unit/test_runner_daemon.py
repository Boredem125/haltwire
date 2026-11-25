"""Tests for arena.runner_daemon -- validation, protocol, concurrency.

All tests run on Windows and Linux: the real setuid executor is never called;
an injectable executor is used instead.  Protocol tests use TCP socketpair
(portable); concurrency tests use a TCP listener on localhost.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from arena.runner_daemon import (
    validate_request,
    _handle_conn,
    MAX_CMD,
    MAX_CONCURRENT,
    MAX_OUTPUT,
    _sem,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_RUNS = "/runs"
if os.name == "nt":
    FAKE_RUNS = "C:/runs"


def _valid_cwd(runs: str = FAKE_RUNS) -> str:
    return f"{runs}/sessions/abc123/ws"


def _valid_cwd_subdir(runs: str = FAKE_RUNS) -> str:
    return f"{runs}/sessions/abc123/ws/subdir"


def _make_request(cwd: str | None = None, cmd: str = "echo ok",
                  proxy: str = "") -> dict:
    return {"cwd": cwd or _valid_cwd(), "cmd": cmd, "proxy": proxy}


def _ok_executor(cwd: str, cmd: str, proxy: str) -> dict:
    return {"out": "hello\n", "rc": 0, "timed_out": False}


def _timeout_executor(cwd: str, cmd: str, proxy: str) -> dict:
    return {"out": "", "rc": -1, "timed_out": True}


def _slow_executor(cwd: str, cmd: str, proxy: str) -> dict:
    time.sleep(0.3)
    return {"out": "done\n", "rc": 0, "timed_out": False}


def _tcp_socketpair():
    """Create a connected pair of TCP sockets (portable, no AF_UNIX needed)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    server, _ = listener.accept()
    listener.close()
    return client, server


# ---------------------------------------------------------------------------
# Path validation tests
# ---------------------------------------------------------------------------

class TestCwdValidation:

    def test_valid_session_ws(self):
        assert validate_request(_make_request(), FAKE_RUNS) is None

    def test_valid_session_ws_subdir(self):
        req = _make_request(cwd=_valid_cwd_subdir())
        assert validate_request(req, FAKE_RUNS) is None

    def test_reject_bare_runs(self):
        req = _make_request(cwd=FAKE_RUNS)
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_sessions_no_ws(self):
        req = _make_request(cwd=f"{FAKE_RUNS}/sessions/abc123")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_other_dir(self):
        req = _make_request(cwd="/etc/passwd")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_dot_dot_escape(self):
        req = _make_request(cwd=f"{FAKE_RUNS}/sessions/abc/../../../etc/ws")
        err = validate_request(req, FAKE_RUNS)
        assert err is not None

    def test_reject_symlink_ish(self):
        req = _make_request(cwd=f"{FAKE_RUNS}/sessions/../../root/ws")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_empty_session_id(self):
        req = _make_request(cwd=f"{FAKE_RUNS}/sessions//ws")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_special_chars_in_session(self):
        req = _make_request(cwd=f"{FAKE_RUNS}/sessions/abc;rm -rf/ws")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_space_in_session(self):
        req = _make_request(cwd=f"{FAKE_RUNS}/sessions/abc def/ws")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_valid_hyphen_underscore(self):
        req = _make_request(cwd=f"{FAKE_RUNS}/sessions/abc-def_123/ws")
        assert validate_request(req, FAKE_RUNS) is None

    def test_custom_runs_root(self):
        custom = "/custom/runs"
        req = _make_request(cwd=f"{custom}/sessions/abc/ws")
        assert validate_request(req, custom) is None


# ---------------------------------------------------------------------------
# Proxy validation tests
# ---------------------------------------------------------------------------

class TestProxyValidation:

    def test_valid_proxy(self):
        req = _make_request(proxy="http://172.31.0.10:9090")
        assert validate_request(req, FAKE_RUNS) is None

    def test_empty_proxy_ok(self):
        req = _make_request(proxy="")
        assert validate_request(req, FAKE_RUNS) is None

    def test_reject_external_proxy(self):
        req = _make_request(proxy="http://evil.com:9090")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_https_proxy(self):
        req = _make_request(proxy="https://172.31.0.10:9090")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_wrong_ip(self):
        req = _make_request(proxy="http://10.0.0.1:9090")
        assert validate_request(req, FAKE_RUNS) is not None

    def test_reject_no_port(self):
        req = _make_request(proxy="http://172.31.0.10")
        assert validate_request(req, FAKE_RUNS) is not None


# ---------------------------------------------------------------------------
# Size cap tests
# ---------------------------------------------------------------------------

class TestSizeCaps:

    def test_cmd_too_long(self):
        req = _make_request(cmd="x" * (MAX_CMD + 1))
        assert validate_request(req, FAKE_RUNS) is not None

    def test_cmd_at_limit(self):
        req = _make_request(cmd="x" * MAX_CMD)
        assert validate_request(req, FAKE_RUNS) is None

    def test_empty_cmd(self):
        req = _make_request(cmd="")
        assert validate_request(req, FAKE_RUNS) is not None


# ---------------------------------------------------------------------------
# Protocol tests (using TCP socketpair for portability)
# ---------------------------------------------------------------------------

class TestProtocol:

    def _roundtrip(self, request: dict, executor=_ok_executor) -> dict:
        client, server = _tcp_socketpair()
        try:
            with patch("arena.runner_daemon.RUNS_ROOT", FAKE_RUNS):
                t = threading.Thread(target=_handle_conn, args=(server, executor))
                t.start()
                client.sendall((json.dumps(request) + "\n").encode("utf-8"))
                client.shutdown(socket.SHUT_WR)
                buf = b""
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                t.join(timeout=5)
                return json.loads(buf.decode("utf-8").strip())
        finally:
            client.close()

    def test_ok_response(self):
        resp = self._roundtrip(_make_request())
        assert resp["rc"] == 0
        assert resp["out"] == "hello\n"
        assert resp["timed_out"] is False

    def test_timeout_response(self):
        resp = self._roundtrip(_make_request(), executor=_timeout_executor)
        assert resp["timed_out"] is True

    def test_bad_cwd_rejected(self):
        resp = self._roundtrip({"cwd": "/etc", "cmd": "id", "proxy": ""})
        assert resp["rc"] == -1
        assert "rejected" in resp["out"]

    def test_bad_json_returns_error(self):
        client, server = _tcp_socketpair()
        try:
            with patch("arena.runner_daemon.RUNS_ROOT", FAKE_RUNS):
                t = threading.Thread(target=_handle_conn, args=(server, _ok_executor))
                t.start()
                client.sendall(b"not json at all\n")
                client.shutdown(socket.SHUT_WR)
                buf = b""
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                t.join(timeout=5)
                resp = json.loads(buf.decode("utf-8").strip())
                assert resp["rc"] == -1
        finally:
            client.close()


# ---------------------------------------------------------------------------
# Concurrency cap test (TCP-based, portable)
# ---------------------------------------------------------------------------

class TestConcurrency:

    def test_reject_over_max(self):
        """When MAX_CONCURRENT connections are active, the next is rejected."""
        from arena.runner_daemon import _threaded_handle

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]

        # Event that blocks executors until we explicitly release them
        hold = threading.Event()
        active_count = threading.Semaphore(0)  # counts how many executors started
        results: list[tuple[int, dict]] = []
        lock = threading.Lock()

        def _blocking_executor(cwd, cmd, proxy):
            active_count.release()  # signal that this slot is occupied
            hold.wait(timeout=10)   # block until released
            return {"out": "ok", "rc": 0, "timed_out": False}

        # Reset the module-level semaphore to a clean state
        while _sem.acquire(blocking=False):
            pass
        for _ in range(MAX_CONCURRENT):
            _sem.release()

        accepted = []

        def _accept_loop():
            with patch("arena.runner_daemon.RUNS_ROOT", FAKE_RUNS):
                for _ in range(MAX_CONCURRENT + 1):
                    try:
                        conn, _ = listener.accept()
                    except OSError:
                        break
                    if not _sem.acquire(blocking=False):
                        try:
                            conn.sendall(json.dumps(
                                {"out": "rejected: at capacity", "rc": -1,
                                 "timed_out": False}
                            ).encode("utf-8") + b"\n")
                        except Exception:
                            pass
                        conn.close()
                        continue
                    t = threading.Thread(
                        target=_threaded_handle,
                        args=(conn, _blocking_executor), daemon=True)
                    t.start()
                    accepted.append(t)

        accept_thread = threading.Thread(target=_accept_loop, daemon=True)
        accept_thread.start()
        time.sleep(0.1)

        def _send_request(idx):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(15)
                s.connect(("127.0.0.1", port))
                req = json.dumps(_make_request()) + "\n"
                s.sendall(req.encode("utf-8"))
                s.shutdown(socket.SHUT_WR)
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                s.close()
                resp = json.loads(buf.decode("utf-8").strip())
                with lock:
                    results.append((idx, resp))
            except Exception as e:
                with lock:
                    results.append((idx, {"error": str(e)}))

        # Send MAX_CONCURRENT requests first and wait for them to occupy slots
        client_threads = []
        for i in range(MAX_CONCURRENT):
            t = threading.Thread(target=_send_request, args=(i,))
            t.start()
            client_threads.append(t)

        # Wait until all MAX_CONCURRENT executors have started
        for _ in range(MAX_CONCURRENT):
            assert active_count.acquire(timeout=5), "executor did not start in time"

        # Now send the extra request -- all slots are occupied
        extra = threading.Thread(target=_send_request, args=(MAX_CONCURRENT,))
        extra.start()
        client_threads.append(extra)
        time.sleep(0.3)  # let the accept loop process the extra connection

        # Release all blocked executors
        hold.set()

        for t in client_threads:
            t.join(timeout=10)
        accept_thread.join(timeout=5)
        listener.close()

        assert len(results) == MAX_CONCURRENT + 1
        # A rejected connection shows as "at capacity" in the JSON response,
        # or as a connection error on Windows (server closes before client reads)
        rejected = [
            r for _, r in results
            if "at capacity" in r.get("out", "") or "error" in r
        ]
        assert len(rejected) >= 1, f"Expected >=1 rejected, got: {results}"


# ---------------------------------------------------------------------------
# Import smoke test
# ---------------------------------------------------------------------------

class TestImport:

    def test_module_imports(self):
        import arena.runner_daemon as m
        assert hasattr(m, "serve")
        assert hasattr(m, "validate_request")
        assert hasattr(m, "_handle_conn")
