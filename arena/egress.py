"""Minimal forward HTTP proxy for the demo agent's outbound traffic.

Limitations (documented honestly):
- Plain HTTP only: requests are read in full (capped at 1 MB), the URL, headers,
  and body are scanned for canary values (plain, base64, hex, reversed), and
  field values are reassembled across requests to catch chunked exfil
  (see arena.exfil_scan).
- Guard ON + canary hit -> 403 Forbidden, on_trip callback fired.
- Guard ON + clean -> forwarded ONLY to the allow-list (the capture server
  host:port); all other destinations get 403 "egress blocked".
- Guard OFF -> ANY plain-HTTP request (any host, any path, any method) is
  re-routed to the capture server at /s/<session>/collect, preserving the
  original method and body, with X-Original-Host and X-Original-Path headers.
  DNS for the original host is never resolved; nothing ever leaves the box.
- HTTPS CONNECT is always refused with 403 (we cannot inspect encrypted traffic
  in this demo).  This is a limitation, not a feature gap: a production system
  would use TLS interception with a workspace-scoped CA.
"""
from __future__ import annotations

import base64
import io
import os
import re
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Any, Callable
from urllib.parse import urlparse
import urllib.request

from arena.exfil_scan import ExfilScanner, canary_values, scan_text

_DEFAULT_BIND = "127.0.0.1"

# 1 MB body cap for proxy reads
_BODY_CAP = 1_048_576


def _mask_preview(text: str, canaries: dict[str, Any], max_len: int = 300) -> str:
    """Return first *max_len* chars of *text* with canary values masked.

    Each canary value is replaced with a short prefix + ``...[CANARY:<name>]``.
    """
    preview = text[:max_len]
    for name, val in _canary_values(canaries):
        if val in preview:
            prefix = val[:min(10, len(val))]
            preview = preview.replace(val, f"{prefix}...[CANARY:{name}]")
    return preview


# Shared scanner (also used by the attacker capture server)
_canary_values = canary_values
_scan_for_canary = scan_text


class _ThreadingProxy(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ProxyHandler(BaseHTTPRequestHandler):
    """HTTP forward proxy handler."""

    def log_message(self, format, *args):
        pass

    def do_CONNECT(self):
        """HTTPS CONNECT: always refuse (cannot inspect encrypted traffic)."""
        self.send_error(403, "CONNECT refused: HTTPS tunneling not supported in demo proxy")

    def _handle_request(self):
        """Forward plain HTTP requests with canary scanning."""
        server = self.server

        # M6: refuse unscannable requests (Transfer-Encoding, Content-Encoding,
        # or Content-Length > 1MB) with 403
        if self.headers.get("Transfer-Encoding"):
            server_cb = server._on_request
            if server_cb:
                try:
                    server_cb({"method": self.command, "host": "", "path": "",
                               "bytes": 0, "decision": "blocked_unscannable",
                               "canary": None, "preview": "",
                               "reason": "Transfer-Encoding present"})
                except Exception:
                    pass
            self.send_error(403, "Blocked: Transfer-Encoding not supported")
            return
        if self.headers.get("Content-Encoding"):
            server_cb = server._on_request
            if server_cb:
                try:
                    server_cb({"method": self.command, "host": "", "path": "",
                               "bytes": 0, "decision": "blocked_unscannable",
                               "canary": None, "preview": "",
                               "reason": "Content-Encoding present"})
                except Exception:
                    pass
            self.send_error(403, "Blocked: Content-Encoding not supported")
            return

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > _BODY_CAP:
            server_cb = server._on_request
            if server_cb:
                try:
                    server_cb({"method": self.command, "host": "", "path": "",
                               "bytes": content_length, "decision": "blocked_unscannable",
                               "canary": None, "preview": "",
                               "reason": f"Content-Length {content_length} > 1MB"})
                except Exception:
                    pass
            self.send_error(403, "Blocked: request body too large")
            return
        body = b""
        if content_length > 0:
            body = self.rfile.read(min(content_length, _BODY_CAP))

        # M6: strip client-sent X-Original-* headers before scanning
        # (they are added by the proxy itself in the reroute path)
        # Scan ALL headers including client-sent ones

        body_text = body.decode("utf-8", errors="replace") if body else ""

        # Parse target
        parsed = urlparse(self.path)
        target_host = parsed.hostname or ""
        target_port = parsed.port or 80
        target_path = parsed.path or "/"

        if server._guard:
            # --- Guard ON ---
            # Canary scan first
            hit = server._scanner.scan(self.path, self.headers.items(), body)
            self._last_hit = hit
            if hit:
                decision = "blocked_canary"
                canary_info = {"name": hit.get("canary_name", ""), "encoding": hit.get("encoding", "")}
                if hit.get("parts"):
                    canary_info["parts"] = hit["parts"]
                self._emit_egress_event(server, target_host, target_path,
                                        body_text, decision, canary_info)
                if server._on_trip:
                    try:
                        server._on_trip(hit)
                    except Exception:
                        pass
                self.send_error(403, "Canary detected in outbound request")
                return

            # M5: guard ON forwards NOTHING. Every non-canary request is blocked.
            decision = "blocked_not_allowed"
            self._emit_egress_event(server, target_host, target_path,
                                    body_text, decision, None)
            self.send_error(403, "Egress blocked: guard ON blocks all outbound")
        else:
            # --- Guard OFF ---
            # Re-route ANY request to the capture server at /s/<session>/collect.
            # DNS for the original host is never resolved; nothing leaves the box.
            self._emit_egress_event(server, target_host, target_path,
                                    body_text, "forwarded_to_attacker", None)
            self._reroute_to_capture(server, target_host, target_path, body,
                                     parsed.query)

    def _emit_egress_event(self, server, host: str, path: str,
                           body_text: str, decision: str,
                           canary_info: dict | None) -> None:
        """Call the on_request callback with egress event data."""
        cb = server._on_request
        if cb is None:
            return
        preview = _mask_preview(body_text, server._canaries) if body_text else ""
        ev = {
            "method": self.command,
            "host": host,
            "path": path,
            "bytes": len(body_text.encode("utf-8")) if body_text else 0,
            "decision": decision,
            "canary": canary_info,
            "preview": preview,
        }
        try:
            # Real carrier: custom headers and query count too (header-channel
            # exfil sends a 4-byte body)
            from arena.exfil_scan import describe_request
            ev.update(describe_request(self.path, self.headers.items(),
                                       body_text.encode("utf-8") if body_text else b"",
                                       server._canaries, getattr(self, "_last_hit", None)))
        except Exception:  # noqa: BLE001 - extra fields are best-effort
            pass
        try:
            cb(ev)
        except Exception:
            pass

    def _forward_direct(self, body: bytes):
        """Forward the request directly to its original destination."""
        try:
            req = urllib.request.Request(
                self.path,
                data=body if body else None,
                headers={k: v for k, v in self.headers.items()
                         if k.lower() not in ("host", "proxy-connection", "proxy-authorization")},
                method=self.command,
            )
            resp = urllib.request.urlopen(req, timeout=30)
            resp_body = resp.read()

            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            self.send_error(e.code, str(e.reason))
        except Exception as e:
            self.send_error(502, f"Proxy error: {e}")

    def _reroute_to_capture(self, server, orig_host: str, orig_path: str, body: bytes,
                            query: str = ""):
        """Re-route the request to the capture server, preserving method/body."""
        session = server._session
        capture_url = server._capture_url
        reroute_url = f"{capture_url}/s/{session}/collect"
        if query:
            # Keep the query string: query-channel exfil must reach the attacker too
            reroute_url += "?" + query

        # M6: strip any client-sent X-Original-* headers before adding our own
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "proxy-connection", "proxy-authorization",
                                         "x-original-host", "x-original-path")}
        headers["X-Original-Host"] = orig_host
        headers["X-Original-Path"] = orig_path
        # M5: add per-proxy secret for the capture server
        if hasattr(server, '_proxy_secret') and server._proxy_secret:
            headers["X-Proxy-Secret"] = server._proxy_secret

        try:
            req = urllib.request.Request(
                reroute_url,
                data=body if body else None,
                headers=headers,
                method=self.command,
            )
            resp = urllib.request.urlopen(req, timeout=30)
            resp_body = resp.read()

            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            self.send_error(e.code, str(e.reason))
        except Exception as e:
            self.send_error(502, f"Proxy error: {e}")

    do_GET = _handle_request
    do_POST = _handle_request
    do_PUT = _handle_request
    do_DELETE = _handle_request
    do_PATCH = _handle_request
    do_HEAD = _handle_request
    do_OPTIONS = _handle_request


class EgressProxy:
    """Minimal forward HTTP proxy with canary scanning.

    Args:
        capture_url: URL of the capture server (the only allowed destination).
        canaries: Canary dict from tripwire.mint().
        guard: If True, scan for canaries and enforce allow-list.
        on_trip: Callback fired when a canary is detected (guard ON only).

    Usage::

        proxy = EgressProxy(capture.url, canaries, guard=True,
                            on_trip=lambda t: print("TRIP!", t))
        proxy.start()
        # Set HTTP_PROXY=proxy.url in agent env
        proxy.stop()
    """

    def __init__(self, capture_url: str, canaries: dict[str, Any],
                 guard: bool, on_trip: Callable[[dict[str, Any]], None] | None = None,
                 session: str = "",
                 on_request: Callable[[dict[str, Any]], None] | None = None):
        self._capture_url = capture_url
        self._canaries = canaries
        self._guard = guard
        self._on_trip = on_trip
        self._on_request = on_request
        self._session = session or "default"
        # M5: per-proxy secret for the capture server
        import secrets as _secrets
        self._proxy_secret = _secrets.token_urlsafe(24)

        parsed = urlparse(capture_url)
        self._allowed_host = parsed.hostname or "127.0.0.1"
        self._allowed_port = parsed.port or 80

        self._server: _ThreadingProxy | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        bind_addr = os.environ.get("ARENA_PROXY_BIND", _DEFAULT_BIND)
        self._server = _ThreadingProxy((bind_addr, 0), _ProxyHandler)
        # Attach config to the server so the handler can access it
        self._server._canaries = self._canaries
        self._server._guard = self._guard
        self._server._on_trip = self._on_trip
        self._server._allowed_host = self._allowed_host
        self._server._allowed_port = self._allowed_port
        self._server._session = self._session
        self._server._capture_url = self._capture_url
        self._server._on_request = self._on_request
        self._server._scanner = ExfilScanner(self._canaries)
        self._server._proxy_secret = self._proxy_secret

        self._bind_addr = self._server.server_address[0]
        self._port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self._bind_addr}:{self._port}"
