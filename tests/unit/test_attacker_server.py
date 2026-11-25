"""Tests for arena.attacker_server — fake attacker capture server."""
from __future__ import annotations

import urllib.request
import urllib.error

import pytest

from arena import tripwire
from arena.attacker_server import CaptureServer


@pytest.fixture
def server():
    s = CaptureServer(host="127.0.0.1", port=0)
    s.start()
    yield s
    s.stop()


@pytest.fixture
def canaries():
    return tripwire.mint("cap-sess")


# ---------------------------------------------------------------- lifecycle

def test_server_starts_and_has_url(server):
    assert server.url.startswith("http://127.0.0.1:")
    # Confirm it is actually listening by hitting a path (expect 404)
    try:
        urllib.request.urlopen(server.url + "/ping", timeout=2)
    except urllib.error.HTTPError as e:
        assert e.code == 404


def test_server_stop_is_clean(server):
    server.stop()
    # After stop, the port should refuse connections
    with pytest.raises(Exception):
        urllib.request.urlopen(server.url + "/collect", timeout=2)


# ---------------------------------------------------------------- /collect

def test_collect_records_loot(server):
    body = b"STRIPE_KEY=sk_live_abc123"
    req = urllib.request.Request(server.url + "/collect", data=body, method="POST")
    resp = urllib.request.urlopen(req, timeout=5)
    assert resp.status == 200
    loot = server.loot()
    assert len(loot) == 1
    assert loot[0]["method"] == "POST"
    assert "sk_live_" in loot[0]["preview"]
    assert loot[0]["has_secret"] is True


def test_collect_get(server):
    req = urllib.request.Request(server.url + "/collect", method="GET")
    resp = urllib.request.urlopen(req, timeout=5)
    assert resp.status == 200
    assert len(server.loot()) == 1


# ---------------------------------------------------------------- /s/<session>/collect

def test_session_collect(server):
    body = b"data=hello"
    req = urllib.request.Request(server.url + "/s/agent-7/collect", data=body, method="POST")
    urllib.request.urlopen(req, timeout=5)
    loot = server.loot(session="agent-7")
    assert len(loot) == 1
    assert loot[0]["side"] == "agent-7"


def test_query_param_session(server):
    body = b"data=world"
    req = urllib.request.Request(server.url + "/collect?session=q-sess", data=body, method="POST")
    urllib.request.urlopen(req, timeout=5)
    loot = server.loot(session="q-sess")
    assert len(loot) == 1


# ---------------------------------------------------------------- body cap

def test_body_cap_64kb(server):
    big = b"X" * 100_000
    req = urllib.request.Request(server.url + "/collect", data=big, method="POST")
    urllib.request.urlopen(req, timeout=5)
    loot = server.loot()
    assert len(loot) == 1
    assert loot[0]["bytes"] <= 65536 + 100  # allow small overhead for string conversion


# ---------------------------------------------------------------- canary watch

def test_canary_hit_flag(server, canaries):
    server.watch("hit-sess", canaries)
    body = canaries["aws_access_key"].encode()
    req = urllib.request.Request(server.url + "/s/hit-sess/collect", data=body, method="POST")
    urllib.request.urlopen(req, timeout=5)
    loot = server.loot(session="hit-sess")
    assert len(loot) == 1
    assert loot[0].get("canary_hit") is True


def test_no_canary_hit_without_watch(server, canaries):
    body = canaries["aws_access_key"].encode()
    req = urllib.request.Request(server.url + "/collect", data=body, method="POST")
    urllib.request.urlopen(req, timeout=5)
    loot = server.loot()
    assert len(loot) == 1
    assert loot[0].get("canary_hit") is not True


# ---------------------------------------------------------------- 404 for other paths

def test_non_collect_404(server):
    try:
        urllib.request.urlopen(server.url + "/other", timeout=2)
        pytest.fail("Expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404
    assert len(server.loot()) == 0


def test_root_404(server):
    try:
        urllib.request.urlopen(server.url + "/", timeout=2)
        pytest.fail("Expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404


# ---------------------------------------------------------------- reset + per-session loot

def test_reset_clears_loot(server):
    req = urllib.request.Request(server.url + "/collect", data=b"x", method="POST")
    urllib.request.urlopen(req, timeout=5)
    assert len(server.loot()) == 1
    server.reset()
    assert len(server.loot()) == 0


def test_loot_per_session_filter(server):
    for sid in ("a", "b", "a"):
        req = urllib.request.Request(server.url + f"/s/{sid}/collect", data=b"y", method="POST")
        urllib.request.urlopen(req, timeout=5)
    assert len(server.loot()) == 3
    assert len(server.loot(session="a")) == 2
    assert len(server.loot(session="b")) == 1


# ---------------------------------------------------------------- target from X-Original headers

def test_target_from_x_original_headers(server):
    """Capture server records target from X-Original-Host and X-Original-Path."""
    body = b"data=exfil"
    req = urllib.request.Request(server.url + "/s/t-sess/collect", data=body, method="POST")
    req.add_header("X-Original-Host", "collect.evil.example")
    req.add_header("X-Original-Path", "/collect")
    urllib.request.urlopen(req, timeout=5)
    loot = server.loot(session="t-sess")
    assert len(loot) == 1
    assert loot[0].get("target") == "collect.evil.example/collect"


def test_target_absent_when_no_headers(server):
    """Without X-Original headers, target is empty or absent."""
    req = urllib.request.Request(server.url + "/collect", data=b"x", method="POST")
    urllib.request.urlopen(req, timeout=5)
    loot = server.loot()
    assert len(loot) == 1
    assert loot[0].get("target", "") == ""
