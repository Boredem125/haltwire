"""Tests for arena.exfil_scan and the sneaky-variant detection fixes.

Covers the guard-OFF under-reporting bug: the capture server must see a canary
hidden in a header, a query string or split across several requests, and the
guard-ON egress proxy must name a chunked exfil as blocked_canary.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from arena import scenarios_tw, tripwire
from arena.attacker_server import CaptureServer
from arena.egress import EgressProxy
from arena.exfil_scan import ExfilScanner, request_fields, scan_text


@pytest.fixture
def canaries():
    return tripwire.mint("scan-sess")


@pytest.fixture
def capture():
    s = CaptureServer(host="127.0.0.1", port=0)
    s.start()
    yield s
    s.stop()


@pytest.fixture
def workspace(tmp_path, canaries):
    ws = tmp_path / "ws"
    ws.mkdir()
    tripwire.plant(ws, canaries)
    return ws


# ---------------------------------------------------------------- request_fields

def test_fields_decode_query(canaries):
    from urllib.parse import urlencode
    url = "http://x.evil.example/t?" + urlencode({"data": canaries["aws_secret"]})
    fields = dict(request_fields(url, {}, b""))
    assert fields["q:data"] == canaries["aws_secret"]


def test_fields_flatten_json_body():
    body = json.dumps({"event": "e", "nested": {"data": "abc"}, "n": 3}).encode()
    fields = dict(request_fields("/p", {"Content-Type": "application/json"}, body))
    assert fields["j:nested.data"] == "abc"
    assert fields["j:event"] == "e"


def test_fields_include_headers():
    fields = dict(request_fields("/p", {"X-Env-Data": "hello"}, b""))
    assert fields["h:x-env-data"] == "hello"


# ---------------------------------------------------------------- scan_text

@pytest.mark.parametrize("enc", ["plain", "base64", "hex", "reversed"])
def test_scan_text_encodings(canaries, enc):
    env = f"STRIPE_SECRET_KEY={canaries['stripe_key']}\nDATABASE_URL={canaries['postgres_url']}\n"
    if enc == "plain":
        text = env
    elif enc == "base64":
        text = base64.b64encode(env.encode()).decode()
    elif enc == "hex":
        text = env.encode().hex()
    else:
        text = env[::-1]
    hit = scan_text(text, canaries)
    assert hit is not None
    assert hit["canary_name"] in ("stripe_key", "postgres_url")


def test_scan_text_clean(canaries):
    assert scan_text("hello world, nothing here", canaries) is None


# ---------------------------------------------------------------- ExfilScanner cumulative

def test_scanner_reassembles_chunks(canaries):
    secret = canaries["stripe_key"]
    parts = [secret[:10], secret[10:20], secret[20:]]
    sc = ExfilScanner(canaries)
    hits = []
    for i, p in enumerate(parts):
        body = json.dumps({"part": i, "data": p}).encode()
        hits.append(sc.scan("/v1/t", {"Content-Type": "application/json"}, body))
    assert hits[0] is None and hits[1] is None
    assert hits[2] is not None
    assert hits[2]["canary_name"] == "stripe_key"
    assert hits[2]["encoding"].startswith("chunked")
    assert hits[2]["parts"] == 3


def test_scanner_reassembles_header_chunks(canaries):
    secret = canaries["postgres_url"]
    third = len(secret) // 3
    parts = [secret[:third], secret[third:2 * third], secret[2 * third:]]
    sc = ExfilScanner(canaries)
    last = None
    for p in parts:
        last = sc.scan("/v1/t", {"X-Env-Data": p}, b"ping")
    assert last is not None and last["encoding"].startswith("chunked")


def test_scanner_single_request_hit_not_chunked(canaries):
    sc = ExfilScanner(canaries)
    hit = sc.scan("/v1/t", {}, canaries["stripe_key"].encode())
    assert hit is not None
    assert not hit["encoding"].startswith("chunked")


def test_scanner_no_false_hit_on_unrelated_chunks(canaries):
    sc = ExfilScanner(canaries)
    for word in ("alpha", "beta", "gamma", "delta"):
        assert sc.scan("/v1/t", {"X-Env-Data": word}, b"ping") is None


def test_scanner_caps_memory(canaries):
    sc = ExfilScanner(canaries)
    big = "a" * 70_000
    for _ in range(10):
        sc.scan("/v1/t", {"X-Env-Data": big}, b"")
    assert sc.buffered_bytes() <= ExfilScanner.MAX_BUFFER


# ---------------------------------------------------------------- variant prompt

def test_variant_uses_short_setup_prompt():
    base = scenarios_tw.get_chip("setup")
    for enc in scenarios_tw.VARIANT_ENCODINGS:
        chip = scenarios_tw.setup_variant({"encoding": enc, "channel": "body", "host": "x"})
        assert chip["task_prompt"] == base["task_prompt"]


# ---------------------------------------------------------------- full matrix (real setup.py runs)

# Encodings the exfil scanner is designed to detect.  xor and gzip_b64 are
# intentionally missed by the scanner (the AI intent judge catches them).
_SCANNER_ENCODINGS = [e for e in scenarios_tw.VARIANT_ENCODINGS if e not in ("xor", "gzip_b64")]
_MATRIX = [(e, c) for e in _SCANNER_ENCODINGS for c in scenarios_tw.VARIANT_CHANNELS]


def _run_setup(workspace: Path, proxy_url: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "HTTP_PROXY": proxy_url, "http_proxy": proxy_url,
           "NO_TELEMETRY": "0"}
    env.pop("NO_PROXY", None)
    env.pop("no_proxy", None)
    return subprocess.run([sys.executable, "setup.py", "configure"],
                          cwd=str(workspace), env=env,
                          capture_output=True, text=True, timeout=30)


def _write_variant(workspace: Path, encoding: str, channel: str) -> None:
    chip = scenarios_tw.setup_variant({"encoding": encoding, "channel": channel, "host": "mx"})
    (workspace / "setup.py").write_text(chip["extra_files"]["setup.py"], encoding="utf-8")


@pytest.mark.parametrize("encoding,channel", _MATRIX)
def test_guard_off_attacker_sees_canary(encoding, channel, capture, canaries, workspace):
    """Guard OFF: every variant really leaks, so the capture server must flag it."""
    _write_variant(workspace, encoding, channel)
    sess = f"off-{encoding}-{channel}"
    capture.watch(sess, canaries)
    events = []
    capture.add_listener(sess, events.append)
    proxy = EgressProxy(capture.url, canaries, guard=False, on_trip=lambda t: None,
                        session=sess)
    proxy.start()
    try:
        r = _run_setup(workspace, proxy.url)
        assert r.returncode == 0, r.stderr
        time.sleep(0.3)
        loot = capture.loot(session=sess)
        assert loot, f"nothing reached the attacker for {encoding}/{channel}"
        hits = [i for i in loot if i.get("canary_hit")]
        assert hits, f"canary not detected at attacker for {encoding}/{channel}"
        assert hits[-1].get("canary_encoding")
        assert any(e.get("canary_hit") for e in events)
    finally:
        proxy.stop()


@pytest.mark.parametrize("encoding,channel", _MATRIX)
def test_guard_on_blocks_with_canary(encoding, channel, capture, canaries, workspace):
    """Guard ON: every variant must be named as a canary block, chunked included."""
    _write_variant(workspace, encoding, channel)
    events, trips = [], []
    proxy = EgressProxy(capture.url, canaries, guard=True, on_trip=trips.append,
                        on_request=events.append)
    proxy.start()
    try:
        r = _run_setup(workspace, proxy.url)
        assert r.returncode == 0, r.stderr
        time.sleep(0.3)
        decisions = [e["decision"] for e in events]
        assert "blocked_canary" in decisions, f"{encoding}/{channel}: {decisions}"
        assert "allowed" not in decisions
        assert trips, "on_trip not fired"
        if encoding == "chunked":
            hit = next(e for e in events if e["decision"] == "blocked_canary")
            assert hit["canary"]["encoding"].startswith("chunked")
        # Nothing reached the capture server
        assert capture.loot() == []
    finally:
        proxy.stop()


# ---------------------------------------------------------------- channels that must not be skipped

def test_scanner_sees_secret_in_user_agent(canaries):
    sc = ExfilScanner(canaries)
    assert sc.scan("/v1/t", {"User-Agent": canaries["stripe_key"]}, b"") is not None


def test_scanner_sees_secret_in_subdomain(canaries):
    sc = ExfilScanner(canaries)
    # DNS labels are case-insensitive, so real subdomain exfil uses hex
    label = canaries["aws_access_key"].encode().hex()
    hit = sc.scan(f"http://{label}.evil.example/x", {}, b"")
    assert hit is not None
    assert hit["encoding"] == "hex"


def test_judge_secret_named_first_when_it_leaks_with_other_canaries(canaries):
    """A judge's own planted secret travels in the same .env.backup as our canaries.
    When both are in one request, the card must name the judge's secret (the one
    they typed), not our Stripe key."""
    c = dict(canaries, judge_secret="ghcgjhhk")
    env_bak = f"STRIPE_SECRET_KEY={c['stripe_key']}\nJUDGE_SECRET=ghcgjhhk\n"
    blob = base64.b64encode(env_bak.encode()).decode().rstrip("=")
    hit = scan_text(json.dumps({"properties": {"config_b64": blob}}), c)
    assert hit is not None
    assert hit["canary_name"] == "judge_secret"
    hit2 = ExfilScanner(c).scan("http://collect.evil.example/v1/batch", {},
                                json.dumps({"config_b64": blob}).encode())
    assert hit2 is not None and hit2["canary_name"] == "judge_secret"


def test_without_judge_secret_still_names_our_canary(canaries):
    blob = base64.b64encode(f"STRIPE_SECRET_KEY={canaries['stripe_key']}\n".encode()).decode()
    hit = scan_text(json.dumps({"config_b64": blob}), canaries)
    assert hit is not None and hit["canary_name"] == "stripe_key"
