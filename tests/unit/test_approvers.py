"""Team approval by QR: anyone can keep the agent frozen; release needs two
different teammates. Each phone joins with a name and gets its own secret."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from arena import approvers, scenarios_tw, server, session as session_mod


@pytest.fixture
def env(tmp_path, monkeypatch):
    mgr = session_mod.SessionManager(runs_dir=tmp_path)
    monkeypatch.setattr(server, "_tw_manager", mgr)
    approvers._reset()
    s = mgr._setup_session(scenarios_tw.get_chip("setup"), guard=True, client_ip="")
    s.handle_trip({"kind": "canary_exfil", "path": "stripe_key", "canary_name": "stripe_key",
                   "evidence": "canary stripe_key exfiltrated (plain)"})
    c = TestClient(server.app)
    r = c.post(f"/api/session/{s.id}/approvers", headers={"X-Session-Token": s.token})
    assert r.status_code == 200, r.text
    return c, s, r.json()


def _join(c, code, name):
    r = c.post(f"/api/approvers/{code}/join", json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()["secret"]


def _vote(c, code, secret, vote):
    return c.post(f"/api/approvers/{code}/vote", json={"vote": vote},
                  headers={"X-Approver-Secret": secret})


def test_create_needs_session_token(env):
    c, s, d = env
    assert c.post(f"/api/session/{s.id}/approvers").status_code == 403
    assert d["url"].endswith("/approve/" + d["code"])
    assert c.get(d["qr_svg_url"]).headers["content-type"].startswith("image/svg")
    assert c.get(f"/approve/{d['code']}").status_code == 200


def test_one_person_can_keep_frozen(env):
    c, s, d = env
    sec = _join(c, d["code"], "Alex")
    r = _vote(c, d["code"], sec, "keep_frozen")
    assert r.status_code == 200, r.text
    assert s.receipt["decision"] == "deny"
    assert s.receipt["reviewer"] == "team:Alex"


def test_release_needs_two_different_people(env):
    c, s, d = env
    a = _join(c, d["code"], "Alex")
    b = _join(c, d["code"], "Sam")
    r1 = _vote(c, d["code"], a, "release")
    assert r1.status_code == 200 and r1.json()["release_votes"] == ["Alex"]
    assert s.receipt is None
    assert _vote(c, d["code"], a, "release").json()["release_votes"] == ["Alex"]  # same person twice
    assert s.receipt is None
    r2 = _vote(c, d["code"], b, "release")
    assert r2.status_code == 200
    assert s.receipt["decision"] == "approve"
    assert s.receipt["reviewer"] == "team:Alex+Sam"


def test_vote_needs_secret_and_state(env):
    c, s, d = env
    assert _vote(c, d["code"], "nope", "keep_frozen").status_code == 403
    sec = _join(c, d["code"], "Alex")
    assert _vote(c, d["code"], sec, "maybe").status_code == 422
    _vote(c, d["code"], sec, "keep_frozen")
    assert _vote(c, d["code"], sec, "release").status_code == 409
    st = c.get(f"/api/approvers/{d['code']}").json()
    assert st["decided"] is True and st["decision"] == "deny" and st["people"] == ["Alex"]


def test_names_validated_and_capped(env):
    c, s, d = env
    for bad in ("", "x" * 30, "<script>", "a;b"):
        assert c.post(f"/api/approvers/{d['code']}/join", json={"name": bad}).status_code in (400, 422)
    for i in range(approvers.MAX_PEOPLE):
        _join(c, d["code"], f"Person {chr(65 + i)}")
    assert c.post(f"/api/approvers/{d['code']}/join", json={"name": "One More"}).status_code == 409


def test_unknown_code_404(env):
    c, s, d = env
    assert c.get("/api/approvers/doesnotexist").status_code == 404


def test_autocall_uses_server_number_never_exposed(env, monkeypatch):
    c, s, d = env
    monkeypatch.delenv("ARENA_AUTOCALL_NUMBER", raising=False)
    assert c.get("/api/autocall").json() == {"enabled": False}
    assert c.post(f"/api/session/{s.id}/autocall", headers={"X-Session-Token": s.token}).status_code == 404
    monkeypatch.setenv("ARENA_AUTOCALL_NUMBER", "+919876543210")
    cfg = c.get("/api/autocall").json()
    assert cfg["enabled"] is True and cfg["ends_with"] == "210"
    assert "9876543210" not in str(cfg)
    placed = {}

    async def fake_post_phone(session_id, body, request):
        placed["number"], placed["sid"] = body.number, session_id
        return {"ok": True, "masked": "+91 98•••••210"}
    monkeypatch.setattr(server, "post_phone", fake_post_phone)
    assert c.post(f"/api/session/{s.id}/autocall").status_code == 403   # token required
    r = c.post(f"/api/session/{s.id}/autocall", headers={"X-Session-Token": s.token})
    assert r.status_code == 202, r.text
    assert placed == {"number": "+919876543210", "sid": s.id}
    assert "9876543210" not in r.text


def test_autocall_dials_every_configured_number(env, monkeypatch):
    c, s, d = env
    monkeypatch.setenv("ARENA_AUTOCALL_NUMBER", "+919876543210, +917000000001")
    assert c.get("/api/autocall").json() == {"enabled": True, "ends_with": "210, 001"}
    placed = []

    async def fake_post_phone(session_id, body, request):
        placed.append((body.number, server._call_slot.get()))
        return {"ok": True, "masked": "x"}
    monkeypatch.setattr(server, "post_phone", fake_post_phone)
    r = c.post(f"/api/session/{s.id}/autocall", headers={"X-Session-Token": s.token})
    assert r.status_code == 202, r.text
    assert sorted(placed) == [("+917000000001", "#auto1"), ("+919876543210", "#auto0")]
    assert r.json()["calls"] == 2


def test_once_per_session_key_uses_slot(monkeypatch):
    # manual calls keep one-per-session; each auto-call slot is its own key
    assert server._phone_key("abc") == "abc"
    tok = server._call_slot.set("#auto1")
    try:
        assert server._phone_key("abc") == "abc#auto1"
    finally:
        server._call_slot.reset(tok)


def test_per_number_cap_zero_means_unlimited():
    import inspect
    src = inspect.getsource(server.post_phone)
    assert "PHONE_PER_NUMBER_CAP" in src and "cap > 0" in src


def test_ensure_code_server_side_and_expiry():
    """ensure_code: server-side only (no token, no IP limit), one live code per
    session, a fresh code after expiry."""
    approvers._reset()
    c1 = approvers.ensure_code("sX")
    assert c1 and approvers.ensure_code("sX") == c1
    assert approvers._by_code[c1]["session_id"] == "sX"
    approvers._by_code[c1]["expires_at"] = 0
    c2 = approvers.ensure_code("sX")
    assert c2 != c1
