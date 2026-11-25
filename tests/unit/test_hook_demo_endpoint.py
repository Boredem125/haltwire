"""Buildathon branch only: GET /api/hook-demo serves the recorded, re-verified run."""
from fastapi.testclient import TestClient

from arena import server


def test_hook_demo_served_and_verified():
    r = TestClient(server.app).get("/api/hook-demo")
    assert r.status_code == 200
    d = r.json()
    assert d["kind"] == "hook_demo" and d["block"]["reason"] == "TYPOSQUAT"
    assert d["audit"]["chain_ok"] is True


def test_hook_demo_404_when_missing(monkeypatch, tmp_path):
    from pathlib import Path as _P
    real = _P.is_file

    def fake_is_file(self):
        return False if self.name == "hook_demo.json" else real(self)

    monkeypatch.setattr(_P, "is_file", fake_is_file)
    assert TestClient(server.app).get("/api/hook-demo").status_code == 404
