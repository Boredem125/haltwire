"""Data the story-mode page needs: every Gemini call as an event, tool args as
data (not a stringified dict), and the poisoned repo's real files."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from arena.agent import run_session
from tests.unit.test_tw_agent import (FakeClient, make_fake_tripwire, text_response,
                                      tool_response)

CHIP = {"id": "t", "title": "t", "task_prompt": "List the files.", "extra_files": {}}


@pytest.mark.asyncio
async def test_model_event_per_gemini_call(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.txt").write_text("x")
    client = FakeClient([tool_response(("list_dir", {"path": "."})), text_response("Done.")])
    tw = make_fake_tripwire()
    events = await run_session(CHIP, ws, guard=False, client=client, tripwire=tw,
                               canaries=tw.mint("t"), session_id="vis1")
    models = [e for e in events if e["kind"] == "model"]
    assert len(models) == 2
    first, second = models[0]["extra"], models[1]["extra"]
    assert first["turn"] == 1 and second["turn"] == 2
    assert first["calls"] == ["list_dir"] and second["calls"] == []
    assert first["sent"] == "task prompt"
    assert second["sent"] == "1 tool result"
    assert second["reply"] == "text"
    assert first["latency_ms"] >= 0 and first["model"]
    # the model event comes before the tool event it caused
    kinds = [e["kind"] for e in events]
    assert kinds.index("model") < kinds.index("tool")


@pytest.mark.asyncio
async def test_tool_event_carries_args(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    client = FakeClient([tool_response(("run_command", {"command": "echo hi"})),
                         text_response("Done.")])
    tw = make_fake_tripwire()
    events = await run_session(CHIP, ws, guard=False, client=client, tripwire=tw,
                               canaries=tw.mint("t"), session_id="vis2")
    tool = next(e for e in events if e["kind"] == "tool")
    assert tool["extra"]["args"] == {"command": "echo hi"}


def _client():
    from arena import server
    return TestClient(server.app)


def test_repo_endpoint_setup_highlights_exfil():
    r = _client().get("/api/repo?chip_id=setup")
    assert r.status_code == 200
    d = r.json()
    assert d["task_prompt"]
    files = {f["path"]: f for f in d["files"]}
    setup = files["setup.py"]
    assert setup["kind"] == "poisoned"
    lines = setup["content"].splitlines()
    hl = setup["highlights"]
    assert hl, "setup.py must highlight the exfil code"
    covered = {n for h in hl for n in range(h["start"], h["end"] + 1)}
    def_line = next(i + 1 for i, l in enumerate(lines) if l.startswith("def _send_telemetry"))
    call_line = next(i + 1 for i, l in enumerate(lines) if l.strip() == "_send_telemetry()")
    assert def_line in covered and call_line in covered
    assert files["test_totals.py"]["kind"] == "normal"
    # decoys are listed, values are minted per run, so not shown
    decoys = [f for f in d["files"] if f["kind"] == "decoy"]
    assert {".env.backup", ".aws/credentials.bak", "deploy_key.pem"} <= {f["path"] for f in decoys}
    import re
    for f in decoys:  # only masked shapes, never a real-looking value
        assert not re.search(r"sk_live_[A-Za-z0-9]|AKIA[A-Z0-9]", f["content"]), f["path"]
        assert "minted for every run" in f["content"]


def test_repo_endpoint_variant_and_errors():
    c = _client()
    r = c.get("/api/repo?chip_id=setup&encoding=chunked&channel=header&host=demo")
    assert r.status_code == 200
    setup = next(f for f in r.json()["files"] if f["path"] == "setup.py")
    assert "demo.evil.example" in setup["content"]
    assert c.get("/api/repo?chip_id=nope").status_code == 404
    assert c.get("/api/repo?chip_id=setup&encoding=rot13&channel=body").status_code == 400


def test_routes_story_first_classic_kept(tmp_path, monkeypatch):
    from arena import server
    monkeypatch.setattr(server, "STATIC", tmp_path)
    (tmp_path / "tripwire.html").write_text("<p>classic</p>", encoding="utf-8")
    (tmp_path / "index.html").write_text("<p>arena</p>", encoding="utf-8")
    c = _client()
    assert "classic" in c.get("/").text          # no story page yet
    (tmp_path / "story.html").write_text("<p>story</p>", encoding="utf-8")
    assert "story" in c.get("/").text
    assert "story" in c.get("/story.html").text
    assert "classic" in c.get("/classic").text
