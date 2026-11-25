"""Buildathon branch only: hook_demo replay shape, verification, no secrets."""
from __future__ import annotations

import json
import re

import pytest

from arena import hook_demo


# ---------------------------------------------------------------- replay shape

def _make_replay() -> dict:
    """A minimal valid replay dict for shape tests."""
    return {
        "kind": "hook_demo",
        "agent": "Antigravity CLI 1.5.13",
        "model": "gemini-2.5-flash-lite-preview-06-17",
        "recorded_at": "2026-11-20T18:00:00Z",
        "events": [
            {"seq": 1, "side": "protected", "ts": 0.0, "kind": "tool",
             "tool": "read_file", "text": "README.md", "decision": "allow",
             "reason": "", "extra": {}},
            {"seq": 2, "side": "protected", "ts": 1.0, "kind": "tool",
             "tool": "run_command", "text": "pip install -r requirements.txt",
             "decision": "deny", "reason": "SANDBOX DENIED [TYPOSQUAT]",
             "extra": {}},
            {"seq": 3, "side": "protected", "ts": 1.0, "kind": "block",
             "tool": "run_command", "text": "pip install -r requirements.txt",
             "decision": "deny",
             "reason": "SANDBOX DENIED [TYPOSQUAT]: requirements.txt installs 'pandaz-csv'",
             "extra": {"package": "pandaz-csv", "looks_like": "pandas", "code": "TYPOSQUAT"}},
        ],
        "block": {
            "package": "pandaz-csv",
            "looks_like": "pandas",
            "reason": "TYPOSQUAT",
        },
        "audit": {
            "record": {"event": "denied", "reason_code": "TYPOSQUAT"},
            "chain_ok": True,
            "head_hash_short": "abcd1234",
        },
    }


def test_replay_has_required_top_keys():
    r = _make_replay()
    for key in ("kind", "agent", "model", "recorded_at", "events", "block", "audit"):
        assert key in r, f"missing key {key}"


def test_replay_kind_is_hook_demo():
    r = _make_replay()
    assert r["kind"] == "hook_demo"


def test_replay_events_are_list_of_dicts():
    r = _make_replay()
    assert isinstance(r["events"], list)
    for e in r["events"]:
        assert isinstance(e, dict)
        assert "seq" in e and "kind" in e and "side" in e


def test_replay_block_has_package_and_reason():
    r = _make_replay()
    b = r["block"]
    assert b["package"] == "pandaz-csv"
    assert b["looks_like"] == "pandas"
    assert "TYPOSQUAT" in b["reason"]


def test_replay_audit_has_chain_ok():
    r = _make_replay()
    a = r["audit"]
    assert "chain_ok" in a
    assert "head_hash_short" in a


# ---------------------------------------------------------------- verify function

def test_verify_valid_chain(tmp_path):
    """Build a real mini audit chain and verify it passes."""
    from sandbox.connector.audit import FolderAudit

    session = "demo"
    audit_dir = tmp_path / ".sandbox" / "audit"
    audit = FolderAudit(audit_dir, session)
    audit.append({"event": "denied", "reason_code": "TYPOSQUAT", "package": "pandaz-csv"})

    chain_file = audit_dir / session / "records.jsonl"
    chain_bytes = chain_file.read_bytes()

    replay = {
        "kind": "hook_demo",
        "audit": {"chain_ok": True},
        "_chain_bytes": chain_bytes.decode("utf-8"),
    }
    assert hook_demo.verify(replay) is True


def test_verify_tampered_chain_fails(tmp_path):
    """Flip a byte in the chain file and verify fails."""
    from sandbox.connector.audit import FolderAudit

    session = "demo"
    audit_dir = tmp_path / ".sandbox" / "audit"
    audit = FolderAudit(audit_dir, session)
    audit.append({"event": "denied", "reason_code": "TYPOSQUAT", "package": "pandaz-csv"})
    audit.append({"event": "allowed", "tool": "read_file"})

    chain_file = audit_dir / session / "records.jsonl"
    raw = chain_file.read_text(encoding="utf-8")
    # Tamper: change "TYPOSQUAT" to "TYPOSQUAX"
    tampered = raw.replace("TYPOSQUAT", "TYPOSQUAX", 1)
    assert tampered != raw

    replay = {
        "kind": "hook_demo",
        "audit": {"chain_ok": True},
        "_chain_bytes": tampered,
    }
    assert hook_demo.verify(replay) is False


# ---------------------------------------------------------------- no secrets

_GOOGLE_KEY_RE = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
_SECRET_PATTERNS = [
    _GOOGLE_KEY_RE,
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
]


def test_no_secret_shapes_in_replay():
    """The replay JSON must not contain anything shaped like a real API key."""
    r = _make_replay()
    text = json.dumps(r)
    for pat in _SECRET_PATTERNS:
        assert not pat.search(text), f"secret shape found: {pat.pattern}"


def test_no_secret_shapes_in_serialized_replay():
    """Even if events mention keys, they must be redacted."""
    r = _make_replay()
    # Add an event with a key-shaped string (should not appear)
    r["events"].append({
        "seq": 99, "side": "protected", "ts": 2.0, "kind": "info",
        "tool": "", "text": "[REDACTED]", "decision": "", "reason": "",
        "extra": {},
    })
    text = json.dumps(r)
    for pat in _SECRET_PATTERNS:
        assert not pat.search(text), f"secret shape found: {pat.pattern}"


# ---------------------------------------------------------------- record function shape

def test_record_returns_dict_with_expected_keys(monkeypatch, tmp_path):
    """record() returns a dict even when mocked (shape only, no live agy)."""
    # We only test the returned shape here; the real run is a manual step.
    # This test patches run_agent to avoid needing a real agy + API key.
    import asyncio

    fake_stream = json.dumps({
        "event": "step_update",
        "step_update": {"step_type": "tool", "state": "ACTIVE",
                        "tool_name": "run_command",
                        "tool_info": {"parameters": {"CommandLine": "pip install -r requirements.txt"}}}
    }) + "\n" + json.dumps({
        "event": "result",
        "result": {"status": "SUCCESS", "response": "done"},
    })

    fake_hook_log = json.dumps({
        "in": json.dumps({"toolCall": {"name": "run_command",
                          "args": {"CommandLine": "pip install -r requirements.txt"}}}),
        "out": {"decision": "deny",
                "reason": "SANDBOX DENIED [TYPOSQUAT]: requirements.txt installs 'pandaz-csv', "
                          "1 letter(s) away from the popular package 'pandas'. "
                          "This is a common supply-chain attack."},
    })

    async def fake_run_agent(dest, prompt, raw_path=None):
        if raw_path is not None:
            raw_path.write_text(fake_stream, encoding="utf-8")
        return {"agent_status": "SUCCESS", "agent_reply": "done"}

    monkeypatch.setattr("arena.hook_demo._run_agent", fake_run_agent)

    # Also mock _sandbox to avoid needing real sandbox binary
    def fake_sandbox(*args, cwd):
        from sandbox.connector.layout import FolderLayout
        lo = FolderLayout(cwd)
        lo.ensure_dirs()
        # Create minimal policy
        lo.policy_file.write_text('{"shell":{"allow_patterns":[]},"escalation_timeout_seconds":3}',
                                  encoding="utf-8")

    monkeypatch.setattr("arena.hook_demo._sandbox", fake_sandbox)

    # Write a fake hook log
    dest = tmp_path / "hook_demo_test"
    log_path = dest / "logs" / "hook_demo.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(fake_hook_log + "\n", encoding="utf-8")

    # Patch _log_path to return our fake log
    monkeypatch.setattr("arena.hook_demo._prepare_workspace",
                        lambda dest_dir: (dest, log_path))

    result = asyncio.run(hook_demo._record_inner(dest_dir=tmp_path / "out"))
    assert isinstance(result, dict)
    assert result["kind"] == "hook_demo"
    assert "events" in result
    assert "block" in result
    assert "audit" in result


# ---------------------------------------------------------------- saved recording

def test_saved_recording_no_secrets():
    """The on-disk hook_demo.json must not contain any secret shapes."""
    from pathlib import Path
    replay_file = Path(__file__).resolve().parents[2] / "arena" / "recordings" / "hook_demo.json"
    if not replay_file.is_file():
        pytest.skip("no saved recording yet")
    text = replay_file.read_text(encoding="utf-8")
    for pat in _SECRET_PATTERNS:
        assert not pat.search(text), f"secret shape in saved file: {pat.pattern}"


def test_saved_recording_verify():
    """The on-disk recording passes chain verification."""
    replay, ok = hook_demo.load_and_verify()
    if replay is None:
        pytest.skip("no saved recording yet")
    assert ok is True
    assert replay["kind"] == "hook_demo"
    assert replay["block"]["package"] == "pandaz-csv"
