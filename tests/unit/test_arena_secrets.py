"""Buildathon branch only: the arena never shows or leaks API keys."""
from __future__ import annotations

from arena import runner

KEY_A = "AIza" + "A" * 35
KEY_B = "AIza" + "B" * 35


def test_redact_known_values_and_google_key_shape(monkeypatch):
    monkeypatch.setenv("ARENA_ADMIN_TOKEN", "admin-tok-123456")
    monkeypatch.setenv("ARENA_AGENT_KEY", KEY_B)
    data = {"agent_reply": f"the key is {KEY_A} and {KEY_B}",
            "tool_calls": [{"args": {"CommandLine": "echo admin-tok-123456"}}]}
    out = runner.redact(data)
    s = str(out)
    assert KEY_A not in s and KEY_B not in s and "admin-tok-123456" not in s
    assert "[REDACTED]" in s


def test_short_values_not_redacted(monkeypatch):
    monkeypatch.setenv("ARENA_ADMIN_TOKEN", "abc")
    assert runner.redact({"x": "abc def"}) == {"x": "abc def"}


def test_agent_env_drops_attacker_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", KEY_A)
    monkeypatch.setenv("ARENA_ATTACKER_KEY", KEY_A)
    monkeypatch.setenv("ARENA_ADMIN_TOKEN", "admin-tok-123456")
    monkeypatch.setenv("ARENA_AGENT_KEY", KEY_B)
    env = runner.agent_env()
    assert KEY_A not in env.values()
    assert "admin-tok-123456" not in env.values()
    assert env["GEMINI_API_KEY"] == KEY_B
    assert "ARENA_AGENT_KEY" not in env


def test_agent_env_without_agent_key_has_no_gemini_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", KEY_A)
    monkeypatch.delenv("ARENA_AGENT_KEY", raising=False)
    assert "GEMINI_API_KEY" not in runner.agent_env()
