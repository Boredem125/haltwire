"""Tests: settable client factory in sandbox.connector.intent.

The arena shim sets its own _make_client via set_client_factory so that
judge_tool_call uses the arena's client (arena/.env + ARENA_JUDGE_KEYS ordering)
instead of the connector's env-only client.

Fix review #5: with keys only in arena/.env and no env vars, judge_tool_call
uses the shim's client and returns no "no GEMINI_API_KEY" error.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import sandbox.connector.intent as ci


class FakeGenaiResponse:
    def __init__(self, text: str):
        self.candidates = [MagicMock()]
        self.candidates[0].content.parts = [MagicMock()]
        self.candidates[0].content.parts[0].text = text


class FakeClient:
    """A fake genai client."""
    def __init__(self, name: str = "FakeClient"):
        self._name = name
        self.calls: list[dict] = []
        self.models = self

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return FakeGenaiResponse('{"flag": false, "reason": "ok", "confidence": 0.1}')


@pytest.fixture(autouse=True)
def clean_factory():
    """Reset the client factory after each test."""
    old = ci._client_factory
    yield
    ci._client_factory = old


@pytest.fixture
def no_gemini_env(monkeypatch):
    """Remove all GEMINI_API_KEY* and ARENA_* env vars."""
    for k in list(os.environ):
        if k.startswith("GEMINI_API_KEY") or k.startswith("ARENA_"):
            monkeypatch.delenv(k, raising=False)


def test_set_client_factory_exists():
    """set_client_factory is importable."""
    assert hasattr(ci, "set_client_factory")
    assert callable(ci.set_client_factory)


def test_default_factory_uses_env_keys(monkeypatch):
    """Without a custom factory, _make_client reads GEMINI_API_KEY from env."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    client = ci._make_client()
    assert hasattr(client, "_keys")
    assert "test-key" in client._keys


def test_custom_factory_overrides(no_gemini_env):
    """set_client_factory makes _make_client use the custom factory."""
    custom = FakeClient("custom")
    ci.set_client_factory(lambda: custom)

    result = ci._make_client()
    assert result is custom


def test_judge_uses_custom_factory(no_gemini_env, monkeypatch):
    """judge_tool_call uses the custom factory when no env key is set."""
    custom = FakeClient("custom-judge")
    ci.set_client_factory(lambda: custom)

    # Patch _generate to track the client
    seen_clients = []
    orig_generate = ci._generate

    def patched_generate(gclient, system, prompt):
        seen_clients.append(gclient)
        return FakeGenaiResponse('{"flag": false, "reason": "ok", "confidence": 0.1}'), "test-model"

    monkeypatch.setattr(ci, "_generate", patched_generate)

    verdict = ci.judge_tool_call(
        "test task", "Bash", {"command": "ls"}, [],
        canaries={},
    )
    # Must NOT have "no GEMINI_API_KEY" error
    assert verdict.get("error") is None or "GEMINI_API_KEY" not in str(verdict.get("error", ""))
    assert len(seen_clients) == 1
    assert seen_clients[0] is custom


def test_arena_shim_sets_factory(no_gemini_env, monkeypatch, tmp_path):
    """When arena.intent is imported, it sets the client factory on
    sandbox.connector.intent so judge_tool_call uses arena's client."""
    # Create a fake arena/.env with a key
    arena_dir = tmp_path / "arena"
    arena_dir.mkdir()
    env_file = arena_dir / ".env"
    env_file.write_text("GEMINI_API_KEY=arena-key-from-file\n", encoding="utf-8")

    # Patch arena.agent.__file__ to point at our temp arena dir
    import arena.agent as ag
    monkeypatch.setattr(ag, "__file__", str(arena_dir / "agent.py"))

    # Import the shim (re-import forces _make_client reassignment)
    import arena.intent as ai

    # The shim's _make_client should load from arena/.env
    client = ai._make_client()
    assert hasattr(client, "_keys")
    assert "arena-key-from-file" in client._keys


def test_explicit_client_param_overrides_factory(no_gemini_env, monkeypatch):
    """Passing client= explicitly to judge_tool_call overrides the factory."""
    custom_factory = FakeClient("from-factory")
    ci.set_client_factory(lambda: custom_factory)

    explicit = FakeClient("explicit")

    seen_clients = []

    def patched_generate(gclient, system, prompt):
        seen_clients.append(gclient)
        return FakeGenaiResponse('{"flag": false, "reason": "ok", "confidence": 0.1}'), "test-model"

    monkeypatch.setattr(ci, "_generate", patched_generate)

    ci.judge_tool_call(
        "test task", "Bash", {"command": "ls"}, [],
        client=explicit,
        canaries={},
    )
    assert seen_clients[0] is explicit


def test_env_client_has_http_timeout(monkeypatch):
    """The env-based client is built with an HTTP-level timeout."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    # Ensure no custom factory overrides the env-based path
    ci._client_factory = None
    client = ci._make_client(timeout_ms=12000)
    assert isinstance(client, ci._EnvKeyRotatingClient)
    assert client._timeout_ms == 12000


def test_default_timeout_is_12000(monkeypatch):
    """The default HTTP timeout is 12000 ms (Gemini min 10s deadline)."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    ci._client_factory = None
    client = ci._make_client()
    assert client._timeout_ms == 12000


def test_judge_passes_timeout_to_client(monkeypatch):
    """judge_tool_call passes timeout_ms to _make_client."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    ci._client_factory = None

    created_clients = []
    orig_make = ci._make_client

    def patched_make(client=None, timeout_ms=8000):
        result = orig_make(client, timeout_ms=timeout_ms)
        created_clients.append(result)
        return result

    monkeypatch.setattr(ci, "_make_client", patched_make)

    def patched_generate(gclient, system, prompt):
        return FakeGenaiResponse('{"flag": false, "reason": "ok", "confidence": 0.1}'), "test-model"

    monkeypatch.setattr(ci, "_generate", patched_generate)

    ci.judge_tool_call(
        "test task", "Bash", {"command": "ls"}, [],
        canaries={}, timeout_ms=15000,
    )
    assert len(created_clients) == 1
    assert created_clients[0]._timeout_ms == 15000
