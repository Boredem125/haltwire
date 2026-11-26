"""Bug 3 root cause: Gemini 400 INVALID_ARGUMENT for deadline < 10s.

Policy default 12, clamp 10..20. HttpOptions never below 10000.
Error classification: 400/INVALID_ARGUMENT -> "config", not "timeout".
"""
from __future__ import annotations

import json
import os
from unittest import mock

import pytest


def test_policy_intent_default_12():
    """IntentPolicy default timeout_seconds is 12."""
    from sandbox.connector.policy import IntentPolicy
    p = IntentPolicy()
    assert p.timeout_seconds == 12


@pytest.mark.parametrize("raw,expected", [
    (5, 10), (8, 10), (10, 10), (12, 12), (15, 15), (20, 20), (25, 20), (0, 10),
])
def test_policy_intent_clamp(raw, expected):
    """timeout_seconds is clamped to 10..20."""
    from sandbox.connector.policy import IntentPolicy
    p = IntentPolicy(timeout_seconds=raw)
    assert p.timeout_seconds == expected


def test_http_timeout_never_below_10000():
    """The timeout passed to HttpOptions is never below 10000 ms."""
    from sandbox.connector.intent import _EnvKeyRotatingClient
    c = _EnvKeyRotatingClient(["fake-key"], timeout_ms=5000)
    # The client should use max(timeout_ms, 10000)
    assert c._timeout_ms >= 10000


def test_400_invalid_argument_is_config():
    """A 400 INVALID_ARGUMENT error (deadline too short) -> 'config'."""
    from sandbox.connector.intent import judge_tool_call

    class FakeClient:
        @property
        def models(self):
            return self
        def generate_content(self, **kw):
            raise RuntimeError(
                "400 INVALID_ARGUMENT: Manually set deadline 8s is too short. "
                "Minimum allowed deadline is 10s."
            )

    v = judge_tool_call("test", "Bash", {"command": "ls"}, [], client=FakeClient())
    assert v["error"] == "config", f"expected 'config', got '{v['error']}'"


def test_real_timeout_is_timeout():
    """A real httpx/socket timeout -> 'timeout'."""
    from sandbox.connector.intent import judge_tool_call

    class FakeClient:
        @property
        def models(self):
            return self
        def generate_content(self, **kw):
            raise TimeoutError("timed out waiting for response")

    v = judge_tool_call("test", "Bash", {"command": "ls"}, [], client=FakeClient())
    assert v["error"] == "timeout"


def test_401_is_auth():
    """A 401 error -> 'auth'."""
    from sandbox.connector.intent import judge_tool_call

    class FakeClient:
        @property
        def models(self):
            return self
        def generate_content(self, **kw):
            raise RuntimeError("401 Unauthorized: invalid API key")

    v = judge_tool_call("test", "Bash", {"command": "ls"}, [], client=FakeClient())
    assert v["error"] == "auth"


def test_429_is_quota():
    """A 429 error -> 'quota'."""
    from sandbox.connector.intent import judge_tool_call

    class FakeClient:
        @property
        def models(self):
            return self
        def generate_content(self, **kw):
            raise RuntimeError("429 RESOURCE_EXHAUSTED: quota exceeded")

    v = judge_tool_call("test", "Bash", {"command": "ls"}, [], client=FakeClient())
    assert v["error"] == "quota"
