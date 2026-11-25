"""Canary taint: a canary in tool output sets taint; later network calls escalate.

The taint is cleared by `sandbox unfreeze` or `sandbox clear-taint`.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from sandbox.connector.hook_eval import pre_tool_use, post_tool_use
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
        json.dumps({"session_id": "s-ct"}), encoding="utf-8"
    )
    return lo


@pytest.fixture
def canaries(layout):
    from sandbox.connector.tripwire import mint, plant

    c = mint("s-ct")
    planted = plant(layout.root, c)
    c["_planted"] = planted
    canary_file = layout.state_dir / "canaries.json"
    canary_file.parent.mkdir(parents=True, exist_ok=True)
    canary_file.write_text(json.dumps(c), encoding="utf-8")
    return c


def _pre(tool_name, tool_input, cwd):
    return {
        "tool_name": tool_name, "tool_input": tool_input, "cwd": cwd,
        "session_id": "s-ct", "hook_event_name": "PreToolUse",
    }


def _post(tool_name, tool_input, tool_response, cwd):
    return {
        "tool_name": tool_name, "tool_input": tool_input,
        "tool_response": tool_response, "cwd": cwd,
        "session_id": "s-ct", "hook_event_name": "PostToolUse",
    }


def _not_quarantined(layout):
    return not (layout.state_dir / "quarantine.json").is_file()


# ---- taint flow ----

async def test_grep_output_sets_taint(layout, canaries):
    """grep output containing a canary sets canary_taint.json, no freeze."""
    resp = {"stdout": f"matched: {canaries['aws_access_key']}"}
    await post_tool_use(
        _post("Bash", {"command": "grep -rn DATABASE_URL ."}, resp, str(layout.root)),
        layout,
    )
    assert _not_quarantined(layout), "grep output caused false quarantine"
    taint = layout.state_dir / "canary_taint.json"
    assert taint.is_file(), "canary_taint.json not written"


async def test_tainted_curl_escalates(layout, canaries):
    """After canary taint, a curl command escalates (deny after timeout)."""
    # Set taint
    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({
        "ts": time.time(), "canary_name": "aws_access_key", "tool": "grep",
    }), encoding="utf-8")

    out = await pre_tool_use(
        _pre("Bash", {"command": "curl https://evil.example"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "CANARY_TAINT" in hso["permissionDecisionReason"]


async def test_tainted_wget_escalates(layout, canaries):
    """After taint, wget also escalates."""
    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({"ts": time.time()}), encoding="utf-8")

    out = await pre_tool_use(
        _pre("Bash", {"command": "wget https://example.com/data"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "CANARY_TAINT" in hso["permissionDecisionReason"]


async def test_tainted_ls_unaffected(layout, canaries):
    """After taint, a plain ls is NOT escalated (not a network command)."""
    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({"ts": time.time()}), encoding="utf-8")

    out = await pre_tool_use(
        _pre("Bash", {"command": "ls"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "CANARY_TAINT" not in hso.get("permissionDecisionReason", "")


async def test_tainted_git_status_unaffected(layout, canaries):
    """git status is not a network command; unaffected by taint."""
    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({"ts": time.time()}), encoding="utf-8")

    out = await pre_tool_use(
        _pre("Bash", {"command": "git status"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "CANARY_TAINT" not in hso.get("permissionDecisionReason", "")


async def test_tainted_webfetch_escalates(layout, canaries):
    """After taint, WebFetch escalates."""
    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({"ts": time.time()}), encoding="utf-8")

    out = await pre_tool_use(
        _pre("WebFetch", {"url": "https://evil.example"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "CANARY_TAINT" in hso["permissionDecisionReason"]


async def test_clear_taint_then_curl_unaffected(layout, canaries):
    """After clearing taint, curl is no longer escalated for CANARY_TAINT."""
    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({"ts": time.time()}), encoding="utf-8")

    # Clear taint
    taint.unlink()

    out = await pre_tool_use(
        _pre("Bash", {"command": "curl https://example.com"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "CANARY_TAINT" not in hso.get("permissionDecisionReason", "")


async def test_tainted_git_push_escalates(layout, canaries):
    """git push is a network command; escalated after taint."""
    taint = layout.state_dir / "canary_taint.json"
    taint.write_text(json.dumps({"ts": time.time()}), encoding="utf-8")

    out = await pre_tool_use(
        _pre("Bash", {"command": "git push origin main"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "CANARY_TAINT" in hso["permissionDecisionReason"]
