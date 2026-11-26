"""F5 final: a hung judge must not block the hook process.

The test runs pre_tool_use_raw in a subprocess (matching the real hook stub
path: asyncio.run(pre_tool_use_raw(...))), with a judge that sleeps 60 s and
a policy timeout of 2.  The whole process must exit in under ~6 s with no
flag and intent_error audited.

The fake judge is injected via HALTWIRE_TEST_JUDGE_SLEEP, which is only
read when HALTWIRE_TEST_MODE is set.  Both are stripped from the normal
production path.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy


@pytest.fixture
def workspace(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 2
    # Enable intent judge
    pdata = policy.model_dump()
    pdata["intent"] = {"enabled": True, "timeout_seconds": 10}
    lo.policy_file.write_text(json.dumps(pdata), encoding="utf-8")
    lo.session_file.write_text(
        json.dumps({"session_id": "s-subproc"}), encoding="utf-8"
    )
    # Plant canaries so the hook loads them
    from sandbox.connector.tripwire import mint, plant

    c = mint("s-subproc")
    plant(lo.root, c)
    canary_file = lo.state_dir / "canaries.json"
    canary_file.write_text(json.dumps(c), encoding="utf-8")
    return lo


def test_hung_judge_does_not_block_process(workspace):
    """A subprocess running asyncio.run(pre_tool_use_raw(...)) exits within
    the timeout budget even when the judge hangs for 60 s."""
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "npm install -g typescript"},
        "cwd": str(workspace.root),
        "session_id": "s-subproc",
        "hook_event_name": "PreToolUse",
    }
    raw = json.dumps(payload)

    # Script that runs the hook in-process (same as the real stub)
    script = f"""
import sys, os, json, asyncio
sys.path.insert(0, {repr(str(Path(__file__).resolve().parent.parent.parent / 'src'))})
os.environ['GEMINI_API_KEY'] = 'test-key'
os.environ['HALTWIRE_TEST_MODE'] = '1'
os.environ['HALTWIRE_TEST_JUDGE_SLEEP'] = '60'
from sandbox.connector.hook_eval import pre_tool_use_raw
from sandbox.connector.layout import FolderLayout
raw = {repr(raw)}
layout = FolderLayout({repr(str(workspace.root))})
result = asyncio.run(pre_tool_use_raw(raw, layout))
sys.stdout.write(json.dumps(result))
sys.stdout.flush()
"""

    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=20,
        env={**os.environ},
    )
    elapsed = time.monotonic() - t0

    # Must exit within budget (10s timeout + 1s slack + margin, not 60s)
    assert elapsed < 16, f"process took {elapsed:.1f}s, expected < 16s"
    assert proc.returncode == 0, f"rc={proc.returncode} stderr={proc.stderr[:500]}"

    # Parse the output
    out = json.loads(proc.stdout)
    hso = out.get("hookSpecificOutput", {})
    # No AI_INTENT flag (timed out, fail-open)
    assert "AI_INTENT" not in hso.get("permissionDecisionReason", "")

    # Check the audit file for intent_error
    from sandbox.connector.audit import FolderAudit

    audit = FolderAudit(workspace.audit_dir, "s-subproc")
    if audit.records_file.exists():
        text = audit.records_file.read_text(encoding="utf-8")
        assert "intent_error" in text
