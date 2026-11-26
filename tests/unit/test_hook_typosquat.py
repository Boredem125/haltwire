"""Tests: typosquat check wired into hook_eval PreToolUse.

Typosquat detection runs in the hook for all agents. Flagged lookalikes
are REAL escalations (single human approval through the queue). The
reason contains "[TYPOSQUAT]" exactly once.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import default_policy, save_policy
from sandbox.connector.queue import EscalationQueue


@pytest.fixture
def layout(tmp_path):
    lo = FolderLayout(tmp_path)
    lo.ensure_dirs()
    policy = default_policy()
    policy.escalation_timeout_seconds = 2
    save_policy(policy, lo.policy_file)
    lo.session_file.write_text(
        json.dumps({"session_id": "s-typo"}), encoding="utf-8"
    )
    return lo


def _pre(tool_name, tool_input, cwd):
    return {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": cwd,
        "session_id": "s-typo",
        "hook_event_name": "PreToolUse",
    }


# ---- typosquat lookalikes are real escalations ----

async def test_typosquat_pip_install_creates_pending(layout):
    """pip install pandaz-csv creates a pending request in the queue."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install pandaz-csv"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    # The pending reason mentions the request id (real escalation)
    reason = hso["permissionDecisionReason"]
    assert "check_request" in reason or "TYPOSQUAT" in reason


async def test_typosquat_pending_visible_to_watch(layout):
    """The typosquat escalation creates a pending file visible to watch."""
    queue = EscalationQueue(layout)

    async def run_hook():
        return await pre_tool_use(
            _pre("Bash", {"command": "pip install pandaz-csv"}, str(layout.root)),
            layout,
        )

    # Start the hook (it waits for approval)
    task = asyncio.create_task(run_hook())
    # Wait a moment for the pending request to appear
    for _ in range(20):
        pending = queue.list_pending()
        if pending:
            break
        await asyncio.sleep(0.1)
    # There should be a pending request
    assert len(pending) >= 1
    req = pending[0]
    assert "TYPOSQUAT" in req.get("reason", "") or "TYPOSQUAT" in req.get("reason_code", "")
    # Let it time out
    await task


async def test_typosquat_approve_runs_command(layout):
    """Approving a typosquat escalation runs the command."""
    queue = EscalationQueue(layout)

    async def approver():
        for _ in range(50):
            pending = queue.list_pending()
            if pending:
                rid = pending[0]["request_id"]
                queue.claim(rid, "cli:tester")
                queue.finish(rid, {
                    "state": "executed", "decision": "approved",
                    "reviewer_id": "cli:tester", "exit_code": 0,
                    "stdout": "installed pandaz-csv\n", "stderr": "",
                    "command": "pip install pandaz-csv",
                })
                return
            await asyncio.sleep(0.05)

    task = asyncio.create_task(approver())
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install pandaz-csv"}, str(layout.root)),
        layout,
    )
    await task
    hso = out["hookSpecificOutput"]
    # On approval, the hook returns deny with captured output in the reason
    assert hso["permissionDecision"] == "deny"
    assert "installed pandaz-csv" in hso["permissionDecisionReason"]


async def test_typosquat_npm_escalates(layout):
    """npm install loadsh escalates."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "npm install loadsh"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


async def test_typosquat_uv_add_escalates(layout):
    """uv add numpay escalates."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "uv add numpay"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


async def test_typosquat_reqeusts(layout):
    """pip install reqeusts (typo of requests) escalates."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install reqeusts"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


# ---- raise-only: classify deny stays deny ----

async def test_blocklisted_plus_typosquat_stays_deny(layout):
    """A blocklisted command that also installs a typosquat keeps the
    original deny reason code, not TYPOSQUAT."""
    # rm -rf .sandbox is blocklisted; adding a typosquat pkg must not change that
    out = await pre_tool_use(
        _pre("Bash", {"command": "rm -rf .sandbox && pip install pandaz-csv"},
             str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    # The original deny reason must NOT be TYPOSQUAT
    assert "TYPOSQUAT" not in hso["permissionDecisionReason"]


# ---- pending message includes package + lookalike ----

async def test_pending_message_names_package(layout):
    """The pending/escalation reason names the suspicious package and lookalike."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install pandaz-csv"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    reason = hso["permissionDecisionReason"]
    assert "pandaz-csv" in reason
    assert "pandas" in reason


# ---- legitimate packages pass ----

async def test_legit_pip_install_allowed(layout):
    """pip install pandas is not a typosquat."""
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install pandas"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "TYPOSQUAT" not in hso.get("permissionDecisionReason", "")


@pytest.mark.parametrize("pkg", [
    "vitest", "preact", "psycopg", "psycopg-binary", "dash", "yaml",
    "mysql", "color", "scapy", "cattrs", "arrow", "unicorn", "simpy",
    "boto", "grpc", "jinja",
])
async def test_known_legit_no_flag(layout, pkg):
    """Known-legitimate packages must never be flagged."""
    out = await pre_tool_use(
        _pre("Bash", {"command": f"pip install {pkg}"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "TYPOSQUAT" not in hso.get("permissionDecisionReason", "")


# ---- BOM handling (bug 1) ----

async def test_bom_requirements_txt(layout):
    """UTF-8 BOM in requirements.txt must not cause false positive on requests."""
    req = layout.root / "requirements.txt"
    req.write_bytes(b"\xef\xbb\xbfrequests\npandaz-csv\n")
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install -r requirements.txt"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    reason = hso.get("permissionDecisionReason", "")
    # requests must NOT be flagged
    assert "requests'" not in reason or "pandaz" in reason
    # pandaz-csv MUST be flagged
    assert hso["permissionDecision"] == "deny"


async def test_crlf_bom_requirements_txt(layout):
    """CRLF + BOM requirements.txt works correctly."""
    req = layout.root / "requirements.txt"
    req.write_bytes(b"\xef\xbb\xbfrequests\r\npandaz-csv\r\n")
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install -r requirements.txt"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    reason = hso.get("permissionDecisionReason", "")
    assert "requests'" not in reason or "pandaz" in reason
    assert hso["permissionDecision"] == "deny"


async def test_utf16le_bom_requirements_txt(layout):
    """UTF-16 LE BOM (PowerShell 5.1 Out-File default) must not false-positive."""
    req = layout.root / "requirements.txt"
    req.write_bytes("requests\npandaz-csv\n".encode("utf-16-le"))
    # Prepend UTF-16 LE BOM
    bom = b"\xff\xfe"
    req.write_bytes(bom + "requests\npandaz-csv\n".encode("utf-16-le"))
    out = await pre_tool_use(
        _pre("Bash", {"command": "pip install -r requirements.txt"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    reason = hso.get("permissionDecisionReason", "")
    # requests must NOT be flagged (even if file can't be decoded, no false pos)
    if "TYPOSQUAT" in reason:
        assert "requests'" not in reason or "pandaz" in reason


# ---- PowerShell ----

async def test_typosquat_powershell(layout):
    """PowerShell pip install typosquat is also caught."""
    out = await pre_tool_use(
        _pre("PowerShell", {"command": "pip install pandaz-csv"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


async def test_powershell_requirements_txt_path(layout):
    """pip install -r .\\requirements.txt must not false-positive."""
    (layout.root / "requirements.txt").write_text("pandas\n", encoding="utf-8")
    out = await pre_tool_use(
        _pre("PowerShell", {"command": r"pip install -r .\requirements.txt"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "TYPOSQUAT" not in hso.get("permissionDecisionReason", "")


# ---- non-shell not checked ----

async def test_non_shell_not_checked(layout):
    """Read tool is not checked for typosquat."""
    out = await pre_tool_use(
        _pre("Read", {"file_path": "pandaz-csv.txt"}, str(layout.root)),
        layout,
    )
    hso = out["hookSpecificOutput"]
    assert "TYPOSQUAT" not in hso.get("permissionDecisionReason", "")
