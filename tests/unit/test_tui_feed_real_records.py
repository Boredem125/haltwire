"""Feed lines for real audit record shapes (seen in the live see-ui run).

Before: "??:??:?? EVENT policy_version_accepted", "ALLOW allowed",
"EVENT d29e6ab9" for a denial.
"""
from __future__ import annotations

from sandbox.tui.app import _effective_type, _event_badge, _format_feed_line


def test_shell_decided_denied_is_deny():
    ev = {"event": "shell_decided", "request_id": "d29e6ab977e6f2e9", "state": "denied"}
    assert _event_badge(_effective_type(ev)) == "DENY"


def test_shell_decided_approved_is_approve():
    ev = {"event": "shell_decided", "request_id": "x", "state": "approved"}
    assert _event_badge(_effective_type(ev)) == "APPROVE"


def test_setup_records_are_quiet():
    for raw in ("policy_version_accepted", "key_pinned"):
        ev = {"event": raw, "by": "someone", "how": "baseline"}
        assert _event_badge(_effective_type(ev)) == "SETUP"
    line = _format_feed_line({"event": "key_pinned"}, "setup")
    assert "approver key pinned" in line


def test_allowed_read_shows_tool_and_file():
    ev = {"event": "allowed", "tool": "Read", "command": "",
          "target": r"D:\proj\requirements.txt"}
    line = _format_feed_line(ev, _effective_type(ev))
    assert "Read" in line and "requirements.txt" in line
    assert "proj" not in line


def test_escalated_shows_command_and_reason():
    ev = {"event": "shell_escalated", "request_id": "d29e6ab977e6f2e9",
          "command": "pip install -r requirements.txt", "reason_code": "TYPOSQUAT"}
    line = _format_feed_line(ev, _effective_type(ev))
    assert "pip install -r requirements.txt" in line and "TYPOSQUAT" in line
