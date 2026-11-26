"""haltwire watch -- Textual TUI dashboard.

Displays pending escalations, audit events, workspace status, and
the AI intent judge state.  Approve, deny, unfreeze, set a Gemini
key, and toggle the AI judge from the keyboard.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Colour-system detection (called BEFORE textual is imported elsewhere)
# ---------------------------------------------------------------------------

def detect_color_system() -> str:
    """Detect the best Textual colour system for the current terminal.

    Returns "truecolor", "256", or "standard".  Respects NO_COLOR.
    Called by the CLI watch entry point before importing textual so the
    cached constant picks up the right value.
    """
    if os.environ.get("NO_COLOR") is not None:
        return "standard"
    # Explicit override
    explicit = os.environ.get("TEXTUAL_COLOR_SYSTEM", "").strip()
    if explicit:
        return explicit
    # COLORTERM is the standard signal
    colorterm = os.environ.get("COLORTERM", "").lower()
    if colorterm in ("truecolor", "24bit"):
        return "truecolor"
    # Windows Terminal always supports 24-bit
    if os.environ.get("WT_SESSION"):
        return "truecolor"
    # VS Code, iTerm, WezTerm integrated terminals
    term_program = os.environ.get("TERM_PROGRAM", "")
    if term_program in ("vscode", "iTerm.app", "WezTerm"):
        return "truecolor"
    if term_program == "Apple_Terminal":
        return "256"
    # Windows 10 build 15063+ supports VT/24-bit in conhost
    if sys.platform == "win32":
        try:
            ver = sys.getwindowsversion()
            if ver.major >= 10 and ver.build >= 15063:
                return "truecolor"
        except Exception:
            pass
    # Fallback
    return "auto"


def ensure_color_system() -> None:
    """Set TEXTUAL_COLOR_SYSTEM if not already set, using detect_color_system().

    Must be called before textual is imported (it caches at import time).
    Also patches the already-cached constant if textual was imported earlier.
    """
    if os.environ.get("TEXTUAL_COLOR_SYSTEM"):
        return
    cs = detect_color_system()
    if cs != "auto":
        os.environ["TEXTUAL_COLOR_SYSTEM"] = cs


# Ensure colour is set BEFORE textual is imported (this module IS the
# entry point for `from sandbox.tui.app import HaltwireApp`).
ensure_color_system()

from textual import on, work  # noqa: E402
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Input,
    Label,
    Static,
)

# Also patch the cached constant in case textual was imported before us.
import textual.constants as _tc  # noqa: E402
if os.environ.get("TEXTUAL_COLOR_SYSTEM") and _tc.COLOR_SYSTEM != os.environ["TEXTUAL_COLOR_SYSTEM"]:
    _tc.COLOR_SYSTEM = os.environ["TEXTUAL_COLOR_SYSTEM"]

# ---------------------------------------------------------------------------
# Rich markup helpers (Textual renders Rich markup in Static/Label widgets)
# ---------------------------------------------------------------------------


def _safe(text: str, maxlen: int = 200) -> str:
    """Truncate and strip control chars for display; escape Rich markup."""
    t = text[:maxlen].replace("\r", "").replace("\n", " ")
    # Escape Rich markup brackets
    t = t.replace("[", "\\[")
    return t


def _short_id(rid: str) -> str:
    return rid[:8] if len(rid) > 8 else rid


def _short_path(p: str) -> str:
    """Show at most the last two path components, with an ellipsis prefix."""
    parts = Path(p).parts
    if len(parts) <= 2:
        return p
    return "..." + os.sep + os.sep.join(parts[-2:])


def _age(ts: float) -> str:
    delta = time.time() - ts
    if delta < 60:
        return f"{int(delta)}s"
    if delta < 3600:
        return f"{int(delta / 60)}m"
    return f"{int(delta / 3600)}h{int((delta % 3600) / 60)}m"


def _relative_time(ts: float) -> str:
    """Human-readable relative timestamp for banners."""
    delta = time.time() - ts
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta / 60)}m ago"
    if delta < 86400:
        return f"{int(delta / 3600)}h ago"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


# Reason code colours (Rich markup colour names)
_REASON_COLOURS: dict[str, str] = {
    "TYPOSQUAT": "magenta",
    "CANARY_TAINT": "yellow",
    "AI_INTENT": "#a29bfe",
    "TRIPWIRE": "red",
    "QUARANTINE": "red",
    "EXFILTRATION": "red",
    "SHELL_ESCALATION": "yellow",
}

# Risk band colours
_BAND_COLOURS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "#e17055",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _coloured_reason(code: str) -> str:
    """Rich markup for a reason code."""
    colour = _REASON_COLOURS.get(code.upper(), "yellow")
    return f"[{colour}]{code}[/{colour}]"


def _event_colour(event: str) -> str:
    """Rich colour hex for an audit event type (explicit hex for SVG fidelity)."""
    e = event.lower()
    if e == "setup":
        return "#636e72"
    if "quarantine" in e or "tripwire" in e:
        return "bold #ff4444"
    if "denied" in e or "deny" in e or "refused" in e:
        return "#ff4444"
    if "escalat" in e:
        return "#fdcb6e"
    if "approved" in e or "approve" in e:
        return "#00b894"
    if "unfreeze" in e:
        return "#0fbcf9"
    if e.startswith("ai_") or "intent" in e or "judge" in e:
        return "#a29bfe"
    if "allowed" in e or "allow" in e:
        return "#636e72"
    return "#b2bec3"


def _event_icon(event: str) -> str:
    """Short glyph for event types (Windows Terminal / Cascadia safe)."""
    e = event.lower()
    if e == "setup":
        return "·"
    if "quarantine" in e or "tripwire" in e:
        return "■"
    if "denied" in e or "deny" in e or "refused" in e:
        return "✗"
    if "escalat" in e:
        return "▲"
    if "approved" in e or "approve" in e:
        return "✓"
    if "unfreeze" in e:
        return "⏸"
    if e.startswith("ai_") or "intent" in e or "judge" in e:
        return "◆"
    return "●"


def _event_badge(event: str) -> str:
    """Short badge label for the event feed."""
    e = event.lower()
    if e == "setup":
        return "SETUP"
    if "quarantine" in e or "tripwire" in e:
        return "FROZEN"
    if "denied" in e or "deny" in e or "refused" in e:
        return "DENY"
    if "escalat" in e:
        return "WAIT"
    if "approved" in e or "approve" in e:
        return "APPROVE"
    if "unfreeze" in e:
        return "RESUME"
    if e.startswith("ai_") or "intent" in e or "judge" in e:
        return "AI"
    if "allowed" in e or "allow" in e:
        return "ALLOW"
    return "EVENT"


# ---------------------------------------------------------------------------
# Explanation reader
# ---------------------------------------------------------------------------

def _read_explanation(layout: Any, record: dict[str, Any]) -> str | None:
    """Read the Gemini explanation text for a record."""
    if layout is None:
        return None
    exp_dir = layout.state_dir / "explanations"
    if not exp_dir.is_dir():
        return None

    exp_id = record.get("explanation_id", record.get("request_id"))
    if exp_id:
        exp_file = exp_dir / f"{exp_id}.json"
        if exp_file.is_file():
            try:
                data = json.loads(exp_file.read_text(encoding="utf-8"))
                return data.get("text") or data.get("explanation") or None
            except (OSError, ValueError):
                pass

    # Fallback: newest file by mtime
    try:
        files = sorted(exp_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
        if files:
            data = json.loads(files[0].read_text(encoding="utf-8"))
            return data.get("text") or data.get("explanation")
    except (OSError, ValueError):
        pass
    return None


def _format_freeze_time(qdata: dict) -> str:
    """Return HH:MM for when the workspace froze, or "?".

    quarantine.json may carry ``since`` (ISO string), ``stopped_at`` /
    ``frozen_at`` / ``ts`` (epoch float).  Never raises: a bad value must
    not crash the dashboard at the moment the human needs it.
    """
    for key in ("since", "frozen_at", "stopped_at", "ts"):
        val = qdata.get(key)
        if val in (None, "", 0):
            continue
        try:
            if isinstance(val, (int, float)):
                return time.strftime("%H:%M", time.localtime(float(val)))
            if isinstance(val, str):
                try:
                    return time.strftime("%H:%M", time.localtime(float(val)))
                except ValueError:
                    import datetime as _dt
                    return _dt.datetime.fromisoformat(val).strftime("%H:%M")
        except (ValueError, OverflowError, OSError, TypeError):
            continue
    return "?"


def _read_quarantine_explanation(layout: Any) -> str | None:
    """Read explanation for the quarantine."""
    if layout is None:
        return None
    qf = layout.state_dir / "quarantine.json"
    if not qf.is_file():
        return None
    try:
        qdata = json.loads(qf.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    exp_id = qdata.get("explanation_id")
    if exp_id:
        exp_dir = layout.state_dir / "explanations"
        exp_file = exp_dir / f"{exp_id}.json"
        if exp_file.is_file():
            try:
                data = json.loads(exp_file.read_text(encoding="utf-8"))
                return data.get("text") or data.get("explanation")
            except (OSError, ValueError):
                pass
    return qdata.get("reason", "")


# ---------------------------------------------------------------------------
# Event feed formatting
# ---------------------------------------------------------------------------

def _format_event(ev: dict[str, Any], etype: str) -> str:
    """Build a readable one-line description for an audit event."""
    e = etype.lower()
    rid = _short_id(ev.get("request_id", "")) if ev.get("request_id") else ""

    # intent_error -> "AI judge unavailable (<error>)"
    if e == "intent_error":
        err = ev.get("error", "unknown")
        return f"AI judge unavailable ({_safe(str(err), 40)})"

    # typosquat_escalated -> "typosquat: <pkg> looks like <target>"
    if e == "typosquat_escalated":
        pkg = ev.get("package", "")
        target = ev.get("target", "")
        if pkg and target:
            return f"typosquat: {_safe(pkg, 20)} looks like {_safe(target, 20)}"
        cmd = ev.get("command", "")
        return f"typosquat {rid} {_safe(cmd, 40)}" if cmd else f"typosquat escalated {rid}"

    # denied -> show the command and who denied
    if "denied" in e or "deny" in e:
        cmd = ev.get("command", "")
        reviewer = ev.get("reviewer_id", "")
        parts = [f"denied {rid}"]
        if cmd:
            parts.append(_safe(cmd, 35))
        if reviewer:
            parts.append(f"by {reviewer}")
        return " ".join(parts)

    # approved -> show command and who
    if "approved" in e or "approve" in e:
        cmd = ev.get("command", "")
        reviewer = ev.get("reviewer_id", "")
        parts = [f"approved {rid}"]
        if cmd:
            parts.append(_safe(cmd, 35))
        if reviewer:
            parts.append(f"by {reviewer}")
        return " ".join(parts)

    # Default: event type + rid + command
    extra = ""
    if rid:
        extra += f" {rid}"
    if ev.get("command"):
        extra += f" {_safe(ev['command'], 40)}"
    if ev.get("reviewer_id"):
        extra += f" by {ev['reviewer_id']}"
    return f"{etype}{extra}"


_SETUP_EVENTS = {
    "policy_version_accepted": "policy loaded",
    "key_pinned": "approver key pinned",
    "folder_initialized": "folder initialised",
    "canaries_planted": "decoys planted",
}


def _effective_type(ev: dict[str, Any]) -> str:
    """Map raw audit event names to what the human cares about.

    ``shell_decided`` carries the outcome in ``state``; setup records
    (policy load, key pin) are shown as a quiet SETUP line.
    """
    etype = str(ev.get("event", ev.get("type", "unknown")))
    e = etype.lower()
    if e.endswith("_decided") or e == "decided":
        state = str(ev.get("state", "")).lower()
        if state in ("approved", "allowed", "approve"):
            return "approved"
        if state in ("denied", "deny", "expired", "timeout", "rejected"):
            return "denied"
    if e in _SETUP_EVENTS:
        return "setup"
    return etype


def _feed_target(ev: dict[str, Any]) -> str:
    """What the action touched: command, else file name, else host."""
    if ev.get("command"):
        return _safe(str(ev["command"]), 60)
    target = str(ev.get("target") or "")
    if target:
        return _safe(Path(target).name or target, 60)
    if ev.get("host"):
        return _safe(str(ev["host"]), 60)
    return ""


def _format_feed_line(ev: dict[str, Any], etype: str) -> str:
    """Compact one-line description for the event feed (badge shows type)."""
    e = etype.lower()
    rid = _short_id(ev.get("request_id", "")) if ev.get("request_id") else ""
    raw = str(ev.get("event", ev.get("type", ""))).lower()

    if e == "setup":
        label = _SETUP_EVENTS.get(raw, raw.replace("_", " "))
        how = ev.get("how")
        return f"[#636e72]{label}{f' ({_safe(str(how), 20)})' if how else ''}[/]"

    if e in ("allowed", "allow"):
        tool = _safe(str(ev.get("tool", "")), 32)
        what = _feed_target(ev)
        return f"[#8a8f98]{tool}[/] {what}".strip() if tool else (what or "allowed")

    if e.endswith("_escalated") and e != "typosquat_escalated":
        code = str(ev.get("reason_code", ""))
        tail = f"  {_coloured_reason(code)}" if code else ""
        return " ".join(p for p in (rid, _feed_target(ev)) if p) + tail

    if e == "intent_error":
        err = ev.get("error", "unknown")
        return f"AI judge unavailable ({_safe(str(err), 40)})"

    if e == "typosquat_escalated":
        pkg = ev.get("package", "")
        target = ev.get("target", "")
        if pkg and target:
            return f"{_safe(pkg, 20)} looks like {_safe(target, 20)}"
        return _safe(ev.get("command", rid), 50)

    # For other events: command + reviewer, no event-type prefix
    cmd = _safe(ev.get("command", ""), 45)
    reviewer = ev.get("reviewer_id", "")
    parts: list[str] = []
    if rid:
        parts.append(rid)
    if cmd:
        parts.append(cmd)
    if reviewer:
        parts.append(f"by {reviewer}")
    return " ".join(parts) if parts else etype


# ---------------------------------------------------------------------------
# Help Modal
# ---------------------------------------------------------------------------

class HelpModal(ModalScreen[None]):
    """Help screen showing all keys and status meanings."""

    BINDINGS = [Binding("escape", "dismiss", "Close"), Binding("question_mark", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-container"):
            yield Label("haltwire watch -- keyboard reference", id="help-title")
            yield Static(
                "\n"
                "[bold #0fbcf9]a[/]  Approve the selected escalation\n"
                "[bold #0fbcf9]d[/]  Deny the selected escalation\n"
                "[bold #0fbcf9]u[/]  Unfreeze the workspace (requires pinned key)\n"
                "[bold #0fbcf9]k[/]  Set / replace the Gemini API key\n"
                "[bold #0fbcf9]j[/]  Toggle the AI intent judge\n"
                "[bold #0fbcf9]r[/]  Refresh all panels now\n"
                "[bold #0fbcf9]?[/]  This help screen\n"
                "[bold #0fbcf9]q[/]  Quit\n"
                "\n"
                "[bold]Status badges:[/]\n"
                "  [black on green] PROTECTED [/]  Normal operation\n"
                "  [bold white on red] FROZEN [/]     Tripwire/quarantine tripped\n"
                "  [black on yellow] TAINTED [/]    Canary seen in output\n"
                "\n"
                "[bold]AI judge:[/]\n"
                "  [#a29bfe]AI ON[/]   Gemini reviews every escalation\n"
                "  [#8a8f98]AI OFF[/]  Rules still protect; no AI opinion\n"
                "\n"
                "[bold]Key storage:[/]\n"
                "  SANDBOX_KEY_HOME or platform default\n"
                "  Env GEMINI_API_KEY takes precedence over file\n"
            )
            yield Label("[#8a8f98]Press Escape to close.[/]")


# ---------------------------------------------------------------------------
# Key Modal
# ---------------------------------------------------------------------------

class KeyModal(ModalScreen[str | None]):
    """Modal for entering/testing a Gemini API key."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        from sandbox.connector.aikey import get_key, key_source, mask

        current = get_key()
        src = key_source()
        hint = ""
        if current and src:
            hint = f"Current: {mask(current)} from {src}"

        with Vertical(id="key-modal-container"):
            yield Label("Gemini API Key", id="key-modal-title")
            if hint:
                yield Label(hint, id="key-current")
            yield Label("")
            yield Input(placeholder="Paste your API key...", password=True, id="key-input")
            yield Label("", id="key-status")
            yield Static(
                "[bold #0fbcf9]Enter[/] Test & save    [#8a8f98]Escape[/] Cancel"
            )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted, "#key-input")
    def on_submit(self, event: Input.Submitted) -> None:
        key = event.value.strip()
        if not key:
            lbl = self.query_one("#key-status", Label)
            lbl.update("[red]Key cannot be empty.[/]")
            return
        self._test_and_save(key)

    @work(thread=True)
    def _test_and_save(self, key: str) -> None:
        from sandbox.connector.aikey import InvalidKeyError, mask, set_key, test_key

        status_label = self.query_one("#key-status", Label)

        try:
            from sandbox.connector.aikey import _validate
            _validate(key)
        except InvalidKeyError as exc:
            self.app.call_from_thread(status_label.update, f"[red]Invalid: {exc}[/]")
            return

        self.app.call_from_thread(status_label.update, "[yellow]Testing key...[/]")

        try:
            err = test_key(key)
        except Exception as exc:
            err = str(exc)

        if err:
            self.app.call_from_thread(status_label.update, f"[red]Failed: {err}[/]")
            return

        try:
            set_key(key)
            masked = mask(key)
            self.app.call_from_thread(status_label.update, f"[green]Saved: {masked}[/]")
            import time as _time
            _time.sleep(0.6)
            self.app.call_from_thread(self.dismiss, key)
        except OSError as exc:
            self.app.call_from_thread(status_label.update, f"[red]Save failed: {exc}[/]")


# ---------------------------------------------------------------------------
# Unfreeze Modal
# ---------------------------------------------------------------------------

class UnfreezeModal(ModalScreen[str | None]):
    """Modal for entering a reviewer id to unfreeze."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="unfreeze-modal-container"):
            yield Label("Unfreeze Workspace", id="unfreeze-title")
            yield Label("Reviewer id (must have a pinned signing key):")
            yield Input(placeholder="reviewer-id", id="unfreeze-input")
            yield Label("", id="unfreeze-status")
            yield Static(
                "[bold #0fbcf9]Enter[/] Unfreeze    [#8a8f98]Escape[/] Cancel\n"
                "[#8a8f98]No pinned key? Run haltwire keys pin <id>[/]"
            )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted, "#unfreeze-input")
    def on_submit(self, event: Input.Submitted) -> None:
        reviewer = event.value.strip()
        if not reviewer:
            self.query_one("#unfreeze-status", Label).update(
                "[red]Reviewer id required.[/]"
            )
            return
        self.dismiss(reviewer)


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class HaltwireApp(App[None]):
    """The haltwire watch dashboard."""

    CSS_PATH = "styles.tcss"
    TITLE = "haltwire"

    BINDINGS = [
        Binding("a", "approve", "Approve", show=True),
        Binding("d", "deny_selected", "Deny", show=True),
        Binding("u", "unfreeze", "Unfreeze", show=True),
        Binding("k", "set_key", "Key", show=True),
        Binding("j", "toggle_judge", "AI", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("question_mark", "help_screen", "?Help", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(
        self,
        watch_path: str = ".",
        reviewer: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._watch_path = watch_path
        self._reviewer = reviewer
        self._layout: Any = None
        self._pending: list[dict[str, Any]] = []
        self._selected_rid: str | None = None
        self._event_stats: dict[str, int] = {"allowed": 0, "denied": 0, "ai": 0}

    def compose(self) -> ComposeResult:
        with Horizontal(id="header-bar"):
            yield Static(" haltwire ", id="header-title")
            yield Static("", id="header-path")
            yield Static("", id="header-status")
            yield Static("", id="header-ai")
        yield Static("", id="stats-strip")
        yield Static("", id="frozen-banner", classes="banner-hidden")
        yield Static("", id="tainted-banner", classes="banner-hidden")
        with Horizontal(id="main-area"):
            with Vertical(id="left-column"):
                with Vertical(id="pending-panel"):
                    yield DataTable(id="escalation-table")
                    yield Static("", id="pending-empty", classes="hidden")
                with Vertical(id="feed-panel"):
                    yield Static("", id="event-feed")
            with VerticalScroll(id="detail-scroll", can_focus=True):
                yield Static("", id="detail-pane")
        yield Footer()

    def on_mount(self) -> None:
        from sandbox.connector.layout import FolderLayout

        self._layout = FolderLayout.discover(self._watch_path)
        if self._layout is None:
            self.query_one("#header-path", Static).update(
                f"No .sandbox/ in {os.path.abspath(self._watch_path)}"
            )
            self.query_one("#header-status", Static).update(" NO SANDBOX ")
            return

        if self._reviewer is None:
            from sandbox.connector.approval import default_reviewer
            self._reviewer = default_reviewer()

        self.query_one("#header-path", Static).update(
            _short_path(str(self._layout.root))
        )

        # Panel border titles
        self.query_one("#pending-panel", Vertical).border_title = "Waiting for you"
        self.query_one("#detail-scroll", VerticalScroll).border_title = "Details"
        self.query_one("#feed-panel", Vertical).border_title = "Live activity"

        table = self.query_one("#escalation-table", DataTable)
        # Fixed-width columns: ID(9)+Age(5)+Tool(6)+Reason(14)+AI(4) = 38
        # Plus ~6 for cell padding/borders. Command gets the rest.
        table.add_column("ID", width=8)
        table.add_column("Age", width=4)
        table.add_column("Tool", width=5)
        table.add_column("Command", width=22)
        table.add_column("Reason", width=14)
        table.add_column("AI", width=4)
        table.cursor_type = "row"

        self._do_refresh()
        self.set_interval(1.0, self._do_refresh)

    def _do_refresh(self) -> None:
        if self._layout is None:
            return
        # Each panel refreshes independently: a bad record or file must never
        # take the whole dashboard down while a human is watching it.
        for _refresh in (self._refresh_header, self._refresh_banners,
                         self._refresh_pending, self._refresh_events,
                         self._refresh_stats):
            try:
                _refresh()
            except Exception as exc:  # noqa: BLE001
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "dashboard refresh %s failed: %s", _refresh.__name__, exc)

    # --- header ---

    def _refresh_header(self) -> None:
        if self._layout is None:
            return

        status_w = self.query_one("#header-status", Static)
        ai_w = self.query_one("#header-ai", Static)

        qf = self._layout.state_dir / "quarantine.json"
        taint_file = self._layout.state_dir / "canary_taint.json"

        if qf.is_file():
            try:
                qdata = json.loads(qf.read_text(encoding="utf-8"))
                kind = qdata.get("trip_kind", "")
                label = f" FROZEN ({kind}) " if kind else " FROZEN "
            except (OSError, ValueError):
                label = " FROZEN "
            status_w.update(label)
            status_w.set_classes("badge-frozen")
        elif taint_file.is_file():
            status_w.update(" TAINTED ")
            status_w.set_classes("badge-tainted")
        else:
            status_w.update(" PROTECTED ")
            status_w.set_classes("badge-protected")

        from sandbox.connector.aikey import get_key, key_source
        ks = key_source()
        try:
            from sandbox.connector.policy import load_policy
            _intent = getattr(load_policy(self._layout.policy_file), "intent", None)
            judge_on = bool(getattr(_intent, "enabled", False))
        except Exception:  # noqa: BLE001
            judge_on = False
        # "on" only when the hook will really call the judge: key AND policy.
        if ks and judge_on:
            ai_w.update(" AI judge: on ")
            ai_w.set_classes("ai-on")
        elif ks:
            ai_w.update(" AI: off - press j ")
            ai_w.set_classes("ai-nokey")
        elif judge_on:
            ai_w.update(" AI: no key - press k ")
            ai_w.set_classes("ai-nokey")
        else:
            ai_w.update(" AI: off - press k ")
            ai_w.set_classes("ai-nokey")

    # --- banners ---

    def _refresh_banners(self) -> None:
        if self._layout is None:
            return

        frozen_b = self.query_one("#frozen-banner", Static)
        tainted_b = self.query_one("#tainted-banner", Static)

        qf = self._layout.state_dir / "quarantine.json"
        taint_file = self._layout.state_dir / "canary_taint.json"

        if qf.is_file():
            try:
                qdata = json.loads(qf.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                qdata = {}
            # Line 1: action hint (always visible, never truncated)
            line1 = "WORKSPACE FROZEN -- press u to unfreeze"
            # Line 2: what tripped + optional AI summary
            trigger = qdata.get("trigger", "")
            ts_str = _format_freeze_time(qdata)
            what = trigger or qdata.get("reason", qdata.get("trip_kind", "tripwire"))
            line2 = f"{what} at {ts_str}"
            ai_text = _read_quarantine_explanation(self._layout)
            if ai_text and qdata.get("explanation_id"):
                first_sentence = ai_text.split(".")[0].strip()
                if first_sentence:
                    line2 += f"  |  AI: {first_sentence}"
            frozen_b.update(f" {line1}\n {line2}")
            frozen_b.remove_class("banner-hidden")
            tainted_b.add_class("banner-hidden")
        elif taint_file.is_file():
            tainted_b.update(
                " TAINTED -- press u to clear | canary seen in output | network calls need approval "
            )
            tainted_b.remove_class("banner-hidden")
            frozen_b.add_class("banner-hidden")
        else:
            frozen_b.add_class("banner-hidden")
            tainted_b.add_class("banner-hidden")

    # --- pending table ---

    def _all_clear_text(self) -> str:
        """Build the detail pane text when there are no pending escalations.

        Shows a green "All clear" header plus the last 5 decisions from the
        done directory so the reviewer can see recent activity.
        """
        parts: list[str] = [
            "[bold #00b894]All clear[/]",
            "[#636e72]Nothing pending -- agent is running freely.[/]\n",
        ]
        if self._layout:
            done_dir = self._layout.done_dir
            if done_dir.is_dir():
                try:
                    done_files = sorted(
                        done_dir.glob("*.json"),
                        key=lambda f: f.stat().st_mtime,
                        reverse=True,
                    )[:5]
                except OSError:
                    done_files = []
                if done_files:
                    parts.append("[bold]Recent decisions:[/]")
                    for df in done_files:
                        try:
                            rec = json.loads(df.read_text(encoding="utf-8"))
                            decision = rec.get("decision", rec.get("state", "?"))
                            cmd = rec.get("command", "")[:40]
                            reviewer = rec.get("reviewer_id", "?")
                            dc = "green" if "approv" in str(decision).lower() else "red"
                            icon = "✓" if "approv" in str(decision).lower() else "✗"
                            parts.append(
                                f"  [{dc}]{icon} {decision}[/{dc}] {_safe(cmd, 40)} by {reviewer}"
                            )
                        except (OSError, json.JSONDecodeError):
                            pass
        return "\n".join(parts)

    def _refresh_pending(self) -> None:
        if self._layout is None:
            return
        from sandbox.connector.queue import EscalationQueue

        queue = EscalationQueue(self._layout)
        self._pending = queue.list_pending()

        table = self.query_one("#escalation-table", DataTable)
        table.clear()

        # Update panel title with count
        try:
            panel = self.query_one("#pending-panel", Vertical)
            n = len(self._pending)
            panel.border_title = f"Waiting for you ({n})" if n else "Waiting for you"
        except Exception:
            pass

        # Toggle empty-state message
        try:
            empty_w = self.query_one("#pending-empty", Static)
            if not self._pending:
                empty_w.update(
                    "[#636e72]  Nothing waiting -- agent running freely[/]"
                )
                empty_w.remove_class("hidden")
            else:
                empty_w.add_class("hidden")
        except Exception:
            pass

        if not self._pending:
            detail = self.query_one("#detail-pane", Static)
            detail.update(self._all_clear_text())
            # Reset detail panel border
            try:
                ds = self.query_one("#detail-scroll", VerticalScroll)
                ds.border_title = "Details"
                ds.styles.border = ("solid", "#2d3436")
            except Exception:
                pass
            return

        for rec in self._pending:
            rid = rec.get("request_id", "?")
            ts = rec.get("created_at", 0)
            tool = rec.get("tool_name", rec.get("kind", ""))[:12]
            cmd = rec.get("command", rec.get("path", rec.get("url", "")))
            reason = rec.get("reason_code", "")
            verdict = rec.get("ai_verdict", {})
            ai_flag = ""
            if isinstance(verdict, dict) and verdict.get("flag"):
                ai_flag = "AI!"
            elif rec.get("ai_reason"):
                ai_flag = "AI!"

            table.add_row(
                _short_id(rid),
                _age(ts),
                tool,
                cmd[:19] + ("..." if len(cmd) > 19 else ""),
                reason,
                ai_flag,
                key=rid,
            )

        if self._selected_rid:
            try:
                idx = next(
                    i for i, r in enumerate(self._pending)
                    if r.get("request_id") == self._selected_rid
                )
                table.move_cursor(row=idx)
            except (StopIteration, Exception):
                pass

    # --- detail pane ---

    @on(DataTable.RowSelected)
    @on(DataTable.RowHighlighted)
    def on_row_event(self, event: DataTable.RowHighlighted | DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        rid = str(event.row_key.value)
        self._selected_rid = rid
        rec = next((r for r in self._pending if r.get("request_id") == rid), None)
        if rec is not None:
            self._show_detail(rec)

    def _show_detail(self, rec: dict[str, Any]) -> None:
        detail = self.query_one("#detail-pane", Static)

        # Update detail panel border colour by severity
        risk = rec.get("risk", {})
        band = str(risk.get("band", "")).upper()
        try:
            ds = self.query_one("#detail-scroll", VerticalScroll)
            if band == "CRITICAL":
                ds.styles.border = ("solid", "#d63031")
                ds.border_title = f"Details -- {band}"
            elif band == "HIGH":
                ds.styles.border = ("solid", "#e17055")
                ds.border_title = f"Details -- {band}"
            elif band == "MEDIUM":
                ds.styles.border = ("solid", "#fdcb6e")
                ds.border_title = f"Details -- {band}"
            else:
                ds.styles.border = ("solid", "#2d3436")
                ds.border_title = "Details"
        except Exception:
            pass

        parts: list[str] = []

        rid = rec.get("request_id", "?")
        parts.append(f"[bold #0fbcf9]Request:[/] {rid}")

        # Command
        cmd = rec.get("command", rec.get("path", rec.get("url", "")))
        parts.append(f"[bold]Command:[/]")
        parts.append(f"[on #2d3436] {_safe(cmd, 300)} [/]")

        # Why stopped
        triggers = rec.get("trigger", [])
        reason = rec.get("reason_code", "")
        parts.append(f"[bold]Why stopped:[/] {_coloured_reason(reason)}")
        if triggers:
            parts.append(f"  Trigger: {', '.join(str(t) for t in triggers)}")

        # Risk
        risk = rec.get("risk", {})
        if risk:
            band = str(risk.get("band", "?")).upper()
            score = risk.get("score", "?")
            bc = _BAND_COLOURS.get(band, "white")
            parts.append(f"  Risk: {score}/100 [{bc}]{band}[/{bc}]")
            if rec.get("requires_dual"):
                parts.append("  [bold red]** DUAL CONTROL **[/]")
            for f in sorted(risk.get("factors", []), key=lambda x: -abs(x.get("points", 0))):
                sign = "+" if f.get("points", 0) >= 0 else ""
                parts.append(f"    {sign}{f.get('points'):>3} {f.get('name', '')}")
        parts.append("")

        # AI judge
        verdict = rec.get("ai_verdict", {})
        if isinstance(verdict, dict) and (verdict.get("flag") or verdict.get("reason")):
            conf = verdict.get("confidence", 0)
            parts.append(f"[bold #a29bfe]AI Judge:[/] [#a29bfe]{_safe(verdict.get('reason', ''), 200)}[/]")
            parts.append(f"  Confidence: {conf:.0%}")
        elif rec.get("ai_reason"):
            parts.append(f"[bold #a29bfe]AI Judge:[/] [#a29bfe]{_safe(str(rec['ai_reason']), 200)}[/]")

        # Explanation text (labelled as AI advisory per F3)
        explanation = _read_explanation(self._layout, rec)
        if explanation:
            parts.append(f"[bold #a29bfe]AI analysis (advisory):[/]")
            parts.append(f"[dim #a29bfe]{_safe(explanation, 400)}[/]")

        # Agent description
        if rec.get("described_as"):
            parts.append(f"[bold]Agent says:[/] {_safe(rec['described_as'])}")

        # Action keys (prominent button-style)
        parts.append(
            "[bold white on #0984e3] a [/] [bold]APPROVE[/]    "
            "[bold white on #d63031] d [/] [bold]DENY[/]"
        )
        detail.update("\n".join(parts))

    # --- event feed ---

    def _refresh_events(self) -> None:
        if self._layout is None:
            return

        events: list[dict[str, Any]] = []
        audit_dir = self._layout.audit_dir
        if audit_dir.is_dir():
            for session_dir in sorted(audit_dir.iterdir()):
                if not session_dir.is_dir():
                    continue
                rf = session_dir / "records.jsonl"
                if rf.is_file():
                    try:
                        for line in rf.read_text(encoding="utf-8").strip().splitlines()[-30:]:
                            try:
                                events.append(json.loads(line))
                            except (json.JSONDecodeError, ValueError):
                                pass
                    except OSError:
                        pass

        events.sort(key=lambda e: e.get("ts", e.get("timestamp", 0)))

        # Compute stats from all events (before slicing for display)
        stats: dict[str, int] = {"allowed": 0, "denied": 0, "ai": 0}
        for ev in events:
            et = _effective_type(ev).lower()
            if "allowed" in et or "allow" in et:
                stats["allowed"] += 1
            if "denied" in et or "refuse" in et:
                stats["denied"] += 1
            if et.startswith("ai_") or "intent" in et:
                stats["ai"] += 1
        self._event_stats = stats

        events = events[-30:]

        # Update feed panel title
        try:
            fp = self.query_one("#feed-panel", Vertical)
            fp.border_title = "Live activity"
        except Exception:
            pass

        feed = self.query_one("#event-feed", Static)
        if not events:
            feed.update(
                "[#636e72]No activity recorded yet.  "
                "Waiting for the agent to start...[/]"
            )
            return

        # Decisions carry only request_id: borrow the command from the
        # escalation.  A typosquat_escalated line is followed by the
        # shell_escalated for the same command: show only the latter.
        cmd_by_rid: dict[str, str] = {}
        for ev in events:
            if ev.get("request_id") and ev.get("command"):
                cmd_by_rid[ev["request_id"]] = ev["command"]
        shown: list[dict[str, Any]] = []
        for i, ev in enumerate(events):
            raw = str(ev.get("event", "")).lower()
            nxt = events[i + 1] if i + 1 < len(events) else {}
            if (raw == "typosquat_escalated"
                    and str(nxt.get("event", "")).lower().endswith("_escalated")
                    and nxt.get("command") == ev.get("command")):
                continue
            if not ev.get("command") and ev.get("request_id") in cmd_by_rid:
                ev = {**ev, "command": cmd_by_rid[ev["request_id"]]}
            shown.append(ev)
        events = shown
        try:
            self.query_one("#feed-panel", Vertical).border_title = (
                f"Live activity ({len(events)})")
        except Exception:
            pass

        lines: list[str] = []
        for ev in events:
            etype = _effective_type(ev)
            ts = ev.get("ts", ev.get("timestamp", 0))
            try:
                ts_str = time.strftime("%H:%M:%S", time.localtime(float(ts))) if ts else "--:--:--"
            except (TypeError, ValueError, OverflowError, OSError):
                ts_str = "--:--:--"
            colour = _event_colour(etype)
            icon = _event_icon(etype)
            badge = _event_badge(etype)
            desc = _format_feed_line(ev, etype)
            lines.append(
                f"[#8a8f98]{ts_str}[/]  [{colour}]{icon} {badge:<7s}[/{colour}]  {desc}"
            )

        feed.update("\n".join(lines[-20:]))

    # --- stats strip ---

    def _refresh_stats(self) -> None:
        """Update the stats strip with counts from audit + pending queue."""
        strip = self.query_one("#stats-strip", Static)
        allowed = self._event_stats.get("allowed", 0)
        denied = self._event_stats.get("denied", 0)
        waiting = len(self._pending)
        ai = self._event_stats.get("ai", 0)

        parts: list[str] = []
        parts.append(f"[#00b894]✓ {allowed} allowed[/]")
        parts.append(f"[#d63031]✗ {denied} denied[/]")
        if waiting > 0:
            parts.append(f"[bold #fdcb6e]▲ {waiting} waiting[/]")
        else:
            parts.append(f"[#636e72]▲ 0 waiting[/]")
        if ai > 0:
            parts.append(f"[#a29bfe]◆ {ai} AI[/]")
        strip.update("  " + "    ".join(parts))

    # --- actions ---

    def action_approve(self) -> None:
        if not self._selected_rid or not self._layout:
            self.notify("No escalation selected.", severity="warning")
            return
        self._do_approve(self._selected_rid)

    @work(thread=True)
    def _do_approve(self, rid: str) -> None:
        import asyncio
        from sandbox.connector.approval import approve

        try:
            outcome = asyncio.run(approve(self._layout, rid, self._reviewer))
        except Exception as exc:
            self.app.call_from_thread(self.notify, f"Approve failed: {exc}", severity="error")
            return

        status = outcome.get("status", "")
        if status == "awaiting_second":
            self.app.call_from_thread(
                self.notify, "Approval 1/2 (dual control). Second reviewer needed.",
                severity="information",
            )
        elif status == "same_reviewer":
            self.app.call_from_thread(
                self.notify, "Dual control: different reviewer must approve.",
                severity="warning",
            )
        elif status == "not_pending":
            self.app.call_from_thread(self.notify, "Already taken.", severity="warning")
        elif status == "key_unavailable":
            self.app.call_from_thread(
                self.notify, f"No signing key: {outcome.get('reason', '')}",
                severity="error",
            )
        elif status == "reason_required":
            self.app.call_from_thread(
                self.notify, "Oversight requires a reason. Use CLI.",
                severity="warning",
            )
        else:
            ec = outcome.get("result", {}).get("exit_code", "?")
            self.app.call_from_thread(
                self.notify, f"Approved {_short_id(rid)} (exit {ec})",
                severity="information",
            )
        self.app.call_from_thread(self._do_refresh)

    def action_deny_selected(self) -> None:
        if not self._selected_rid or not self._layout:
            self.notify("No escalation selected.", severity="warning")
            return
        self._do_deny(self._selected_rid)

    @work(thread=True)
    def _do_deny(self, rid: str) -> None:
        from sandbox.connector.broker import FolderBroker
        from sandbox.connector.queue import EscalationQueue

        queue = EscalationQueue(self._layout)
        claimed = queue.claim(rid, self._reviewer)
        if claimed is None:
            self.app.call_from_thread(self.notify, "Could not claim.", severity="warning")
            return
        queue.finish(rid, FolderBroker.denial(claimed, self._reviewer, "denied via TUI"))
        self.app.call_from_thread(self.notify, f"Denied {_short_id(rid)}.", severity="information")
        self.app.call_from_thread(self._do_refresh)

    def action_unfreeze(self) -> None:
        if not self._layout:
            self.notify("No sandbox.", severity="warning")
            return
        self.push_screen(UnfreezeModal(), self._handle_unfreeze)

    def _handle_unfreeze(self, reviewer: str | None) -> None:
        if not reviewer:
            return
        self._do_unfreeze(reviewer)

    @work(thread=True)
    def _do_unfreeze(self, reviewer: str) -> None:
        if not self._layout:
            return
        import json as _json

        from sandbox.connector.audit import FolderAudit
        from sandbox.connector.signing import sign_record

        qf = self._layout.state_dir / "quarantine.json"
        taint_file = self._layout.state_dir / "canary_taint.json"

        if not qf.is_file() and not taint_file.is_file():
            self.app.call_from_thread(self.notify, "Not frozen.", severity="warning")
            return

        qdata: dict = {}
        if qf.is_file():
            try:
                qdata = _json.loads(qf.read_text(encoding="utf-8"))
            except Exception:
                qdata = {}

        from sandbox.connector import keyhome
        try:
            pinned = keyhome.get_pinned_key(self._layout, reviewer)
        except keyhome.KeyHomeError as exc:
            self.app.call_from_thread(
                self.notify,
                f"Key home error: {exc}. Run haltwire keys pin {reviewer}.",
                severity="error",
            )
            return

        if pinned is None:
            self.app.call_from_thread(
                self.notify,
                f"No pinned key for {reviewer}. Run haltwire keys pin {reviewer}.",
                severity="error",
            )
            return

        record: dict[str, Any] = {
            "event": "unfreeze",
            "reviewer_id": reviewer,
            "quarantine_reason": qdata.get("reason", ""),
            "quarantine_trip_kind": qdata.get("trip_kind", ""),
            "was_frozen": qf.is_file(),
            "cleared_canary_taint": taint_file.is_file(),
            "unfrozen_at": time.time(),
        }
        try:
            sign_record(self._layout, reviewer, record)
        except Exception as exc:
            self.app.call_from_thread(self.notify, f"Sign failed: {exc}", severity="error")
            return

        if record.get("signer_public_key") != pinned:
            self.app.call_from_thread(
                self.notify, "Key mismatch: signing key != pinned key.", severity="error"
            )
            return

        session_id = ""
        try:
            session = _json.loads(self._layout.session_file.read_text(encoding="utf-8"))
            session_id = session.get("session_id", "")
        except Exception:
            pass

        audit = FolderAudit(self._layout.audit_dir, session_id or "unfreeze")
        audit.append(record)

        if qf.is_file():
            qf.unlink()
        if taint_file.is_file():
            taint_file.unlink()
        legacy = self._layout.base / "tripwire_stop"
        if legacy.is_file():
            legacy.unlink()

        self.app.call_from_thread(
            self.notify, f"Unfrozen by {reviewer}.", severity="information"
        )
        self.app.call_from_thread(self._do_refresh)

    def action_set_key(self) -> None:
        self.push_screen(KeyModal(), self._handle_key_set)

    def _handle_key_set(self, result: str | None) -> None:
        if result:
            from sandbox.connector.aikey import mask
            self.notify(f"Key saved: {mask(result)}", severity="information")
        self._do_refresh()

    def action_toggle_judge(self) -> None:
        if not self._layout:
            self.notify("No sandbox.", severity="warning")
            return

        from sandbox.connector.policy import load_policy
        pol = load_policy(self._layout.policy_file)
        intent_cfg = getattr(pol, "intent", None)
        currently_on = getattr(intent_cfg, "enabled", False) if intent_cfg else False

        if currently_on:
            self.notify(
                "Turning AI off is a loosening change. "
                "Use haltwire policy set intent.enabled false with a second reviewer.",
                severity="warning",
            )
        else:
            from sandbox.connector.aikey import get_key
            if not get_key():
                self.notify("No Gemini API key. Press k to set one first.", severity="warning")
                return
            # Turning the judge on only tightens the policy, so one reviewer
            # (the human at this keyboard) is enough; it is recorded as a
            # policy version like `haltwire ai on`.
            try:
                from sandbox.connector.approval import default_reviewer
                from sandbox.connector.policy_versions import apply_edit

                pol.intent.enabled = True
                out = apply_edit(self._layout, pol, default_reviewer(), "ai on (watch: j)")
                if out.get("status") == "proposed":
                    self.notify("AI judge change proposed; a second reviewer must approve it.",
                                severity="warning")
                else:
                    self.notify("AI judge on: shell, write and network calls are now checked.",
                                severity="information")
            except Exception as exc:  # noqa: BLE001 - never crash the dashboard
                self.notify(f"Could not turn the AI judge on: {exc}. Run: haltwire ai on",
                            severity="error")
        self._do_refresh()

    def action_refresh(self) -> None:
        self._do_refresh()

    def action_help_screen(self) -> None:
        self.push_screen(HelpModal())
