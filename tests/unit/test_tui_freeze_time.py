"""Regression: the watch dashboard crashed when the workspace froze.

tripwire.quarantine() writes quarantine.json with ``since`` as an ISO
string and ``stopped_at`` as an epoch float.  The TUI passed the ISO
string to time.localtime() and died with TypeError exactly when the
human needed it (found in the live Windows Terminal test of 0.1.3).
"""
from __future__ import annotations

import os

os.environ.setdefault("TEXTUAL_COLOR_SYSTEM", "truecolor")

import json
import time

import pytest

from sandbox.tui.app import _format_freeze_time


def test_iso_since():
    assert _format_freeze_time({"since": "2026-11-26T06:22:37"}) == "06:22"


def test_epoch_stopped_at():
    ts = time.mktime((2026, 11, 26, 6, 22, 37, 0, 0, -1))
    assert _format_freeze_time({"stopped_at": ts}) == "06:22"


def test_real_quarantine_shape():
    q = {
        "reason": "tripwire_stop",
        "session_id": "s-2026-11-26-459b37",
        "stopped_at": 1795654357.578,
        "trip_kind": "decoy_read",
        "since": "2026-11-26T06:22:37",
        "trigger": ".aws/credentials.bak",
        "explanation_id": "tw-f3fd72d8",
    }
    assert _format_freeze_time(q) == "06:22"


@pytest.mark.parametrize("bad", [
    {}, {"since": "not-a-time"}, {"since": None}, {"ts": "abc"},
    {"stopped_at": 1e30}, {"since": ["x"]},
])
def test_bad_values_never_raise(bad):
    assert isinstance(_format_freeze_time(bad), str)


@pytest.mark.asyncio
async def test_dashboard_survives_real_quarantine_json(tmp_path):
    """Mount the app on a workspace frozen with the real quarantine shape."""
    from sandbox.connector.install import init_folder
    from sandbox.connector.layout import FolderLayout
    from sandbox.tui.app import HaltwireApp

    init_folder(tmp_path, claude=False, mcp=False, no_canaries=True)
    lay = FolderLayout.discover(str(tmp_path))
    (lay.state_dir / "quarantine.json").write_text(json.dumps({
        "reason": "tripwire_stop", "stopped_at": time.time(),
        "trip_kind": "decoy_read", "since": "2026-11-26T06:22:37",
        "trigger": ".aws/credentials.bak", "explanation_id": "tw-missing",
    }), encoding="utf-8")

    app = HaltwireApp(str(tmp_path))
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.pause(1.5)
        banner = str(app.query_one("#frozen-banner").render())
        assert "press u to unfreeze" in banner
        assert ".aws/credentials.bak" in banner
        assert "06:22" in banner


@pytest.mark.asyncio
async def test_one_failing_panel_does_not_kill_dashboard(tmp_path, monkeypatch):
    from sandbox.connector.install import init_folder
    from sandbox.tui import app as app_mod

    init_folder(tmp_path, claude=False, mcp=False, no_canaries=True)
    calls = {"pending": 0}

    def boom(self):
        raise TypeError("simulated bad record")

    orig_pending = app_mod.HaltwireApp._refresh_pending

    def counting_pending(self):
        calls["pending"] += 1
        return orig_pending(self)

    monkeypatch.setattr(app_mod.HaltwireApp, "_refresh_banners", boom)
    monkeypatch.setattr(app_mod.HaltwireApp, "_refresh_pending", counting_pending)
    app = app_mod.HaltwireApp(str(tmp_path))
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.pause(2.5)
        assert app.is_running
        assert calls["pending"] >= 2
