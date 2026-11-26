"""The header shows the judge as on only when the hook will call it.

Live (26 Nov): a saved key made the header say "AI judge: on" while the
folder policy had intent.enabled false, and `j` only showed a hint, so no
judgement was ever made.
"""
from __future__ import annotations

import os

os.environ.setdefault("TEXTUAL_COLOR_SYSTEM", "truecolor")

import pytest

from sandbox.connector.install import init_folder
from sandbox.connector.layout import FolderLayout
from sandbox.connector.policy import load_policy

FAKE_KEY = "AIza" + "x" * 35  # shape only; never sent anywhere in this test


@pytest.fixture
def folder(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
    init_folder(tmp_path, claude=False, mcp=False, no_canaries=True)
    return tmp_path


async def test_key_without_policy_is_not_on(folder):
    from sandbox.tui.app import HaltwireApp

    app = HaltwireApp(str(folder))
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.pause(1.0)
        text = str(app.query_one("#header-ai").render())
        assert "AI judge: on" not in text
        assert "press j" in text


async def test_j_turns_judge_on(folder):
    from sandbox.tui.app import HaltwireApp

    app = HaltwireApp(str(folder))
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.pause(0.5)
        await pilot.press("j")
        await pilot.pause(1.0)
        lay = FolderLayout.discover(str(folder))
        assert load_policy(lay.policy_file).intent.enabled is True
        assert "AI judge: on" in str(app.query_one("#header-ai").render())


async def test_pending_message_guides_agents_without_mcp():
    from sandbox.connector.hook_eval import _format_pending

    msg = _format_pending("abc123", "SHELL")
    assert "check_request" in msg
    assert "do not have that tool" in msg
