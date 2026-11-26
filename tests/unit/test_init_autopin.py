"""`init` pins the person running it as the first reviewer.

Live pilot friction: after a freeze, pressing u in `watch` asked for a
reviewer with a pinned key, and a fresh folder had none.
"""
from __future__ import annotations

from click.testing import CliRunner

from sandbox.cli.main import cli
from sandbox.connector import keyhome
from sandbox.connector.layout import FolderLayout


def test_init_pins_current_reviewer(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_REVIEWER", "pilotdev")
    r = CliRunner().invoke(cli, ["init", str(tmp_path), "--no-claude", "--no-mcp", "--no-canaries"])
    assert r.exit_code == 0, r.output
    lay = FolderLayout(tmp_path)
    assert keyhome.get_pinned_key(lay, "pilotdev")
    assert "pilotdev" in r.output


def test_reinit_never_replaces_existing_pin(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_REVIEWER", "first")
    CliRunner().invoke(cli, ["init", str(tmp_path), "--no-claude", "--no-mcp", "--no-canaries"])
    lay = FolderLayout(tmp_path)
    before = keyhome.read_pins(lay)
    monkeypatch.setenv("SANDBOX_REVIEWER", "second")
    r = CliRunner().invoke(cli, ["init", str(tmp_path), "--no-claude", "--no-mcp", "--no-canaries"])
    assert r.exit_code == 0, r.output
    assert keyhome.read_pins(lay) == before
    assert keyhome.get_pinned_key(lay, "second") is None
