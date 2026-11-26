"""`haltwire ai` / `sandbox ai`: manage the AI intent judge.

Approver CLI: a human runs it, never the agent (classify denies it).
"""
from __future__ import annotations

import os

import click


@click.group("ai")
def ai_group() -> None:
    """AI intent judge: Gemini-based raise-only security check on tool calls."""


def _layout(path: str):
    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found. Run `haltwire init` first.")
        raise SystemExit(1)
    return layout


def _key_info() -> tuple[str | None, str]:
    """Return (source, display) for the Gemini key.

    *source* is ``"env"``, ``"file"`` or ``None``.
    *display* is e.g. ``"env (AIza...abcd)"`` or ``"not set ..."``.
    """
    from sandbox.connector.aikey import get_key, key_source, mask

    src = key_source()
    key = get_key()
    masked = mask(key)
    if src:
        return src, f"{src} ({masked})"
    return None, (
        "not set -- press k in `haltwire watch` or set "
        "$env:GEMINI_API_KEY"
    )


def _genai_installed() -> bool:
    """True if the google-genai package is importable."""
    try:
        import google.genai  # noqa: F401
        return True
    except ImportError:
        return False


@ai_group.command("on")
@click.argument("path", default=None, required=False)
@click.option("--path", "opt_path", default=".", help="Project folder.")
@click.option("--timeout", "timeout_s", type=int, default=None,
              help="Judge timeout in seconds (1..20, default 8).")
def ai_on(path: str | None, opt_path: str, timeout_s: int | None) -> None:
    """Enable the AI intent judge (tightening change: one reviewer is enough)."""
    from sandbox.connector.policy import load_policy

    path = path if path is not None else opt_path
    layout = _layout(path)
    policy = load_policy(layout.policy_file)

    policy.intent.enabled = True
    if timeout_s is not None:
        policy.intent.timeout_seconds = max(1, min(20, timeout_s))

    from sandbox.cli.connector_cmds import _save_edit
    from sandbox.connector.approval import default_reviewer

    actor = default_reviewer()
    ok = _save_edit(layout, policy, f"ai on (timeout={policy.intent.timeout_seconds}s)", actor)
    if ok:
        click.echo(f"AI intent judge enabled (timeout {policy.intent.timeout_seconds}s).")
    else:
        click.echo("AI intent judge change proposed (see above).")

    # Key visibility
    src, display = _key_info()
    if src:
        click.echo(f"Gemini key:    {display}")
    else:
        click.echo(f"WARNING: Gemini key {display}")


@ai_group.command("off")
@click.argument("path", default=None, required=False)
@click.option("--path", "opt_path", default=".", help="Project folder.")
def ai_off(path: str | None, opt_path: str) -> None:
    """Disable the AI intent judge (loosening change: needs two reviewers)."""
    from sandbox.connector.policy import load_policy

    path = path if path is not None else opt_path
    layout = _layout(path)
    policy = load_policy(layout.policy_file)

    if not policy.intent.enabled:
        click.echo("AI intent judge is already off.")
        return

    policy.intent.enabled = False

    from sandbox.cli.connector_cmds import _save_edit

    ok = _save_edit(layout, policy, "ai off")
    if ok:
        click.echo("AI intent judge disabled.")
    # If not ok, _save_edit already printed the proposal instructions


@ai_group.command("status")
@click.argument("path", default=None, required=False)
@click.option("--path", "opt_path", default=".", help="Project folder.")
def ai_status(path: str | None, opt_path: str) -> None:
    """Show AI intent judge status: enabled, timeout, key, package."""
    from sandbox.connector.policy import load_policy

    path = path if path is not None else opt_path
    layout = _layout(path)
    policy = load_policy(layout.policy_file)

    click.echo(f"Enabled:       {'yes' if policy.intent.enabled else 'no'}")
    click.echo(f"Timeout:       {policy.intent.timeout_seconds}s")
    _src, _display = _key_info()
    click.echo(f"Gemini key:    {_display}")

    installed = _genai_installed()
    click.echo(f"google-genai:  {'installed' if installed else 'NOT installed'}")
    if not installed:
        click.echo(
            "  Install with: uv tool install --force "
            '"haltwire[ai] @ git+https://github.com/Boredem125/haltwire@v0.1.2"'
        )


def register(cli: click.Group) -> None:
    """Attach the ai commands to *cli*."""
    cli.add_command(ai_group)
