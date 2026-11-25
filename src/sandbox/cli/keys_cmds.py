"""`sandbox keys`: reviewer signing keys (ADR 0007). Approver CLI: a human runs it, never the agent."""
from __future__ import annotations

import click


@click.group("keys")
def keys_group() -> None:
    """Where this folder's signing keys live, and retiring pre-M1 in-tree seeds."""


def _layout(path: str):
    from sandbox.connector.layout import FolderLayout

    layout = FolderLayout.discover(path)
    if layout is None:
        click.echo("No .sandbox/ found.")
        raise SystemExit(1)
    return layout


@keys_group.command("status")
@click.option("--path", default=".", help="A folder inside the workspace.")
def keys_status(path: str) -> None:
    """Show the key home for this workspace and any retired in-tree seeds left behind."""
    from sandbox.connector import keyhome

    layout = _layout(path)
    try:
        d = keyhome.workspace_key_dir(layout, create=False)
        click.echo(f"Key home for this workspace: {d}")
        click.echo(f"Reviewer seeds there: {len(list(d.glob('*.seed'))) if d.is_dir() else 0}")
    except keyhome.KeyHomeError as exc:
        click.echo(f"Key home unavailable (nothing can be signed): {exc}")
    root = keyhome.key_home_root()
    exposed = keyhome.root_exposure(root) if root else None
    if exposed:
        click.echo(f"WARNING: the key home {root} is readable by others: {exposed}. "
                   "Restrict it to your account (keys are only tightened on a folder this tool creates).")
    legacy = sorted((layout.state_dir / "keys").glob("*.seed")) if (layout.state_dir / "keys").is_dir() else []
    if legacy:
        click.echo(f"{len(legacy)} retired pre-M1 seed(s) still in {layout.state_dir / 'keys'} "
                   "(retired, but still readable to anything that can search the folder, and not yet "
                   "refused as signers: remove them). "
                   "Remove them with `sandbox keys purge-legacy`.")
    else:
        click.echo("No retired in-tree seeds.")


@keys_group.command("pin")
@click.argument("reviewer_id")
@click.option("--path", default=".", help="A folder inside the workspace.")
@click.option("--force", is_flag=True, help="Overwrite an existing pin with a different key.")
def keys_pin(reviewer_id: str, path: str, force: bool) -> None:
    """Create or load a reviewer's signing key and pin it for this workspace.

    The pinned key is what `unfreeze --reviewer` checks. If the reviewer is
    already pinned with the same key, this is a no-op. If pinned with a
    different key, the command refuses unless --force is given.
    """
    from sandbox.connector import keyhome
    from sandbox.connector.signing import _load_or_create_key

    layout = _layout(path)
    try:
        key = _load_or_create_key(layout, reviewer_id)
    except keyhome.KeyHomeError as exc:
        click.echo(f"Key home unavailable: {exc}", err=True)
        raise SystemExit(1)

    pub_hex = bytes(key.verify_key).hex()
    fingerprint = pub_hex[:16]

    # Check existing pin
    existing = keyhome.get_pinned_key(layout, reviewer_id)
    if existing is not None:
        if existing == pub_hex:
            click.echo(f"Reviewer {reviewer_id!r} is already pinned with this key (fingerprint {fingerprint}).")
            return
        # Different key
        if not force:
            old_fp = existing[:16]
            click.echo(
                f"Reviewer {reviewer_id!r} is already pinned with a different key.\n"
                f"  old fingerprint: {old_fp}\n"
                f"  new fingerprint: {fingerprint}\n"
                f"Use --force to overwrite.",
                err=True,
            )
            raise SystemExit(1)
        # Force: overwrite the pin by writing the pins file directly
        import json as _json
        import time
        pins = keyhome.read_pins(layout)
        pins[reviewer_id] = {
            "public_key": pub_hex,
            "workspace_root": str(layout.root),
            "pinned_at": time.time(),
            "retired_at": None,
        }
        p = keyhome._pins_path(layout)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_json.dumps(pins, indent=2), encoding="utf-8")
        click.echo(f"Reviewer {reviewer_id!r} re-pinned (--force).")
        click.echo(f"  fingerprint: {fingerprint}")
        try:
            d = keyhome.workspace_key_dir(layout, create=False)
            click.echo(f"  key home:    {d}")
        except keyhome.KeyHomeError:
            pass
        return

    # New pin
    keyhome.write_pin(layout, reviewer_id, pub_hex)
    click.echo(f"Reviewer {reviewer_id!r} pinned.")
    click.echo(f"  fingerprint: {fingerprint}")
    try:
        d = keyhome.workspace_key_dir(layout, create=False)
        click.echo(f"  key home:    {d}")
    except keyhome.KeyHomeError:
        pass


@keys_group.command("purge-legacy")
@click.option("--path", default=".", help="A folder inside the workspace.")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.option("--by", default="", help="Who runs this (recorded in the audit chain).")
def keys_purge_legacy(path: str, yes: bool, by: str) -> None:
    """Delete the retired pre-M1 seeds from .sandbox/state/keys. Cannot be undone.

    Each reviewer is rotated first if that has not happened yet (audited `key_rotated`),
    so the audit chain keeps the head that legacy records are checked against. Old
    records signed by a deleted seed still verify as before; nothing new can be signed by it.
    """
    import getpass
    import time

    from sandbox.connector import keyhome
    from sandbox.connector.policy_versions import audit
    from sandbox.connector.signing import _safe_name, ensure_signing_key

    layout = _layout(path)
    keys_dir = layout.state_dir / "keys"
    seeds = sorted(keys_dir.glob("*.seed")) if keys_dir.is_dir() else []
    if not seeds:
        click.echo("No retired in-tree seeds.")
        return
    click.echo("Will delete:\n" + "\n".join(f"  {p}" for p in seeds))
    if not yes and not click.confirm("Delete these files for good?", default=False):
        click.echo("Nothing deleted.")
        raise SystemExit(1)
    removed: list[str] = []
    try:
        for p in seeds:
            ensure_signing_key(layout, p.stem)  # rotates (and audits key_rotated) if not done yet
    except keyhome.KeyHomeError as exc:
        click.echo(f"Refused: no usable key home, so nothing was deleted: {exc}")
        raise SystemExit(1)
    for p in seeds:
        if _safe_name(p.stem) != p.stem:
            continue
        p.unlink()
        removed.append(p.name)
    audit(layout, {"event": "legacy_seeds_purged", "ts": time.time(), "by": by or getpass.getuser(),
                   "removed": removed})
    click.echo(f"Deleted {len(removed)} retired seed(s).")
