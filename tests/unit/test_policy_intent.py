"""Tests: FolderPolicy.intent nested model survives save/load.

The intent field is a pydantic nested model with:
  enabled: bool = False
  timeout_seconds: int = 8 (1..20)

It must survive save_policy -> load_policy round-trip, and
policy versioning (meet/only_tightens).
"""
from __future__ import annotations

import json

import pytest

from sandbox.connector.policy import (
    FolderPolicy,
    default_policy,
    load_policy,
    save_policy,
)


def test_intent_default():
    """The default policy has intent disabled with 12s timeout (Gemini min 10s)."""
    p = default_policy()
    assert hasattr(p, "intent")
    assert p.intent.enabled is False
    assert p.intent.timeout_seconds == 12


def test_intent_survives_round_trip(tmp_path):
    """intent config survives save_policy -> load_policy."""
    path = tmp_path / "policy.json"
    p = default_policy()
    p.intent.enabled = True
    p.intent.timeout_seconds = 12
    save_policy(p, path)

    loaded = load_policy(path)
    assert loaded.intent.enabled is True
    assert loaded.intent.timeout_seconds == 12


def test_intent_in_json_dump(tmp_path):
    """intent appears in the JSON dump."""
    path = tmp_path / "policy.json"
    p = default_policy()
    p.intent.enabled = True
    p.intent.timeout_seconds = 15
    save_policy(p, path)

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert "intent" in raw
    assert raw["intent"]["enabled"] is True
    assert raw["intent"]["timeout_seconds"] == 15


def test_intent_timeout_clamped():
    """timeout_seconds outside 1..20 is clamped."""
    p = FolderPolicy(intent={"enabled": True, "timeout_seconds": 0})
    assert p.intent.timeout_seconds >= 1

    p = FolderPolicy(intent={"enabled": True, "timeout_seconds": 100})
    assert p.intent.timeout_seconds <= 20


def test_intent_missing_key_gets_default(tmp_path):
    """A policy.json without 'intent' key loads with defaults."""
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1}), encoding="utf-8")

    loaded = load_policy(path)
    assert loaded.intent.enabled is False
    assert loaded.intent.timeout_seconds == 12


def test_intent_versioning_meet():
    """policy_versions.meet preserves intent settings."""
    from sandbox.connector.policy_versions import meet

    approved = default_policy().model_dump()
    approved["intent"]["enabled"] = True
    approved["intent"]["timeout_seconds"] = 10

    on_disk = default_policy().model_dump()
    on_disk["intent"]["enabled"] = False
    on_disk["intent"]["timeout_seconds"] = 15

    merged = meet(approved, on_disk)
    # meet takes the stricter: enabled=True is stricter (more scrutiny)
    assert merged["intent"]["enabled"] is True


def test_intent_versioning_only_tightens():
    """only_tightens: enabling intent is tightening, disabling is loosening."""
    from sandbox.connector.policy_versions import only_tightens

    base = default_policy().model_dump()
    base["intent"]["enabled"] = False

    candidate = default_policy().model_dump()
    candidate["intent"]["enabled"] = True

    # Enabling intent (more scrutiny) should be tightening
    assert only_tightens(base, candidate) is True

    # Disabling intent (less scrutiny) should be loosening
    base2 = default_policy().model_dump()
    base2["intent"]["enabled"] = True
    candidate2 = default_policy().model_dump()
    candidate2["intent"]["enabled"] = False
    assert only_tightens(base2, candidate2) is False
