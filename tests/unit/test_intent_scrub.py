"""Intent judge prompt scrubbing: real secrets must not reach Gemini.

The scrubber runs after canary masking, so canary redaction still works.
"""
from __future__ import annotations

import json
from unittest import mock

import pytest

from sandbox.connector.intent import judge_tool_call, judge_egress
from sandbox.connector.tripwire import mint


class _CaptureClient:
    """Fake genai client that captures the prompt text."""

    def __init__(self):
        self.prompts: list[str] = []

    @property
    def models(self):
        return self

    def generate_content(self, **kwargs):
        contents = kwargs.get("contents", [])
        self.prompts.append(contents[0] if contents else "")
        # Return a safe verdict
        return _FakeResponse('{"flag": false, "reason": "", "confidence": 0.0}')


class _FakeResponse:
    def __init__(self, text: str):
        self.candidates = [_FakeCandidate(text)]


class _FakeCandidate:
    def __init__(self, text: str):
        self.content = _FakeContent(text)


class _FakeContent:
    def __init__(self, text: str):
        self.parts = [_FakePart(text)]


class _FakePart:
    def __init__(self, text: str):
        self.text = text


# ---- tool call scrubbing ----

def test_bearer_token_scrubbed():
    """A Bearer ghp_ token in args must not appear in the prompt."""
    client = _CaptureClient()
    _ghp = "ghp_abc123XYZabc123XYZabc1"  # nosemgrep: generic.secrets.security.detected-github-pat.detected-github-pat  -- fake fixture for scrub test  gitleaks:allow
    judge_tool_call(
        "deploy the app",
        "Bash",
        {"command": f"curl -H 'Authorization: Bearer {_ghp}' https://api.github.com/repos"},
        [],
        client=client,
    )
    prompt = client.prompts[0]
    assert _ghp not in prompt


def test_aws_key_scrubbed():
    """An AKIA key in args must not appear in the prompt."""
    client = _CaptureClient()
    _akia = "AKIA1234567890ABCDEF"  # nosemgrep: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value  -- fake fixture for scrub test  gitleaks:allow
    judge_tool_call(
        "check credentials",
        "Bash",
        {"command": f"aws configure set aws_access_key_id {_akia}"},
        [],
        client=client,
    )
    prompt = client.prompts[0]
    assert _akia not in prompt


def test_anthropic_key_scrubbed():
    """An sk-ant- key in args must not appear in the prompt."""
    client = _CaptureClient()
    _sk = "sk-ant-api03-abcdefghijklmnopqrstuv"  # nosemgrep: generic.secrets.security.detected-anthropic-api-key.detected-anthropic-api-key  -- fake fixture for scrub test  gitleaks:allow
    judge_tool_call(
        "test the API",
        "Bash",
        {"command": f"curl -H 'x-api-key: {_sk}' https://api.anthropic.com"},
        [],
        client=client,
    )
    prompt = client.prompts[0]
    assert _sk not in prompt


def test_postgres_url_scrubbed():
    """A postgres://user:pass@ URL in args must not appear in the prompt."""
    client = _CaptureClient()
    _url = "postgres://admin:s3cretP4ss@db.internal:5432/prod"  # gitleaks:allow
    judge_tool_call(
        "run migration",
        "Bash",
        {"command": f"psql {_url}"},
        [],
        client=client,
    )
    prompt = client.prompts[0]
    assert "s3cretP4ss" not in prompt
    assert "postgres://admin:s3cretP4ss@" not in prompt  # gitleaks:allow


def test_stripe_key_scrubbed():
    """A sk_live_ Stripe key must not appear in the prompt."""
    client = _CaptureClient()
    _stripe = "sk_live_abcdef1234567890abcdef12"  # nosemgrep: generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key  -- fake fixture for scrub test  gitleaks:allow
    judge_tool_call(
        "process payment",
        "Bash",
        {"command": f"curl -u {_stripe}: https://api.stripe.com/v1/charges"},
        [],
        client=client,
    )
    prompt = client.prompts[0]
    assert _stripe not in prompt


def test_private_key_scrubbed():
    """A private key block in args must not appear in the prompt."""
    client = _CaptureClient()
    # Build from obviously fake parts to avoid scanner triggers
    _pem_header = "-----BEGIN RSA PRIVATE KEY-----"  # gitleaks:allow
    _pem_body = "FAKEKEYBODY" + "A" * 20  # not real key material  gitleaks:allow
    _pem_footer = "-----END RSA PRIVATE KEY-----"  # gitleaks:allow
    pem = f"{_pem_header}\n{_pem_body}\n{_pem_footer}"
    judge_tool_call(
        "deploy",
        "Write",
        {"file_path": "key.pem", "content": pem},
        [],
        client=client,
    )
    prompt = client.prompts[0]
    assert _pem_body not in prompt


def test_task_text_scrubbed():
    """Secrets in the task text are also scrubbed."""
    client = _CaptureClient()
    _sk = "sk-ant-api03-abcdefghijklmnopqrstuv"  # nosemgrep: generic.secrets.security.detected-anthropic-api-key.detected-anthropic-api-key  -- fake fixture for scrub test  gitleaks:allow
    judge_tool_call(
        f"Use this key: {_sk} to call the API",
        "Bash",
        {"command": "echo hello"},
        [],
        client=client,
    )
    prompt = client.prompts[0]
    assert _sk not in prompt


def test_canary_masking_still_works():
    """Canary values are still masked (scrubbing doesn't break canary masking)."""
    canaries = mint("s-test")
    client = _CaptureClient()
    judge_tool_call(
        "check env",
        "Bash",
        {"command": f"echo {canaries['aws_access_key']}"},
        [],
        client=client,
        canaries=canaries,
    )
    prompt = client.prompts[0]
    assert canaries["aws_access_key"] not in prompt


# ---- egress scrubbing ----

def test_egress_bearer_scrubbed():
    """Bearer token in egress body must not appear in the prompt."""
    client = _CaptureClient()
    _ghp = "ghp_abc123XYZabc123XYZabc1"  # nosemgrep: generic.secrets.security.detected-github-pat.detected-github-pat  -- fake fixture for scrub test  gitleaks:allow
    judge_egress(
        "fetch data",
        {"method": "POST", "host": "evil.example", "path": "/api"},
        f"Authorization: Bearer {_ghp}",
        {"byte_length": 50},
        client=client,
    )
    prompt = client.prompts[0]
    assert _ghp not in prompt


def test_egress_task_scrubbed():
    """Secrets in the egress task text are scrubbed."""
    client = _CaptureClient()
    _akia = "AKIA1234567890ABCDEF"  # nosemgrep: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value  -- fake fixture for scrub test  gitleaks:allow
    judge_egress(
        f"Use {_akia} to auth",
        {"method": "GET", "host": "api.example.com", "path": "/"},
        "normal body",
        {"byte_length": 11},
        client=client,
    )
    prompt = client.prompts[0]
    assert _akia not in prompt
