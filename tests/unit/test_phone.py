"""Tests for arena.phone — Bolna phone call integration.

Covers: validation, masking, place_call, poll, build_call_message,
decision extraction, and injectable HTTP client.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from arena import phone


# ---------------------------------------------------------------- fixtures

@pytest.fixture(autouse=True)
def reset_agent_id():
    """Reset the cached agent id between tests."""
    phone._AGENT_ID = None
    yield
    phone._AGENT_ID = None


@pytest.fixture
def agent_json(tmp_path, monkeypatch):
    """Write a fake phone_agent.json and point the module at it."""
    p = tmp_path / "phone_agent.json"
    p.write_text(json.dumps({"agent_id": "test-agent-123"}), encoding="utf-8")
    monkeypatch.setattr(phone, "_AGENT_JSON", p)
    return p


@pytest.fixture
def bolna_key(monkeypatch):
    """Set a fake Bolna API key."""
    monkeypatch.setenv("BOLNA_API_KEY", "fake-key-for-tests")


class FakeHTTPClient:
    """Injectable HTTP client that records calls and returns canned responses."""

    def __init__(self, post_response=None, get_response=None,
                 post_error=None, get_error=None):
        self.posts: list[dict] = []
        self.gets: list[dict] = []
        self._post_response = post_response or {}
        self._get_response = get_response or {}
        self._post_error = post_error
        self._get_error = get_error

    def post(self, url: str, *, headers: dict[str, str],
             json_body: dict[str, Any]) -> dict[str, Any]:
        self.posts.append({"url": url, "headers": headers, "body": json_body})
        if self._post_error:
            raise self._post_error
        return self._post_response

    def get(self, url: str, *, headers: dict[str, str]) -> dict[str, Any]:
        self.gets.append({"url": url, "headers": headers})
        if self._get_error:
            raise self._get_error
        return self._get_response


# ---------------------------------------------------------------- validate_number

class TestValidateNumber:
    """E.164 India mobile validation."""

    def test_valid_number(self):
        assert phone.validate_number("+919876543210") is True

    def test_valid_number_starts_6(self):
        assert phone.validate_number("+916012345678") is True

    def test_valid_number_starts_7(self):
        assert phone.validate_number("+917012345678") is True

    def test_valid_number_starts_8(self):
        assert phone.validate_number("+918012345678") is True

    def test_valid_number_starts_9(self):
        assert phone.validate_number("+919012345678") is True

    def test_reject_non_plus91(self):
        assert phone.validate_number("+12125551234") is False

    def test_reject_landline_starts_with_0(self):
        # Indian landlines don't start with 6-9
        assert phone.validate_number("+910112345678") is False

    def test_reject_landline_starts_with_2(self):
        assert phone.validate_number("+912212345678") is False

    def test_reject_too_short(self):
        assert phone.validate_number("+9198765432") is False

    def test_reject_too_long(self):
        assert phone.validate_number("+91989547038900") is False

    def test_reject_no_plus(self):
        assert phone.validate_number("919876543210") is False

    def test_reject_empty(self):
        assert phone.validate_number("") is False

    def test_reject_alpha(self):
        assert phone.validate_number("+91abcdefghij") is False

    def test_reject_junk(self):
        assert phone.validate_number("hello world") is False

    def test_reject_starts_5(self):
        assert phone.validate_number("+915012345678") is False

    def test_reject_starts_1(self):
        assert phone.validate_number("+911012345678") is False


# ---------------------------------------------------------------- mask_number

class TestMaskNumber:
    """Number masking: full number must never appear in display."""

    def test_mask_standard(self):
        masked = phone.mask_number("+919876543210")
        assert "9876543210" not in masked
        assert masked.startswith("+91")
        # Should show first 2 and last 3
        assert "98" in masked
        assert "210" in masked
        # Should have bullet chars
        assert chr(0x2022) in masked

    def test_mask_different_number(self):
        masked = phone.mask_number("+916012345678")
        assert "6012345678" not in masked
        assert "60" in masked
        assert "678" in masked

    def test_mask_short_input(self):
        masked = phone.mask_number("+91")
        assert masked == "***"

    def test_mask_empty(self):
        assert phone.mask_number("") == "***"


# ---------------------------------------------------------------- build_call_message

class TestBuildCallMessage:

    def test_decoy_read(self):
        trip = {
            "kind": "decoy_read",
            "path": ".aws/credentials.bak",
            "tool": "read_file",
            "evidence": "accessed decoy file",
            "agent_task": "Fix deploy script",
        }
        msg = phone.build_call_message(trip)
        assert "decoy secret file" in msg
        assert "credentials.bak" in msg
        assert "frozen" in msg
        # M2: agent_task is no longer included in the Bolna message
        assert "Fix deploy script" not in msg

    def test_canary_exfil(self):
        trip = {
            "kind": "canary_exfil",
            "path": ".env.backup",
            "tool": "run_command",
            "evidence": "canary stripe_key exfiltrated",
            "agent_task": "Setup project",
        }
        msg = phone.build_call_message(trip)
        assert "exfiltrate" in msg
        assert "frozen" in msg

    def test_includes_signature(self):
        trip = {
            "kind": "decoy_read",
            "path": "file.pem",
            "tool": "read_file",
            "evidence": "read decoy",
            "agent_task": "task",
            "signature_short": "abc12345...xyz789",
        }
        msg = phone.build_call_message(trip)
        assert "abc12345" in msg
        assert "signed" in msg

    def test_no_full_paths(self):
        trip = {
            "kind": "decoy_read",
            "path": "C:/Users/secret/.aws/credentials.bak",
            "tool": "read_file",
            "evidence": "read",
            "agent_task": "task",
        }
        msg = phone.build_call_message(trip)
        assert "C:/Users" not in msg
        assert "credentials.bak" in msg


# ---------------------------------------------------------------- place_call

class TestPlaceCall:

    def test_place_call_success(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {"kind": "decoy_read", "path": "f.pem",
                        "tool": "read_file", "evidence": "e", "agent_task": "t"}
        client = FakeHTTPClient(post_response={"execution_id": "exec-999", "status": "queued"})

        result = phone.place_call(session, "+919876543210", "en", http_client=client)
        assert result["execution_id"] == "exec-999"
        assert len(client.posts) == 1
        body = client.posts[0]["body"]
        assert body["agent_id"] == "test-agent-123"
        assert body["recipient_phone_number"] == "+919876543210"
        assert "message" in body["user_data"]
        assert "lang" in body["user_data"]

    def test_place_call_invalid_number(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {}
        with pytest.raises(ValueError, match="Invalid phone number"):
            phone.place_call(session, "+12125551234", "en")

    def test_place_call_landline_rejected(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {}
        with pytest.raises(ValueError, match="Invalid phone number"):
            phone.place_call(session, "+910112345678", "en")

    def test_place_call_api_error(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {"kind": "test", "path": "x", "tool": "y",
                        "evidence": "z", "agent_task": "a"}
        client = FakeHTTPClient(post_error=ConnectionError("timeout"))

        with pytest.raises(RuntimeError, match="Bolna API error"):
            phone.place_call(session, "+919876543210", "en", http_client=client)

    def test_place_call_no_execution_id(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {"kind": "test", "path": "x", "tool": "y",
                        "evidence": "z", "agent_task": "a"}
        client = FakeHTTPClient(post_response={"status": "error"})

        with pytest.raises(RuntimeError, match="no execution_id"):
            phone.place_call(session, "+919876543210", "en", http_client=client)

    def test_place_call_hindi(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {"kind": "decoy_read", "path": "f", "tool": "t",
                        "evidence": "e", "agent_task": "a"}
        client = FakeHTTPClient(post_response={"execution_id": "exec-hi"})

        phone.place_call(session, "+919876543210", "hi", http_client=client)
        body = client.posts[0]["body"]
        assert body["user_data"]["lang"] == "Hindi"

    def test_place_call_telugu(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {"kind": "decoy_read", "path": "f", "tool": "t",
                        "evidence": "e", "agent_task": "a"}
        client = FakeHTTPClient(post_response={"execution_id": "exec-te"})

        phone.place_call(session, "+919876543210", "te", http_client=client)
        body = client.posts[0]["body"]
        assert body["user_data"]["lang"] == "Telugu"

    def test_place_call_unknown_lang_defaults_en(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {"kind": "test", "path": "x", "tool": "y",
                        "evidence": "z", "agent_task": "a"}
        client = FakeHTTPClient(post_response={"execution_id": "exec-de"})

        phone.place_call(session, "+919876543210", "de", http_client=client)
        body = client.posts[0]["body"]
        assert body["user_data"]["lang"] == "English"

    def test_place_call_no_agent_json(self, bolna_key, monkeypatch, tmp_path):
        monkeypatch.setattr(phone, "_AGENT_JSON", tmp_path / "nope.json")
        session = MagicMock()
        session.trip = {}
        with pytest.raises(RuntimeError, match="phone_agent.json not found"):
            phone.place_call(session, "+919876543210", "en")

    def test_place_call_auth_header(self, agent_json, bolna_key):
        session = MagicMock()
        session.trip = {"kind": "test", "path": "x", "tool": "y",
                        "evidence": "z", "agent_task": "a"}
        client = FakeHTTPClient(post_response={"execution_id": "exec-auth"})

        phone.place_call(session, "+919876543210", "en", http_client=client)
        headers = client.posts[0]["headers"]
        assert "Bearer" in headers.get("Authorization", "")


# ---------------------------------------------------------------- poll

class TestPoll:

    def test_poll_completed_with_extraction(self, bolna_key):
        resp = {
            "status": "completed",
            "transcript": [
                {"role": "assistant", "text": "Keep frozen?"},
                {"role": "user", "text": "Yes keep frozen"},
            ],
            "extracted_data": {
                "Tripwire Decision": {
                    "decision": {"objective": "keep_frozen", "confidence": 0.95},
                    "confirmed": {"objective": "true", "confidence": 0.9},
                }
            },
        }
        client = FakeHTTPClient(get_response=resp)
        result = phone.poll("exec-123", http_client=client)
        assert result["status"] == "completed"
        assert result["decision"] == "keep_frozen"
        assert result["confirmed"] is True

    def test_poll_completed_release(self, bolna_key):
        resp = {
            "status": "completed",
            "transcript": [
                {"role": "assistant", "text": "Frozen or release?"},
                {"role": "user", "text": "release it"},
                {"role": "user", "text": "yes"},
            ],
            "extracted_data": {
                "Tripwire Decision": {
                    "decision": {"objective": "release", "confidence": 0.9},
                    "confirmed": {"objective": "true", "confidence": 0.9},
                }
            },
        }
        client = FakeHTTPClient(get_response=resp)
        result = phone.poll("exec-456", http_client=client)
        assert result["decision"] == "release"
        assert result["confirmed"] is True

    def test_poll_no_extraction_fallback_transcript(self, bolna_key):
        """With list transcript and user roles, fallback works."""
        resp = {
            "status": "completed",
            "transcript": [
                {"role": "assistant", "text": "Frozen or release?"},
                {"role": "user", "text": "keep it frozen"},
                {"role": "assistant", "text": "Keeping frozen. Correct?"},
                {"role": "user", "text": "yes"},
            ],
        }
        client = FakeHTTPClient(get_response=resp)
        result = phone.poll("exec-789", http_client=client)
        assert result["decision"] == "keep_frozen"
        assert result["confirmed"] is True

    def test_poll_flat_string_no_roles_no_decision(self, bolna_key):
        """Flat string without role markers -> cannot safely parse -> no decision.
        This is the safety fix: a guessed decision must never be signed."""
        resp = {
            "status": "completed",
            "transcript": (
                "Should the agent remain frozen, or should it be released? "
                "confirm frozen. "
                "You have decided that the agent should remain frozen. Is that correct? "
                "yes. Thank you."
            ),
        }
        client = FakeHTTPClient(get_response=resp)
        result = phone.poll("exec-flat", http_client=client)
        # Cannot distinguish user from agent in flat text -> no decision
        assert result["decision"] is None

    def test_poll_unclear_decision(self, bolna_key):
        resp = {
            "status": "completed",
            "transcript": [
                {"role": "assistant", "text": "Frozen or release?"},
                {"role": "user", "text": "I'm not sure what to do"},
            ],
        }
        client = FakeHTTPClient(get_response=resp)
        result = phone.poll("exec-unclear", http_client=client)
        assert result["decision"] is None
        assert result["confirmed"] is False

    def test_poll_still_ringing(self, bolna_key):
        resp = {"status": "queued", "transcript": ""}
        client = FakeHTTPClient(get_response=resp)
        result = phone.poll("exec-ring", http_client=client)
        assert result["status"] == "queued"
        assert result["decision"] is None

    def test_poll_api_error(self, bolna_key):
        client = FakeHTTPClient(get_error=ConnectionError("network"))
        result = phone.poll("exec-err", http_client=client)
        assert result["status"] == "error"
        assert "API error" in result["transcript_excerpt"]

    def test_poll_transcript_list_format(self, bolna_key):
        resp = {
            "status": "completed",
            "transcript": [
                {"role": "assistant", "text": "Hello, your agent has been frozen."},
                {"role": "user", "text": "Keep it frozen please."},
                {"role": "assistant", "text": "Keeping frozen. Confirmed?"},
                {"role": "user", "text": "confirmed"},
            ],
        }
        client = FakeHTTPClient(get_response=resp)
        result = phone.poll("exec-list", http_client=client)
        assert result["transcript_excerpt"]
        assert result["decision"] == "keep_frozen"
        assert result["confirmed"] is True

    def test_poll_decision_unconfirmed(self, bolna_key):
        """User states decision but never confirms."""
        resp = {
            "status": "completed",
            "transcript": [
                {"role": "assistant", "text": "Frozen or release?"},
                {"role": "user", "text": "keep it frozen"},
            ],
        }
        client = FakeHTTPClient(get_response=resp)
        result = phone.poll("exec-noconfirm", http_client=client)
        assert result["decision"] == "keep_frozen"
        assert result["confirmed"] is False


# ---------------------------------------------------------------- _extract_decision: structured extraction

class TestStructuredExtraction:
    """Bolna extracted_data (dispositions) are preferred over transcript parsing."""

    def test_extraction_keep_frozen_confirmed(self):
        resp = {"extracted_data": {"Tripwire Decision": {
            "decision": {"objective": "keep_frozen", "confidence": 0.95},
            "confirmed": {"objective": "true", "confidence": 0.9},
        }}}
        d, c = phone._extract_decision(resp, "")
        assert d == "keep_frozen"
        assert c is True

    def test_extraction_release_confirmed(self):
        resp = {"extracted_data": {"Tripwire Decision": {
            "decision": {"objective": "release", "confidence": 0.9},
            "confirmed": {"objective": "true", "confidence": 0.9},
        }}}
        d, c = phone._extract_decision(resp, "")
        assert d == "release"
        assert c is True

    def test_extraction_unclear_no_decide(self):
        """Extraction says unclear -> no decision signed."""
        resp = {"extracted_data": {"Tripwire Decision": {
            "decision": {"objective": "unclear", "confidence": 0.8},
            "confirmed": {"objective": "false", "confidence": 0.9},
        }}}
        d, c = phone._extract_decision(resp, "")
        assert d is None
        assert c is False

    def test_extraction_keep_frozen_unconfirmed(self):
        resp = {"extracted_data": {"Tripwire Decision": {
            "decision": {"objective": "keep_frozen", "confidence": 0.9},
            "confirmed": {"objective": "false", "confidence": 0.8},
        }}}
        d, c = phone._extract_decision(resp, "")
        assert d == "keep_frozen"
        assert c is False

    def test_extraction_empty(self):
        d, c = phone._extract_decision({}, "")
        assert d is None
        assert c is False

    def test_extraction_null(self):
        d, c = phone._extract_decision({"extracted_data": None}, "")
        assert d is None
        assert c is False


# ---------------------------------------------------------------- _extract_decision: transcript fallback

class TestTranscriptFallback:
    """Transcript fallback parses ONLY user turns, requires confirmation."""

    def test_real_transcript_keep_frozen(self):
        """Exact transcript from the real live call: user said 'confirm frozen', 'yes'.
        Agent asked 'frozen, or ... released?' -- agent turns must NOT be parsed."""
        transcript = [
            {"role": "assistant", "text": "Hello, this is a security notification call. "
             "Your AI coding agent opened a decoy secret file and has been frozen. "
             "Should the agent remain frozen, or should it be released?"},
            {"role": "user", "text": "confirm frozen"},
            {"role": "assistant", "text": "You have decided that the agent should remain frozen. Is that correct?"},
            {"role": "user", "text": "yes"},
            {"role": "assistant", "text": "Thank you. That decision is recorded."},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d == "keep_frozen"
        assert c is True

    def test_user_says_release_confirmed(self):
        transcript = [
            {"role": "assistant", "text": "Should the agent remain frozen, or should it be released?"},
            {"role": "user", "text": "release it"},
            {"role": "assistant", "text": "You want to release the agent. Is that correct?"},
            {"role": "user", "text": "yes"},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d == "release"
        assert c is True

    def test_user_changes_mind_last_wins(self):
        """H1: 'no, keep it frozen' has 'no' + 'keep frozen' -> unclear (negation anywhere).
        The user must state the new decision cleanly in a separate turn."""
        transcript = [
            {"role": "assistant", "text": "Should the agent remain frozen, or released?"},
            {"role": "user", "text": "release it"},
            {"role": "assistant", "text": "You want to release. Is that correct?"},
            {"role": "user", "text": "no, keep it frozen"},
            {"role": "assistant", "text": "You want to keep it frozen. Is that correct?"},
            {"role": "user", "text": "yes"},
        ]
        d, c = phone._extract_decision({}, transcript)
        # H1: "no, keep it frozen" is unclear (negation in same turn as decision)
        # The last clean decision is "release it" but it was not confirmed with readback
        # Overall result: unclear / no decision
        assert d is None

    def test_user_changes_mind_to_release(self):
        """H1: 'no, actually release it' has 'no' + 'release' -> unclear."""
        transcript = [
            {"role": "assistant", "text": "Should the agent remain frozen, or released?"},
            {"role": "user", "text": "keep frozen"},
            {"role": "assistant", "text": "Keep frozen. Correct?"},
            {"role": "user", "text": "no, actually release it"},
            {"role": "assistant", "text": "You want to release. Is that correct?"},
            {"role": "user", "text": "correct"},
        ]
        d, c = phone._extract_decision({}, transcript)
        # H1: "no, actually release it" is unclear
        assert d is None or d == "keep_frozen"

    def test_conflict_same_turn_unclear(self):
        """Both freeze and release in same user turn -> unclear."""
        transcript = [
            {"role": "assistant", "text": "Frozen or release?"},
            {"role": "user", "text": "keep frozen no release it"},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d is None
        assert c is False

    def test_no_confirmation_unconfirmed(self):
        """User states decision but never confirms -> unconfirmed."""
        transcript = [
            {"role": "assistant", "text": "Frozen or release?"},
            {"role": "user", "text": "keep it frozen"},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d == "keep_frozen"
        assert c is False

    def test_hindi_confirmation_haan(self):
        """Hindi 'haan' counts as confirmation."""
        transcript = [
            {"role": "assistant", "text": "Agent ko frozen rakhein ya release karein?"},
            {"role": "user", "text": "frozen"},
            {"role": "assistant", "text": "Frozen rakh rahe hain. Sahi hai?"},
            {"role": "user", "text": "haan"},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d == "keep_frozen"
        assert c is True

    def test_hindi_confirmation_ji(self):
        """Hindi 'ji' counts as confirmation."""
        transcript = [
            {"role": "assistant", "text": "Frozen ya release?"},
            {"role": "user", "text": "release"},
            {"role": "assistant", "text": "Release. Theek hai?"},
            {"role": "user", "text": "ji"},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d == "release"
        assert c is True

    def test_telugu_confirmation_avunu(self):
        """Telugu 'avunu' counts as confirmation."""
        transcript = [
            {"role": "assistant", "text": "Agent ni frozen ga unchali, leda release cheyali?"},
            {"role": "user", "text": "frozen"},
            {"role": "assistant", "text": "Frozen. Correct aa?"},
            {"role": "user", "text": "avunu"},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d == "keep_frozen"
        assert c is True

    def test_no_user_turns_no_decision(self):
        """No user turns at all -> no decision."""
        transcript = [
            {"role": "assistant", "text": "Hello? Anyone there?"},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d is None
        assert c is False

    def test_flat_string_no_role_prefix_no_decision(self):
        """Flat string with no role prefixes -> cannot distinguish user from agent -> no decision.
        This is the safety fix: never parse agent text as user text."""
        transcript = (
            "Should the agent remain frozen, or should it be released? "
            "confirm frozen. "
            "You have decided that the agent should remain frozen. Is that correct? "
            "yes"
        )
        d, c = phone._extract_decision({}, transcript)
        # Flat string without role markers -> cannot safely parse -> no decision
        assert d is None
        assert c is False

    def test_string_with_role_prefixes(self):
        """String transcript with 'user:' and 'assistant:' prefixes."""
        transcript = (
            "assistant: Should the agent remain frozen, or should it be released?\n"
            "user: keep frozen\n"
            "assistant: You want to keep it frozen. Is that correct?\n"
            "user: yes\n"
        )
        d, c = phone._extract_decision({}, transcript)
        assert d == "keep_frozen"
        assert c is True

    def test_unclear_user_says_nothing_decisive(self):
        transcript = [
            {"role": "assistant", "text": "Frozen or release?"},
            {"role": "user", "text": "I don't know what to do"},
            {"role": "assistant", "text": "Could you please decide?"},
            {"role": "user", "text": "Let me think about it"},
        ]
        d, c = phone._extract_decision({}, transcript)
        assert d is None
        assert c is False

    def test_extraction_preferred_over_transcript(self):
        """When extraction has a clear decision, transcript is ignored."""
        resp = {"extracted_data": {"Tripwire Decision": {
            "decision": {"objective": "release", "confidence": 0.95},
            "confirmed": {"objective": "true", "confidence": 0.9},
        }}}
        # Transcript says keep frozen -- but extraction says release
        transcript = [
            {"role": "user", "text": "keep frozen"},
            {"role": "user", "text": "yes"},
        ]
        d, c = phone._extract_decision(resp, transcript)
        assert d == "release"
        assert c is True


class TestParserWordBoundariesAndNegation:
    """Confirmation and decision words match whole words only; negation is never flipped."""

    def _parse(self, *turns):
        from arena import phone
        return phone._parse_user_turns(list(turns))

    def test_ha_inside_other_words_is_not_confirmation(self):
        assert self._parse("keep it frozen", "that is the thing") == ("keep_frozen", False)
        assert self._parse("keep it frozen", "whatever") == ("keep_frozen", False)

    def test_real_confirmations_still_work(self):
        assert self._parse("keep it frozen", "haan") == ("keep_frozen", True)
        assert self._parse("keep it frozen", "yes") == ("keep_frozen", True)
        assert self._parse("release it", "avunu") == ("release", True)

    def test_negated_freeze_is_unclear_not_release(self):
        assert self._parse("don't keep it frozen", "yes") == (None, False)

    def test_negated_release_is_unclear_not_freeze(self):
        assert self._parse("do not release it", "yes") == (None, False)
        # H1: "mat" is a Hindi negation; "release mat karo" -> unclear
        assert self._parse("release mat karo", "haan") == (None, False)

    def test_no_comma_keep_frozen_after_no(self):
        # H1: "no" is a negation word; with "keep frozen" in same turn -> unclear
        assert self._parse("no, keep it frozen", "yes") == (None, False)

    def test_unfreeze_is_release(self):
        assert self._parse("unfreeze it", "yes") == ("release", True)
