# Re-export shim: all intent judge logic lives in sandbox.connector.intent now.
# Arena callers still work through this shim. The arena's agent.py passes
# its own client via the client= parameter.
#
# _sleep and _generate/_generate_round need special handling so monkeypatch on
# arena.intent._sleep actually affects the _generate calls.
from __future__ import annotations

import sandbox.connector.intent as _cintent

# Re-export everything except _sleep and _make_client (which need special handling)
from sandbox.connector.intent import (  # noqa: F401
    CONFIDENCE_THRESHOLD,
    _BODY_TRUNCATE,
    _JUDGE_TEMPERATURE,
    _JUDGE_TIMEOUT_MS,
    _RATE_LIMIT_BACKOFF_S,
    _RETRYABLE,
    _TOOL_SYSTEM,
    _get_models,
    _is_rate_limit,
    _make_verdict,
    _mask_canaries,
    _safe_verdict,
    egress_stats,
    event_text,
    judge_egress,
    judge_tool_call,
)

# _sleep forwarding: __getattr__ handles reads, and monkeypatch.setattr
# writes directly to globals(). The _generate function in the connector
# references its own module's _sleep, so we need to redirect there.
_sleep = _cintent._sleep  # noqa: F811 — initial value


def __getattr__(name):
    if name == "_sleep":
        return _cintent._sleep
    # Fallback to connector module for anything not explicitly imported
    return getattr(_cintent, name)


# Override setattr via a custom module wrapper to forward _sleep patches
import sys as _sys  # noqa: E402
import types as _types  # noqa: E402


class _ShimModule(_types.ModuleType):
    """Module wrapper that forwards _sleep assignments to the real module."""

    def __setattr__(self, name, value):
        if name == "_sleep":
            _cintent._sleep = value
            # Also set locally so hasattr checks work
            super().__setattr__(name, value)
            return
        super().__setattr__(name, value)

    def __getattr__(self, name):
        if name == "_sleep":
            return _cintent._sleep
        return getattr(_cintent, name)


# Install the shim module
_this = _sys.modules[__name__]
_shim = _ShimModule(__name__)
_shim.__dict__.update({k: v for k, v in _this.__dict__.items() if not k.startswith("_ShimModule")})
_shim.__file__ = __file__
_shim.__spec__ = getattr(_this, "__spec__", None)
_sys.modules[__name__] = _shim


def _make_client(client=None):
    """Arena-compatible _make_client: tries arena.agent._KeyRotatingClient first,
    falls back to the connector's env-based client."""
    if client is not None:
        return client
    try:
        from arena.agent import _KeyRotatingClient, _key_names, _load_keys
        judge_names = _key_names("ARENA_JUDGE_KEYS")
        if judge_names:
            return _KeyRotatingClient(_load_keys(judge_names))
        return _KeyRotatingClient(list(reversed(_load_keys())))
    except (ImportError, Exception):
        return _cintent._make_client(client)


# Register the arena _make_client as the connector's client factory
# so that judge_tool_call (which lives in the connector) uses arena's keys.
_cintent.set_client_factory(lambda: _make_client())

# Attach _make_client to the shim module
_sys.modules[__name__]._make_client = _make_client
