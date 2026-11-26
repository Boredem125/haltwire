"""Gemini rejects request deadlines under 10 s with 400 INVALID_ARGUMENT
("Manually set deadline 5s is too short. Minimum allowed deadline is 10s").

Every literal HttpOptions(timeout=...) in the source must be >= 10000 ms.
Found twice in live use: the hook judge (8 s) and the TUI key test (5 s).
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"


def test_no_literal_gemini_timeout_below_10s():
    bad = []
    for py in SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for m in re.finditer(r"HttpOptions\(\s*timeout\s*=\s*(\d+)", text):
            if int(m.group(1)) < 10000:
                line = text.count("\n", 0, m.start()) + 1
                bad.append(f"{py.relative_to(SRC)}:{line} timeout={m.group(1)}")
    assert not bad, "Gemini minimum deadline is 10000 ms: " + ", ".join(bad)


def test_intent_client_clamps_to_10s():
    from sandbox.connector import intent

    c = intent._EnvKeyRotatingClient(["k"], timeout_ms=3000)
    assert c._timeout_ms >= 10000
