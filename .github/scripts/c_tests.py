"""Print the connector (Class C) test files, one per line, for the standalone job.

    python .github/scripts/c_tests.py

C = every tracked tests/**/test_*.py except the Class A and B files listed in
docs/control-plane/REVIEW_QA.md section 2 / M0_INVENTORY.md section 2. A files
test legacy code deleted in M0; B files test legacy API routes and are being
rewritten. When QA's docs/control-plane/M0_C_MANIFEST.sha256 exists, the job
also runs `sha256sum -c` on it (gate check 1), so C files stay byte-identical.

Arena tests (Class D) are also excluded: they import from the ``arena`` package
which requires the ``.[arena]`` extras (segno, google-genai, etc.) that the
standalone connector job deliberately does not install.  Arena tests run in the
full ``pytest`` job which installs ``.[dev,arena]``.
"""
from __future__ import annotations

import re
import subprocess
import sys

CLASS_A = {
    "tests/integration/test_pipeline.py",
    "tests/unit/test_message_models.py",
    "tests/unit/test_request_evaluator.py",
    "tests/unit/test_policy_engine.py",
}
CLASS_B = {
    "tests/security/test_api_robustness.py",
    "tests/security/test_api_auth.py",
    "tests/integration/test_api_connector.py",
    "tests/unit/test_recorder_scan.py",
}

# Pattern that matches arena imports at any indentation level, including
# function-local imports like ``from arena.voice import build_system_prompt``.
_ARENA_IMPORT = re.compile(
    r"(?:from\s+arena\b|import\s+arena\b)"
)


def _imports_arena(filepath: str) -> bool:
    """Return True if *filepath* contains a top-level ``arena`` import."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            return bool(_ARENA_IMPORT.search(fh.read()))
    except OSError:
        return False


def main() -> None:
    sys.stdout.reconfigure(newline="\n")  # no CRLF on Windows: paths go through $(cat ...)
    tracked = subprocess.run(
        ["git", "ls-files", "tests"], capture_output=True, text=True, check=True
    ).stdout.split()
    excluded = CLASS_A | CLASS_B
    for path in sorted(tracked):
        name = path.rsplit("/", 1)[-1]
        if name.startswith("test_") and name.endswith(".py") and path not in excluded:
            if _imports_arena(path):
                continue  # arena test -- needs .[arena] extras
            print(path)


if __name__ == "__main__":
    main()
