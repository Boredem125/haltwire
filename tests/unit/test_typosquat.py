"""Buildathon branch only: deterministic typosquat check on package installs."""
from __future__ import annotations

import json

import pytest

from sandbox.connector import google_adapter as ga
from sandbox.connector import typosquat as ts
from tests.unit.test_google_adapter import agy, gem, layout  # noqa: F401 — fixture


@pytest.mark.parametrize("name,target", [
    ("pandaz-csv", "pandas"),
    ("reqeusts", "requests"),
    ("requets", "request"),  # ties with "requests"; same length wins
    ("numpi", "numpy"),
    ("expresss", "express"),
    ("lodahs", "lodash"),
    ("python-dateutils", "python-dateutil"),
])
def test_lookalikes_flagged(name, target):
    hit = ts.lookalike(name)
    assert hit is not None and hit[0] == target


@pytest.mark.parametrize("name", [
    "pandas", "requests", "numpy", "express", "lodash", "Flask", "PyYAML",
    "python_dateutil", "my-internal-tool", "rich", "six", "zzz-unrelated",
    "python-dotenv", "django-cors-headers", "react-router", "pytest-asyncio",
    "types-requests", "pandas-stubs", "requests-oauthlib", "numpy-financial",
])
def test_real_or_unrelated_not_flagged(name):
    assert ts.lookalike(name) is None


@pytest.mark.parametrize("cmd,expected", [
    ("pip install pandaz-csv", ["pandaz-csv"]),
    ("pip3 install -U reqeusts==2.0 rich", ["reqeusts", "rich"]),
    ("python -m pip install 'numpi>=1.0'", ["numpi"]),
    ("uv pip install flask", ["flask"]),
    ("npm install expresss --save", ["expresss"]),
    ("npm i @types/node lodahs", ["@types/node", "lodahs"]),
    ("yarn add lodahs", ["lodahs"]),
    ("pnpm add expresss", ["expresss"]),
    ("git status; pip install numpi", ["numpi"]),
    ("echo pip install numpi", []),
    ("pip list", []),
])
def test_package_names_from_command(cmd, expected, tmp_path):
    assert ts.packages_in_command(cmd, str(tmp_path)) == expected


def test_requirements_file_is_read(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# deps\npandas==2.1\npandaz-csv==1.4.2  # csv\n-e .\n\n", encoding="utf-8")
    assert ts.packages_in_command("pip install -r requirements.txt", str(tmp_path)) == [
        "pandas", "pandaz-csv"]


def test_check_command_reports_first_lookalike(tmp_path):
    (tmp_path / "requirements.txt").write_text("pandaz-csv==1.4.2\n", encoding="utf-8")
    hit = ts.check_command("pip install -r requirements.txt", str(tmp_path))
    assert hit is not None
    assert hit.package == "pandaz-csv" and hit.looks_like == "pandas"
    assert "requirements.txt" in hit.source


def test_check_command_clean(tmp_path):
    assert ts.check_command("pip install pandas requests", str(tmp_path)) is None


# ---------------------------------------------------------------- via adapter

async def test_adapter_denies_typosquat_from_requirements(layout):  # noqa: F811
    (layout.root / "requirements.txt").write_text("pandaz-csv==1.4.2\n", encoding="utf-8")
    out = await ga.evaluate(json.dumps(agy(
        "run_command", {"CommandLine": "pip install -r requirements.txt"}, layout.root)))
    assert out["decision"] in ("deny", "block")
    # The escalation pending message contains TYPOSQUAT in the reason_code bracket
    assert "TYPOSQUAT" in out["reason"]
    audit = list((layout.root / ".sandbox" / "audit").rglob("*.jsonl"))
    assert audit, "typosquat escalation must be written to the audit chain"
    assert any("TYPOSQUAT" in p.read_text(encoding="utf-8") for p in audit)


async def test_adapter_denies_typosquat_gemini(layout):  # noqa: F811
    out = await ga.evaluate(json.dumps(gem("run_shell_command", {"command": "npm i expresss"}, layout.root)))
    assert out["decision"] in ("deny", "block")
    assert "TYPOSQUAT" in out["reason"]
