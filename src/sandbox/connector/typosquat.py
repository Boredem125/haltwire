"""Deterministic typosquat check for package installs.

An agent told to "install the requirements" never types the package name, so
a one-letter typo in ``requirements.txt`` (``pandaz-csv`` for ``pandas``) gets
past both the model and a reviewer skimming the command. This module pulls the
package names out of ``pip``/``uv``/``npm``/``yarn``/``pnpm`` install
commands, including ``-r`` requirement files, and flags any name that is one
or two edits away from a popular package without being that package.

Raise-only: a hit escalates (single human approval); no hit changes nothing.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

# Popular PyPI and npm names. A lookalike of one of these is suspicious.
POPULAR = frozenset("""
pandas numpy requests scipy matplotlib flask django fastapi pydantic sqlalchemy
boto3 botocore urllib3 certifi idna setuptools wheel pip six python-dateutil
pyyaml jinja2 markupsafe click attrs packaging cryptography pyopenssl jsonschema
pytest pillow beautifulsoup4 lxml selenium scrapy tensorflow torch keras
scikit-learn transformers openai anthropic langchain httpx aiohttp uvicorn gunicorn
celery redis psycopg2 pymysql pymongo paramiko colorama tqdm rich typer docker
kubernetes google-cloud-storage google-generativeai protobuf grpcio pyjwt
websockets toml tomli black ruff mypy isort coverage virtualenv poetry
simplejson ujson orjson pytz tzdata babel nltk spacy opencv-python seaborn plotly
xgboost lightgbm networkx sympy pyarrow polars dask ipython jupyter notebook
express react react-dom lodash axios moment chalk commander debug vue angular
typescript webpack babel-core eslint prettier jest mocha next nuxt dotenv cors
body-parser mongoose sequelize socket.io uuid yargs inquirer async underscore
jquery bootstrap tailwindcss vite rollup esbuild nodemon cross-env colors
request node-fetch got bluebird rxjs zod tslib minimist semver glob rimraf
""".split())

# Known-legitimate packages that look like typosquats but are real.
# Membership means never flagged.
KNOWN_LEGIT = frozenset("""
vitest preact psycopg psycopg-binary psycopg2-binary dash yaml mysql color
scapy cattrs arrow unicorn simpy boto grpc jinja
pyyaml simplejson ujson orjson pytz tzdata babel toml tomli
httpx aiohttp uvloop gunicorn celery redis pymysql pymongo
paramiko colorama tqdm rich typer docker kubernetes
websockets pyjwt grpcio protobuf polars dask seaborn plotly
xgboost lightgbm networkx sympy pyarrow ipython jupyter notebook
vite rollup esbuild nodemon cross-env colors semver glob rimraf
tslib minimist lodash axios moment chalk commander debug zod
bluebird rxjs got yargs inquirer underscore uuid cors dotenv
mocha jest eslint prettier typescript webpack next nuxt
react react-dom vue angular express body-parser mongoose
sequelize socket.io jquery bootstrap tailwindcss
""".split())

_CORE = {name.replace("_", "-") for name in POPULAR} | {name.replace("_", "-") for name in KNOWN_LEGIT}
_PREFIXES = {
    "python", "py", "django", "flask", "pytest", "sphinx", "types", "google",
    "azure", "aws", "react", "vue", "node", "babel", "eslint", "webpack",
    "jupyter", "apache", "opentelemetry", "mkdocs", "fastapi", "sqlalchemy",
}
_INSTALL_VERBS = {
    "pip": {"install"}, "pip3": {"install"}, "npm": {"install", "i", "add"},
    "yarn": {"add"}, "pnpm": {"add", "install", "i"}, "uv": {"add"},
}
_SEPARATORS = {";", "&&", "||", "|", "&"}
_VERSION_RE = re.compile(r"[\[<>=!~;@ ].*$")


@dataclass(frozen=True)
class Hit:
    package: str
    looks_like: str
    distance: int
    source: str  # "command" or the requirements file it came from


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _distance(a: str, b: str, cap: int = 3) -> int:
    """Optimal string alignment distance (Damerau-Levenshtein, adjacent swaps)."""
    if abs(len(a) - len(b)) >= cap:
        return cap
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def lookalike(name: str) -> tuple[str, int] | None:
    """(popular name, distance) if *name* imitates one, else None."""
    n = _norm(name)
    if not n or n in _CORE or n.startswith("@"):
        return None
    # Whole name first; only then the first word ("pandaz-csv" -> "pandaz"),
    # and never an ecosystem prefix such as "python-" or "django-".
    candidates = [n]
    head = n.split("-")[0]
    if head != n and head not in _PREFIXES:
        candidates.append(head)
    for cand in candidates:
        if cand in _CORE:
            return None
        hits: list[tuple[int, int, str]] = []
        for real in _CORE:
            if len(real) < 4:
                continue
            limit = 1 if len(real) < 6 else 2
            d = _distance(cand, real)
            if 0 < d <= limit:
                hits.append((d, abs(len(cand) - len(real)), real))
        if hits:
            d, _, real = min(hits)  # deterministic: distance, length gap, name
            return real, d
    return None


def _clean(token: str) -> str:
    return _VERSION_RE.sub("", token.strip("'\""))


def _read_requirements(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    names = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = _clean(line)
        if name:
            names.append(name)
    return names


def _segments(command: str) -> list[list[str]]:
    # Normalise Windows path separators so shlex.posix doesn't eat backslashes.
    # pip install -r .\requirements.txt  ->  pip install -r ./requirements.txt
    normalised = command.replace("\\", "/")
    try:
        lexer = shlex.shlex(normalised, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = normalised.split()
    segs, cur = [], []
    for t in tokens:
        if t in _SEPARATORS:
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _install_args(seg: list[str]) -> list[str] | None:
    """The arguments after the install verb, or None if not an install."""
    words = [w for w in seg]
    # python -m pip install ... / python3 -m pip ...
    if len(words) >= 3 and Path(words[0]).name.lower().startswith(("python", "py")) \
            and words[1] == "-m":
        words = words[2:]
    if words and words[0] == "uv" and len(words) > 1 and words[1] == "pip":
        words = ["pip", *words[2:]]
    if len(words) < 2:
        return None
    tool = Path(words[0]).name.lower().removesuffix(".exe").removesuffix(".cmd")
    if tool not in _INSTALL_VERBS or words[1] not in _INSTALL_VERBS[tool]:
        return None
    return words[2:]


def _packages(seg: list[str], cwd: str) -> list[tuple[str, str]]:
    args = _install_args(seg)
    if args is None:
        return []
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in {"-r", "--requirement", "-c", "--constraint"} and i + 1 < len(args):
            req = Path(args[i + 1])
            req = req if req.is_absolute() else Path(cwd) / req
            out += [(n, str(args[i + 1])) for n in _read_requirements(req)]
            i += 2
            continue
        if a.startswith("--requirement="):
            req = Path(a.split("=", 1)[1])
            req = req if req.is_absolute() else Path(cwd) / req
            out += [(n, a.split("=", 1)[1]) for n in _read_requirements(req)]
        elif not a.startswith("-") and not a.startswith((".", "/", "\\", ".\\", "./")) and "://" not in a:
            name = a.strip("'\"") if a.startswith("@") else _clean(a)
            if name:
                out.append((name, "command"))
        i += 1
    return out


def packages_in_command(command: str, cwd: str) -> list[str]:
    return [n for seg in _segments(command) for n, _ in _packages(seg, cwd)]


def check_command(command: str, cwd: str) -> Hit | None:
    for seg in _segments(command):
        for name, source in _packages(seg, cwd):
            found = lookalike(name)
            if found:
                return Hit(name, found[0], found[1], source)
    return None


def reason(hit: Hit) -> str:
    where = "the command" if hit.source == "command" else hit.source
    return (
        f"[TYPOSQUAT]: {where} installs '{hit.package}', "
        f"{hit.distance} letter(s) away from the popular package '{hit.looks_like}'. "
        "This may be a supply-chain attack. A human must verify the package name."
    )
