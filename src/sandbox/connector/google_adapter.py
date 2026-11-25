"""Hook adapter for Google's coding agents (buildathon branch only).

Supports two pre-tool hook contracts:

* Antigravity CLI (``agy``), event ``PreToolUse``: stdin carries
  ``toolCall: {name, args}``, ``conversationId`` and ``workspacePaths``;
  stdout is ``{"decision": allow|deny|ask|force_ask, "reason": ...}``.
* Gemini CLI, event ``BeforeTool``: stdin carries ``tool_name``,
  ``tool_input``, ``cwd`` and ``session_id``; stdout is
  ``{"decision": allow|deny, "reason": ...}``.

Each payload is translated into the Claude-shaped payload that
``hook_eval.pre_tool_use`` already evaluates, so every verdict comes from the
same parser, policy, risk score, escalation and audit chain. The verdict is
then translated back.

Fail-closed rules:
* Antigravity's docs say unrecognised output, a non-zero exit or a timeout may
  be treated as allow. So this adapter always prints exactly one JSON object
  and exits 0, and every error path prints a deny.
* A verdict we do not recognise is a deny, never an allow.
* Gemini CLI has no "ask", so an ask becomes a deny that tells the agent why.

Run as: ``python -m sandbox.connector.google_adapter``
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from sandbox.connector.hook_eval import pre_tool_use
from sandbox.connector.layout import FolderLayout

ANTIGRAVITY = "antigravity"
GEMINI = "gemini"

ERROR_REASON = "SANDBOX: hook adapter error, blocking (fail-closed)"
BAD_INPUT_REASON = "SANDBOX: unreadable hook input (fail-closed)"

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


class BadInput(ValueError):
    """The payload can't be translated; the caller denies."""


def _shell_tool() -> str:
    override = os.environ.get("AGG_SHELL_TOOL")
    if override in {"Bash", "PowerShell"}:
        return override
    return "PowerShell" if os.name == "nt" else "Bash"


def detect(payload: Any) -> str | None:
    """Which agent sent this payload, or None if neither shape matches."""
    if not isinstance(payload, dict):
        return None
    if "toolCall" in payload:
        return ANTIGRAVITY
    if "tool_name" in payload:
        return GEMINI
    return None


def _abs(path: Any, base: str) -> Any:
    if not isinstance(path, str) or not path:
        return path
    p = Path(path)
    return str(p if p.is_absolute() else Path(base) / p)


def _str(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d:
            return d[k]
    return None


_PATH_KEYS = ("TargetFile", "AbsolutePath", "Path", "FilePath", "File", "file_path", "path")
_CONTENT_KEYS = ("CodeContent", "Content", "Text", "content", "text")

# The agent must never edit the files that switch its own hooks off.
_GUARD_DIRS = {".agents", ".gemini"}
GUARD_REASON = ("SANDBOX: agents may not edit their own guard config "
                "(.agents/ or .gemini/). Ask the user to change it themselves.")

# Tools that run arbitrary code outside run_command: always a human's call.
_CODE_EXEC_TOOLS = {"notebook_execution", "execute_browser_javascript"}
CODE_EXEC_REASON = "SANDBOX: this tool runs code outside the shell checks; a human must confirm it."

_WRITE_TOOLS = {"Write", "Edit", "MultiEdit"}


ENV_REASON = ("SANDBOX DENIED [ENV_SECRETS]: reading environment variables or credential "
              "files can expose API keys and tokens. Ask the user for the value you need.")
_SECRET_NAME = r"[A-Za-z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*"
_ENV_PATTERNS = [re.compile(p, re.I) for p in (
    r"(^|[;&|(]\s*)(env|printenv|set|export\s+-p|declare\s+-x|compgen\s+-v)\s*($|[;&|)])",
    r"(^|[;&|(]\s*)printenv\b",
    r"(^|[;&|(]\s*)env\s*\|",
    r"\b(gci|ls|dir|get-childitem|get-item|gi)\s+env:",
    r"\$env:",
    r"\[environment\]::",
    r"/proc/[^\s/]+/environ",
    r"\bos\.environ\b|\bos\.getenv\b|\bprocess\.env\b|\bgetenv\s*\(",
    r"\$\{?" + _SECRET_NAME,
    r"\b(GEMINI_API_KEY|GOOGLE_API_KEY|ARENA_[A-Z_]+)\b",
)]
_CRED_PATH = re.compile(r"(/proc/[^/]+/environ|[\\/]\.gemini[\\/])", re.I)


def env_secret_hit(command: str) -> str | None:
    """The pattern a command matched if it would dump secrets, else None."""
    for pat in _ENV_PATTERNS:
        m = pat.search(command)
        if m:
            return m.group(0)
    return None


def _find_url(args: dict[str, Any]) -> str:
    for k in ("Url", "URL", "url"):
        if isinstance(args.get(k), str):
            return args[k]
    m = _URL_RE.search(json.dumps(args))
    return m.group(0) if m else ""


def _touches_guard(claude_payload: dict[str, Any]) -> bool:
    if claude_payload["tool_name"] not in _WRITE_TOOLS:
        return False
    path = claude_payload["tool_input"].get("file_path")
    if not isinstance(path, str) or not path:
        return False
    parts = {p.lower() for p in Path(path.replace("\\", "/")).parts}
    return bool(parts & _GUARD_DIRS)


# ------------------------------------------------------------- Antigravity

def _antigravity(payload: dict[str, Any]) -> dict[str, Any]:
    call = payload.get("toolCall")
    if not isinstance(call, dict):
        raise BadInput("toolCall is not an object")
    name = call.get("name")
    if not isinstance(name, str) or not name.strip():
        raise BadInput("missing toolCall.name")
    args = call.get("args") or {}
    if not isinstance(args, dict):
        raise BadInput("toolCall.args is not an object")

    ws = payload.get("workspacePaths") or []
    if isinstance(ws, list) and ws and isinstance(ws[0], str) and ws[0]:
        root = ws[0]
    elif isinstance(payload.get("cwd"), str) and payload["cwd"]:
        root = payload["cwd"]
    else:
        root = os.getcwd()
    cwd = root

    if name == "run_command":
        tool, tin = _shell_tool(), {"command": args.get("CommandLine", "")}
        cwd = _abs(args.get("Cwd"), root) or root
    elif name in {"write_to_file", "write_file"}:
        tool = "Write"
        tin = {"file_path": _abs(_str(args, *_PATH_KEYS), root),
               "content": _str(args, *_CONTENT_KEYS) or ""}
    elif name == "replace_file_content":
        tool = "Edit"
        tin = {"file_path": _abs(args.get("TargetFile"), root),
               "old_string": args.get("TargetContent", ""),
               "new_string": args.get("ReplacementContent", "")}
    elif name == "multi_replace_file_content":
        chunks = args.get("ReplacementChunks") or []
        if not isinstance(chunks, list):
            raise BadInput("ReplacementChunks is not a list")
        tool = "MultiEdit"
        tin = {"file_path": _abs(args.get("TargetFile"), root),
               "edits": [{"old_string": _str(c, "TargetContent", "targetContent") or "",
                          "new_string": _str(c, "ReplacementContent", "replacementContent") or ""}
                         for c in chunks if isinstance(c, dict)]}
    elif name == "sed_file":
        tool = "Edit"
        tin = {"file_path": _abs(_str(args, *_PATH_KEYS), root),
               "old_string": "", "new_string": json.dumps(args)}
    elif name in {"view_file", "read_file"}:
        tool, tin = "Read", {"file_path": _abs(_str(args, *_PATH_KEYS), root)}
    elif name in {"read_url_content", "open_browser_url", "read_browser_page"}:
        tool, tin = "WebFetch", {"url": _find_url(args)}
    elif name == "call_mcp_tool":
        server, mtool = args.get("ServerName"), args.get("ToolName")
        if not isinstance(server, str) or not isinstance(mtool, str) or not server or not mtool:
            raise BadInput("call_mcp_tool without ServerName/ToolName")
        inner = args.get("Arguments") or {}
        tool, tin = f"mcp__{server}__{mtool}", inner if isinstance(inner, dict) else {"value": inner}
    elif name == "search_web":
        tool, tin = "WebSearch", {"query": args.get("query", "")}
    elif name == "grep_search":
        tool = "Grep"
        tin = {"pattern": args.get("Query", ""), "path": _abs(args.get("SearchPath"), root)}
    elif name == "list_dir":
        tool, tin = "Glob", {"pattern": "*", "path": _abs(args.get("DirectoryPath"), root)}
    elif _str(args, *_PATH_KEYS) is not None and name not in _CODE_EXEC_TOOLS:
        # Undocumented file tool: judge it by shape so it still gets the
        # write/read checks (the arena found agy's undocumented write_file).
        path = _abs(_str(args, *_PATH_KEYS), root)
        content = _str(args, *_CONTENT_KEYS)
        if content is not None:
            tool, tin = "Write", {"file_path": path, "content": content}
        else:
            tool, tin = "Read", {"file_path": path}
    else:
        tool, tin = name, args

    return {"tool_name": tool, "tool_input": tin, "cwd": cwd,
            "session_id": str(payload.get("conversationId", "")),
            "agent_type": "antigravity-cli"}


# ------------------------------------------------------------- Gemini CLI

def _gemini(payload: dict[str, Any]) -> dict[str, Any]:
    name = payload.get("tool_name")
    if not isinstance(name, str) or not name.strip():
        raise BadInput("missing tool_name")
    args = payload.get("tool_input") or {}
    if not isinstance(args, dict):
        raise BadInput("tool_input is not an object")
    root = payload.get("cwd")
    if not isinstance(root, str) or not root:
        root = os.environ.get("GEMINI_CWD") or os.getcwd()
    cwd = root

    if name == "run_shell_command":
        tool, tin = _shell_tool(), {"command": args.get("command", "")}
        cwd = _abs(args.get("dir_path"), root) or root
    elif name == "write_file":
        tool = "Write"
        tin = {"file_path": _abs(args.get("file_path"), root), "content": args.get("content", "")}
    elif name == "replace":
        tool = "Edit"
        tin = {"file_path": _abs(args.get("file_path"), root),
               "old_string": args.get("old_string", ""),
               "new_string": args.get("new_string", "")}
    elif name == "read_file":
        tool, tin = "Read", {"file_path": _abs(args.get("file_path"), root)}
    elif name == "web_fetch":
        prompt = str(args.get("prompt", ""))
        m = _URL_RE.search(prompt)
        tool, tin = "WebFetch", {"url": m.group(0) if m else "", "prompt": prompt}
    elif name == "google_web_search":
        tool, tin = "WebSearch", {"query": args.get("query", "")}
    elif name in {"grep_search", "search_file_content"}:
        tool = "Grep"
        tin = {"pattern": args.get("pattern", ""), "path": _abs(args.get("dir_path"), root)}
    elif name == "glob":
        tool = "Glob"
        tin = {"pattern": args.get("pattern", ""), "path": _abs(args.get("dir_path"), root)}
    else:
        tool, tin = name, args

    return {"tool_name": tool, "tool_input": tin, "cwd": cwd,
            "session_id": str(payload.get("session_id", "")),
            "agent_type": "gemini-cli"}


def to_claude(flavour: str, payload: dict[str, Any]) -> dict[str, Any]:
    if flavour == ANTIGRAVITY:
        return _antigravity(payload)
    if flavour == GEMINI:
        return _gemini(payload)
    raise BadInput(f"unknown flavour {flavour!r}")


# ------------------------------------------------------------- verdicts

def _deny(reason: str) -> dict[str, Any]:
    return {"decision": "deny", "reason": reason}


def from_claude(flavour: str, out: dict[str, Any]) -> dict[str, Any]:
    """Translate a hook_eval PreToolUse result into the agent's format."""
    hso = out.get("hookSpecificOutput") if isinstance(out, dict) else None
    if not isinstance(hso, dict):
        return _deny(ERROR_REASON)
    decision = hso.get("permissionDecision")
    reason = str(hso.get("permissionDecisionReason") or "")

    if decision is None:
        # hook_eval had no opinion: let the agent's own permission flow run.
        return {"decision": "allow"} if flavour == ANTIGRAVITY else {}
    if decision == "allow":
        return {"decision": "allow"}
    if decision == "deny":
        return _deny(reason or "SANDBOX: denied by policy")
    if decision == "ask":
        if flavour == ANTIGRAVITY:
            return {"decision": "force_ask", "reason": reason}
        return _deny(
            "SANDBOX: this action needs a human's confirmation, and Gemini CLI "
            f"hooks cannot ask. Ask the user to run it themselves. {reason}".strip())
    return _deny(ERROR_REASON)


# ------------------------------------------------------------- entry points

async def evaluate(raw: str) -> dict[str, Any]:
    """Evaluate one raw stdin payload; always returns the agent's output."""
    try:
        payload = json.loads(raw)
    except ValueError:
        return _deny(BAD_INPUT_REASON)
    flavour = detect(payload)
    if flavour is None:
        return _deny(BAD_INPUT_REASON)
    try:
        claude_payload = to_claude(flavour, payload)
    except BadInput:
        return _deny(BAD_INPUT_REASON)

    if _touches_guard(claude_payload):
        return _deny(GUARD_REASON)
    tin = claude_payload["tool_input"]
    if claude_payload["tool_name"] in {"Bash", "PowerShell"}:
        if env_secret_hit(str(tin.get("command", ""))):
            return _deny(ENV_REASON)
    for key in ("file_path", "path"):
        if isinstance(tin.get(key), str) and _CRED_PATH.search(tin[key].replace("\\", "/")):
            return _deny(ENV_REASON)
    if claude_payload["tool_name"] in _CODE_EXEC_TOOLS:
        if flavour == ANTIGRAVITY:
            return {"decision": "force_ask", "reason": CODE_EXEC_REASON}
        return _deny(CODE_EXEC_REASON)

    layout = FolderLayout.discover(claude_payload["cwd"])

    # F10: typosquat check removed from here; the hook's pre_tool_use covers
    # all agents (Claude Code, Antigravity, Gemini CLI) uniformly.

    if layout is None:
        # No sandbox folder here: same as the Claude Code hook, do nothing.
        return {"decision": "allow"} if flavour == ANTIGRAVITY else {}
    return from_claude(flavour, await pre_tool_use(claude_payload, layout))


def main(argv: list[str] | None = None) -> int:
    """Read one payload on stdin, print one JSON object, exit 0."""
    argv = sys.argv[1:] if argv is None else argv
    log_path = argv[argv.index("--log") + 1] if "--log" in argv[:-1] else None
    real_stdout = sys.stdout
    raw = ""
    try:
        raw = sys.stdin.read()
        # Anything the evaluator prints must not corrupt the JSON on stdout.
        with contextlib.redirect_stdout(sys.stderr):
            result = asyncio.run(evaluate(raw))
    except Exception as exc:  # noqa: BLE001 — fail closed
        sys.stderr.write(f"SANDBOX: adapter internal error: {exc}\n")
        sys.stderr.flush()
        result = _deny(ERROR_REASON)
    if log_path:
        # Debug only: record what the agent sent and what we answered.
        with contextlib.suppress(OSError):
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"in": raw, "out": result}) + "\n")
    real_stdout.write(json.dumps(result))
    real_stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
