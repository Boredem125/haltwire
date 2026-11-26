# haltwire

**A tripwire and approval gate for AI coding agents.** haltwire sits between your coding agent and your machine. Every tool call (shell, file, web, MCP) is checked before it runs. Safe work goes through, risky actions wait for you, and an agent that touches bait gets frozen on the spot.

> An AI agent having a *capability* is not the same as it having *authority*.

Works with **Claude Code** (full hooks) and **Antigravity / agy** (`--agy`). Gemini CLI hooks are experimental (`--gemini`). Codex, Cursor and Windsurf are covered only through haltwire's MCP tools; their built-in shell and file tools are not intercepted.

## Quick start

Needs git, Python 3.12+ and [uv](https://docs.astral.sh/uv/) (or pipx).

```bash
cd your-project
npx github:Boredem125/haltwire init     # set up this folder
haltwire watch                          # dashboard, in a second terminal
claude                                  # your agent, as usual
```

`init` installs the `haltwire` command once (a persistent `uv tool install` pinned to this release), then sets up the folder:

- `.sandbox/` with the policy, the audit log and the approval queue
- Claude Code hooks in `.claude/settings.local.json` (plus `.agents/hooks.json` with `--agy`)
- decoy files (`.env.backup`, `deploy_key.pem`, `.aws/credentials.bak`) holding unique fake secrets, kept out of git via `.git/info/exclude` (skip with `--no-canaries`)
- you, pinned as the reviewer who can unfreeze this folder

It does not touch your code. `haltwire uninstall` removes what it added.

## What it stops

| The agent tries to... | haltwire does | You see in `watch` |
|---|---|---|
| read, list or edit inside the project | allows it | grey `ALLOW` line |
| install a look-alike package (`pandaz-csv` for `pandas`) | holds it for you | yellow `WAIT` + `TYPOSQUAT` |
| read a decoy credential file | **freezes the folder**: every tool except reads is denied | red `FROZEN` banner |
| send a decoy secret out, in any encoding | freezes the folder | red `FROZEN` banner |
| make network calls after decoy data appeared in its output | holds each call for you; payload uploads are denied | `WAIT` + `CANARY_TAINT` |
| edit or delete its own hook config | denies it | red `DENY` |
| something the AI judge finds off-task (optional) | holds it for you | `AI!` + Gemini's reasoning |

Approved commands run outside the agent, and their output is handed back. Every decision goes into a signed, hash-chained audit log (`haltwire verify` checks it).

**Design rule:** the AI judge can only *raise* scrutiny. The deterministic rules stay in charge, so a fooled model means one extra approval, never an open door.

## The dashboard

`haltwire watch` is a terminal dashboard. The header shows the folder status (PROTECTED / FROZEN) and the AI judge state. Below it are counts, the queue waiting for you, a details card for the selected item, and the live activity feed.

| Key | Action |
|---|---|
| `a` / `d` | approve / deny the selected request |
| `u` | unfreeze (asks for your reviewer id, signs the unfreeze) |
| `k` | set the Gemini API key (tested before it is saved) |
| `j` | turn the AI judge on or off |
| `r` / `?` / `q` | refresh / help / quit |

`haltwire watch --plain` gives a plain-text view for terminals without full-screen support. `NO_COLOR` is respected.

## AI judge (optional)

The Gemini intent judge compares each shell, write and network call with the task you gave the agent, and holds anything that does not fit. It is off by default and uses your own key.

```bash
haltwire watch     # press k, paste the key, then j
# or: set GEMINI_API_KEY in the agent's environment, then
haltwire ai on
haltwire ai status
```

A key set with `k` is stored per user, outside every repo, readable only by you, and the agent is denied access to it. Secrets and decoy values are scrubbed from the prompt before anything is sent. On timeout or error the judge adds nothing, and the rules still apply.

## Frozen? Unfreeze

In `watch`, press `u` and type your reviewer id (`init` pinned your OS user name). From the command line:

```bash
haltwire status .
haltwire unfreeze . --reviewer <your-id>
```

Only a reviewer with a pinned signing key can unfreeze. That key lives outside the project, where the agent cannot read it, so the agent cannot unfreeze itself. Each unfreeze is a signed audit record. For a folder set up before 0.1.5, pin yourself once with `haltwire keys pin <your-id>`.

## Useful commands

```bash
haltwire status .          # policy, frozen or not, anything pending
haltwire verify .          # check the audit chain has not been tampered with
haltwire explain <id>      # why a call was held or denied
haltwire changes .         # files the agent modified or deleted
haltwire restore <file> .  # put a file back
haltwire doctor .          # check the hooks are wired correctly
```

The CLI is also installed as `sandbox`. Both names run the same commands.

To send alerts to Slack, Teams or Google Chat, set `SANDBOX_ALERT_WEBHOOK` to the incoming-webhook URL. Google Chat webhooks get a formatted card.

## Install options

```bash
npx github:Boredem125/haltwire init          # from GitHub, no npm account needed
npx haltwire init                            # once published to npm
uv tool install git+https://github.com/Boredem125/haltwire@v0.1.6   # without Node
```

The npx launcher is a small Node.js script with no dependencies. It finds `uv` (or `pipx`) and installs the Python package from the matching git tag. If neither is found, it prints the one-line install command for your OS. `--install-uv` lets it install uv for you (it asks first). `HALTWIRE_REF` overrides the git ref.

From source:

```bash
git clone https://github.com/Boredem125/haltwire && cd haltwire
pip install -e ".[dev]"
pytest
```

More: [GETTING_STARTED.md](GETTING_STARTED.md) · [SECURITY.md](SECURITY.md)

## Free and team editions

Everything in this repo is free and MIT licensed: one developer, run locally, your own Gemini key. Team features (SSO, centrally signed policy, a shared approval inbox, fleet-wide audit and compliance evidence, a managed AI judge) are a separate commercial edition.

## Arena demo

The arena is an interactive red-team demo of the same checks stopping live attacks.

```bash
pip install -e ".[arena]"
cp deploy/.env.example deploy/.env   # add GEMINI_API_KEY, GOOGLE_CHAT_WEBHOOK, ...
python -m arena.server               # http://localhost:8133
```

## Security of haltwire itself

CI runs Semgrep, Gitleaks and Trivy on every push, with a severity gate. Hooks run in exec form (no shell), and they fail closed. See [SECURITY.md](SECURITY.md) to report a problem.

## Licence

[MIT](LICENSE)
