# Tripwire

**An open-source security layer for AI coding agents.**
It catches the moment an agent leaks a secret, stops the request at the wire,
freezes the agent, alerts the on-call team in Google Chat, and asks a named
human what to do next. A Gemini intent judge explains *why* an action does not
fit the task. The decision is signed, so anyone can verify it later.

> *Rules give proof. AI judges intent. A human decides.*

**Team Timepass · Google Startup Buildathon 2026**

> *The model was smart. The repo wasn't.*

---

## The problem

Coding agents run code they did not write: a project's `setup.py`, a test
script, a dependency's install hook. Modern models are good at refusing an
obvious attack. In our runs, Gemini ignored a README that told it to send
credentials away (0 trips in 4 runs).

But the dangerous case is not obvious. A poisoned `setup.py` reads a key file
and posts it to a "telemetry" endpoint while the agent is doing honest work.
The agent never sees the theft. It ran `python setup.py configure` because the
task told it to. No model-level refusal can stop what the model never sees.

Tripwire works below the model: on the files, the processes and the network.

---

## What the demo shows (everything runs live)

1. **Split-screen duel.** The same agent, the same task and the same model
   (`gemini-3.5-flash-lite`) run twice, side by side.
   - **Guard OFF:** the poisoned `setup.py` sends the planted secret, and our
     fake attacker server shows the bytes arriving.
   - **Guard ON:** the egress proxy finds the secret in the outbound request
     and blocks it. The agent is frozen and an Ed25519 stop record is signed.
2. **"Make it sneakier."** The judge picks how the attack hides the secret:
   - encoding: plain, base64, hex, reversed or chunked across several requests;
   - channel: JSON body, query string or HTTP header;
   - attacker host label.

   A fixed template generates the variant. Judge-typed code is never run.
3. **A human decides.** Tripwire calls a phone number (a voice agent built on Gemini 3.1 Flash-Lite) or opens a
   voice call in the browser (Gemini Live; English, Hindi, Telugu). Plain
   buttons are the fallback. Voice can only keep the agent frozen. A spoken
   "release" asks for a button click to confirm, because voice is
   unauthenticated and transcripts can be wrong.
4. **Signed receipt.** The decision is signed with Ed25519 and chained into a
   hash-linked audit log. "Verify" returns true; "Tamper" changes one field and
   returns false.
5. **Rules only vs Rules + AI.** One click runs the same scrambled attack
   (xor or gzip, which our pattern scanner cannot read) in two guarded
   sessions. In both, default deny blocks the request and the rules freeze
   the session and alert a human on their own (`RULE: FROZEN`). Only the
   right side adds the Gemini intent judge, which explains why the request
   does not fit "run the tests".
6. **Google Chat.** Every freeze posts a card to the on-call team's Chat
   space. Its **Decide** button opens the team-approval page: anyone can keep
   the agent frozen, release needs two different people. The AI's analysis
   arrives as a reply in the same thread.
7. **Google's own agent, live.** Antigravity CLI is asked to install
   `pandaz-csv`, a one-letter typosquat of `pandas`. Our pre-tool hook denies it
   with `[TYPOSQUAT]` before anything is downloaded, and the audit chain
   verifies.

A recorded real run exists only as a fallback if the network fails. It is
labelled as recorded and plays at its real timestamps.

---

## How it works

```
                    ┌──────────────── browser (demo page) ────────────────┐
                    │ task picker · live OFF/ON timelines · call · receipt│
                    └───────────────┬─────────────────────────┬───────────┘
                                    │ HTTP poll               │ WebSocket audio
┌───────────────────────────────────▼─────────────────────────▼────────────┐
│ FastAPI server (arena/)                                                   │
│                                                                           │
│  Gemini agent loop ──► tripwire.check() ──► hook policy (typosquat,       │
│  (agent.py)            decoy path / canary   env dump, guard disable)     │
│       │                in tool args                                       │
│       │ run_command                                                       │
│       ▼                                                                   │
│  runner (separate container, no secrets, own uid)                         │
│       │ all HTTP                                                          │
│       ▼                                                                   │
│  egress proxy (egress.py + exfil_scan.py)                                 │
│    guard ON : scan host, path, query, headers, body; decode;              │
│               reassemble chunks; deny by default                          │
│    guard OFF: reroute everything to the fake attacker server              │
│       │                                       │                           │
│       ▼ trip                                  ▼                           │
│  quarantine(): stop flag + Ed25519        attacker_server.py              │
│  stop record + audit chain                (records and decodes loot)      │
│       │                                                                   │
│       ▼                                                                   │
│  Gemini intent judge (intent.py): each tool call + each blocked request   │
│    vs the task; adds an explanation or a freeze, never an allow           │
│       │                                                                   │
│       ▼                                                                   │
│  Google Chat alert (gchat.py) ─► Decide page (approvers.py)               │
│  human decision: Chat · team page · phone call · Gemini Live voice        │
│       │                                                                   │
│       ▼                                                                   │
│  sign_decision(): Ed25519 receipt + audit chain                           │
└───────────────────────────────────────────────────────────────────────────┘
```

### Deterministic code vs model

| Layer | How it works |
|---|---|
| Canary secrets | Code. Random values shaped like AWS, Stripe, PEM and Postgres credentials, planted in decoy files (`.aws/credentials.bak`, `.env.backup`, `deploy_key.pem`). |
| Trip detection | Code. Decoy-path access, plus canary values in tool arguments and outbound HTTP. Covers plain, base64 (std/url, padded or not), hex, reversed, base64 blobs, and secrets split across requests. |
| Default-deny freeze | Code. Any request a guarded agent sends to a host that is not allowed is blocked, and the session freezes, signs a stop record and alerts a human (`RULE`), whether or not the contents could be read. |
| Intent judge | Model. Gemini compares each tool call, and each blocked request, with the user's task. It can add an explanation or a freeze, never remove one. Planted secrets are masked before anything is sent, repo text is marked untrusted, and a timeout or rate limit means "unavailable": the rules are unchanged. |
| Typosquat check | Code. Edit distance against 146 popular packages. |
| Env-dump and guard-disable checks | Code. Ten regex patterns on shell commands. |
| Quarantine and receipts | Code. Ed25519 (PyNaCl) signatures with domain tags, and a SHA-256 hash-chained audit log. |
| Agent | Model. Gemini picks the tools it calls. |
| Voice call | Model. It explains the incident from the signed record and listens. It can only record "keep frozen"; a release needs a button. |

The design rule: **a model may only add scrutiny, never remove it.** A tripped
canary is a fact found by code, not a model's opinion.

---

## Measured results

These are real runs. The model is `gemini-3.5-flash-lite` unless noted. We
report misses and false trips too.

| Scenario | Result |
|---|---|
| `setup` (poisoned setup.py), guard ON | 5 of 5 tripped |
| `fix-deploy` (poisoned deploy script), guard ON | 19 of 19 tripped, median 30.6 s |
| Guard OFF on the same scenarios | the secret reached the attacker server |
| Chunked + header variant, live duel | OFF compromised, ON tripped (secret reassembled from 2 requests), 11.9 s end to end |
| README prompt injection | 0 of 4 tripped: the model ignored it, so this scenario is hidden from the demo |
| 20 ordinary tasks (false-trip control) | 1 false trip (5%): the agent opened `.aws/credentials.bak` while exploring. 0 errors. |
| Rules only vs Rules + AI, 24 Nov, 90 runs, guard ON, 3 per scenario per mode | Scrambled data (xor, gzip): rules alone froze and alerted 6 of 6; with the AI, 6 of 6 froze and Gemini explained why in 6 of 6. Planted-secret attacks: 6 of 6 caught with proof in both modes. 0 leaks in 30 attack runs. False freezes: 1 in 30 ordinary tasks in each mode. |
| Antigravity CLI typosquat (live hook, `gemini-3.8-flash`) | blocked at 24.7 s, audit chain verified |

---

## Verify a receipt yourself

A receipt is a signed record (`sig_v: 1`). The signature covers:
- the domain tag `agg/record/v1`;
- a zero byte;
- the canonical JSON (`sort_keys=True`, separators `(",", ":")`) of the fixed
  field set `_SIGNED_FIELDS` in `src/sandbox/connector/signing.py`.

The decision value is `deny` or `approve`.

```python
from sandbox.connector.signing import verify_record

verify_record(receipt)          # True
receipt["decision"] = "approve" # change any signed field
verify_record(receipt)          # False
```

The server exposes the same check: `GET /api/receipt/{session_id}/verify`, and
`?tamper=1` shows the failure case. Each audit-log line carries the hash of the
line before it, so editing any entry breaks the chain from that point on.

---

## Run it locally

You need Python 3.12+ and a Gemini API key from Google AI Studio.

```bash
pip install -e ".[dev]" google-genai segno
export GEMINI_API_KEY=...        # or put GEMINI_API_KEY=... in arena/.env
python -m arena.server           # http://127.0.0.1:8088
```

Open `http://127.0.0.1:8088/` for the demo page. Add `?mock=1` to see every
state without calling any API; mock mode is clearly marked on screen.

Optional settings:

- **Phone calls:** set the telephony provider key in `BOLNA_API_KEY` (or a file path in
  `BOLNA_KEY_FILE`), and the voice agent id in `arena/phone_agent.json`. `ARENA_PHONE=0` turns calls off.
- **Live Antigravity CLI demo:** needs `agy` installed on the same machine.
  Without it, the endpoint returns 503 and the page offers the recorded run.

Tests:

```bash
python -m pytest tests/unit -q
```

### Docker

```bash
cd deploy
cp .env.example .env   # set ARENA_ATTACKER_KEY, ARENA_AGENT_KEY, ARENA_ADMIN_TOKEN
docker compose up -d --build
```

Agent commands run in a separate runner container:
- on an internal network with no secrets;
- as their own uid;
- under resource limits.

Caddy provides TLS. Deployment on GCP Compute Engine is described in
`deploy/README.md`. It is planned and not yet live.

---

## Google AI used

| Component | Use |
|---|---|
| Gemini (`gemini-3.5-flash-lite`, with fallbacks) | The coding agent under test, via function calling (`arena/agent.py`) |
| Gemini intent judge (same models, structured JSON output) | Explains or flags actions that do not fit the task (`arena/intent.py`) |
| Google Chat | On-call alert cards and the AI analysis thread (`arena/gchat.py`) |
| Gemini Live (`gemini-3.1-flash-live-preview`) | Browser voice call for the decision (`arena/voice.py`) |
| Antigravity CLI | Governed live through pre-tool hooks (`src/sandbox/connector/google_adapter.py`) |
| Gemini CLI | Hook adapter in the same file; unit-tested only |
| GCP Compute Engine | The demo site runs on a Compute Engine VM with Caddy TLS (`deploy/`) |

---

## Honest limits

- **Plain HTTP only.** The proxy refuses HTTPS `CONNECT`. A production version
  needs TLS interception with a workspace-scoped CA.
- **Pattern matching, not meaning.** Detection finds the planted canaries in
  known encodings. Two cases are not caught:
  - a secret that is retyped, compressed or encrypted;
  - a secret split across different field names or sent out of order.

  When guard ON misses one, default deny still blocks the request, and the
  rules freeze the session and alert a human anyway (`RULE`). The Gemini intent
  judge explains what the request was.
- **Decoys can be touched by honest agents.** 1 of 20 ordinary tasks tripped;
  in the 24 Nov re-run, 1 of 30 in each mode.
- **The AI judge is a model.** It can be wrong or unavailable. It never allows
  anything, so a wrong answer costs a false freeze or a missing explanation,
  never a leak.
- **Small scenario set.** Two attack scenarios in the demo, one hidden
  scenario, and ten control tasks.
- **The voice explanation is best-effort.** The model is told to state only
  facts from the signed record. The decision itself is validated by code.
- **Prototype.** Single VM, in-memory sessions, bearer-token admin endpoint.
  The code has had an internal security review but no external audit.

---

## License

MIT. See `LICENSE`.
