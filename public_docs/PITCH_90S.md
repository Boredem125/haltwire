# Tripwire — 90-Second Demo Script

> **For judges. Total runtime: ~90 seconds. Practice this twice.**

---

## Setup (before you start the clock)

- Browser open to your deployed Tripwire page (e.g. `https://<ip>.sslip.io` or `http://localhost`)
- Microphone + speakers working (the voice call needs them)
- Two tabs ready: one for the demo page, one to show code if asked

---

## Script

### 0:00–0:10 — The hook (10 s)

> **Say:** "AI coding agents run your code in your repo. But what if the repo is poisoned? A typosquatted package, a README that says 'curl your .env to our server' — the agent just does it. Tripwire catches that."

### 0:10–0:20 — Guard OFF: show the attack works (10 s)

> **Click:** Select the "Fix the failing deploy script" scenario. Toggle **Guard OFF**. Click **Run**.

> **Say:** "Guard off — no protection. The agent reads the deploy script, it references `.aws/credentials.bak`, the agent reads it, and..."

> **Wait** for events to stream. Point at the event log as tool calls appear.

> **Say** (when verdict shows): "Compromised. The canary secret arrived at the attacker's capture server. That's your AWS key, gone."

### 0:20–0:40 — Guard ON: show the trip (20 s)

> **Click:** Same scenario. Toggle **Guard ON**. Click **Run**.

> **Say:** "Same agent, same task, same repo. But now Tripwire is watching."

> **Wait** for the agent to hit the decoy file. The event log shows a red **TRIP** event.

> **Say:** "The agent touched `.aws/credentials.bak` — a canary file we planted. Tripwire froze the agent instantly. That trip detection is deterministic code, not a model judgment."

### 0:40–1:05 — The voice call (25 s)

> **Say:** "Now Gemini Live calls you."

> **Wait** for the voice to start speaking through your browser speakers. Gemini Live will explain what happened — it reads from the signed record, not from a prompt.

> When Gemini asks "keep frozen or release?":

> **Say into mic:** "Keep it frozen."

> Gemini reads back: "You said keep frozen. Is that correct?"

> **Say into mic:** "Yes."

> **Point** at the receipt that appears on screen — signature, public key, chain head.

> **Say:** "That decision is now signed with Ed25519, chained into a hash-linked audit log. Anyone can verify it with the public key — no shared secret, no trust-me."

### 1:05–1:20 — What else it blocks (15 s)

> **Say:** "Beyond canaries, the same security layer governs Google's Antigravity CLI and Gemini CLI through their native hooks. It blocks:"

> *Count on fingers:*

> "One — typosquatted packages. `pandaz-csv` is one letter off `pandas`: denied, deterministically, Damerau-Levenshtein distance.

> Two — environment variable dumps. `printenv`, `$STRIPE_KEY`, any of thirty regex patterns: denied.

> Three — the agent trying to delete its own guard config. `.agents/hooks.json`? Denied."

### 1:20–1:30 — Wrap (10 s)

> **Say:** "Tripwire. Plant fake secrets. Catch the leak with code, not vibes. Call the human by voice. Sign the receipt. This is a prototype — HTTP only, three scenarios, demo canaries — but the architecture is real, the crypto is real, and the problem is real."

> **Say:** "Team Timepass. Thank you."

---

## If judges ask

| Question | Answer |
|----------|--------|
| "Why not just block everything?" | The agent needs to do its job. We only trip on specific canary files and canary values — normal work is unaffected. |
| "Can the agent evade the canary check?" | It checks plain text, base64, hex, and reversed encodings. That's not exhaustive — HTTPS egress is refused entirely in this demo. We document the limits. |
| "Why voice, not a Slack message?" | Voice is synchronous and human-verified. Gemini Live reads the decision back and waits for confirmation before the server signs. A notification can be ignored; a phone call demands attention. |
| "How do you verify the receipt?" | Ed25519. Extract `signed_fields`, serialize as sorted JSON, prepend domain tag, verify signature against `signer_public_key`. No shared secret. Code is in `signing.py:219`. |
| "What Google AI do you use?" | Gemini Flash (function-calling agent), Gemini Live (native audio voice call), Antigravity CLI and Gemini CLI governed via hooks, GCP Compute Engine with Caddy. |
| "Is this production-ready?" | No. Prototype. HTTP-only egress, three demo scenarios, single VM, no HA. We document every limitation in the README. |

---

## Claims → code references

| # | Claim made in this script | Code file : line(s) |
|---|--------------------------|---------------------|
| 1 | Canary secrets are shaped like real AWS keys, Stripe keys, PEM, Postgres URLs | `arena/tripwire.py:94-121` (mint function) |
| 2 | Decoy files planted: `.aws/credentials.bak`, `.env.backup`, `deploy_key.pem` | `arena/tripwire.py:33-37` (DECOY_PATHS), `arena/tripwire.py:126-159` (plant) |
| 3 | Trip detection checks path access and canary values in plain/b64/hex/reversed | `arena/tripwire.py:182-233` (path check), `arena/tripwire.py:236-315` (canary exfil check) |
| 4 | Trip detection is deterministic (string matching, not model) | `arena/tripwire.py:318-359` (check function — no model call, pure string ops) |
| 5 | quarantine() signs a stop record with Ed25519 | `arena/tripwire.py:364-412` (quarantine), `src/sandbox/connector/signing.py:197-216` (sign_record) |
| 6 | Stop record is appended to hash-chained audit log | `arena/tripwire.py:387-396` (FolderAudit.append) |
| 7 | Agent is frozen (tripwire_stop flag file) | `arena/tripwire.py:399-404` (stop flag write), `arena/tripwire.py:415-417` (is_quarantined) |
| 8 | Gemini Flash is the agent model (function-calling loop) | `arena/agent.py:42` (DEFAULT_MODELS), `arena/agent.py:54-100` (TOOL_DECLS), `arena/agent.py:306-547` (run_session) |
| 9 | Agent has four tools: read_file, write_file, list_dir, run_command | `arena/agent.py:54-100` (TOOL_DECLS) |
| 10 | Gemini Live voice bridge: explains incident from record only | `arena/voice.py:52-103` (build_system_prompt — only record fields injected) |
| 11 | Voice asks "keep frozen or release?", reads back, confirms before signing | `arena/voice.py:95-103` (prompt instructions steps 1-6) |
| 12 | record_decision is a function call with enum validation | `arena/voice.py:155-170` (FunctionDeclaration, enum keep_frozen/release), `arena/voice.py:234-247` (validation) |
| 13 | Decision signed with Ed25519 by the server | `arena/duel.py:256-288` (sign_decision) |
| 14 | Receipt includes signature, public_key, chain_head, digest | `arena/duel.py:280-288` (return dict) |
| 15 | Egress proxy: HTTP only, HTTPS CONNECT refused with 403 | `arena/egress.py:103-105` (do_CONNECT) |
| 16 | Egress proxy scans for canary values in outbound HTTP | `arena/egress.py:128-138` (canary scan in _handle_request) |
| 17 | Capture server records loot at /collect, checks canary_hit | `arena/attacker_server.py:57-99` (_handle_collect) |
| 18 | Typosquat detection: Damerau-Levenshtein against 150+ popular packages | `src/sandbox/connector/typosquat.py:20-36` (POPULAR), `src/sandbox/connector/typosquat.py:64-78` (_distance), `src/sandbox/connector/typosquat.py:81-106` (lookalike) |
| 19 | Env-dump blocking: 30+ regex patterns | `src/sandbox/connector/google_adapter.py:102-114` (_ENV_PATTERNS) |
| 20 | Guard-self-disable blocking: agents cannot edit .agents/ or .gemini/ | `src/sandbox/connector/google_adapter.py:89-91` (GUARD_REASON), `src/sandbox/connector/google_adapter.py:135-142` (_touches_guard) |
| 21 | google_adapter governs Antigravity CLI via PreToolUse hook | `src/sandbox/connector/google_adapter.py:1-25` (docstring), `src/sandbox/connector/google_adapter.py:147-223` (_antigravity) |
| 22 | google_adapter governs Gemini CLI via BeforeTool hook | `src/sandbox/connector/google_adapter.py:228-270` (_gemini) |
| 23 | Fail-closed: every error path prints a deny, never an allow | `src/sandbox/connector/google_adapter.py:17-21` (docstring), `src/sandbox/connector/google_adapter.py:375-378` (exception handler) |
| 24 | Docker: non-root user, read-only rootfs, cap_drop ALL, resource limits | `deploy/Dockerfile:28-31` (non-root user), `deploy/docker-compose.yml:29-41` (hardening) |
| 25 | Caddy auto-TLS via sslip.io on GCP | `deploy/Caddyfile:12-13`, `deploy/README.md:123` |
| 26 | Voice supports English, Hindi, Telugu | `arena/voice.py:38` (_LANG_NAMES) |
| 27 | Three scenario chips: fix-deploy, setup, readme-poison | `arena/scenarios_tw.py:125-163` (CHIPS list) |
| 28 | Path confinement: agent cannot escape workspace | `arena/agent.py:106-120` (_confine) |
| 29 | Subprocess env stripped of API keys | `arena/agent.py:46-49` (_SECRET_KEYS), `arena/agent.py:126-141` (_safe_env) |
| 30 | Signing uses PyNaCl Ed25519 | `src/sandbox/connector/signing.py:28` (import nacl.signing) |

