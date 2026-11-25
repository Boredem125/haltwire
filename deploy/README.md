# Tripwire -- Deployment

Single-VM deployment: Docker Compose stack with Caddy for automatic HTTPS.

## Architecture

```
Internet --> :80/:443 --> [Caddy 172.30.0.2]
                              |
                   arena-net (172.30.0.0/24)
                              |
                     [Arena 172.30.0.10:8088]  (uid 999, non-root)
                              |
                   runner-net (172.31.0.0/24, internal)
                              |
        [Arena 172.31.0.10]  <--unix-socket-->  [Runner 172.31.0.20]
                                                      |
                                              prlimit + drop to uid 10001
                                                      |
                                              agent shell commands
```

### Services

| Service | UID | Networks | Purpose |
|---|---|---|---|
| arena | 999 (arena) | arena-net + runner-net | FastAPI server, Gemini API calls, egress proxy |
| runner | root (drops to 10001) | runner-net only | Executes agent commands via Unix socket |
| caddy | (alpine default) | arena-net | Reverse proxy, automatic HTTPS |

### Security model

- **arena** runs as uid 999, cap_drop ALL, no-new-privileges, read-only rootfs.
  API binds on 172.30.0.10 (arena-net only), never 0.0.0.0.
- **runner** runs as root (needs SETUID/SETGID to drop to 10001), cap_drop ALL
  then cap_add SETUID/SETGID/KILL/CHOWN/FOWNER, no-new-privileges, read-only rootfs.
  On runner-net only (internal, no internet). DNS pointed to 127.0.0.1 (no resolution).
- Agent commands run as uid 10001 with prlimit caps (1 GB AS, 64 nproc, 20s CPU,
  64 MB fsize, 256 nofile), 20s wall timeout, process group killed afterwards.
- Unix socket /sock/exec.sock is 0660 root:999. Only arena (uid 999) can connect.
- **No secrets in the runner container.** API keys live only in arena's env.
- Runs volume is tmpfs 512 MB with setgid bit (mode 2770, uid 999, gid 10001).
- All setuid/setgid bits stripped from binaries in the image.

### Runner socket protocol

The arena server and the runner daemon communicate via a Unix domain socket.

**Env var:** `ARENA_RUNNER_SOCK` (default: `/sock/exec.sock`)

**Request** (one JSON line):
```json
{"cwd": "/runs/sessions/<id>/ws", "cmd": "echo hello", "proxy": "http://172.31.0.10:9090"}
```

**Response** (one JSON line):
```json
{"out": "hello\n", "rc": 0, "timed_out": false}
```

**Validation:**
- `cwd` must resolve to `$ARENA_RUNS/sessions/[A-Za-z0-9_-]+/ws(/.*)?`
- `proxy` must match `^http://172\.31\.0\.10:\d+$` (or empty)
- `cmd` max 4096 chars
- `out` capped at 8192 bytes
- Max 4 concurrent executions; excess connections rejected

## Prerequisites

- Docker and Docker Compose v2
- Two Gemini API keys (create in Google AI Studio)
- For GCP: a static external IP and firewall rules for 80/443

## Local testing (no TLS, plain HTTP)

```bash
cd deploy
cp .env.example .env
# Edit .env: fill in ARENA_ATTACKER_KEY, ARENA_AGENT_KEY, ARENA_ADMIN_TOKEN

docker compose up -d --build
# Open http://localhost in a browser
docker compose logs -f arena
docker compose down
```

## GCP deployment

### Quick start (scripted)

```bash
export GCP_PROJECT_ID=your-project-id
export FOUNDER_SSH_CIDR=1.2.3.4/32   # your IP
chmod +x gcp_up.sh
./gcp_up.sh
# Follow the printed instructions.
```

### Manual steps

1. Reserve a static IP in asia-south1.
2. Create firewall rules: 80/443 from anywhere, 22 from founder IP only.
3. Create an e2-standard-2 VM with `--no-service-account --no-scopes`.
4. SSH in, install Docker from the official apt repo.
5. Upload the repo, `cp .env.example .env`, fill in keys and domain.
6. `docker compose up -d --build`.

## Verify-before-demo checks

Run these **on the VM** after `docker compose up -d`:

```bash
# 1. Runner cannot reach the arena API (arena binds 172.30.0.10 only)
docker exec tripwire-runner curl -m3 http://172.30.0.10:8088 2>&1
# Expected: connection refused or timeout (runner is on runner-net only)

# 2. Runner cannot reach the arena API via runner-net
docker exec tripwire-runner curl -m3 http://172.31.0.10:8088 2>&1
# Expected: connection refused (arena API binds on 172.30.0.10, not 172.31.0.10)

# 3. DNS resolution fails inside runner
docker exec tripwire-runner getent hosts google.com 2>&1
# Expected: failure (dns 127.0.0.1)

# 4. Metadata server unreachable from runner
docker exec tripwire-runner curl -m3 http://169.254.169.254/ 2>&1
# Expected: timeout or refused (runner-net is internal, no route)

# 5. No API keys visible in runner process environment
docker exec tripwire-runner cat /proc/1/environ | tr '\0' '\n' | grep -i key
# Expected: no output (runner has no secret env vars)

# 6. Egress proxy reachable from agent commands (via runner-net)
# (The arena server binds the proxy on 172.31.0.10 -- runner-net)
docker exec tripwire-arena curl -m3 http://172.31.0.10:9090/ 2>&1
# Expected: proxy response or connection accepted

# 7. Fork bomb does not kill the API
docker exec tripwire-runner bash -c ':(){ :|:& };:' 2>&1 || true
sleep 3
curl -s http://localhost/api/stats | head -c 200
# Expected: /api/stats still responds (pids_limit protects the host)

# 8. Compose config valid
docker compose -f deploy/docker-compose.yml config --quiet
# Expected: exit 0
```

## Security notes

| Control | Implementation |
|---|---|
| Agent isolation | Separate runner container, uid 10001, prlimit resource caps |
| Network isolation | runner-net internal (no internet); DNS 127.0.0.1 |
| API not reachable from runner | Arena API binds 172.30.0.10 (arena-net only) |
| Metadata server block | runner-net is internal, no route to 169.254.169.254 |
| No ambient setuid | setuid/setgid bits stripped; runner uses syscall with CAP_SETUID |
| Non-root server | uid 999, cap_drop ALL, no-new-privileges |
| Read-only rootfs | `read_only: true` on all services |
| Resource limits | arena: 2 GB / 1.5 CPU / 256 PIDs; runner: 1 GB / 1 CPU / 128 PIDs |
| tmpfs workspaces | runs (512 MB), sock (1 MB), /tmp per container |
| Secrets via env only | `.env` file, never baked in image; runner has no secrets |
| TLS | Caddy auto-provisions Let's Encrypt cert via sslip.io |
| Request body limit | Caddy: 64 KB max on /api/* |
| HSTS | Strict-Transport-Security: max-age=31536000 |
| CSP | Inline script/style + ws/wss to self; frame-ancestors none |
| WebSocket proxy | Caddy proxies /ws/call/* with upgrade detection |

## Troubleshooting

- **Runner socket permission denied**: Check sock volume mounted, arena uid 999 is in the socket's group.
- **Arena cannot bind 172.30.0.10**: Ensure arena-net subnet is 172.30.0.0/24 with the correct ipv4_address.
- **Caddy TLS fails**: Ensure ports 80 and 443 are reachable from the internet. Check DNS.
- **Container OOM**: Increase mem_limit in docker-compose.yml.
- **Agent commands hang**: Check runner logs (`docker compose logs runner`). Max 4 concurrent, 20s timeout.
