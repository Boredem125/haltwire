# Tripwire -- hardened demo image
#
# Two non-root users:
#   arena    (uid 999)   -- runs the FastAPI server
#   agentrun (uid 10001) -- runner_daemon drops to this uid for shell commands
#
# Build context must be the REPO ROOT (one level above deploy/):
#   docker build -f deploy/Dockerfile -t tripwire .
#
# Secrets arrive via environment at runtime -- nothing is baked in.

# ---- stage 1: Python packages ----
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install . google-genai segno


# ---- stage 2: runtime ----
FROM python:3.12-slim

# System deps: bash for agent commands, util-linux for prlimit,
# ca-certificates for HTTPS.  No iptables, no libcap2-bin, no setpriv.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- users ---
# arena (uid 999): runs the server process
RUN groupadd -g 999 arena \
    && useradd -r -g arena -u 999 -d /home/arena -m -s /sbin/nologin arena

# agentrun (uid 10001): runner_daemon drops to this uid for shell commands
RUN groupadd -g 10001 agentrun \
    && useradd -r -g agentrun -u 10001 -d /home/agentrun -m -s /bin/bash agentrun

# Python packages from builder
COPY --from=builder /install /usr/local

# ---- application code ----
COPY arena/ /app/arena/
COPY deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# H6: pre-create /data/keys owned by arena (uid 999)
RUN mkdir -p /data/keys && chown 999:999 /data/keys

# H5: pre-create /runs/recordings owned by arena so agent uid cannot plant files
RUN mkdir -p /runs/recordings && chown 999:999 /runs && chown 999:999 /runs/recordings && chmod 2750 /runs

# Strip setuid/setgid bits from every binary (defense in depth)
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

WORKDIR /app

# Default environment (overridable in compose / at runtime)
ENV PYTHONPATH=/app \
    ARENA_HOST=127.0.0.1 \
    ARENA_PORT=8088 \
    ARENA_RUNS=/runs \
    ARENA_RUNNER_SOCK=/sock/exec.sock

# Run as uid 999 by default; the runner service overrides to root in compose
USER 999

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8088/api/state')"

ENTRYPOINT ["/app/entrypoint.sh"]
