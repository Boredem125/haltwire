#!/bin/sh
set -e

# ------------------------------------------------------------------
# Tripwire entrypoint
#
# Runs as uid 999 (arena).  No privilege operations.
# Maps ARENA_AGENT_KEY -> GEMINI_API_KEY for the server's Gemini calls.
# ------------------------------------------------------------------

# --- Map agent key -> GEMINI_API_KEY ---
if [ -n "${ARENA_AGENT_KEY}" ]; then
    export GEMINI_API_KEY="${ARENA_AGENT_KEY}"
fi
# Fallback key, used when the primary hits a 429 (rate limit or quota)
if [ -n "${ARENA_AGENT_KEY1}" ]; then
    export GEMINI_API_KEY1="${ARENA_AGENT_KEY1}"
fi

# A service that passes its own command (the runner daemon) runs that command.
# Without this, compose's `command:` became arguments to this script and the
# runner container started the web server instead of the daemon.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec python -m arena.server
