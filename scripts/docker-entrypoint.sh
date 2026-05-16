#!/usr/bin/env bash
#
# Container entrypoint for the MonkeyClaw dev-env image.
#
# Prepares the environment on container start, then hands off to the command
# (CMD -- an interactive shell by default):
#
#   - NVIDIA_API_KEY set  -> runs the full NemoClaw setup (starts the inner
#     Docker daemon, installs + onboards NemoClaw, creates the clean-baseline
#     snapshot). One `docker run --privileged -e NVIDIA_API_KEY=...` brings the
#     whole live environment up by itself.
#   - NVIDIA_API_KEY unset -> setup is skipped; the offline mock path is ready
#     immediately (`uv run monkeyclaw run --mock`).
#
# A sentinel file makes setup run at most once per container, so a restart
# does not re-onboard.

set -u

SENTINEL=/var/lib/monkeyclaw/.nemoclaw-setup-done

if [ -f "$SENTINEL" ]; then
    echo "[entrypoint] NemoClaw already set up; skipping."
elif [ -n "${NVIDIA_API_KEY:-}" ]; then
    echo "[entrypoint] NVIDIA_API_KEY detected -- running NemoClaw setup..."
    if nemoclaw-setup; then
        mkdir -p "$(dirname "$SENTINEL")" && touch "$SENTINEL"
        echo "[entrypoint] NemoClaw setup complete."
    else
        echo "[entrypoint] WARNING: NemoClaw setup failed -- dropping to shell." >&2
        echo "[entrypoint] check --privileged / RAM / disk, then re-run: nemoclaw-setup" >&2
    fi
else
    echo "[entrypoint] no NVIDIA_API_KEY -- skipping NemoClaw setup (mock path ready)."
fi

exec "$@"
