#!/usr/bin/env bash
#
# Container entrypoint for the MonkeyClaw dev-env image.
#
# Prepares the environment on container start, then hands off to the command
# (CMD -- an interactive shell by default):
#
#   - sentinel present     -> NemoClaw was already onboarded and its state is
#     persisted on named volumes; nemoclaw-recover restarts the daemon /
#     gateway / sandbox without rebuilding the cached sandbox image.
#   - NVIDIA_API_KEY set    -> first run: full NemoClaw setup (starts the inner
#     Docker daemon, installs + onboards NemoClaw, creates the clean-baseline
#     snapshot), then writes the sentinel.
#   - NVIDIA_API_KEY unset  -> setup is skipped; the offline mock path is ready
#     immediately (`uv run monkeyclaw run --mock`).
#
# The sentinel lives on a named volume (see docker-compose.yml), so it -- and
# the recover-instead-of-onboard behaviour -- survives container recreation.

set -u

SENTINEL=/var/lib/monkeyclaw/.nemoclaw-setup-done

if [ -f "$SENTINEL" ]; then
    # NemoClaw was onboarded on an earlier run; its state is persisted on named
    # volumes. The inner daemon / gateway / sandbox processes do not survive a
    # container restart, so recover them -- this reuses the cached sandbox
    # image rather than rebuilding it.
    echo "[entrypoint] NemoClaw state present -- recovering..."
    if nemoclaw-recover; then
        echo "[entrypoint] NemoClaw recovered."
    else
        echo "[entrypoint] WARNING: NemoClaw recovery failed -- dropping to shell." >&2
        echo "[entrypoint] re-run manually: nemoclaw-setup" >&2
    fi
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
