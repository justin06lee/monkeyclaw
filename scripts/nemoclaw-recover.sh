#!/usr/bin/env bash
#
# Fast NemoClaw recovery for the MonkeyClaw dev container.
#
# Runs (from docker-entrypoint.sh) when the container is restarted or recreated
# but the NemoClaw setup state is still present on named volumes -- nemoclaw-
# state (/root/.nemoclaw), dind-storage (/var/lib/docker, which holds the
# ~2.4 GB sandbox image) and monkeyclaw-state (the setup sentinel). See
# docker-compose.yml.
#
# The inner Docker daemon, gateway and sandbox processes do NOT survive a
# container restart, so they are brought back here:
#   1. start the Docker-in-Docker daemon if it is down,
#   2. `nemoclaw <sandbox> recover` -- restarts the sandbox gateway and the
#      dashboard port-forward; takes seconds when it succeeds,
#   3. if that does not succeed, fall back to the full `nemoclaw-setup`. That
#      reuses the cached sandbox image from dind-storage, so it costs minutes,
#      never the ~8-minute first-run image build.

set -uo pipefail

SANDBOX="${MC_SANDBOX_NAME:-monkey-victim}"

# --- Docker-in-Docker daemon ----------------------------------------------
if ! docker info >/dev/null 2>&1; then
    echo "[nemoclaw-recover] starting dockerd (Docker-in-Docker)..."
    dockerd >/var/log/dockerd.log 2>&1 &
    for _ in $(seq 1 30); do
        docker info >/dev/null 2>&1 && break
        sleep 1
    done
    if ! docker info >/dev/null 2>&1; then
        echo "[nemoclaw-recover] ERROR: dockerd did not come up." >&2
        echo "  - start the container with --privileged" >&2
        echo "  - inspect /var/log/dockerd.log" >&2
        exit 1
    fi
fi
echo "[nemoclaw-recover] Docker daemon is up."

# --- fast path: nemoclaw recover ------------------------------------------
# `recover` restarts the sandbox gateway and re-establishes the dashboard
# port-forward; it is documented as safe to re-run.
echo "[nemoclaw-recover] recovering sandbox '${SANDBOX}'..."
if nemoclaw "${SANDBOX}" recover; then
    echo "[nemoclaw-recover] sandbox '${SANDBOX}' recovered."
    exit 0
fi

# --- fall back to a full (image-cached) setup -----------------------------
# recover could not bring the sandbox back (e.g. the gateway process is gone
# after a full container restart). Re-run the full setup -- the ~2.4 GB sandbox
# image is still cached in the dind-storage volume, so this costs minutes, not
# the ~8-minute first-run build.
echo "[nemoclaw-recover] recover did not succeed -- running full nemoclaw-setup"
echo "  (the cached sandbox image is reused; no ~8-minute rebuild)."
exec nemoclaw-setup
