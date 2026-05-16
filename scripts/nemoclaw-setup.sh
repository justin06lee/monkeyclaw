#!/usr/bin/env bash
#
# One-shot NemoClaw setup for the MonkeyClaw dev container.
#
# Run this ONCE inside a --privileged container after first start. It:
#   1. starts the bundled Docker-in-Docker daemon,
#   2. installs + onboards NemoClaw (creates the victim sandbox),
#   3. creates the `clean-baseline` snapshot MonkeyClaw resets the victim to.
#
# After this completes, the live loop works:
#   uv run monkeyclaw run --cycles 3 --target monkey-victim
#
# The offline/mock path needs none of this -- just `uv run monkeyclaw run --mock`.
#
# Requirements: --privileged container, NVIDIA_API_KEY in the environment,
# >=8 GB RAM and >=20 GB free disk (NemoClaw's sandbox image is ~2.4 GB and
# onboarding can trip the OOM killer below 8 GB).

set -euo pipefail

SANDBOX="${MC_SANDBOX_NAME:-monkey-victim}"
SNAPSHOT="${MC_CLEAN_SNAPSHOT:-clean-baseline}"

# --- 1. Docker-in-Docker daemon -------------------------------------------
if ! docker info >/dev/null 2>&1; then
    echo "[nemoclaw-setup] starting dockerd (Docker-in-Docker)..."
    dockerd >/var/log/dockerd.log 2>&1 &
    for _ in $(seq 1 30); do
        docker info >/dev/null 2>&1 && break
        sleep 1
    done
    if ! docker info >/dev/null 2>&1; then
        echo "[nemoclaw-setup] ERROR: dockerd did not come up." >&2
        echo "  - start the container with --privileged" >&2
        echo "  - inspect /var/log/dockerd.log" >&2
        exit 1
    fi
fi
echo "[nemoclaw-setup] Docker daemon is up."

# --- 2. Install + onboard NemoClaw ----------------------------------------
: "${NVIDIA_API_KEY:?[nemoclaw-setup] set NVIDIA_API_KEY before running}"
echo "[nemoclaw-setup] installing + onboarding NemoClaw (sandbox: ${SANDBOX})..."
echo "  this builds the ~2.4 GB sandbox image -- this can take several minutes."
# Non-interactive flags avoid the stdin-EOF hang that a piped installer hits
# at the onboarding prompts (NVIDIA/NemoClaw issue #362).
curl -fsSL https://www.nvidia.com/nemoclaw.sh | \
    NEMOCLAW_NON_INTERACTIVE=1 \
    NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 \
    NEMOCLAW_PROVIDER=routed \
    NEMOCLAW_SANDBOX_NAME="${SANDBOX}" \
    bash

# --- 3. clean-baseline snapshot -------------------------------------------
# MonkeyClaw's provisioner resets the victim with
# `nemoclaw <sandbox> snapshot restore clean-baseline`, so that snapshot must
# exist. Capture it now, from the freshly-onboarded clean state.
echo "[nemoclaw-setup] creating snapshot '${SNAPSHOT}'..."
nemoclaw "${SANDBOX}" snapshot create --name "${SNAPSHOT}"

echo
echo "[nemoclaw-setup] done."
echo "  sandbox  : ${SANDBOX}"
echo "  snapshot : ${SNAPSHOT}"
echo "  live run : uv run monkeyclaw run --cycles 3 --target ${SANDBOX}"
