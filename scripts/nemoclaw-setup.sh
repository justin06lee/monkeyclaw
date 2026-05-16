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

# Discard state a previous failed run leaves behind so a re-run starts clean:
#   - ~/.nemoclaw/onboard-session.json -> installer aborts "previous
#     onboarding session failed";
#   - the model-router process on port 4000 -> onboard refuses "Port 4000
#     already has a healthy router endpoint".
clean_stale_state() {
    rm -f "${HOME:-/root}/.nemoclaw/onboard-session.json"
    pkill -f 'model-router-venv/bin/model-router' 2>/dev/null || true
}

# A current NemoClaw `latest` installer regression extracts the OpenShell
# `openshell-sandbox` binary as a DIRECTORY (openshell-sandbox/openshell-
# sandbox) instead of a file; the gateway then aborts ("docker supervisor
# binary /usr/local/bin/openshell-sandbox does not exist or is not a file").
# Flatten it back to a plain executable.
repair_openshell_sandbox() {
    local osb=/usr/local/bin/openshell-sandbox
    if [ -d "${osb}" ] && [ -f "${osb}/openshell-sandbox" ]; then
        echo "[nemoclaw-setup] repairing openshell-sandbox (installer left a directory)..."
        mv "${osb}/openshell-sandbox" "${osb}.bin" \
            && rm -rf "${osb}" \
            && mv "${osb}.bin" "${osb}" \
            && chmod 0755 "${osb}"
    fi
}

# Non-interactive flags avoid the stdin-EOF hang that a piped installer hits
# at the onboarding prompts (NVIDIA/NemoClaw issue #362).
run_installer() {
    curl -fsSL https://www.nvidia.com/nemoclaw.sh | \
        NEMOCLAW_NON_INTERACTIVE=1 \
        NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 \
        NEMOCLAW_PROVIDER=routed \
        NEMOCLAW_SANDBOX_NAME="${SANDBOX}" \
        bash
}

# Run the installer, retrying through the known transient failure modes
# (NemoClaw `latest` is brittle, and the persisted volumes can carry stale
# state across container recreation). Each retry repairs what the previous
# attempt revealed:
#   - openshell-sandbox extracted as a directory -> flatten it;
#   - sandbox already registered in the gateway  -> delete it.
clean_stale_state
attempt=1
max_attempts=3
until run_installer; do
    if [ "${attempt}" -ge "${max_attempts}" ]; then
        echo "[nemoclaw-setup] ERROR: onboarding failed after ${attempt} attempts." >&2
        exit 1
    fi
    echo "[nemoclaw-setup] attempt ${attempt} failed -- repairing, then retrying..."
    repair_openshell_sandbox
    # A prior or partial run can leave the sandbox registered in the gateway,
    # so onboarding aborts "sandbox already exists". Drop it (best effort --
    # the gateway is reachable once an attempt has reached the sandbox step)
    # so the retry creates it fresh.
    openshell sandbox delete "${SANDBOX}" 2>/dev/null || true
    clean_stale_state
    attempt=$((attempt + 1))
done

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
