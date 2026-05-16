#!/usr/bin/env bash
# MonkeyClaw hackathon demo runner (spec C10).
#
# Two modes:
#   fallback  (default) — seed a pre-built knowledge base, open the
#                         dashboard. No model credentials required.
#   live                — run one real red-team cycle + the blue-team
#                         pipeline, then open the dashboard. Needs
#                         NVIDIA_API_KEY (falls back automatically if
#                         the key is missing).
#
# Usage:
#   demo/run_hackathon_demo.sh            # fallback mode
#   demo/run_hackathon_demo.sh live       # live mode
#   demo/run_hackathon_demo.sh fallback   # explicit fallback
set -euo pipefail

# Resolve the repo root (this script lives in demo/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

MODE="${1:-fallback}"
PORT="${MONKEYCLAW_DASHBOARD_PORT:-8787}"

if ! command -v uv >/dev/null 2>&1; then
  echo "error: 'uv' is not installed — see https://docs.astral.sh/uv/" >&2
  exit 1
fi

banner() { printf '\n\033[1;33m== %s ==\033[0m\n' "$1"; }

# If live mode was asked for but there is no API key, degrade gracefully.
if [ "${MODE}" = "live" ] && [ -z "${NVIDIA_API_KEY:-}" ]; then
  echo "note: NVIDIA_API_KEY is not set — falling back to seeded-DB mode." >&2
  MODE="fallback"
fi

case "${MODE}" in
  live)
    banner "Live mode — running one red-team cycle (mock provisioner)"
    uv run monkeyclaw run --cycles 1 --target monkey-victim --mock

    banner "Blue team — triage -> patch -> test -> verify"
    uv run monkeyclaw blue-team

    banner "Coverage + findings summary"
    uv run monkeyclaw status || true
    ;;

  fallback)
    banner "Fallback mode — seeding the demo knowledge base"
    uv run python demo/seed_demo_db.py
    ;;

  *)
    echo "error: unknown mode '${MODE}' (expected 'live' or 'fallback')" >&2
    exit 1
    ;;
esac

banner "Starting the dashboard on http://127.0.0.1:${PORT}"
echo "Open the URL above. Walk the panels top-to-bottom: overview,"
echo "coverage heatmap, finding timeline, repro packages, blue team,"
echo "evidence timeline, search intelligence, cost/model stats."
echo "Press Ctrl-C to stop."
exec uv run monkeyclaw dashboard --port "${PORT}"
