#!/usr/bin/env bash
# MonkeyClaw hackathon demo runner (spec C10).
#
# Runs the full pipeline end-to-end against a planted-vulnerability victim
# using the in-memory mock provisioner, then opens the live dashboard. No
# fabricated/seeded data — every panel is populated by a real pipeline run.
#
# Usage:
#   demo/run_hackathon_demo.sh
set -euo pipefail

# Resolve the repo root (this script lives in demo/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${MONKEYCLAW_DASHBOARD_PORT:-8787}"

if ! command -v uv >/dev/null 2>&1; then
  echo "error: 'uv' is not installed — see https://docs.astral.sh/uv/" >&2
  exit 1
fi

banner() { printf '\n\033[1;33m== %s ==\033[0m\n' "$1"; }

banner "Red team — running one cycle (mock provisioner, planted victim)"
uv run monkeyclaw run --cycles 1 --target monkey-victim --mock

banner "Blue team — triage -> patch -> test -> verify"
uv run monkeyclaw blue-team

banner "Coverage + findings summary"
uv run monkeyclaw status || true

banner "Starting the dashboard on http://127.0.0.1:${PORT}"
echo "Open the URL above. Walk the panels top-to-bottom: overview,"
echo "coverage heatmap, finding timeline, repro packages, blue team,"
echo "evidence timeline, search intelligence, cost/model stats."
echo "Press Ctrl-C to stop."
exec uv run monkeyclaw dashboard --port "${PORT}"
