#!/usr/bin/env bash
# MonkeyClaw hackathon demo runner (spec C10).
#
# Two modes:
#
#   live (default)  Runs the full pipeline end-to-end against a planted-
#                   vulnerability victim using the in-memory mock provisioner,
#                   then opens the live dashboard. Every panel is populated by
#                   a real pipeline run.
#
#   --seeded        Skips the live pipeline and opens the dashboard against a
#   (--fallback)    checked-in, pre-seeded database fixture. Use this as the
#                   backup demo if a live run fails on stage. Regenerate the
#                   fixture with demo/build_seed_db.sh.
#
# Usage:
#   demo/run_hackathon_demo.sh
#   demo/run_hackathon_demo.sh --seeded
set -euo pipefail

# Resolve the repo root (this script lives in demo/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${MONKEYCLAW_DASHBOARD_PORT:-8787}"
SEED_DB="demo/fixtures/seed.db"

SEEDED=0
for arg in "$@"; do
  case "${arg}" in
    --seeded|--fallback) SEEDED=1 ;;
    -h|--help)
      sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown argument '${arg}' (try --seeded or --help)" >&2
      exit 2
      ;;
  esac
done

if ! command -v uv >/dev/null 2>&1; then
  echo "error: 'uv' is not installed — see https://docs.astral.sh/uv/" >&2
  exit 1
fi

banner() { printf '\n\033[1;33m== %s ==\033[0m\n' "$1"; }

if [[ "${SEEDED}" -eq 1 ]]; then
  # Pre-seeded fallback mode: no live pipeline run, just serve the fixture.
  if [[ ! -s "${SEED_DB}" ]]; then
    echo "error: seed fixture '${SEED_DB}' is missing or empty." >&2
    echo "       regenerate it with: demo/build_seed_db.sh" >&2
    exit 1
  fi
  # status/dashboard read the plain db_path (no -mock suffix), so pointing the
  # layered-config override straight at the fixture is enough.
  export MC_STORAGE__DB_PATH="${SEED_DB}"

  banner "Pre-seeded fallback mode — serving checked-in fixture ${SEED_DB}"
  echo "No live pipeline run. Every panel is backed by the committed demo fixture."

  banner "Coverage + findings summary"
  uv run monkeyclaw status || true
else
  # Live mode — deterministic, zero-credential pipeline.
  #   * MC_RED__DEMO_PLAYBOOKS seeds the cycle from the planted-victim
  #     playbooks, so a cycle is reproducible and needs no LLM ideation.
  #   * MC_LLM_BACKEND=mock uses the in-process mock LLM — no NVIDIA_API_KEY,
  #     no network, ~seconds per cycle (a live Nemotron cycle takes minutes).
  #   * The run writes to LIVE_DB; `run --mock` appends a `-mock` suffix, so
  #     the pipeline actually writes LIVE_MOCK_DB. status/dashboard read the
  #     un-suffixed path, so we fold the mock DB across at the end.
  export MC_RED__DEMO_PLAYBOOKS=true
  export MC_LLM_BACKEND="${MC_LLM_BACKEND:-mock}"
  LIVE_DB="demo/fixtures/demo-run.db"
  LIVE_MOCK_DB="demo/fixtures/demo-run-mock.db"
  export MC_STORAGE__DB_PATH="${LIVE_DB}"
  rm -f "${LIVE_DB}" "${LIVE_DB}-shm" "${LIVE_DB}-wal" \
        "${LIVE_MOCK_DB}" "${LIVE_MOCK_DB}-shm" "${LIVE_MOCK_DB}-wal"

  banner "Red team -> repro -> blue -> purple — one deterministic cycle"
  uv run monkeyclaw run --cycles 1 --target monkey-victim --mock

  banner "Folding the mock DB into the path status/dashboard read"
  cp "${LIVE_MOCK_DB}" "${LIVE_DB}"
  uv run python - <<PY
import sqlite3
conn = sqlite3.connect("${LIVE_DB}")
conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
conn.execute("PRAGMA journal_mode = DELETE")
conn.close()
PY
  rm -f "${LIVE_DB}-shm" "${LIVE_DB}-wal"

  banner "Coverage + findings summary"
  uv run monkeyclaw status || true
fi

banner "Starting the dashboard on http://127.0.0.1:${PORT}"
echo "Open the URL above. Walk the panels top-to-bottom: overview,"
echo "coverage heatmap, finding timeline, repro packages, blue team,"
echo "evidence timeline, search intelligence, cost/model stats."
echo "Press Ctrl-C to stop."
exec uv run monkeyclaw dashboard --port "${PORT}"
