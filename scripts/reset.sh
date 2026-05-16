#!/usr/bin/env bash
#
# MonkeyClaw — full reset to a from-scratch state.
#
# Kills every MonkeyClaw process, deletes the SQLite knowledge base, the
# logs, and the build caches. With --docker it also tears down the
# docker-compose stack and its named volumes. The next `monkeyclaw run`
# re-creates the database and re-seeds the attack-skill priors automatically
# (infra/bootstrap.py), so this leaves a genuine clean slate.
#
# Usage:
#   scripts/reset.sh                # kill processes + wipe data / logs / caches
#   scripts/reset.sh --docker       # also: docker compose down -v --remove-orphans
#   scripts/reset.sh --keep-logs    # keep logs/ (wipe everything else)
#   scripts/reset.sh -y, --yes      # skip the confirmation prompt
#   scripts/reset.sh -h, --help

set -euo pipefail

# --- locate the repo root (this script lives in <root>/scripts) ------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"
SELF_PID=$$

usage() {
  sed -n '3,16p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'
}

# --- flags -----------------------------------------------------------------
DO_DOCKER=0
ASSUME_YES=0
KEEP_LOGS=0
for arg in "$@"; do
  case "$arg" in
    --docker)    DO_DOCKER=1 ;;
    -y|--yes)    ASSUME_YES=1 ;;
    --keep-logs) KEEP_LOGS=1 ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "reset.sh: unknown option '$arg' (try -h)" >&2; exit 2 ;;
  esac
done

# --- output helpers --------------------------------------------------------
if [ -t 1 ]; then BOLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
else BOLD=''; DIM=''; RST=''; fi
step() { printf '%s==>%s %s\n' "$BOLD" "$RST" "$*"; }
note() { printf '    %s%s%s\n' "$DIM" "$*" "$RST"; }

# --- summary + confirmation ------------------------------------------------
step "MonkeyClaw reset — this will permanently:"
note "kill MonkeyClaw processes (dashboard, orchestrator, MCP servers, runs)"
note "delete the knowledge base   data/*.db*"
if [ "$KEEP_LOGS" -eq 0 ]; then note "delete logs                 logs/*"; fi
note "delete build caches         .pytest_cache .ruff_cache .mypy_cache __pycache__"
if [ "$DO_DOCKER" -eq 1 ]; then
  note "docker compose down -v      (removes the stack + the dind-storage,"
  note "                             nemoclaw-state, monkeyclaw-state volumes)"
fi

if [ "$ASSUME_YES" -eq 0 ]; then
  printf '%sProceed? [y/N] %s' "$BOLD" "$RST"
  read -r reply || reply=""
  case "$reply" in
    y|Y|yes|YES) ;;
    *) echo "aborted."; exit 1 ;;
  esac
fi

# --- 1. kill processes -----------------------------------------------------
step "Stopping MonkeyClaw processes"

# Specific patterns only. None of these match this script's own command line
# ('bash .../scripts/reset.sh'); we also exclude our own PID below as a
# belt-and-suspenders guard.
PATTERNS=(
  '/bin/monkeyclaw'        # venv console-script: dashboard / run / status / ...
  'uv run monkeyclaw'      # the uv wrapper that spawns it
  'mc-orchestrator' 'mc-mcp' 'mc-mock-mcp'
  'infra.orchestrator' 'infra.mcp_server' 'infra.mock_mcp'
)
PORTS=(8787 7321 7322)     # dashboard, mock MCP, MCP server

collect_pids() {
  {
    for p in "${PATTERNS[@]}"; do pgrep -f "$p" 2>/dev/null || true; done
    # -sTCP:LISTEN: only the process *listening* on the port, never a
    # connected client (e.g. a browser tab open on the dashboard).
    for port in "${PORTS[@]}"; do
      lsof -ti "tcp:$port" -sTCP:LISTEN 2>/dev/null || true
    done
  } | sort -u | grep -vx "$SELF_PID" || true
}

pids="$(collect_pids)"
if [ -z "$pids" ]; then
  note "no MonkeyClaw processes running"
else
  note "TERM -> $(echo "$pids" | tr '\n' ' ')"
  echo "$pids" | xargs kill -TERM 2>/dev/null || true
  # Give them up to ~3s to exit cleanly before escalating.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -z "$(collect_pids)" ] && break
    sleep 0.3
  done
  leftover="$(collect_pids)"
  if [ -n "$leftover" ]; then
    note "KILL -> $(echo "$leftover" | tr '\n' ' ')"
    echo "$leftover" | xargs kill -KILL 2>/dev/null || true
  fi
fi

# --- 2. delete the knowledge base ------------------------------------------
step "Deleting the knowledge base"
db_removed=0
for f in data/*.db data/*.db-wal data/*.db-shm data/*.db-journal; do
  [ -e "$f" ] || continue
  rm -f "$f"; note "rm $f"; db_removed=1
done
if [ "$db_removed" -eq 0 ]; then note "no database files"; fi
mkdir -p data

# --- 3. delete logs --------------------------------------------------------
if [ "$KEEP_LOGS" -eq 0 ]; then
  step "Deleting logs"
  if [ -d logs ] && [ -n "$(ls -A logs 2>/dev/null)" ]; then
    rm -rf logs/*; note "cleared logs/"
  else
    note "no logs"
  fi
  mkdir -p logs
else
  step "Keeping logs (--keep-logs)"
fi

# --- 4. delete build caches ------------------------------------------------
step "Deleting build caches"
for d in .pytest_cache .ruff_cache .mypy_cache .codegraph; do
  if [ -e "$d" ]; then rm -rf "$d"; note "rm $d/"; fi
done
# __pycache__ everywhere except inside the virtualenv.
find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true
note "removed __pycache__ directories"

# --- 5. docker teardown (opt-in) -------------------------------------------
if [ "$DO_DOCKER" -eq 1 ]; then
  step "Tearing down the docker-compose stack"
  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      docker compose down -v --remove-orphans || note "docker compose down reported an error"
    elif command -v docker-compose >/dev/null 2>&1; then
      docker-compose down -v --remove-orphans || note "docker-compose down reported an error"
    else
      note "docker compose plugin not found — skipping"
    fi
    note "stack + named volumes removed (NemoClaw re-onboards on next live start)"
  else
    note "docker not installed — skipping"
  fi
else
  step "Skipping Docker teardown (pass --docker to include it)"
fi

# --- done ------------------------------------------------------------------
step "Reset complete — clean slate"
note "the next run re-creates and re-seeds the database from scratch:"
echo
echo "    uv run monkeyclaw run --cycles 1 --target monkey-victim --mock"
echo "    uv run monkeyclaw dashboard"
echo
