#!/usr/bin/env bash
# Regenerate the pre-seeded fallback demo database (demo/fixtures/seed.db).
#
# This runs the exact same mock pipeline as the live demo, but writes into a
# checked-in fixture so `run_hackathon_demo.sh --seeded` has a guaranteed-good
# database to fall back on if a live run fails on stage.
#
# Run this whenever the schema or demo pipeline changes:
#   demo/build_seed_db.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

SEED_DB="demo/fixtures/seed.db"
# `--mock` runs boot with the mock provisioner, which appends a `-mock` suffix
# to the configured db path (see infra/bootstrap.py). So the pipeline actually
# writes here; we fold it back into SEED_DB at the end.
MOCK_DB="demo/fixtures/seed-mock.db"
mkdir -p demo/fixtures

banner() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

# Start from a clean slate so the fixture is deterministic.
rm -f "${SEED_DB}" "${SEED_DB}-shm" "${SEED_DB}-wal" \
      "${MOCK_DB}" "${MOCK_DB}-shm" "${MOCK_DB}-wal"

# Point every command at the fixture path via the layered-config env override.
export MC_STORAGE__DB_PATH="${SEED_DB}"

banner "Red team — one mock cycle against the planted victim"
uv run monkeyclaw run --cycles 1 --target monkey-victim --mock

banner "Blue team — triage -> patch -> test -> verify"
uv run monkeyclaw blue-team

banner "Folding the mock DB into the committed fixture"
# `monkeyclaw status`/`dashboard` read the plain db_path (no `-mock` suffix), so
# the committed fixture must be the un-suffixed file. Copy + checkpoint so the
# fixture is a single self-contained .db with no -wal/-shm sidecars.
cp "${MOCK_DB}" "${SEED_DB}"
uv run python - <<'PY'
import sqlite3
conn = sqlite3.connect("demo/fixtures/seed.db")
conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
conn.execute("PRAGMA journal_mode = DELETE")
conn.close()
PY
rm -f "${SEED_DB}-shm" "${SEED_DB}-wal" \
      "${MOCK_DB}" "${MOCK_DB}-shm" "${MOCK_DB}-wal"

banner "Done"
ls -la "${SEED_DB}"
echo "Commit demo/fixtures/seed.db so the fallback demo mode has data."
