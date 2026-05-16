#!/usr/bin/env bash
# check_env.sh — verify the MonkeyClaw dev environment is usable.
set -u
fail=0

echo "== MonkeyClaw environment check =="

if command -v uv >/dev/null 2>&1; then
  echo "[ok]   uv: $(uv --version)"
else
  echo "[FAIL] uv not found. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
  fail=1
fi

py_ok=$(uv run python -c "import sys; print(1 if (3,12)<=sys.version_info<(3,14) else 0)" 2>/dev/null)
if [ "$py_ok" = "1" ]; then
  echo "[ok]   python: $(uv run python -c 'import sys;print(sys.version.split()[0])')"
else
  echo "[FAIL] python not in [3.12, 3.14). Run: uv python install 3.12 && uv python pin 3.12"
  fail=1
fi

ext_ok=$(uv run python -c "import sqlite3; c=sqlite3.connect(':memory:'); print(1 if hasattr(c,'enable_load_extension') else 0)" 2>/dev/null)
if [ "$ext_ok" = "1" ]; then
  echo "[ok]   sqlite3 loadable extensions supported"
else
  echo "[FAIL] sqlite3 lacks enable_load_extension — use a uv-managed CPython"
  fail=1
fi

vec_ok=$(uv run python -c "import sqlite3,sqlite_vec; c=sqlite3.connect(':memory:'); c.enable_load_extension(True); sqlite_vec.load(c); c.execute('select vec_version()'); print(1)" 2>/dev/null)
if [ "$vec_ok" = "1" ]; then
  echo "[ok]   sqlite-vec loads"
else
  echo "[FAIL] sqlite-vec failed to load — run 'uv sync'"
  fail=1
fi

# Optional tooling — informational only, never fails the check.
command -v argyph   >/dev/null 2>&1 && echo "[ok]   argyph present (code-context backend available)" || echo "[info] argyph not on PATH (Python indexer fallback will be used)"
command -v nemoclaw >/dev/null 2>&1 && echo "[ok]   nemoclaw present (real provisioning available)"      || echo "[info] nemoclaw not found (use --mock; real provisioning unavailable)"
docker info >/dev/null 2>&1        && echo "[ok]   docker daemon running"                                || echo "[info] docker daemon not running (needed only for real provisioning)"

[ "$fail" = "0" ] && echo "== environment OK ==" || echo "== environment has FAILURES =="
exit $fail
