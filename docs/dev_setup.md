# MonkeyClaw — Developer Setup

This guide covers the only supported setup path for MonkeyClaw development.
Follow every step in order; the environment check at the end will confirm
everything is wired up correctly.

---

## Prerequisites

- macOS or Linux (arm64 or x86-64)
- Internet access to download uv and Python

---

## Setup steps

### 1. Install uv

uv manages both the Python toolchain and the dependency lockfile for this
project. It is the only supported way to run MonkeyClaw.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then restart your shell (or run `source $HOME/.local/bin/env`) so that `uv` is
on your PATH.

### 2. Pin the Python toolchain

MonkeyClaw requires CPython 3.12 compiled with loadable-SQLite-extension
support. The uv-managed CPython satisfies this; the system Python on macOS does
not.

```bash
uv python install 3.12
uv python pin 3.12
```

This writes a `.python-version` file that uv respects for all subsequent
commands in the repository.

### 3. Install dependencies

```bash
uv sync
```

This resolves `uv.lock` exactly and installs all packages (including
`sqlite-vec` and `sentence-transformers`) into the project's managed virtual
environment.

### 4. Verify the environment

```bash
./scripts/check_env.sh
```

Expected final line: `== environment OK ==` (exit 0). If any `[FAIL]` lines
appear, follow their remediation instructions before continuing.

### 5. Acceptance commands

Run these to confirm the development environment is fully functional:

```bash
# Full test suite (326 tests across red, blue, infra, and the dashboard)
uv run pytest

# Lint check — must be clean before any commit
uv run ruff check .

# End-to-end smoke test with the mock provisioner
uv run monkeyclaw run --cycles 1 --target planted-filesystem --mock
```

---

## Without uv

uv manages two things simultaneously: the Python toolchain and the dependency
lockfile (`uv.lock`). Without uv, neither can be resolved automatically.

A manual fallback is technically possible:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
```

However, this fallback:

- Does **not** reproduce the exact locked dependency versions in `uv.lock`.
- **Still requires** a CPython 3.12 compiled with `enable_load_extension`
  support in `sqlite3`. The system Python shipped with macOS lacks this flag.
  Homebrew Python may or may not have it depending on the build. Only a
  uv-managed CPython is guaranteed to have it.
- Will fail at import time for `sqlite-vec` if the above condition is not met.

For this reason, `uv` is a hard prerequisite, not an optional convenience.

---

## Real NemoClaw provisioning

The default `--mock` flag bypasses the live NemoClaw provisioner. To use real
provisioning you need:

1. The `nemoclaw` CLI installed and on your PATH.
2. A running Docker daemon.
3. The `monkey-victim` sandbox snapshot accessible to nemoclaw.

Until all three are present, always use `--mock`. The provisioner itself is
fully unit-tested against a mocked subprocess:

```bash
uv run pytest test/test_provisioning.py
```

Once the real provisioner is available, run a live cycle with:

```bash
uv run monkeyclaw run --cycles 1 --target monkey-victim
```
