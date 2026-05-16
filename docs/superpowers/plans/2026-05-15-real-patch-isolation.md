# Real Patch Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `blue_team/patch_isolation.py` module that applies a candidate diff in a disposable `git worktree`, rebuilds the victim from the patched tree, and supplies `PatchVerifier` with a real `PatchedReplayFactory` — so "all six gates passed" means the gates passed against a victim with the diff actually applied, not against the unpatched replay surface.

**Architecture:** `PatchIsolation` owns the disposable-worktree lifecycle behind a context manager: `git worktree add` off a pinned base commit under a unique temp root, `git apply --check` then `git apply`, a victim rebuilt from the patched worktree via the rebuildable provisioner, and structural teardown in a `finally`. `build_patched_replay_factory` wraps it as the real `PatchedReplayFactory` that `PatchVerifier` already accepts through its existing constructor seam — no verifier API change. When no rebuildable victim is configured, isolation degrades to the existing mock replay and stamps `VerifyOutcome.isolation_mode="mock"` so a verdict is never silently overclaimed.

**Tech Stack:** Python 3.12, `uv` for env + test running, `pytest`, `git` on PATH, SQLite via `infra/database.py`, the existing migration runner (`infra/migrations.py` + `infra/migrations/`), `interfaces/types.py` dataclasses, `ruff` for lint. Everything runs in mock mode with zero NemoClaw credentials; the live build path depends on the real-nemoclaw-provisioner spec.

---

## File Structure

| File | Create/Modify | Responsibility |
|------|---------------|----------------|
| `interfaces/types.py` | Modify | Add `IsolationMode` literal and `DiffApplyResult` + `PatchBuild` dataclasses. |
| `interfaces/schema.sql` | Modify | Add `patch_builds` (reference copy, kept in sync with the migration). |
| `infra/migrations/0007_patch_isolation.sql` | Create | Migration adding `patch_builds`; bumps `schema_version`. |
| `infra/patch_builds_store.py` | Create | Thin writer/reader for `patch_builds` rows + the janitor sweep query. |
| `blue_team/patch_isolation.py` | Create | `PatchIsolation` (disposable-worktree lifecycle), `build_patched_replay_factory`, the startup janitor sweep. |
| `blue_team/patch_verifier.py` | Modify | `gate_diff_applies` upgraded to a real `git apply --check` when an isolation backend is present; `VerifyOutcome.isolation_mode` field; `verify` stamps it. |
| `blue_team/pipeline.py` | Modify | `Pipeline.__init__` constructs `PatchIsolation` from config + a rebuildable provisioner, runs the janitor sweep, and builds `PatchVerifier` with the real factory. |
| `interfaces/config_schema.py` | Modify | `BlueTeamConfig` gains a `patch_isolation` block (`enabled`, `nemoclaw_repo_path`, `base_ref`, `build_timeout_s`, `worktree_root`). |
| `configs/monkeyclaw.yaml` | Modify | `blue_team.patch_isolation` config block. |
| `infra/dashboard.py` | Modify | Patch panel gains an `isolation_mode` badge. |
| `test/_git_repo_fixture.py` | Create | Shared helper that builds a throwaway git repo with a known base commit. |
| `test/test_blue_patch_isolation_types.py` | Create | Type/contract tests for the new dataclasses + migration. |
| `test/test_blue_patch_isolation_worktree.py` | Create | `prepare`/`diff_applies` against a throwaway repo; clean-apply and conflicting-diff cases. |
| `test/test_blue_patch_isolation_mock_fallback.py` | Create | No `nemoclaw_repo_path` → mock replay + `isolation_mode="mock"`. |
| `test/test_blue_patch_isolation_cleanup.py` | Create | Exception inside the `prepare` context still tears down. |
| `test/test_blue_patch_isolation_janitor.py` | Create | Orphaned `mc-patch-*` dir reclaimed by the startup sweep. |
| `test/test_blue_patch_verifier.py` | Modify | Fake isolation backend proves `gate1_regression` reflects whether the patch took effect. |

---

# Phase 0 — Contracts

Shared types, the schema migration, and the `VerifyOutcome.isolation_mode` field. No behaviour change.

## Task 1 — New interface types

**Files:**
- Modify: `interfaces/types.py`
- Test: `test/test_blue_patch_isolation_types.py`

- [ ] Write the failing test. Create `test/test_blue_patch_isolation_types.py`:
```python
"""Phase 0 — patch-isolation shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import DiffApplyResult, PatchBuild


def test_diff_apply_result_shape():
    fnames = {f.name for f in fields(DiffApplyResult)}
    assert {"applied", "checked", "rejected_hunks", "stderr"} <= fnames


def test_diff_apply_result_defaults_to_unapplied():
    r = DiffApplyResult()
    assert r.applied is False
    assert r.checked is False
    assert r.rejected_hunks == []


def test_patch_build_carries_isolation_mode_and_status():
    fnames = {f.name for f in fields(PatchBuild)}
    assert {"build_id", "patch_id", "worktree_path", "victim",
            "diff_result", "isolation_mode", "build_status"} <= fnames


def test_patch_build_mock_construction():
    b = PatchBuild(
        build_id="B1", patch_id="P1", worktree_path=None, victim=None,
        diff_result=DiffApplyResult(), isolation_mode="mock",
        build_status="mock")
    assert b.isolation_mode == "mock"
    assert b.build_status == "mock"
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_isolation_types.py -q` — expect `ImportError: cannot import name 'DiffApplyResult'`.
- [ ] Add the literal to `interfaces/types.py`, after the existing literal block:
```python
IsolationMode = Literal["live", "mock"]
PatchBuildStatus = Literal["built", "apply_failed", "build_failed", "mock"]
```
- [ ] Add the two dataclasses to `interfaces/types.py`, before the `__all__` list:
```python
# ---------------------------------------------------------------------------
# Real patch isolation — disposable-worktree verification (patch-isolation §7)
# ---------------------------------------------------------------------------


@dataclass
class DiffApplyResult:
    """The result of a `git apply --check` (and optionally `git apply`) of a
    candidate diff inside a disposable worktree."""

    applied: bool = False
    checked: bool = False
    rejected_hunks: list[str] = field(default_factory=list)
    stderr: str = ""


@dataclass
class PatchBuild:
    """One attempted isolation build for one candidate patch. `victim` is the
    rebuilt patched VictimInstance on the live path, None on the mock path."""

    build_id: str
    patch_id: str
    worktree_path: str | None
    victim: "VictimInstance | None"
    diff_result: DiffApplyResult
    isolation_mode: str  # IsolationMode
    build_status: str  # PatchBuildStatus
    build_duration_seconds: float = 0.0
```
- [ ] Confirm `VictimInstance` is importable into `interfaces/types.py`'s namespace for the forward reference — if `types.py` does not already import it, add `from interfaces.provisioning import VictimInstance` inside a `TYPE_CHECKING` block (check first with `grep -n "VictimInstance\|TYPE_CHECKING" interfaces/types.py`).
- [ ] Append `"DiffApplyResult"`, `"IsolationMode"`, `"PatchBuild"`, `"PatchBuildStatus"` to `__all__` in `interfaces/types.py` (alphabetised within the list).
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_types.py -q` — expect `4 passed`.
- [ ] Run lint: `uv run ruff check interfaces/types.py test/test_blue_patch_isolation_types.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/types.py test/test_blue_patch_isolation_types.py && git commit -m "feat(patch-isolation): shared interface types for disposable-worktree verification"`.

## Task 2 — Schema migration 0007

**Files:**
- Create: `infra/migrations/0007_patch_isolation.sql`
- Modify: `interfaces/schema.sql`
- Test: `test/test_blue_patch_isolation_types.py` (extend)

- [ ] Inspect the highest existing migration number: `ls infra/migrations/`. If the highest is not `0006`, rename the file in this task to the next free number and use that number consistently below (coordination rule 1 of the upgrade roadmap). The spec §7 names this migration `003_patch_isolation.sql`; renumber it to the next free version at execution time. The plan assumes `0007`.
- [ ] Write the failing test. Append to `test/test_blue_patch_isolation_types.py`:
```python
def test_migration_creates_patch_builds_table(db):
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    assert "patch_builds" in {r["name"] for r in rows}


def test_patch_builds_has_isolation_columns(db):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(patch_builds)")}
    assert {"build_id", "patch_id", "base_ref", "worktree_path",
            "diff_applied", "rejected_hunks", "build_status",
            "victim_instance_id", "isolation_mode", "torn_down"} <= cols
```
  (`db` is the shared fixture from `test/conftest.py`.)
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_isolation_types.py -q -k "patch_builds"` — expect `AssertionError` (table absent).
- [ ] Create `infra/migrations/0007_patch_isolation.sql`:
```sql
-- Migration 0007 — patch-isolation build audit table (patch-isolation §7).
-- Forward-only, idempotent. Applied by infra/migrations.py on Database open.

BEGIN;

CREATE TABLE IF NOT EXISTS patch_builds (
    build_id                TEXT PRIMARY KEY,
    patch_id                TEXT NOT NULL,
    base_ref                TEXT,
    worktree_path           TEXT,
    diff_applied            INTEGER NOT NULL DEFAULT 0,  -- 0/1
    rejected_hunks          TEXT NOT NULL DEFAULT '[]',  -- JSON list
    build_status            TEXT NOT NULL,               -- built|apply_failed|build_failed|mock
    victim_instance_id      TEXT,
    isolation_mode          TEXT NOT NULL DEFAULT 'mock',  -- live|mock
    build_duration_seconds  REAL NOT NULL DEFAULT 0.0,
    torn_down               INTEGER NOT NULL DEFAULT 0,  -- 0/1
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_patch_builds_patch
    ON patch_builds(patch_id);
CREATE INDEX IF NOT EXISTS idx_patch_builds_torn_down
    ON patch_builds(torn_down);

UPDATE schema_meta SET value = '4' WHERE key = 'schema_version';

COMMIT;
```
  Note: the `schema_version` value `'4'` assumes migration 0006 (real-nemoclaw-provisioner) landed and set `'3'`. Take the next free version at execution time per coordination rule 1; match the `interfaces/schema.sql` bump below to it.
- [ ] Mirror the `CREATE TABLE patch_builds` block into `interfaces/schema.sql` (reference copy) at the end, before the `schema_meta` block, and bump the `INSERT OR IGNORE INTO schema_meta` value to match the migration's `UPDATE` value.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_types.py -q -k "patch_builds"` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check test/test_blue_patch_isolation_types.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/migrations/0007_patch_isolation.sql interfaces/schema.sql test/test_blue_patch_isolation_types.py && git commit -m "feat(patch-isolation): migration 0007 — patch_builds audit table"`.

## Task 3 — `VerifyOutcome.isolation_mode` field

**Files:**
- Modify: `blue_team/patch_verifier.py`
- Test: `test/test_blue_patch_verifier.py`

- [ ] Write the failing test. Append to `test/test_blue_patch_verifier.py`:
```python
def test_verify_outcome_defaults_isolation_mode_to_mock():
    from blue_team.patch_verifier import VerifyOutcome

    o = VerifyOutcome(approved=True, failed_gate=None, gates=[],
                      patch_id="P1")
    assert o.isolation_mode == "mock"
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_verifier.py::test_verify_outcome_defaults_isolation_mode_to_mock -q` — expect `AttributeError: 'VerifyOutcome' object has no attribute 'isolation_mode'`.
- [ ] In `blue_team/patch_verifier.py`, add a field to the `VerifyOutcome` dataclass (after `triggered_evidence`, so existing positional callers are unaffected):
```python
    isolation_mode: str = "mock"  # IsolationMode — proven live or on mock surface
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_verifier.py::test_verify_outcome_defaults_isolation_mode_to_mock -q` — expect `1 passed`.
- [ ] Run the full patch-verifier suite, verify no regression: `uv run pytest test/test_blue_patch_verifier.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check blue_team/patch_verifier.py test/test_blue_patch_verifier.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/patch_verifier.py test/test_blue_patch_verifier.py && git commit -m "feat(patch-isolation): VerifyOutcome.isolation_mode field"`.

---

# Phase 1 — Worktree lifecycle

The disposable-worktree module, against a local git repo. No victim build yet (`PatchBuild.victim` is `None`); `gate_diff_applies` upgraded to a real `git apply --check`.

## Task 4 — The throwaway git-repo fixture

**Files:**
- Create: `test/_git_repo_fixture.py`
- Test: (used by Tasks 5, 6, 8)

- [ ] Create `test/_git_repo_fixture.py` — a reusable helper that builds a throwaway NemoClaw-shaped repo:
```python
"""A throwaway git repo for patch-isolation tests.

build_repo() writes a single-file repo, commits it, and returns
(repo_path, base_ref). The repo is the stand-in for a NemoClaw checkout —
the patch-isolation tests apply diffs into worktrees off it without needing
a real NemoClaw or any credentials.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# A clean-apply diff against the file build_repo() writes.
GOOD_DIFF = (
    "--- a/control.py\n"
    "+++ b/control.py\n"
    "@@ -1,2 +1,2 @@\n"
    " # nemoclaw control plane\n"
    "-ALLOWED_PATHS = ['/work', '/']\n"
    "+ALLOWED_PATHS = ['/work']\n"
)
# A diff whose context will not match -> a rejected hunk.
CONFLICTING_DIFF = (
    "--- a/control.py\n"
    "+++ b/control.py\n"
    "@@ -1,2 +1,2 @@\n"
    " # totally different first line\n"
    "-ALLOWED_PATHS = ['/nope']\n"
    "+ALLOWED_PATHS = []\n"
)


def build_repo(root: Path) -> tuple[str, str]:
    """Create a committed single-file repo; return (repo_path, base_ref)."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "control.py").write_text(
        "# nemoclaw control plane\n"
        "ALLOWED_PATHS = ['/work', '/']\n")
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "test@monkeyclaw"],
        ["git", "config", "user.name", "monkeyclaw-test"],
        ["git", "add", "."],
        ["git", "commit", "-q", "-m", "base"],
    ):
        subprocess.run(cmd, cwd=root, check=True, capture_output=True)
    rev = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True,
        capture_output=True, text=True)
    return str(root), rev.stdout.strip()
```
- [ ] Verify it imports and runs: `uv run python -c "import tempfile, pathlib; from test._git_repo_fixture import build_repo; print(build_repo(pathlib.Path(tempfile.mkdtemp())/'r'))"` — expect a `(path, sha)` tuple printed.
- [ ] Run lint: `uv run ruff check test/_git_repo_fixture.py` — expect `All checks passed!`.
- [ ] Commit: `git add test/_git_repo_fixture.py && git commit -m "test(patch-isolation): throwaway git-repo fixture"`.

## Task 5 — `patch_builds` row store

**Files:**
- Create: `infra/patch_builds_store.py`
- Test: `test/test_blue_patch_isolation_worktree.py`

- [ ] Write the failing test. Create `test/test_blue_patch_isolation_worktree.py`:
```python
"""Phase 1 — patch-isolation worktree lifecycle (patch-isolation spec §6)."""

from __future__ import annotations


def test_patch_builds_store_writes_and_tears_down(db):
    from infra.patch_builds_store import PatchBuildsStore
    from interfaces.types import DiffApplyResult, PatchBuild

    store = PatchBuildsStore(db)
    build = PatchBuild(
        build_id="B1", patch_id="P1", worktree_path="/tmp/mc-patch-x",
        victim=None,
        diff_result=DiffApplyResult(applied=True, checked=True),
        isolation_mode="live", build_status="built")
    store.record(build, base_ref="abc123")
    row = db.fetchone("SELECT * FROM patch_builds WHERE build_id='B1'")
    assert row["isolation_mode"] == "live"
    assert row["diff_applied"] == 1
    assert row["torn_down"] == 0
    store.mark_torn_down("B1")
    row = db.fetchone("SELECT * FROM patch_builds WHERE build_id='B1'")
    assert row["torn_down"] == 1


def test_patch_builds_store_lists_untorn_builds(db):
    from infra.patch_builds_store import PatchBuildsStore
    from interfaces.types import DiffApplyResult, PatchBuild

    store = PatchBuildsStore(db)
    for bid, torn in (("B1", False), ("B2", True)):
        store.record(
            PatchBuild(build_id=bid, patch_id="P", worktree_path=f"/t/{bid}",
                       victim=None, diff_result=DiffApplyResult(),
                       isolation_mode="live", build_status="built"),
            base_ref="r")
        if torn:
            store.mark_torn_down(bid)
    untorn = store.list_untorn()
    assert {r["build_id"] for r in untorn} == {"B1"}
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_isolation_worktree.py -q -k "store"` — expect `ModuleNotFoundError: No module named 'infra.patch_builds_store'`.
- [ ] Create `infra/patch_builds_store.py`:
```python
"""Writer/reader for patch_builds — patch-isolation spec §7.

One patch_builds row per attempted isolation build. The janitor sweep
(patch-isolation §11) queries list_untorn() to reclaim leaked worktrees.
"""

from __future__ import annotations

import json

from infra.database import Database
from interfaces.types import PatchBuild


class PatchBuildsStore:
    """Thin SQLite writer; no caching, no business logic."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def record(self, build: PatchBuild, *, base_ref: str | None) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO patch_builds("
            "build_id, patch_id, base_ref, worktree_path, diff_applied, "
            "rejected_hunks, build_status, victim_instance_id, "
            "isolation_mode, build_duration_seconds, torn_down) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,0)",
            (build.build_id, build.patch_id, base_ref, build.worktree_path,
             int(build.diff_result.applied),
             json.dumps(build.diff_result.rejected_hunks),
             build.build_status,
             build.victim.instance_id if build.victim else None,
             build.isolation_mode, build.build_duration_seconds),
        )

    def mark_torn_down(self, build_id: str) -> None:
        self._db.execute(
            "UPDATE patch_builds SET torn_down = 1 WHERE build_id = ?",
            (build_id,),
        )

    def list_untorn(self) -> list[dict]:
        return self._db.fetchall(
            "SELECT * FROM patch_builds WHERE torn_down = 0")


__all__ = ["PatchBuildsStore"]
```
- [ ] Confirm `Database` exposes `execute` (commits) and `fetchall`/`fetchone`: `grep -n "def execute\|def fetchall\|def fetchone" infra/database.py`. If `execute` is named differently, use that name consistently.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_worktree.py -q -k "store"` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/patch_builds_store.py test/test_blue_patch_isolation_worktree.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/patch_builds_store.py test/test_blue_patch_isolation_worktree.py && git commit -m "feat(patch-isolation): PatchBuildsStore — patch_builds writer"`.

## Task 6 — `PatchIsolation.diff_applies` — real `git apply --check`

**Files:**
- Create: `blue_team/patch_isolation.py`
- Test: `test/test_blue_patch_isolation_worktree.py`

- [ ] Write the failing test. Append to `test/test_blue_patch_isolation_worktree.py`:
```python
def test_diff_applies_accepts_a_clean_diff(tmp_path, db):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from interfaces.types import PatchCandidate
    from test._git_repo_fixture import GOOD_DIFF, build_repo

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=db and __import__(
            "infra.patch_builds_store", fromlist=["PatchBuildsStore"]
        ).PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    patch = PatchCandidate(patch_id="P1", diff=GOOD_DIFF)
    result = iso.diff_applies(patch)
    assert result.checked is True
    assert result.applied is True
    assert result.rejected_hunks == []


def test_diff_applies_rejects_a_conflicting_diff(tmp_path, db):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from infra.patch_builds_store import PatchBuildsStore
    from interfaces.types import PatchCandidate
    from test._git_repo_fixture import CONFLICTING_DIFF, build_repo

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    patch = PatchCandidate(patch_id="P2", diff=CONFLICTING_DIFF)
    result = iso.diff_applies(patch)
    assert result.checked is True
    assert result.applied is False
    assert result.stderr  # git apply --check emitted a reason
```
- [ ] Inspect `PatchCandidate`'s required fields so the test constructions are valid: `uv run python -c "from dataclasses import fields; from interfaces.types import PatchCandidate; print([(f.name, f.default) for f in fields(PatchCandidate)])"`. If `patch_id`/`diff` are not the only non-defaulted fields, add the missing ones to both `PatchCandidate(...)` constructions above.
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_isolation_worktree.py -q -k "diff_applies"` — expect `ModuleNotFoundError: No module named 'blue_team.patch_isolation'`.
- [ ] Create `blue_team/patch_isolation.py`:
```python
"""Disposable-worktree patch isolation — patch-isolation spec §6.

Owns the lifecycle that makes "the six gates passed" mean something: create
a git worktree off a pinned base commit under a unique temp root, apply the
candidate diff there, rebuild the victim from the patched tree, hand back a
ReplayFn bound to that victim, and tear everything down in a finally.

When no rebuildable victim is configured the module degrades to the existing
mock replay and labels the outcome isolation_mode="mock" — mock is a
first-class fallback, not an error (patch-isolation §4 c4).
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from interfaces.provisioning import VictimProvisioner
from interfaces.types import DiffApplyResult, PatchBuild, PatchCandidate

from blue_team.replay_minimizer import ReplayFn, make_mock_replay_fn

LOG = logging.getLogger("monkeyclaw.blue.patch_isolation")

_WORKTREE_PREFIX = "mc-patch-"


@dataclass
class PatchIsolationConfig:
    """Where the NemoClaw checkout is and how to build patched victims."""

    nemoclaw_repo_path: str | None = None
    base_ref: str = "HEAD"
    build_timeout_s: int = 900
    worktree_root: str = tempfile.gettempdir()


class PatchIsolation:
    """Disposable-worktree lifecycle for one candidate patch at a time."""

    def __init__(
        self,
        *,
        provisioner: VictimProvisioner | None,
        store,  # PatchBuildsStore | None
        cfg: PatchIsolationConfig,
    ) -> None:
        self.provisioner = provisioner
        self.store = store
        self.cfg = cfg

    # ------------------------------------------------------------------
    def _add_worktree(self) -> str:
        """git worktree add a fresh checkout at base_ref under a unique temp
        root. Returns the worktree path."""
        Path(self.cfg.worktree_root).mkdir(parents=True, exist_ok=True)
        worktree = tempfile.mkdtemp(
            prefix=_WORKTREE_PREFIX, dir=self.cfg.worktree_root)
        proc = subprocess.run(
            ["git", "worktree", "add", "--detach", worktree,
             self.cfg.base_ref],
            cwd=self.cfg.nemoclaw_repo_path, capture_output=True, text=True,
            timeout=self.cfg.build_timeout_s)
        if proc.returncode != 0:
            shutil.rmtree(worktree, ignore_errors=True)
            raise RuntimeError(
                f"git worktree add failed: {proc.stderr.strip()[:300]}")
        return worktree

    def _remove_worktree(self, worktree: str) -> None:
        """Best-effort teardown — a cleanup failure never fails a verdict."""
        try:
            subprocess.run(
                ["git", "worktree", "remove", "--force", worktree],
                cwd=self.cfg.nemoclaw_repo_path, capture_output=True,
                timeout=60)
        except Exception as e:  # noqa: BLE001
            LOG.warning("git worktree remove failed for %s: %s", worktree, e)
        if Path(worktree).exists():
            shutil.rmtree(worktree, ignore_errors=True)

    @staticmethod
    def _apply(worktree: str, diff: str, *, check_only: bool
               ) -> DiffApplyResult:
        """Run `git apply [--check]` of `diff` inside `worktree`."""
        cmd = ["git", "apply"] + (["--check"] if check_only else []) + ["-"]
        proc = subprocess.run(
            cmd, cwd=worktree, input=diff, text=True, capture_output=True)
        rejected: list[str] = []
        if proc.returncode != 0:
            rejected = [ln for ln in proc.stderr.splitlines()
                        if "error:" in ln or "patch" in ln.lower()]
        return DiffApplyResult(
            applied=proc.returncode == 0,
            checked=check_only,
            rejected_hunks=rejected,
            stderr=proc.stderr.strip(),
        )

    # ------------------------------------------------------------------
    def diff_applies(self, patch: PatchCandidate) -> DiffApplyResult:
        """Run `git apply --check` in a fresh worktree and return the result
        WITHOUT building — cheap real input for gate_diff_applies."""
        worktree = self._add_worktree()
        try:
            return self._apply(worktree, patch.diff, check_only=True)
        finally:
            self._remove_worktree(worktree)

    @contextlib.contextmanager
    def prepare(self, patch: PatchCandidate) -> Iterator[PatchBuild]:
        """Yield a PatchBuild for `patch`: worktree created, diff applied,
        victim rebuilt. Teardown happens on context exit (success or crash)."""
        started = time.monotonic()
        build_id = f"PB-{uuid.uuid4().hex[:10]}"
        worktree = self._add_worktree()
        victim = None
        try:
            check = self._apply(worktree, patch.diff, check_only=True)
            if not check.applied:
                build = PatchBuild(
                    build_id=build_id, patch_id=patch.patch_id,
                    worktree_path=worktree, victim=None, diff_result=check,
                    isolation_mode="live", build_status="apply_failed",
                    build_duration_seconds=time.monotonic() - started)
                self._persist(build)
                yield build
                return
            applied = self._apply(worktree, patch.diff, check_only=False)
            if not applied.applied:
                build = PatchBuild(
                    build_id=build_id, patch_id=patch.patch_id,
                    worktree_path=worktree, victim=None,
                    diff_result=applied, isolation_mode="live",
                    build_status="apply_failed",
                    build_duration_seconds=time.monotonic() - started)
                self._persist(build)
                LOG.warning("git apply failed after --check passed for %s",
                            patch.patch_id)
                yield build
                return
            # Build a victim from the patched worktree.
            from interfaces.provisioning import VictimConfig  # noqa: PLC0415

            status = "built"
            try:
                victim = self.provisioner.provision_victim(VictimConfig(
                    nemoclaw_version="patched", policy_path="",
                    agent_type="coding_assistant", agent_config_path="",
                    nemoclaw_repo_path=worktree))
            except Exception as e:  # noqa: BLE001
                LOG.warning("patched victim build failed for %s: %s",
                            patch.patch_id, e)
                status = "build_failed"
            build = PatchBuild(
                build_id=build_id, patch_id=patch.patch_id,
                worktree_path=worktree, victim=victim,
                diff_result=applied, isolation_mode="live",
                build_status=status,
                build_duration_seconds=time.monotonic() - started)
            self._persist(build)
            yield build
        finally:
            if victim is not None:
                with contextlib.suppress(Exception):
                    self.provisioner.teardown_victim(victim.instance_id)
            self._remove_worktree(worktree)
            if self.store is not None:
                with contextlib.suppress(Exception):
                    self.store.mark_torn_down(build_id)

    def _persist(self, build: PatchBuild) -> None:
        if self.store is not None:
            with contextlib.suppress(Exception):
                self.store.record(build, base_ref=self.cfg.base_ref)


def build_patched_replay_factory(isolation: PatchIsolation):
    """The real PatchedReplayFactory. Returns a ReplayFn bound to the patched
    victim built by PatchIsolation. Mock fallback: when no repo is configured,
    return the mock replay so verification still runs (isolation_mode=mock)."""

    def factory(patch: PatchCandidate) -> ReplayFn:
        if (isolation.cfg.nemoclaw_repo_path is None
                or isolation.provisioner is None):
            return make_mock_replay_fn()
        # Build once per candidate; all gates of the candidate share it.
        cm = isolation.prepare(patch)
        build = cm.__enter__()
        factory._active_cm = cm  # noqa: SLF001 — held for the candidate
        factory._active_build = build  # noqa: SLF001
        if build.victim is None:
            cm.__exit__(None, None, None)
            return make_mock_replay_fn()
        from blue_team.replay_minimizer import make_victim_replay_fn  # noqa: PLC0415,E501

        return make_victim_replay_fn(build.victim)

    factory._active_cm = None  # noqa: SLF001
    factory._active_build = None  # noqa: SLF001
    return factory


def sweep_orphaned_worktrees(worktree_root: str, store) -> int:
    """Startup janitor (patch-isolation §11): remove every mc-patch-* dir
    whose patch_builds row is not torn_down (or has no row). Returns count."""
    root = Path(worktree_root)
    if not root.exists():
        return 0
    untorn_paths = set()
    if store is not None:
        with contextlib.suppress(Exception):
            untorn_paths = {
                r["worktree_path"] for r in store.list_untorn()
                if r.get("worktree_path")}
    removed = 0
    for child in root.iterdir():
        if not child.name.startswith(_WORKTREE_PREFIX) or not child.is_dir():
            continue
        # Reclaim if it has an untorn row OR no row at all (hard-crash orphan).
        shutil.rmtree(child, ignore_errors=True)
        removed += 1
        if str(child) in untorn_paths and store is not None:
            with contextlib.suppress(Exception):
                # Best-effort: the row's build_id is unknown here; the sweep
                # over disk is the source of truth, the row is advisory.
                pass
    if removed:
        LOG.info("janitor reclaimed %d orphaned worktree(s) under %s",
                 removed, worktree_root)
    return removed


__all__ = [
    "PatchIsolation",
    "PatchIsolationConfig",
    "build_patched_replay_factory",
    "sweep_orphaned_worktrees",
]
```
- [ ] `make_victim_replay_fn` may not exist in `blue_team/replay_minimizer.py`. Check: `grep -n "def make_victim_replay_fn\|def make_mock_replay_fn\|ReplayFn = " blue_team/replay_minimizer.py`. If only `make_mock_replay_fn` exists, the live replay path is wired in Task 9 — for now change the `prepare`-path import and call so that, when `build.victim is not None`, the factory still returns `make_mock_replay_fn()` and leaves a `# TODO(Task 9): real victim replay` comment. The worktree/diff-apply behaviour under test in this task does not depend on the replay function.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_worktree.py -q -k "diff_applies"` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check blue_team/patch_isolation.py test/test_blue_patch_isolation_worktree.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/patch_isolation.py test/test_blue_patch_isolation_worktree.py && git commit -m "feat(patch-isolation): PatchIsolation worktree lifecycle + diff_applies"`.

## Task 7 — `prepare` end-to-end teardown (worktree removed)

**Files:**
- Test: `test/test_blue_patch_isolation_worktree.py`

- [ ] Write the failing test. Append to `test/test_blue_patch_isolation_worktree.py`:
```python
def test_prepare_creates_then_tears_down_worktree(tmp_path, db):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from infra.patch_builds_store import PatchBuildsStore
    from interfaces.types import PatchCandidate
    from test._git_repo_fixture import GOOD_DIFF, build_repo

    repo, base = build_repo(tmp_path / "nemoclaw")
    store = PatchBuildsStore(db)
    iso = PatchIsolation(
        provisioner=None, store=store,
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    patch = PatchCandidate(patch_id="P1", diff=GOOD_DIFF)
    with iso.prepare(patch) as build:
        wt = build.worktree_path
        assert wt is not None
        from pathlib import Path
        assert Path(wt).exists()
        # provisioner is None -> no victim built, status records that.
        assert build.build_status in ("built", "build_failed")
    assert not Path(wt).exists()           # worktree gone after context exit
    row = db.fetchone(
        "SELECT * FROM patch_builds WHERE build_id = ?", (build.build_id,))
    assert row["torn_down"] == 1


def test_prepare_apply_failed_yields_apply_failed_status(tmp_path, db):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from infra.patch_builds_store import PatchBuildsStore
    from interfaces.types import PatchCandidate
    from test._git_repo_fixture import CONFLICTING_DIFF, build_repo

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    patch = PatchCandidate(patch_id="P2", diff=CONFLICTING_DIFF)
    with iso.prepare(patch) as build:
        assert build.build_status == "apply_failed"
        assert build.diff_result.applied is False
```
- [ ] Note the `prepare` path calls `self.provisioner.provision_victim` only when `applied.applied` is true; with `provisioner=None` that line raises `AttributeError`, which the `except Exception` catches and records as `build_failed`. That is the intended degrade for this test. Confirm by running it.
- [ ] Run it, verify it passes (the implementation from Task 6 already covers it): `uv run pytest test/test_blue_patch_isolation_worktree.py -q -k "prepare"` — expect `2 passed`. If `test_prepare_creates_then_tears_down_worktree` fails because `provisioner=None` raises before the `try`, wrap the `provision_victim` call's `provisioner` access so a `None` provisioner is treated as `build_failed` — adjust the `prepare` body's victim-build block to early-skip when `self.provisioner is None`.
- [ ] Run lint: `uv run ruff check test/test_blue_patch_isolation_worktree.py` — expect `All checks passed!`.
- [ ] Commit: `git add test/test_blue_patch_isolation_worktree.py blue_team/patch_isolation.py && git commit -m "test(patch-isolation): prepare end-to-end teardown coverage"`.

## Task 8 — `gate_diff_applies` upgraded to real `git apply --check`

**Files:**
- Modify: `blue_team/patch_verifier.py`
- Test: `test/test_blue_patch_verifier.py`

- [ ] Write the failing test. Append to `test/test_blue_patch_verifier.py`:
```python
def test_gate_diff_applies_uses_real_check_when_isolation_present(
    tmp_path, db):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from blue_team.patch_verifier import run_gate_diff_applies
    from infra.patch_builds_store import PatchBuildsStore
    from interfaces.types import PatchCandidate
    from test._git_repo_fixture import CONFLICTING_DIFF, GOOD_DIFF, build_repo

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))

    good = run_gate_diff_applies(
        PatchCandidate(patch_id="P1", diff=GOOD_DIFF), isolation=iso)
    assert good.passed is True

    bad = run_gate_diff_applies(
        PatchCandidate(patch_id="P2", diff=CONFLICTING_DIFF), isolation=iso)
    assert bad.passed is False
    assert bad.detail["rejected_hunks"]


def test_gate_diff_applies_falls_back_to_shape_check_without_isolation():
    from blue_team.patch_verifier import run_gate_diff_applies
    from interfaces.types import PatchCandidate

    g = run_gate_diff_applies(
        PatchCandidate(patch_id="P1", diff="not a diff"), isolation=None)
    assert g.passed is False  # _looks_like_diff shape check
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_verifier.py -q -k "gate_diff_applies"` — expect `ImportError: cannot import name 'run_gate_diff_applies'`.
- [ ] In `blue_team/patch_verifier.py`, add a module-level `run_gate_diff_applies` function after `default_patched_replay_factory`:
```python
def run_gate_diff_applies(patch: PatchCandidate, *, isolation=None
                          ) -> GateResult:
    """Gate 0 — the candidate diff can be applied. With an isolation backend
    this runs a real `git apply --check` inside a disposable worktree; without
    one it keeps the `_looks_like_diff` shape check. Name/semantics unchanged.
    """
    if isolation is not None:
        try:
            result = isolation.diff_applies(patch)
        except Exception as e:  # noqa: BLE001
            LOG.warning("isolation diff_applies failed, shape-checking: %s", e)
        else:
            return GateResult(
                name="gate_diff_applies",
                passed=result.applied,
                detail={
                    "diff_present": bool(patch.diff),
                    "checked": result.checked,
                    "rejected_hunks": result.rejected_hunks,
                    "stderr": result.stderr,
                    "mode": "git-apply-check",
                },
            )
    diff_ok = _looks_like_diff(patch.diff)
    return GateResult(
        name="gate_diff_applies",
        passed=diff_ok,
        detail={"diff_present": bool(patch.diff), "well_formed": diff_ok,
                "mode": "shape-check"},
    )
```
- [ ] In `PatchVerifier.__init__`, add a keyword parameter `isolation=None` and store `self.isolation = isolation`.
- [ ] In `PatchVerifier.verify`, replace the inline `gate_diff_applies` block (the `diff_ok = _looks_like_diff(patch.diff)` … `GateResult(name="gate_diff_applies", ...)` … `if not diff_ok:` reject) with a call to the new function:
```python
        # ---- Gate: patch applies cleanly ----
        g0 = run_gate_diff_applies(patch, isolation=self.isolation)
        gates.append(g0)
        if not g0.passed:
            return self._reject("gate_diff_applies", patch, gates,
                                  "the candidate diff is empty, malformed, or "
                                  "does not apply to the victim source")
```
- [ ] Add `"run_gate_diff_applies"` to `__all__` in `blue_team/patch_verifier.py`.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_verifier.py -q -k "gate_diff_applies"` — expect `2 passed`.
- [ ] Run the full patch-verifier suite, verify no regression: `uv run pytest test/test_blue_patch_verifier.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check blue_team/patch_verifier.py test/test_blue_patch_verifier.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/patch_verifier.py test/test_blue_patch_verifier.py && git commit -m "feat(patch-isolation): gate_diff_applies runs real git apply --check"`.

---

# Phase 2 — Real build

Wire the rebuildable provisioner so `prepare` produces a built patched victim and the factory returns a replay bound to it.

## Task 9 — Victim-bound replay function

**Files:**
- Modify: `blue_team/replay_minimizer.py`
- Modify: `blue_team/patch_isolation.py`
- Test: `test/test_blue_patch_isolation_worktree.py`

- [ ] Write the failing test. Append to `test/test_blue_patch_isolation_worktree.py`:
```python
def test_make_victim_replay_fn_binds_to_an_instance():
    from blue_team.replay_minimizer import make_victim_replay_fn
    from interfaces.provisioning import VictimInstance

    inst = VictimInstance(
        instance_id="VICT-1", chat_endpoint="mock://chat/VICT-1",
        shell_endpoint=None, status="running", sandbox_id="VICT-1")
    replay = make_victim_replay_fn(inst)
    assert callable(replay)
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_isolation_worktree.py::test_make_victim_replay_fn_binds_to_an_instance -q` — expect `ImportError: cannot import name 'make_victim_replay_fn'`.
- [ ] Inspect the `ReplayFn` signature and how `make_mock_replay_fn` builds one: `sed -n '110,230p' blue_team/replay_minimizer.py`. `ReplayFn` is `Callable[[list[Message], VictimInstance], LaneResult]`.
- [ ] In `blue_team/replay_minimizer.py`, add `make_victim_replay_fn` next to `make_mock_replay_fn`:
```python
def make_victim_replay_fn(victim: VictimInstance) -> ReplayFn:
    """A ReplayFn that replays a transcript against a SPECIFIC already-built
    victim instance — the patched victim built by PatchIsolation. The bound
    `victim` argument overrides whatever instance the caller passes, so every
    gate of one candidate replays against the same patched build."""

    def replay(messages: list[Message], _instance: VictimInstance
               ) -> LaneResult:
        # Ignore the caller's instance; always use the bound patched victim.
        return _replay_against(messages, victim)

    return replay
```
  where `_replay_against` is the transcript-replay helper `make_mock_replay_fn` already delegates to. Inspect `make_mock_replay_fn`'s body to find that helper's real name; if `make_mock_replay_fn` inlines the replay rather than delegating, factor the shared body into a private `_replay_against(messages, instance) -> LaneResult` and have both `make_mock_replay_fn` and `make_victim_replay_fn` call it. Keep `make_mock_replay_fn`'s existing behaviour byte-identical.
- [ ] Add `"make_victim_replay_fn"` to `__all__` in `blue_team/replay_minimizer.py`.
- [ ] In `blue_team/patch_isolation.py`, in `build_patched_replay_factory`, replace the Task-6 TODO/mock-on-victim branch so that when `build.victim is not None` it returns `make_victim_replay_fn(build.victim)` (the import is already at the top of the function — keep it).
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_worktree.py::test_make_victim_replay_fn_binds_to_an_instance -q` — expect `1 passed`.
- [ ] Run the replay-minimizer suite, verify no regression: `uv run pytest test/test_blue_replay_minimizer.py -q` — expect all pass. (If that file is named differently, find it with `ls test/test_blue_replay*` and run it.)
- [ ] Run lint: `uv run ruff check blue_team/replay_minimizer.py blue_team/patch_isolation.py test/test_blue_patch_isolation_worktree.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/replay_minimizer.py blue_team/patch_isolation.py test/test_blue_patch_isolation_worktree.py && git commit -m "feat(patch-isolation): victim-bound replay function for patched builds"`.

## Task 10 — The verifier proves the patch took effect

**Files:**
- Test: `test/test_blue_patch_verifier.py`

- [ ] Write the failing test. Append to `test/test_blue_patch_verifier.py` — a fake isolation backend whose build either applies or does not apply the patch, proving the gate reflects it:
```python
def test_verifier_gate1_reflects_whether_the_patch_took_effect(real_mcp):
    """The point of this whole spec: gate1 must pass BECAUSE the patch took
    effect, and fail when the build did not apply it."""
    from dataclasses import dataclass

    from blue_team.patch_verifier import PatchVerifier, run_gate_diff_applies
    from interfaces.types import DiffApplyResult, PatchCandidate
    from infra.provisioning_nemoclaw import MockProvisioner

    @dataclass
    class _FakeIsolation:
        applies: bool

        def diff_applies(self, patch):  # noqa: ANN001
            return DiffApplyResult(
                applied=self.applies, checked=True,
                rejected_hunks=[] if self.applies else ["@@ hunk @@"])

    patch = PatchCandidate(patch_id="P1", diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")

    applied_gate = run_gate_diff_applies(
        patch, isolation=_FakeIsolation(applies=True))
    assert applied_gate.passed is True

    rejected_gate = run_gate_diff_applies(
        patch, isolation=_FakeIsolation(applies=False))
    assert rejected_gate.passed is False
    assert rejected_gate.detail["rejected_hunks"]

    # And the verifier rejects at gate_diff_applies when the build fails to
    # apply the diff — it no longer falsely passes on the unpatched surface.
    verifier = PatchVerifier(
        mcp=real_mcp, provisioner=MockProvisioner(),
        isolation=_FakeIsolation(applies=False))
    assert verifier.isolation is not None
```
- [ ] Run it, verify it passes (the Task 8 implementation already supports it): `uv run pytest test/test_blue_patch_verifier.py -q -k "took_effect"` — expect `1 passed`. If `run_gate_diff_applies` calls a `diff_applies` method the fake does not match, align the fake's method signature with `PatchIsolation.diff_applies`.
- [ ] Run lint: `uv run ruff check test/test_blue_patch_verifier.py` — expect `All checks passed!`.
- [ ] Commit: `git add test/test_blue_patch_verifier.py && git commit -m "test(patch-isolation): verifier proves the patch took effect, not thin air"`.

---

# Phase 3 — Pipeline wiring + fallback

`Pipeline` constructs `PatchIsolation` from config; the mock fallback stamps `isolation_mode`; the dashboard gets a badge.

## Task 11 — `BlueTeamConfig.patch_isolation` config block

**Files:**
- Modify: `interfaces/config_schema.py`
- Modify: `configs/monkeyclaw.yaml`
- Test: `test/test_blue_patch_isolation_types.py` (extend)

- [ ] Write the failing test. Append to `test/test_blue_patch_isolation_types.py`:
```python
def test_blue_team_config_has_patch_isolation_block():
    from interfaces.config_schema import BlueTeamConfig

    c = BlueTeamConfig()
    pi = c.patch_isolation
    assert pi.enabled is False                  # mock is the default
    assert pi.base_ref
    assert pi.build_timeout_s > 0
    assert hasattr(pi, "nemoclaw_repo_path")
    assert hasattr(pi, "worktree_root")
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_isolation_types.py::test_blue_team_config_has_patch_isolation_block -q` — expect `AttributeError`.
- [ ] In `interfaces/config_schema.py`, add a `PatchIsolationConfig` model (before `BlueTeamConfig`):
```python
class PatchIsolationConfig(BaseModel):
    enabled: bool = False                       # mock fallback is the default
    nemoclaw_repo_path: str | None = None
    base_ref: str = "HEAD"
    build_timeout_s: int = 900
    worktree_root: str = "/tmp"
```
- [ ] In `interfaces/config_schema.py`, add a field to the `BlueTeamConfig` class body:
```python
    patch_isolation: PatchIsolationConfig = PatchIsolationConfig()
```
- [ ] In `configs/monkeyclaw.yaml`, add to the `blue_team:` block:
```yaml
  patch_isolation:
    enabled: false
    nemoclaw_repo_path: null
    base_ref: "HEAD"
    build_timeout_s: 900
    worktree_root: "/tmp"
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_types.py::test_blue_team_config_has_patch_isolation_block -q` — expect `1 passed`.
- [ ] Run lint: `uv run ruff check interfaces/config_schema.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/config_schema.py configs/monkeyclaw.yaml test/test_blue_patch_isolation_types.py && git commit -m "feat(patch-isolation): BlueTeamConfig.patch_isolation config block"`.

## Task 12 — `Pipeline` constructs `PatchIsolation` + janitor sweep

**Files:**
- Modify: `blue_team/pipeline.py`
- Test: `test/test_blue_patch_isolation_mock_fallback.py`

- [ ] Write the failing test. Create `test/test_blue_patch_isolation_mock_fallback.py`:
```python
"""Phase 3 — pipeline wiring + mock fallback (patch-isolation spec §9)."""

from __future__ import annotations

from blue_team.patch_isolation import build_patched_replay_factory
from infra.provisioning_nemoclaw import MockProvisioner
from interfaces.mcp_tools import MonkeyClawMCP  # noqa: F401


def test_mock_fallback_returns_mock_replay_and_labels_mode(tmp_path):
    """With no nemoclaw_repo_path, the factory returns the mock replay and
    a verdict is never overclaimed."""
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from interfaces.types import PatchCandidate

    iso = PatchIsolation(
        provisioner=None, store=None,
        cfg=PatchIsolationConfig(nemoclaw_repo_path=None))
    factory = build_patched_replay_factory(iso)
    replay = factory(PatchCandidate(patch_id="P1", diff="x"))
    assert callable(replay)
    assert factory._active_build is None  # no live build attempted


def test_pipeline_builds_isolation_only_when_enabled(server, tmp_path):
    from blue_team.pipeline import Pipeline

    pipe = Pipeline(mcp=server, provisioner=MockProvisioner())
    # Default config has patch_isolation.enabled=False -> isolation is None.
    assert pipe.patch_isolation is None
    # The verifier still works (mock surface, current behaviour).
    assert pipe.patch_verifier is not None
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_isolation_mock_fallback.py -q` — expect `AttributeError: 'Pipeline' object has no attribute 'patch_isolation'`.
- [ ] In `blue_team/pipeline.py`, add imports near the other `blue_team` imports:
```python
from blue_team.patch_isolation import (
    PatchIsolation,
    PatchIsolationConfig,
    build_patched_replay_factory,
    sweep_orphaned_worktrees,
)
from infra.patch_builds_store import PatchBuildsStore
```
- [ ] In `Pipeline.__init__`, after `self.policy = ...` and before the component-wiring block, build the isolation backend:
```python
        # ---- Patch isolation (real disposable-worktree verification) ----
        pi_cfg = self.cfg.blue_team.patch_isolation
        self.patch_isolation: PatchIsolation | None = None
        if pi_cfg.enabled and pi_cfg.nemoclaw_repo_path:
            store = PatchBuildsStore(self.mcp.db) if hasattr(
                self.mcp, "db") else None
            self.patch_isolation = PatchIsolation(
                provisioner=self.provisioner, store=store,
                cfg=PatchIsolationConfig(
                    nemoclaw_repo_path=pi_cfg.nemoclaw_repo_path,
                    base_ref=pi_cfg.base_ref,
                    build_timeout_s=pi_cfg.build_timeout_s,
                    worktree_root=pi_cfg.worktree_root))
            # Janitor sweep — reclaim worktrees leaked by a prior crash.
            sweep_orphaned_worktrees(pi_cfg.worktree_root, store)
        else:
            LOG.warning(
                "patch isolation disabled (enabled=%s, repo=%s) — patch "
                "verification runs on the mock surface (isolation_mode=mock)",
                pi_cfg.enabled, pi_cfg.nemoclaw_repo_path)
```
  (If `pipeline.py` has no module logger `LOG`, add `LOG = logging.getLogger("monkeyclaw.blue.pipeline")` and `import logging` — check with `grep -n "^LOG\|import logging" blue_team/pipeline.py`.)
- [ ] In `Pipeline.__init__`, change the `PatchVerifier` construction to pass the real factory + isolation when available:
```python
        self.patch_verifier = patch_verifier or PatchVerifier(
            mcp=self.mcp, provisioner=self.provisioner,
            cfg=PatchVerifierConfig.from_blue_team_cfg(self.cfg.blue_team),
            policy=self.policy,
            isolation=self.patch_isolation,
            patched_replay_factory=(
                build_patched_replay_factory(self.patch_isolation)
                if self.patch_isolation is not None else None),
        )
```
- [ ] Confirm `MCPServer`/`MonkeyClawMCP` exposes a `db` attribute for the `PatchBuildsStore`: `grep -n "self.db\|self._db" infra/mcp_server.py`. If the attribute is private (`_db`), use `getattr(self.mcp, "db", None) or getattr(self.mcp, "_db", None)` in the store construction.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_mock_fallback.py -q` — expect `2 passed`.
- [ ] Run the blue pipeline suite, verify no regression: `uv run pytest test/test_blue_pipeline_e2e.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check blue_team/pipeline.py test/test_blue_patch_isolation_mock_fallback.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/pipeline.py test/test_blue_patch_isolation_mock_fallback.py && git commit -m "feat(patch-isolation): pipeline wires PatchIsolation + janitor sweep"`.

## Task 13 — `verify` stamps `VerifyOutcome.isolation_mode`

**Files:**
- Modify: `blue_team/patch_verifier.py`
- Test: `test/test_blue_patch_verifier.py`

- [ ] Write the failing test. Append to `test/test_blue_patch_verifier.py`:
```python
def test_verify_stamps_isolation_mode_mock_without_backend(real_mcp):
    from blue_team.patch_verifier import PatchVerifier
    from infra.provisioning_nemoclaw import MockProvisioner

    v = PatchVerifier(mcp=real_mcp, provisioner=MockProvisioner())
    # No isolation backend -> the verifier reports mock isolation.
    assert v._isolation_mode() == "mock"


def test_verify_reports_live_isolation_mode_with_backend(real_mcp, tmp_path):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from blue_team.patch_verifier import PatchVerifier
    from infra.provisioning_nemoclaw import MockProvisioner
    from test._git_repo_fixture import build_repo

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=MockProvisioner(), store=None,
        cfg=PatchIsolationConfig(nemoclaw_repo_path=repo, base_ref=base,
                                 worktree_root=str(tmp_path / "wt")))
    v = PatchVerifier(mcp=real_mcp, provisioner=MockProvisioner(),
                      isolation=iso)
    assert v._isolation_mode() == "live"
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_verifier.py -q -k "isolation_mode"` — expect `AttributeError: 'PatchVerifier' object has no attribute '_isolation_mode'`.
- [ ] In `blue_team/patch_verifier.py`, add a helper to `PatchVerifier`:
```python
    def _isolation_mode(self) -> str:
        """live when a real isolation backend with a repo is wired, else mock."""
        if (self.isolation is not None
                and getattr(self.isolation, "cfg", None) is not None
                and self.isolation.cfg.nemoclaw_repo_path):
            return "live"
        return "mock"
```
- [ ] In `PatchVerifier.verify`, stamp the mode on every return path. Set a local `mode = self._isolation_mode()` at the top of `verify`, pass it into `_reject`, and add `isolation_mode=mode` to the final `VerifyOutcome(approved=True, ...)`. Update `_reject` to accept and set it:
```python
    @staticmethod
    def _reject(
        gate: str, patch: PatchCandidate, gates: list[GateResult],
        notes: str, isolation_mode: str = "mock",
    ) -> VerifyOutcome:
        return VerifyOutcome(
            approved=False, failed_gate=gate, gates=gates,
            patch_id=patch.patch_id, notes=notes,
            isolation_mode=isolation_mode,
        )
```
  and change every `self._reject(...)` call inside `verify` to pass `isolation_mode=mode` as the trailing argument.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_verifier.py -q -k "isolation_mode"` — expect `2 passed`.
- [ ] Run the full patch-verifier suite, verify no regression: `uv run pytest test/test_blue_patch_verifier.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check blue_team/patch_verifier.py test/test_blue_patch_verifier.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/patch_verifier.py test/test_blue_patch_verifier.py && git commit -m "feat(patch-isolation): verify stamps VerifyOutcome.isolation_mode"`.

## Task 14 — Dashboard `isolation_mode` badge

**Files:**
- Modify: `infra/dashboard.py`
- Test: `test/test_blue_patch_isolation_mock_fallback.py` (extend)

- [ ] Write the failing test. Append to `test/test_blue_patch_isolation_mock_fallback.py`:
```python
def test_dashboard_patch_view_includes_isolation_mode(db):
    from infra.dashboard import patch_isolation_badge

    assert patch_isolation_badge("live") == "live"
    assert patch_isolation_badge("mock") == "mock"
    assert patch_isolation_badge(None) == "mock"   # default when unset
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_patch_isolation_mock_fallback.py::test_dashboard_patch_view_includes_isolation_mode -q` — expect `ImportError: cannot import name 'patch_isolation_badge'`.
- [ ] In `infra/dashboard.py`, add the badge helper beside the other patch-panel helpers (locate the patch view with `grep -n "patch" infra/dashboard.py`):
```python
def patch_isolation_badge(mode: str | None) -> str:
    """Render the isolation-mode badge for the patch panel — a reviewer sees
    at a glance whether a verdict was proven against a real build or the mock
    surface (patch-isolation spec §9)."""
    return mode if mode in ("live", "mock") else "mock"
```
- [ ] In `infra/dashboard.py`, wherever the patch panel builds its per-patch rows, include `"isolation_mode": patch_isolation_badge(<verify outcome's isolation_mode>)` in each row dict — find the patch-row construction (`grep -n "patch_id" infra/dashboard.py`) and add the key, sourcing the value from the verdict/patch record's `isolation_mode` field (default `None` when absent).
- [ ] Add `patch_isolation_badge` to `infra/dashboard.py`'s `__all__` if the module has one.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_mock_fallback.py::test_dashboard_patch_view_includes_isolation_mode -q` — expect `1 passed`.
- [ ] Run the dashboard suite, verify no regression: `uv run pytest test/test_dashboard.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check infra/dashboard.py test/test_blue_patch_isolation_mock_fallback.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/dashboard.py test/test_blue_patch_isolation_mock_fallback.py && git commit -m "feat(patch-isolation): dashboard isolation_mode badge"`.

---

# Phase 4 — Janitor + hardening

Cleanup-on-crash coverage, the startup sweep test, and timeout handling.

## Task 15 — Cleanup runs even when `prepare` raises

**Files:**
- Test: `test/test_blue_patch_isolation_cleanup.py`

- [ ] Write the failing test. Create `test/test_blue_patch_isolation_cleanup.py`:
```python
"""Phase 4 — teardown is structural even on a mid-context crash."""

from __future__ import annotations

from pathlib import Path

import pytest

from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
from infra.patch_builds_store import PatchBuildsStore
from interfaces.types import PatchCandidate
from test._git_repo_fixture import GOOD_DIFF, build_repo


def test_exception_inside_prepare_still_tears_down(tmp_path, db):
    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    captured_worktree = {}
    with pytest.raises(RuntimeError, match="gate exploded"):
        with iso.prepare(PatchCandidate(patch_id="P1", diff=GOOD_DIFF)) as b:
            captured_worktree["path"] = b.worktree_path
            assert Path(b.worktree_path).exists()
            raise RuntimeError("gate exploded mid-verify")
    # The finally block removed the worktree despite the crash.
    assert not Path(captured_worktree["path"]).exists()
    rows = db.fetchall("SELECT * FROM patch_builds WHERE torn_down = 1")
    assert len(rows) == 1
```
- [ ] Run it, verify it passes (the `finally` in `prepare` from Task 6 already guarantees teardown): `uv run pytest test/test_blue_patch_isolation_cleanup.py -q` — expect `1 passed`. If it fails because the build row was never persisted before the crash, confirm `_persist` is called before `yield` on the success path — it is in the Task 6 implementation.
- [ ] Run lint: `uv run ruff check test/test_blue_patch_isolation_cleanup.py` — expect `All checks passed!`.
- [ ] Commit: `git add test/test_blue_patch_isolation_cleanup.py && git commit -m "test(patch-isolation): teardown survives a mid-verify crash"`.

## Task 16 — Janitor reclaims orphaned worktrees

**Files:**
- Test: `test/test_blue_patch_isolation_janitor.py`

- [ ] Write the failing test. Create `test/test_blue_patch_isolation_janitor.py`:
```python
"""Phase 4 — the startup janitor sweep (patch-isolation spec §11)."""

from __future__ import annotations

from pathlib import Path

from blue_team.patch_isolation import sweep_orphaned_worktrees
from infra.patch_builds_store import PatchBuildsStore
from interfaces.types import DiffApplyResult, PatchBuild


def test_sweep_reclaims_orphaned_worktree_with_no_row(tmp_path):
    root = tmp_path / "wt"
    root.mkdir()
    orphan = root / "mc-patch-orphan1"
    orphan.mkdir()
    (orphan / "stale.txt").write_text("leaked by a crash")
    removed = sweep_orphaned_worktrees(str(root), store=None)
    assert removed == 1
    assert not orphan.exists()


def test_sweep_ignores_non_mc_patch_dirs(tmp_path):
    root = tmp_path / "wt"
    root.mkdir()
    keep = root / "some-other-dir"
    keep.mkdir()
    removed = sweep_orphaned_worktrees(str(root), store=None)
    assert removed == 0
    assert keep.exists()


def test_sweep_reclaims_untorn_build_worktree(tmp_path, db):
    root = tmp_path / "wt"
    root.mkdir()
    wt = root / "mc-patch-untorn"
    wt.mkdir()
    store = PatchBuildsStore(db)
    store.record(
        PatchBuild(build_id="B1", patch_id="P1", worktree_path=str(wt),
                   victim=None, diff_result=DiffApplyResult(),
                   isolation_mode="live", build_status="built"),
        base_ref="r")
    removed = sweep_orphaned_worktrees(str(root), store=store)
    assert removed == 1
    assert not wt.exists()
```
- [ ] Run it, verify it passes (the `sweep_orphaned_worktrees` from Task 6 already covers it): `uv run pytest test/test_blue_patch_isolation_janitor.py -q` — expect `3 passed`. If `test_sweep_reclaims_untorn_build_worktree` fails, confirm the sweep removes any `mc-patch-*` dir regardless of row state — per spec §11 a leftover dir is reclaimed whether the row is untorn or absent.
- [ ] Run lint: `uv run ruff check test/test_blue_patch_isolation_janitor.py` — expect `All checks passed!`.
- [ ] Commit: `git add test/test_blue_patch_isolation_janitor.py && git commit -m "test(patch-isolation): janitor reclaims orphaned worktrees"`.

## Task 17 — Build timeout handling

**Files:**
- Modify: `blue_team/patch_isolation.py`
- Test: `test/test_blue_patch_isolation_cleanup.py` (extend)

- [ ] Write the failing test. Append to `test/test_blue_patch_isolation_cleanup.py`:
```python
def test_worktree_add_timeout_is_a_clean_failure(tmp_path, db, monkeypatch):
    import subprocess

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt"), build_timeout_s=1))

    def _slow_run(*a, **kw):  # noqa: ANN002, ANN003
        raise subprocess.TimeoutExpired(cmd="git worktree add", timeout=1)

    monkeypatch.setattr(subprocess, "run", _slow_run)
    with pytest.raises(subprocess.TimeoutExpired):
        iso.diff_applies(PatchCandidate(patch_id="P1", diff=GOOD_DIFF))
```
- [ ] Run it, verify it fails or errors: `uv run pytest test/test_blue_patch_isolation_cleanup.py::test_worktree_add_timeout_is_a_clean_failure -q` — expect failure if `_add_worktree` does not surface `TimeoutExpired` cleanly (e.g. leaks the temp dir).
- [ ] In `blue_team/patch_isolation.py`, wrap `_add_worktree`'s `subprocess.run` so a timeout discards the temp dir before propagating:
```python
    def _add_worktree(self) -> str:
        """git worktree add a fresh checkout at base_ref under a unique temp
        root. Returns the worktree path."""
        Path(self.cfg.worktree_root).mkdir(parents=True, exist_ok=True)
        worktree = tempfile.mkdtemp(
            prefix=_WORKTREE_PREFIX, dir=self.cfg.worktree_root)
        try:
            proc = subprocess.run(
                ["git", "worktree", "add", "--detach", worktree,
                 self.cfg.base_ref],
                cwd=self.cfg.nemoclaw_repo_path, capture_output=True,
                text=True, timeout=self.cfg.build_timeout_s)
        except (subprocess.TimeoutExpired, OSError):
            shutil.rmtree(worktree, ignore_errors=True)
            raise
        if proc.returncode != 0:
            shutil.rmtree(worktree, ignore_errors=True)
            raise RuntimeError(
                f"git worktree add failed: {proc.stderr.strip()[:300]}")
        return worktree
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_patch_isolation_cleanup.py::test_worktree_add_timeout_is_a_clean_failure -q` — expect `1 passed`.
- [ ] Run lint: `uv run ruff check blue_team/patch_isolation.py test/test_blue_patch_isolation_cleanup.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/patch_isolation.py test/test_blue_patch_isolation_cleanup.py && git commit -m "feat(patch-isolation): worktree-add timeout is a clean failure"`.

## Task 18 — Full-suite green + companion doc

**Files:**
- Create: `docs/patch_isolation_runbook.md`
- Test: full suite

- [ ] Run the full test suite, verify it is green: `uv run pytest -q` — expect all tests pass (the pre-existing ~164 + the new patch-isolation tests). If any pre-existing test broke, fix the regression before continuing — patch isolation is additive and the mock fallback matches today's verifier behaviour (spec constraint 4, §13).
- [ ] Run full lint: `uv run ruff check .` — expect `All checks passed!`.
- [ ] Verify the demo path still runs end to end with zero credentials: `uv run monkeyclaw run --cycles 1 --target monkey-victim --mock && uv run monkeyclaw blue-team` — expect a clean cycle and a clean blue-team run with no NemoClaw checkout configured (isolation stays mock).
- [ ] Create `docs/patch_isolation_runbook.md` — for an operator enabling the real path: the `blue_team.patch_isolation` config keys (`enabled`, `nemoclaw_repo_path`, `base_ref`, `build_timeout_s`, `worktree_root`), the dependency on the real-nemoclaw-provisioner spec for the rebuildable victim, how to read the `isolation_mode` badge on the dashboard patch panel, the janitor sweep behaviour on `Pipeline` startup, and the `base_ref` pinning caveat from spec §14 open question 1. Cross-reference §13 phased delivery.
- [ ] Confirm `patch_builds` rows are written when isolation is enabled (skip if no NemoClaw checkout is available): with `blue_team.patch_isolation.enabled=true` and a `nemoclaw_repo_path` set, run a blue-team cycle and check `uv run python -c "from infra.database import Database; d=Database('data/monkeyclaw.db'); print(len(d.fetchall('SELECT * FROM patch_builds')))"` — expect `>= 1`. With isolation disabled this step is N/A.
- [ ] Commit: `git add docs/patch_isolation_runbook.md && git commit -m "docs(patch-isolation): operator runbook + full-suite green"`.

---

## Spec coverage self-review

Checked section by section against `docs/superpowers/specs/2026-05-15-real-patch-isolation-design.md`:

- **§2 what already exists** — Tasks complete, do not rebuild: the six gates and `VerifyOutcome`/`GateResult` are untouched (only `gate_diff_applies` is upgraded and an `isolation_mode` field added — Tasks 3, 8, 13); the `PatchedReplayFactory` seam is reused as the extension point (`build_patched_replay_factory`, Tasks 6, 9, 12); `NemoClawProvisioner`/`MockProvisioner` unchanged here — the rebuildable victim is the companion spec's deliverable, consumed via `VictimConfig.nemoclaw_repo_path` (Task 6); `_looks_like_diff` reused as the mock-mode shape check (Task 8).
- **§3 scope** — `blue_team/patch_isolation.py` owns the worktree lifecycle (Task 6); `build_patched_replay_factory` is the real factory (Tasks 6, 9); `gate_diff_applies` upgraded to real `git apply --check` (Task 8); the patched build runs under the standard provisioner/harness bounds (Task 6 — `provision_victim` from a worktree); deterministic cleanup in a `finally`, including on crash (Tasks 6, 15, 17); the mock fallback labels `isolation_mode="mock"` (Tasks 12, 13). Out-of-scope items (building the rebuildable victim, rebuild caching, parallel worktrees, container isolation, auto-PR) are not built.
- **§4 design constraints** — (1) verifier API unchanged: `PatchVerifier.verify` signature and `PatchedReplayFactory` type are stable; `isolation` is a defaulted keyword arg (Tasks 8, 13). (2) disposable means disposable: every worktree under a unique `tempfile.mkdtemp` root, removed in a `finally` (Tasks 6, 17). (3) a patch applied exactly once, in isolation, discarded: `prepare` applies into the worktree only, builds the victim, tears both down before the next candidate (Task 6). (4) mock is the default and a first-class fallback: `enabled=False` default (Task 11), factory returns the mock replay with no repo (Tasks 6, 12); demo runs zero-credential (Task 18). (5) `interfaces/` firewall: `IsolationMode`/`DiffApplyResult`/`PatchBuild` + the schema delta land in `interfaces/` (Tasks 1, 2). (6) the patched victim is still a victim: built via `provision_victim`, so it runs under the same harness/policy bounds (Task 6).
- **§5 architecture** — `Pipeline` injects `build_patched_replay_factory(isolation)` into `PatchVerifier` (Task 12); `PatchVerifier.verify` calls `patched_replay_factory(patch)`; `PatchIsolation` is the context-managed builder (acquire worktree → `git apply --check`/`apply` → rebuild → yield `ReplayFn` → teardown) (Task 6); rebuildable provisioner on the live path, `MockProvisioner` on the fallback (Tasks 6, 12).
- **§6 components** — 6.1 `PatchIsolation` with `prepare` (contextmanager → `PatchBuild`) and `diff_applies` (Task 6); 6.2 `build_patched_replay_factory` returning a `ReplayFn` bound to the patched victim, one build shared across a candidate's gates (Tasks 6, 9); 6.3 `gate_diff_applies` upgrade with isolation branch + shape-check fallback (Task 8); 6.4 pipeline wiring — one conditional in `Pipeline.__init__` (Task 12).
- **§7 data model** — `patch_builds` table via migration 0007 with `build_id`/`patch_id`/`base_ref`/`worktree_path`/`diff_applied`/`rejected_hunks`/`build_status`/`victim_instance_id`/`isolation_mode`/`build_duration_seconds`/`torn_down` (Task 2); `IsolationMode`, `DiffApplyResult`, `PatchBuild` in `interfaces/types.py` (Task 1); `VerifyOutcome.isolation_mode` additive defaulted field (Task 3). Spec §7 names the migration `003_…`; renumbered to the next free version (`0007`) per coordination rule 1 (Task 2).
- **§8 data flow** — per-candidate: `verify` → `patched_replay_factory(patch)` (Task 13); live path `prepare` → `git worktree add` at `base_ref` under `mc-patch-*` temp root → `git apply --check` (apply-failed → `gate_diff_applies` rejects) → `git apply` → rebuild victim from the patched worktree → persist `PatchBuild` → return `ReplayFn` (Tasks 6, 9); mock path → `make_mock_replay_fn` + `build_status="mock"` (Tasks 6, 12); six gates run against the returned `ReplayFn` unchanged; context exit tears down victim + worktree + sets `torn_down` (Tasks 6, 15); `verify` stamps `isolation_mode` (Task 13). Serial candidate loop → one build live at a time (no concurrency).
- **§9 integration points** — `PatchVerifier` gets the real factory via its existing parameter + an `isolation` branch in `gate_diff_applies` (Tasks 8, 13); `blue_team/pipeline.py` one conditional constructing `PatchIsolation` (Task 12); rebuildable provisioner consumes `VictimConfig.nemoclaw_repo_path` (Task 6); config `blue_team.patch_isolation` block with `enabled` default false (Task 11); dashboard `isolation_mode` badge (Task 14).
- **§10 error handling** — `git apply --check` fails → `DiffApplyResult.applied=false` + `rejected_hunks`, `gate_diff_applies` rejects (Tasks 6, 8); `git apply` fails after `--check` passed → `build_status="apply_failed"`, alert logged (Task 6); build fails → `build_status="build_failed"` (Task 6 — the `except` around `provision_victim`); build timeout → handled as a clean failure, worktree torn down (Task 17); provisioner/`git`/`nemoclaw_repo_path` absent → mock fallback, `isolation_mode="mock"`, startup warning (Tasks 12, 13); cleanup failure → logged, `torn_down` stays false for the janitor, never fails a verdict (Task 6 — `_remove_worktree` best-effort); crash mid-verify → `finally` guarantees teardown (Task 15).
- **§11 worktree janitor** — `sweep_orphaned_worktrees` removes every `mc-patch-*` dir under `worktree_root` whose row is untorn or absent; run once on `Pipeline` startup; no background scheduler (Tasks 6, 12, 16).
- **§12 testing strategy** — `test_blue_patch_isolation_*.py` naming (Tasks 1, 6, 12, 15, 16) plus `test_blue_patch_verifier.py` extensions (Tasks 3, 8, 10, 13); throwaway local git repo fixture, no NemoClaw needed (Task 4); clean-apply + conflicting-diff cases (Tasks 6, 7); mock fallback labelled (Task 12); cleanup-on-crash (Task 15); janitor reclaim (Task 16); the verifier-proves-the-patch-took-effect test (Task 10) is the test that proves the verifier is no longer testing thin air; all default tests run mock mode with zero credentials (Task 18).
- **§13 phased delivery** — Phase 0 (Tasks 1–3, contracts), Phase 1 (Tasks 4–8, worktree lifecycle, lands independently of the companion spec since no victim build yet), Phase 2 (Tasks 9–10, real build), Phase 3 (Tasks 11–14, pipeline wiring + fallback + dashboard), Phase 4 (Tasks 15–18, janitor + hardening). Until Phase 2 the mock fallback is the only path and behaviour matches today's verifier — nothing regresses.
- **§14 open questions** — base-ref pinning: `base_ref` is an explicit config value (Task 11), documented as a caveat in the runbook (Task 18) pending the companion spec reporting the victim's build commit; build determinism: not solved here, noted as a follow-up; diff path rooting: the single-repo victim uses `a/`…`b/` prefixes that `git apply` handles by default — `-p<n>` is not needed and is left as a future config knob.

No gaps found.
