# Real NemoClaw Provisioner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete `NemoClawProvisioner` into a real, snapshot-isolated, telemetry-capturing victim provisioner — ephemeral per-lane work areas cloned from a deterministic baseline, per-lane patch application, real fs/network/process/inference telemetry capture, and a capability-detection layer that degrades gracefully back to mock.

**Architecture:** The `VictimProvisioner` Protocol in `interfaces/provisioning.py` is extended additively with `recover_victim` and `snapshot_victim`; new shared types (`VictimSnapshot`, `SandboxCapabilities`, `VictimTelemetryBundle`) land in `interfaces/`. `NemoClawProvisioner` probes the local `nemoclaw` build once at construction, records a frozen `SandboxCapabilities`, and branches every lifecycle method on it — full capabilities give ephemeral snapshot-isolated victims, partial capabilities degrade to recover-only with `deterministic=False`, and an absent CLI lets bootstrap fall back to `MockProvisioner` with a loud warning. A capability prober, a telemetry capturer, and a patch builder are each one helper in `infra/`; two new tables (`victim_snapshots`, `sandbox_runs`) ship as a migration.

**Tech Stack:** Python 3.12, `uv` for env + test running, `pytest`, SQLite via `infra/database.py`, the existing migration runner (`infra/migrations.py` + `infra/migrations/`), `interfaces/types.py` / `interfaces/provisioning.py` dataclasses, `ruff` for lint. Everything runs in mock mode with zero model credentials; the live NemoClaw path is gated behind the `MC_LIVE_NEMOCLAW=1` env marker.

---

## File Structure

| File | Create/Modify | Responsibility |
|------|---------------|----------------|
| `interfaces/provisioning.py` | Modify | Extend the `VictimProvisioner` Protocol with `recover_victim` / `snapshot_victim`; add `VictimSnapshot` and `SandboxCapabilities` dataclasses; module-level `recover_victim` / `snapshot_victim` convenience wrappers. |
| `interfaces/types.py` | Modify | Add `VictimTelemetryBundle` (container of the five existing observable types) and the literal `SandboxMode`. |
| `interfaces/config_schema.py` | Modify | `NemoClawConfig` gains `baseline_snapshot`, `work_area_dir`, `patch_build_timeout_s`. |
| `interfaces/schema.sql` | Modify | Add `victim_snapshots` + `sandbox_runs` (reference copy, kept in sync with the migration). |
| `infra/migrations/0006_real_provisioner.sql` | Create | Migration adding `victim_snapshots` and `sandbox_runs`; bumps `schema_version`. |
| `infra/sandbox_capabilities.py` | Create | The capability prober — `probe(cli, sandbox_name) -> SandboxCapabilities`. |
| `infra/sandbox_telemetry.py` | Create | `SandboxTelemetryCapturer` — reads real fs/network/process/inference observables → `VictimTelemetryBundle`. |
| `infra/patch_builder.py` | Create | `PatchBuilder.build_patched_snapshot(diff, baseline) -> VictimSnapshot` — disposable clone, apply diff, rebuild. |
| `infra/provisioning_nemoclaw.py` | Modify | Complete `NemoClawProvisioner`: probe at construction, ephemeral provision, `recover_victim`, `snapshot_victim`, real `teardown_victim`; `MockProvisioner` gains trivial `recover_victim` / `snapshot_victim`. |
| `infra/sandbox_runs_store.py` | Create | Thin writer for `sandbox_runs` / `victim_snapshots` rows. |
| `infra/bootstrap.py` | Modify | Backend selection runs the capability prober; falls back to `MockProvisioner` with a warning when `cli_present=False`. |
| `infra/lane_scheduler.py` | Modify | Propagate `instance.metadata["deterministic"]` onto `LaneResult`; write a `sandbox_runs` row per lane. |
| `infra/orchestrator.py` | Modify | Thread the `Database` into the provisioner so `sandbox_runs` rows persist. |
| `infra/dashboard.py` | Modify | One additive operational view backed by `sandbox_runs`. |
| `configs/monkeyclaw.yaml` | Modify | `nemoclaw` block gains `baseline_snapshot`, `work_area_dir`, `patch_build_timeout_s`. |
| `test/_nemoclaw_stub.py` | Create | Shared helper that writes a fake `nemoclaw` CLI script onto a temp PATH for the stubbed-CLI suites. |
| `test/test_provisioning.py` | Modify | `MockProvisioner` satisfies the extended Protocol incl. `recover_victim` / `snapshot_victim`. |
| `test/test_provisioning_capabilities.py` | Create | Prober tests against full / snapshot-less / CLI-absent stubs. |
| `test/test_provisioning_lifecycle.py` | Create | `provision → recover → snapshot → teardown` CLI-call ordering; recover-only `deterministic=False`. |
| `test/test_provisioning_patch_builder.py` | Create | `build_patched_snapshot` isolation; un-appliable diff and snapshot-less errors. |
| `test/test_provisioning_telemetry.py` | Create | Capturer maps stubbed sandbox output into the observable shapes; missing stream degrades. |
| `test/test_provisioning_migration.py` | Create | Migration 0006 applies and creates the two tables. |
| `test/test_provisioning_fallback.py` | Create | Bootstrap with no `nemoclaw` CLI falls back to mock; demo path still passes. |

---

# Phase 0 — Contracts & capability detection

No default change: shared types, the extended Protocol, the migration, and the capability prober. `NemoClawProvisioner` records capabilities but behaviour stays the current recover/restore.

## Task 1 — Extended provisioner contract + new types

**Files:**
- Modify: `interfaces/provisioning.py`
- Modify: `interfaces/types.py`
- Test: `test/test_provisioning.py`

- [ ] Write the failing test. Append to `test/test_provisioning.py`:
```python
def test_victim_snapshot_records_determinism_and_patched():
    from interfaces.provisioning import VictimSnapshot

    s = VictimSnapshot(
        name="clean-baseline", sandbox_id="monkey-victim",
        created_at="2026-05-15T00:00:00Z", deterministic=True,
        patched=False, base_snapshot=None,
    )
    assert s.deterministic is True
    assert s.patched is False


def test_sandbox_capabilities_has_five_flags():
    from dataclasses import fields

    from interfaces.provisioning import SandboxCapabilities

    fnames = {f.name for f in fields(SandboxCapabilities)}
    assert fnames == {"cli_present", "snapshots", "ephemeral",
                      "container_fsdiff", "recover"}


def test_victim_provisioner_protocol_includes_recover_and_snapshot():
    from interfaces.provisioning import VictimProvisioner

    # Method names are part of the extended contract.
    assert hasattr(VictimProvisioner, "recover_victim")
    assert hasattr(VictimProvisioner, "snapshot_victim")


def test_victim_telemetry_bundle_carries_five_observable_lists():
    from dataclasses import fields

    from interfaces.types import VictimTelemetryBundle

    fnames = {f.name for f in fields(VictimTelemetryBundle)}
    assert {"fs_diff", "network_events", "process_events",
            "inference_events", "memory_diff"} <= fnames
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning.py -q -k "snapshot or capabilities or protocol_includes or telemetry_bundle"` — expect `ImportError: cannot import name 'VictimSnapshot'`.
- [ ] Add the two dataclasses to `interfaces/provisioning.py`, immediately after `VictimInstance`:
```python
@dataclass
class VictimSnapshot:
    """A named capture of victim state. `deterministic` is False when the
    capture was taken without true snapshot isolation; `patched` is True for
    snapshots built by the patch builder."""

    name: str
    sandbox_id: str
    created_at: str
    deterministic: bool
    patched: bool = False
    base_snapshot: str | None = None


@dataclass
class SandboxCapabilities:
    """What the local `nemoclaw` build supports. Probed once at provisioner
    construction; every lifecycle method branches on it."""

    cli_present: bool
    snapshots: bool
    ephemeral: bool
    container_fsdiff: bool
    recover: bool
```
- [ ] Add the two methods to the `VictimProvisioner` Protocol body in `interfaces/provisioning.py`, after `list_victims`:
```python
    def recover_victim(self, instance_id: str) -> VictimInstance:
        """Restart the gateway + agent in place, clearing session/
        conversation state without a full reprovision. Idempotent."""
        ...

    def snapshot_victim(self, instance_id: str, name: str) -> VictimSnapshot:
        """Capture the current victim state as a named snapshot."""
        ...
```
- [ ] Add module-level convenience wrappers to `interfaces/provisioning.py`, after `teardown_victim`:
```python
def recover_victim(instance_id: str) -> VictimInstance:
    """Module-level convenience wrapping the configured backend."""
    return get_provisioner().recover_victim(instance_id)


def snapshot_victim(instance_id: str, name: str) -> VictimSnapshot:
    """Module-level convenience wrapping the configured backend."""
    return get_provisioner().snapshot_victim(instance_id, name)
```
- [ ] Extend `__all__` in `interfaces/provisioning.py` to add (alphabetised): `"SandboxCapabilities"`, `"VictimSnapshot"`, `"recover_victim"`, `"snapshot_victim"`.
- [ ] Add the literal to `interfaces/types.py`, after the existing literal block:
```python
SandboxMode = Literal["ephemeral", "recover_only", "mock"]
```
- [ ] Add the `VictimTelemetryBundle` dataclass to `interfaces/types.py`, immediately after the `InferenceEvent` class:
```python
@dataclass
class VictimTelemetryBundle:
    """Real observables captured from a running/just-finished victim sandbox.
    Each field reuses an existing observable type; missing streams degrade to
    an empty list / None rather than aborting the lane."""

    fs_diff: FsDiff | None = None
    network_events: list[NetworkEvent] = field(default_factory=list)
    process_events: list[ProcessEvent] = field(default_factory=list)
    inference_events: list[InferenceEvent] = field(default_factory=list)
    memory_diff: MemoryDiff | None = None
```
- [ ] Append `"SandboxMode"` and `"VictimTelemetryBundle"` to `__all__` in `interfaces/types.py` (alphabetised within the list).
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning.py -q -k "snapshot or capabilities or protocol_includes or telemetry_bundle"` — expect `4 passed`.
- [ ] Run lint: `uv run ruff check interfaces/provisioning.py interfaces/types.py test/test_provisioning.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/provisioning.py interfaces/types.py test/test_provisioning.py && git commit -m "feat(provisioner): extend VictimProvisioner contract with recover/snapshot + new types"`.

## Task 2 — Schema migration 0006

**Files:**
- Create: `infra/migrations/0006_real_provisioner.sql`
- Modify: `interfaces/schema.sql`
- Test: `test/test_provisioning_migration.py`

- [ ] Inspect the highest existing migration number: `ls infra/migrations/`. If the highest is not `0005`, rename the file in this task to the next free number and use that number consistently below (coordination rule 1 of the upgrade roadmap). The plan assumes `0006`.
- [ ] Write the failing test. Create `test/test_provisioning_migration.py`:
```python
"""Phase 0 — migration 0006 creates the real-provisioner tables."""

from __future__ import annotations

from infra.database import Database

PROVISIONER_TABLES = {"victim_snapshots", "sandbox_runs"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_provisioner_tables(db: Database):
    assert PROVISIONER_TABLES <= _table_names(db)


def test_sandbox_runs_has_mode_and_capabilities(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(sandbox_runs)")}
    assert {"run_id", "instance_id", "lane_id", "mode", "deterministic",
            "patch_applied", "capabilities"} <= cols


def test_victim_snapshots_has_patched_and_base(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(victim_snapshots)")}
    assert {"snapshot_id", "name", "sandbox_id", "deterministic",
            "patched", "base_snapshot"} <= cols
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_migration.py -q` — expect `AssertionError` (tables absent).
- [ ] Create `infra/migrations/0006_real_provisioner.sql`:
```sql
-- Migration 0006 — real-provisioner tables (real-nemoclaw-provisioner spec §8).
-- Forward-only, idempotent. Applied by infra/migrations.py on Database open.

BEGIN;

CREATE TABLE IF NOT EXISTS victim_snapshots (
    snapshot_id    TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    sandbox_id     TEXT NOT NULL,
    deterministic  INTEGER NOT NULL DEFAULT 0,   -- 0/1
    patched        INTEGER NOT NULL DEFAULT 0,   -- 0/1
    base_snapshot  TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_victim_snapshots_name
    ON victim_snapshots(name);

CREATE TABLE IF NOT EXISTS sandbox_runs (
    run_id          TEXT PRIMARY KEY,
    instance_id     TEXT NOT NULL,
    lane_id         TEXT,
    mode            TEXT NOT NULL,               -- ephemeral|recover_only|mock
    deterministic   INTEGER NOT NULL DEFAULT 0,  -- 0/1
    patch_applied   INTEGER NOT NULL DEFAULT 0,  -- 0/1
    capabilities    TEXT NOT NULL DEFAULT '{}',  -- JSON SandboxCapabilities
    provisioned_at  TEXT NOT NULL DEFAULT (datetime('now')),
    torn_down_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sandbox_runs_lane
    ON sandbox_runs(lane_id);

UPDATE schema_meta SET value = '3' WHERE key = 'schema_version';

COMMIT;
```
- [ ] Mirror the two `CREATE TABLE` blocks into `interfaces/schema.sql` (reference copy) at the end, before the `schema_meta` block, and bump the `INSERT OR IGNORE INTO schema_meta` value from `'2'` to `'3'`. Note: if another Wave-1 spec already bumped the version, take the next free number per coordination rule 1.
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_migration.py -q` — expect `3 passed`.
- [ ] Run lint: `uv run ruff check test/test_provisioning_migration.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/migrations/0006_real_provisioner.sql interfaces/schema.sql test/test_provisioning_migration.py && git commit -m "feat(provisioner): migration 0006 — victim_snapshots + sandbox_runs"`.

## Task 3 — The `nemoclaw` CLI stub helper

**Files:**
- Create: `test/_nemoclaw_stub.py`
- Test: (used by Tasks 4, 5, 6, 7)

- [ ] Create `test/_nemoclaw_stub.py` — a reusable fake CLI for the stubbed-CLI suites:
```python
"""A fake `nemoclaw` CLI for stubbed-CLI provisioner tests.

write_stub() drops an executable shell script named `nemoclaw` into a temp
dir, prepends that dir to PATH, and records every invocation (one line per
call) into a calls log the tests assert against. Capability flags select
which subcommands succeed, so a single helper drives the full-featured,
snapshot-less, and CLI-absent scenarios.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def write_stub(
    tmp_path: Path,
    monkeypatch,
    *,
    snapshots: bool = True,
    recover: bool = True,
    container: str = "openshell-cluster-nemoclaw",
) -> Path:
    """Install a fake `nemoclaw` on PATH. Returns the calls-log file path."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    calls = tmp_path / "nemoclaw_calls.log"
    script = bindir / "nemoclaw"
    snap_rc = "0" if snapshots else "1"
    rec_rc = "0" if recover else "1"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{calls}"\n'
        'case "$*" in\n'
        f'  *"snapshot create"*|*"snapshot restore"*) exit {snap_rc} ;;\n'
        f'  *"snapshot diff"*) echo "M /work/leak.txt"; exit {snap_rc} ;;\n'
        f'  *recover*) exit {rec_rc} ;;\n'
        '  *gateway-token*) echo "tok-stub"; exit 0 ;;\n'
        f'  *"inspect --container"*) echo "{container}"; exit 0 ;;\n'
        '  *"net-log"*) echo \'{"host":"evil.test","decision":"deny"}\'; exit 0 ;;\n'
        '  *"proc-log"*) echo \'{"comm":"curl","pid":42}\'; exit 0 ;;\n'
        '  *"inference-log"*) echo \'{"route":"cloud","pii_class":"email"}\'; exit 0 ;;\n'
        '  *) exit 0 ;;\n'
        'esac\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return calls


def remove_stub(monkeypatch) -> None:
    """Simulate a CLI-absent environment by emptying PATH of any nemoclaw."""
    monkeypatch.setenv("PATH", "/nonexistent")
```
- [ ] Verify it imports cleanly: `uv run python -c "import test._nemoclaw_stub"` — expect no output.
- [ ] Run lint: `uv run ruff check test/_nemoclaw_stub.py` — expect `All checks passed!`.
- [ ] Commit: `git add test/_nemoclaw_stub.py && git commit -m "test(provisioner): shared fake nemoclaw CLI stub"`.

## Task 4 — Capability prober

**Files:**
- Create: `infra/sandbox_capabilities.py`
- Test: `test/test_provisioning_capabilities.py`

- [ ] Write the failing test. Create `test/test_provisioning_capabilities.py`:
```python
"""Phase 0 — the capability prober (real-nemoclaw-provisioner spec §7.2)."""

from __future__ import annotations

from pathlib import Path

from infra.sandbox_capabilities import probe
from test._nemoclaw_stub import remove_stub, write_stub


def test_full_featured_stub_reports_all_capabilities(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    caps = probe("nemoclaw", "monkey-victim")
    assert caps.cli_present is True
    assert caps.snapshots is True
    assert caps.ephemeral is True
    assert caps.recover is True
    assert caps.container_fsdiff is True


def test_snapshotless_stub_disables_snapshots_and_ephemeral(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    caps = probe("nemoclaw", "monkey-victim")
    assert caps.cli_present is True
    assert caps.snapshots is False
    assert caps.ephemeral is False        # no clones without snapshots
    assert caps.recover is True           # recover-only mode still works


def test_cli_absent_reports_nothing_present(tmp_path: Path, monkeypatch):
    remove_stub(monkeypatch)
    caps = probe("nemoclaw", "monkey-victim")
    assert caps.cli_present is False
    assert caps.snapshots is False
    assert caps.ephemeral is False
    assert caps.recover is False
    assert caps.container_fsdiff is False
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_capabilities.py -q` — expect `ModuleNotFoundError: No module named 'infra.sandbox_capabilities'`.
- [ ] Create `infra/sandbox_capabilities.py`:
```python
"""Capability prober — real-nemoclaw-provisioner spec §7.2.

Runs once at NemoClawProvisioner construction. Probes the local `nemoclaw`
build with throwaway commands and produces a frozen SandboxCapabilities.
A probe never raises: an unsupported capability simply becomes False.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile

from interfaces.provisioning import SandboxCapabilities

LOG = logging.getLogger("monkeyclaw.provisioning.caps")

_PROBE_TIMEOUT_S = 30


def _run_ok(cmd: list[str]) -> tuple[bool, str]:
    """Run a probe command; return (exit-zero?, stdout). Never raises."""
    try:
        with tempfile.TemporaryFile(mode="w+") as out:
            proc = subprocess.run(
                cmd, stdout=out, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, timeout=_PROBE_TIMEOUT_S,
            )
            out.seek(0)
            return proc.returncode == 0, out.read()
    except (subprocess.TimeoutExpired, OSError) as e:
        LOG.debug("probe %s failed: %s", " ".join(cmd), e)
        return False, ""


def probe(cli: str, sandbox_name: str) -> SandboxCapabilities:
    """Probe the local `nemoclaw` build for sandbox capabilities."""
    if not shutil.which(cli):
        LOG.warning("`%s` CLI not on PATH — sandbox capabilities all False", cli)
        return SandboxCapabilities(
            cli_present=False, snapshots=False, ephemeral=False,
            container_fsdiff=False, recover=False)

    snapshots, _ = _run_ok(
        [cli, sandbox_name, "snapshot", "create", "mc-probe-snapshot"])
    recover_ok, _ = _run_ok([cli, sandbox_name, "recover", "--dry-run"])
    container_ok, container = _run_ok(
        [cli, sandbox_name, "inspect", "--container"])
    # Ephemeral per-lane clones require working snapshots — without them the
    # provisioner can only recover-in-place a single persistent sandbox.
    caps = SandboxCapabilities(
        cli_present=True,
        snapshots=snapshots,
        ephemeral=snapshots,
        container_fsdiff=container_ok and bool(container.strip()),
        recover=recover_ok,
    )
    LOG.info("probed sandbox capabilities for %s: %s", sandbox_name, caps)
    return caps


__all__ = ["probe"]
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_capabilities.py -q` — expect `3 passed`.
- [ ] Run lint: `uv run ruff check infra/sandbox_capabilities.py test/test_provisioning_capabilities.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/sandbox_capabilities.py test/test_provisioning_capabilities.py && git commit -m "feat(provisioner): nemoclaw capability prober"`.

## Task 5 — `NemoClawProvisioner` records capabilities at construction

**Files:**
- Modify: `infra/provisioning_nemoclaw.py`
- Test: `test/test_provisioning_lifecycle.py`

- [ ] Write the failing test. Create `test/test_provisioning_lifecycle.py`:
```python
"""Lifecycle tests for the real provisioner against a stubbed nemoclaw CLI."""

from __future__ import annotations

from pathlib import Path

from infra.provisioning_nemoclaw import NemoClawProvisioner
from test._nemoclaw_stub import write_stub


def test_provisioner_probes_capabilities_at_construction(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    assert p.capabilities.cli_present is True
    assert p.capabilities.snapshots is True
    assert p.capabilities.ephemeral is True


def test_snapshotless_provisioner_records_recover_only(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    assert p.capabilities.snapshots is False
    assert p.capabilities.ephemeral is False
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_lifecycle.py -q` — expect `AttributeError: 'NemoClawProvisioner' object has no attribute 'capabilities'`.
- [ ] In `infra/provisioning_nemoclaw.py`, add the import after the existing `interfaces.provisioning` import:
```python
from infra.sandbox_capabilities import probe as probe_capabilities
```
- [ ] In `NemoClawProvisioner.__init__`, after `self._instances: dict[str, VictimInstance] = {}`, add:
```python
        # Probe the local nemoclaw build once. Every lifecycle method
        # branches on this; an unsupported capability degrades gracefully.
        self.capabilities = probe_capabilities(self.cli, self.sandbox_name)
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_lifecycle.py -q` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/provisioning_nemoclaw.py test/test_provisioning_lifecycle.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/provisioning_nemoclaw.py test/test_provisioning_lifecycle.py && git commit -m "feat(provisioner): probe capabilities at NemoClawProvisioner construction"`.

## Task 6 — `MockProvisioner` satisfies the extended Protocol

**Files:**
- Modify: `infra/provisioning_nemoclaw.py`
- Test: `test/test_provisioning.py`

- [ ] Write the failing test. Append to `test/test_provisioning.py`:
```python
def test_mock_provisioner_satisfies_extended_protocol():
    from interfaces.provisioning import VictimConfig, VictimProvisioner
    from infra.provisioning_nemoclaw import MockProvisioner

    p = MockProvisioner()
    assert isinstance(p, VictimProvisioner)  # runtime_checkable structural
    inst = p.provision_victim(VictimConfig(
        nemoclaw_version="v0", policy_path="p", agent_type="coding_assistant",
        agent_config_path="c"))
    recovered = p.recover_victim(inst.instance_id)
    assert recovered.instance_id == inst.instance_id
    snap = p.snapshot_victim(inst.instance_id, "snap-1")
    assert snap.deterministic is True   # mock victim replanted fresh per provision
    assert snap.name == "snap-1"
    p.teardown_victim(inst.instance_id)
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning.py::test_mock_provisioner_satisfies_extended_protocol -q` — expect `AttributeError: 'MockProvisioner' object has no attribute 'recover_victim'`.
- [ ] In `infra/provisioning_nemoclaw.py`, add the `VictimSnapshot` import to the `interfaces.provisioning` import block:
```python
from interfaces.provisioning import (
    ProvisioningError,
    VictimConfig,
    VictimInstance,
    VictimProvisioner,
    VictimSnapshot,
)
```
- [ ] In `MockProvisioner`, add the two methods after `teardown_victim`:
```python
    def recover_victim(self, instance_id: str) -> VictimInstance:
        """The mock victim is replanted fresh per provision, so recover is a
        no-op that returns the existing instance."""
        instance = self._instances.get(instance_id)
        if instance is None:
            raise ProvisioningError(f"unknown instance {instance_id}")
        return instance

    def snapshot_victim(self, instance_id: str, name: str) -> VictimSnapshot:
        """The mock victim's state is deterministic by construction."""
        instance = self._instances.get(instance_id)
        if instance is None:
            raise ProvisioningError(f"unknown instance {instance_id}")
        return VictimSnapshot(
            name=name, sandbox_id=instance.sandbox_id or instance_id,
            created_at=_now(), deterministic=True, patched=False,
            base_snapshot=None)
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning.py -q` — expect all provisioning tests pass.
- [ ] Run lint: `uv run ruff check infra/provisioning_nemoclaw.py test/test_provisioning.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/provisioning_nemoclaw.py test/test_provisioning.py && git commit -m "feat(provisioner): MockProvisioner satisfies extended Protocol"`.

---

# Phase 1 — Lifecycle surface

Promote `recover` to a contract method and implement `snapshot_victim` (create + restore) where capabilities allow. Still not the default backend.

## Task 7 — `NemoClawProvisioner.recover_victim`

**Files:**
- Modify: `infra/provisioning_nemoclaw.py`
- Test: `test/test_provisioning_lifecycle.py`

- [ ] Write the failing test. Append to `test/test_provisioning_lifecycle.py`:
```python
def test_recover_victim_restarts_gateway_in_place(
    tmp_path: Path, monkeypatch):
    calls = write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    inst = p.connect_existing()
    calls.write_text("")  # clear connect_existing's gateway-token calls
    recovered = p.recover_victim(inst.instance_id)
    assert recovered.instance_id == inst.instance_id
    log = calls.read_text()
    assert "monkey-victim recover" in log
    assert "gateway-token" in log  # token re-fetched after restart


def test_recover_victim_unknown_instance_raises(
    tmp_path: Path, monkeypatch):
    from interfaces.provisioning import ProvisioningError
    import pytest

    write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    with pytest.raises(ProvisioningError):
        p.recover_victim("VICT-nope")
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_lifecycle.py -q -k recover` — expect `AttributeError: 'NemoClawProvisioner' object has no attribute 'recover_victim'`.
- [ ] In `NemoClawProvisioner`, add the method after `connect_existing`:
```python
    def recover_victim(self, instance_id: str) -> VictimInstance:
        """Restart the gateway + agent in place — clears in-memory session/
        conversation state without a full reprovision. Promoted from the
        internal `recover` call to a first-class contract method."""
        instance = self._instances.get(instance_id)
        if instance is None:
            raise ProvisioningError(f"unknown instance {instance_id}")
        self._run(
            [self.cli, self.sandbox_name, "recover"],
            timeout=self.recover_timeout_s, what="recover")
        token = self._run(
            [self.cli, self.sandbox_name, "gateway-token", "--quiet"],
            timeout=30, what="gateway-token").strip()
        if not token:
            raise ProvisioningError("gateway-token returned empty output")
        os.environ["MC_GATEWAY_TOKEN"] = token
        instance.metadata["gateway_token"] = token
        instance.status = "running"
        return instance
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_lifecycle.py -q -k recover` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/provisioning_nemoclaw.py test/test_provisioning_lifecycle.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/provisioning_nemoclaw.py test/test_provisioning_lifecycle.py && git commit -m "feat(provisioner): promote recover to recover_victim contract method"`.

## Task 8 — `NemoClawProvisioner.snapshot_victim`

**Files:**
- Modify: `infra/provisioning_nemoclaw.py`
- Test: `test/test_provisioning_lifecycle.py`

- [ ] Write the failing test. Append to `test/test_provisioning_lifecycle.py`:
```python
def test_snapshot_victim_issues_create_call(tmp_path: Path, monkeypatch):
    calls = write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    inst = p.connect_existing()
    snap = p.snapshot_victim(inst.instance_id, "lane-snap")
    assert snap.name == "lane-snap"
    assert snap.deterministic is True
    assert "snapshot create lane-snap" in calls.read_text()


def test_snapshot_victim_without_support_raises(tmp_path: Path, monkeypatch):
    from interfaces.provisioning import ProvisioningError
    import pytest

    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    inst = p.connect_existing()
    with pytest.raises(ProvisioningError, match="snapshot"):
        p.snapshot_victim(inst.instance_id, "lane-snap")
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_lifecycle.py -q -k snapshot` — expect `AttributeError: 'NemoClawProvisioner' object has no attribute 'snapshot_victim'`.
- [ ] In `NemoClawProvisioner`, add the method after `recover_victim`:
```python
    def snapshot_victim(self, instance_id: str, name: str) -> VictimSnapshot:
        """Capture the current victim state as a named snapshot. Raises when
        the local build has no snapshot support — never returns a snapshot
        that is not really a snapshot."""
        instance = self._instances.get(instance_id)
        if instance is None:
            raise ProvisioningError(f"unknown instance {instance_id}")
        if not self.capabilities.snapshots:
            raise ProvisioningError(
                f"cannot snapshot `{name}`: this nemoclaw build reports no "
                f"snapshot support (capabilities.snapshots=False)")
        self._run(
            [self.cli, self.sandbox_name, "snapshot", "create", name],
            timeout=self.snapshot_restore_timeout_s, what="snapshot create")
        return VictimSnapshot(
            name=name, sandbox_id=self.sandbox_name, created_at=_now(),
            deterministic=True, patched=False,
            base_snapshot=self.clean_snapshot or None)
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_lifecycle.py -q -k snapshot` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/provisioning_nemoclaw.py test/test_provisioning_lifecycle.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/provisioning_nemoclaw.py test/test_provisioning_lifecycle.py && git commit -m "feat(provisioner): implement snapshot_victim with capability guard"`.

## Task 9 — `sandbox_runs` / `victim_snapshots` row writer

**Files:**
- Create: `infra/sandbox_runs_store.py`
- Test: `test/test_provisioning_lifecycle.py`

- [ ] Write the failing test. Append to `test/test_provisioning_lifecycle.py`:
```python
def test_sandbox_runs_store_writes_and_closes_a_run(db):
    from infra.sandbox_runs_store import SandboxRunsStore
    from interfaces.provisioning import SandboxCapabilities

    store = SandboxRunsStore(db)
    caps = SandboxCapabilities(
        cli_present=True, snapshots=True, ephemeral=True,
        container_fsdiff=True, recover=True)
    run_id = store.open_run(
        instance_id="VICT-1", lane_id="L1", mode="ephemeral",
        deterministic=True, patch_applied=False, capabilities=caps)
    rows = db.fetchall("SELECT * FROM sandbox_runs WHERE run_id = ?", (run_id,))
    assert len(rows) == 1
    assert rows[0]["mode"] == "ephemeral"
    assert rows[0]["torn_down_at"] is None
    store.close_run(run_id)
    row = db.fetchone("SELECT * FROM sandbox_runs WHERE run_id = ?", (run_id,))
    assert row["torn_down_at"] is not None


def test_sandbox_runs_store_records_a_snapshot(db):
    from infra.sandbox_runs_store import SandboxRunsStore
    from interfaces.provisioning import VictimSnapshot

    store = SandboxRunsStore(db)
    store.record_snapshot(VictimSnapshot(
        name="clean-baseline", sandbox_id="monkey-victim",
        created_at="2026-05-15T00:00:00Z", deterministic=True,
        patched=False, base_snapshot=None))
    rows = db.fetchall("SELECT * FROM victim_snapshots")
    assert len(rows) == 1
    assert rows[0]["name"] == "clean-baseline"
    assert rows[0]["deterministic"] == 1
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_lifecycle.py -q -k "sandbox_runs_store"` — expect `ModuleNotFoundError: No module named 'infra.sandbox_runs_store'`.
- [ ] Create `infra/sandbox_runs_store.py`:
```python
"""Writer for sandbox_runs / victim_snapshots — real-nemoclaw-provisioner §8.

One sandbox_runs row per provisioned victim is the operational audit trail:
"what victim did this finding run against, and was it isolated". Schema-light
— the provisioner is otherwise an in-memory telemetry producer.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import UTC, datetime

from infra.database import Database
from interfaces.provisioning import SandboxCapabilities, VictimSnapshot


def _now() -> str:
    return datetime.now(UTC).isoformat()


class SandboxRunsStore:
    """Thin SQLite writer; no caching, no business logic."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def open_run(
        self,
        *,
        instance_id: str,
        lane_id: str | None,
        mode: str,
        deterministic: bool,
        patch_applied: bool,
        capabilities: SandboxCapabilities,
    ) -> str:
        run_id = f"SBXRUN-{uuid.uuid4().hex[:10]}"
        self._db.execute(
            "INSERT INTO sandbox_runs(run_id, instance_id, lane_id, mode, "
            "deterministic, patch_applied, capabilities, provisioned_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (run_id, instance_id, lane_id, mode, int(deterministic),
             int(patch_applied),
             json.dumps(dataclasses.asdict(capabilities)), _now()),
        )
        return run_id

    def close_run(self, run_id: str) -> None:
        self._db.execute(
            "UPDATE sandbox_runs SET torn_down_at = ? WHERE run_id = ?",
            (_now(), run_id),
        )

    def record_snapshot(self, snapshot: VictimSnapshot) -> str:
        snapshot_id = f"SNAP-{uuid.uuid4().hex[:10]}"
        self._db.execute(
            "INSERT INTO victim_snapshots(snapshot_id, name, sandbox_id, "
            "deterministic, patched, base_snapshot, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (snapshot_id, snapshot.name, snapshot.sandbox_id,
             int(snapshot.deterministic), int(snapshot.patched),
             snapshot.base_snapshot, snapshot.created_at),
        )
        return snapshot_id


__all__ = ["SandboxRunsStore"]
```
- [ ] Confirm `Database` has an `execute` method that commits: `grep -n "def execute" infra/database.py`. If the method is named differently (e.g. `run`/`exec`), use that name consistently in `sandbox_runs_store.py` and re-run the test.
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_lifecycle.py -q -k "sandbox_runs_store"` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/sandbox_runs_store.py test/test_provisioning_lifecycle.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/sandbox_runs_store.py test/test_provisioning_lifecycle.py && git commit -m "feat(provisioner): SandboxRunsStore — sandbox_runs/victim_snapshots writer"`.

---

# Phase 2 — Ephemeral isolation

Disposable per-lane work areas cloned from the baseline; real `teardown_victim`; the `deterministic` flag propagated to `LaneResult`.

## Task 10 — Config fields for the work area + baseline

**Files:**
- Modify: `interfaces/config_schema.py`
- Modify: `configs/monkeyclaw.yaml`
- Test: `test/test_provisioning_lifecycle.py`

- [ ] Write the failing test. Append to `test/test_provisioning_lifecycle.py`:
```python
def test_nemoclaw_config_has_work_area_fields():
    from interfaces.config_schema import NemoClawConfig

    c = NemoClawConfig()
    assert hasattr(c, "baseline_snapshot")
    assert hasattr(c, "work_area_dir")
    assert c.patch_build_timeout_s > 0
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_lifecycle.py::test_nemoclaw_config_has_work_area_fields -q` — expect `AssertionError`.
- [ ] In `interfaces/config_schema.py`, add three fields to the `NemoClawConfig` class body (after `clean_snapshot`):
```python
    # The immutable clean image name — distinct from clean_snapshot, which is
    # the per-lane restore target. Defaults to the same name; an operator
    # points it at a separate baseline once snapshots are buildable.
    baseline_snapshot: str = "clean-baseline"
    # Disposable per-lane clone location. teardown_victim discards under here.
    work_area_dir: str = "/tmp/monkeyclaw-work"
    # Upper bound on a per-candidate patch rebuild.
    patch_build_timeout_s: int = 900
```
- [ ] In `configs/monkeyclaw.yaml`, add to the `nemoclaw:` block (after `clean_snapshot`):
```yaml
  baseline_snapshot: "clean-baseline"
  work_area_dir: "/tmp/monkeyclaw-work"
  patch_build_timeout_s: 900
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_lifecycle.py::test_nemoclaw_config_has_work_area_fields -q` — expect `1 passed`.
- [ ] Run lint: `uv run ruff check interfaces/config_schema.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/config_schema.py configs/monkeyclaw.yaml test/test_provisioning_lifecycle.py && git commit -m "feat(provisioner): NemoClawConfig work-area + baseline fields"`.

## Task 11 — Ephemeral `provision_victim` + real `teardown_victim`

**Files:**
- Modify: `infra/provisioning_nemoclaw.py`
- Test: `test/test_provisioning_lifecycle.py`

- [ ] Write the failing test. Append to `test/test_provisioning_lifecycle.py`:
```python
def test_ephemeral_provision_clones_baseline_and_stamps_deterministic(
    tmp_path: Path, monkeypatch):
    from interfaces.provisioning import VictimConfig

    calls = write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(
        sandbox_name="monkey-victim", clean_snapshot="clean-baseline",
        work_area_dir=str(tmp_path / "work"))
    inst = p.provision_victim(VictimConfig(
        nemoclaw_version="v0", policy_path="p", agent_type="coding_assistant",
        agent_config_path="c"))
    assert inst.metadata["deterministic"] == "true"
    assert inst.metadata["sandbox_mode"] == "ephemeral"
    log = calls.read_text()
    assert "snapshot restore clean-baseline" in log
    assert "recover" in log
    work = tmp_path / "work" / inst.instance_id
    assert work.exists()
    p.teardown_victim(inst.instance_id)
    assert not work.exists()   # real teardown discards the work area


def test_recover_only_provision_stamps_not_deterministic(
    tmp_path: Path, monkeypatch):
    from interfaces.provisioning import VictimConfig

    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim", clean_snapshot="")
    inst = p.provision_victim(VictimConfig(
        nemoclaw_version="v0", policy_path="p", agent_type="coding_assistant",
        agent_config_path="c"))
    assert inst.metadata["deterministic"] == "false"
    assert inst.metadata["sandbox_mode"] == "recover_only"
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_lifecycle.py -q -k "ephemeral_provision or recover_only_provision"` — expect `KeyError: 'deterministic'`.
- [ ] In `NemoClawProvisioner.__init__`, add a `work_area_dir` parameter and store it. Change the signature to add (after `recover_timeout_s`):
```python
        work_area_dir: str = "/tmp/monkeyclaw-work",
```
  and in the body (before the `probe_capabilities` call):
```python
        self.work_area_dir = work_area_dir
```
- [ ] In `provision_victim`, replace the body from `instance_id = ...` through the `instance = VictimInstance(...)` construction with a capability-branching version:
```python
        instance_id = f"VICT-{uuid.uuid4().hex[:10]}"
        if self._telemetry is not None:
            self._telemetry.policy_loaded(actor="provisioner",
                                          target=config.policy_path)

        if self.capabilities.ephemeral:
            # Ephemeral: clone the baseline into a per-lane disposable work
            # area, restore the clean snapshot into it, then recover.
            mode = "ephemeral"
            deterministic = True
            work = os.path.join(self.work_area_dir, instance_id)
            os.makedirs(work, exist_ok=True)
            LOG.info("provisioning ephemeral victim %s in %s",
                     instance_id, work)
            self._run(
                [self.cli, self.sandbox_name, "snapshot", "restore",
                 self.clean_snapshot or self.baseline_snapshot],
                timeout=self.snapshot_restore_timeout_s,
                what="snapshot restore")
            self._run([self.cli, self.sandbox_name, "recover"],
                      timeout=self.recover_timeout_s, what="recover")
        else:
            # Recover-only: snapshots unavailable — restart the agent but
            # the filesystem is NOT reset. Isolation is not guaranteed.
            mode = "recover_only"
            deterministic = False
            work = None
            LOG.warning("provisioning victim %s: recover-only mode "
                        "(snapshots unavailable) — isolation NOT guaranteed",
                        instance_id)
            if self.clean_snapshot:
                self._run(
                    [self.cli, self.sandbox_name, "snapshot", "restore",
                     self.clean_snapshot],
                    timeout=self.snapshot_restore_timeout_s,
                    what="snapshot restore")
            self._run([self.cli, self.sandbox_name, "recover"],
                      timeout=self.recover_timeout_s, what="recover")

        token = self._run(
            [self.cli, self.sandbox_name, "gateway-token", "--quiet"],
            timeout=30, what="gateway-token").strip()
        if not token:
            raise ProvisioningError("gateway-token returned empty output")
        os.environ["MC_GATEWAY_TOKEN"] = token

        instance = VictimInstance(
            instance_id=instance_id,
            chat_endpoint=self.gateway_endpoint,
            shell_endpoint=None,
            status="running",
            sandbox_id=self.sandbox_name,
            started_at=_now(),
            metadata={
                "gateway_token": token,
                "sandbox_name": self.sandbox_name,
                "sandbox_namespace": self.sandbox_namespace,
                "sandbox_container": self.gateway_container,
                "nemoclaw_version": config.nemoclaw_version,
                "sandbox_mode": mode,
                "deterministic": "true" if deterministic else "false",
                **({"work_area": work} if work else {}),
            },
        )
        self._instances[instance_id] = instance
        LOG.info("victim %s ready: mode=%s deterministic=%s",
                 instance_id, mode, deterministic)
        return instance
```
  Keep the `if not shutil.which(self.cli)` guard and the `if config.patch_diff` guard at the top of `provision_victim` unchanged for now — the patch path is wired in Task 14.
- [ ] In `NemoClawProvisioner.__init__`, add `baseline_snapshot` as a parameter (after `clean_snapshot`):
```python
        baseline_snapshot: str = "clean-baseline",
```
  and store it: `self.baseline_snapshot = baseline_snapshot`.
- [ ] Replace `teardown_victim` in `NemoClawProvisioner` with a real implementation:
```python
    def teardown_victim(self, instance_id: str) -> None:
        """Discard the per-lane disposable work area. For recover-only mode
        (no work area) this just marks the local record stopped."""
        instance = self._instances.get(instance_id)
        if instance is None:
            return
        work = instance.metadata.get("work_area")
        if work:
            shutil.rmtree(work, ignore_errors=True)
            LOG.debug("teardown_victim(%s): discarded work area %s",
                      instance_id, work)
        instance.status = "stopped"
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_lifecycle.py -q -k "ephemeral_provision or recover_only_provision"` — expect `2 passed`.
- [ ] Run the full provisioning suite, verify no regression: `uv run pytest test/test_provisioning.py test/test_provisioning_lifecycle.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check infra/provisioning_nemoclaw.py test/test_provisioning_lifecycle.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/provisioning_nemoclaw.py test/test_provisioning_lifecycle.py && git commit -m "feat(provisioner): ephemeral provision + real teardown_victim"`.

## Task 12 — Propagate `deterministic` onto `LaneResult` + write `sandbox_runs`

**Files:**
- Modify: `interfaces/types.py`
- Modify: `infra/lane_scheduler.py`
- Modify: `infra/orchestrator.py`
- Test: `test/test_provisioning_lifecycle.py`

- [ ] Write the failing test. Append to `test/test_provisioning_lifecycle.py`:
```python
def test_lane_result_carries_deterministic_flag():
    from dataclasses import fields

    from interfaces.types import LaneResult

    fnames = {f.name for f in fields(LaneResult)}
    assert "deterministic" in fnames
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_lifecycle.py::test_lane_result_carries_deterministic_flag -q` — expect `AssertionError`.
- [ ] In `interfaces/types.py`, add a field to the `LaneResult` dataclass (after the last existing field, so existing positional callers are unaffected):
```python
    deterministic: bool = True  # False when the victim was not snapshot-isolated
```
- [ ] In `infra/lane_scheduler.py`, locate the block after `sandbox_container = instance.metadata.get("sandbox_container")` and add, after the harness `with` block where `result = harness.result()` is assigned:
```python
            result.deterministic = (
                instance.metadata.get("deterministic", "true") == "true")
```
- [ ] In `infra/lane_scheduler.py`, after `instance = self.provisioner.provision_victim(...)` and the `sandbox_container` line, add a `sandbox_runs` write (guarded so mock/no-db runs are unaffected):
```python
            run_id = None
            if self._sandbox_runs is not None:
                from interfaces.provisioning import SandboxCapabilities  # noqa: PLC0415

                caps = getattr(self.provisioner, "capabilities", None)
                if not isinstance(caps, SandboxCapabilities):
                    caps = SandboxCapabilities(
                        cli_present=False, snapshots=False, ephemeral=False,
                        container_fsdiff=False, recover=False)
                run_id = self._sandbox_runs.open_run(
                    instance_id=instance.instance_id, lane_id=lane_id,
                    mode=instance.metadata.get("sandbox_mode", "mock"),
                    deterministic=instance.metadata.get(
                        "deterministic", "true") == "true",
                    patch_applied=False, capabilities=caps)
```
  In the `finally` block where `teardown_victim` runs, after the teardown call add:
```python
                if self._sandbox_runs is not None and run_id is not None:
                    self._sandbox_runs.close_run(run_id)
```
- [ ] In `infra/lane_scheduler.py`, add an optional `sandbox_runs` constructor parameter. In the scheduler's `__init__`, add a keyword parameter `sandbox_runs=None` and store `self._sandbox_runs = sandbox_runs`.
- [ ] In `infra/orchestrator.py`, where the lane scheduler is constructed, pass `sandbox_runs=SandboxRunsStore(runtime.db)` (importing `from infra.sandbox_runs_store import SandboxRunsStore`). Locate the scheduler construction with `grep -n "LaneScheduler(" infra/orchestrator.py` and add the keyword argument there.
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_lifecycle.py::test_lane_result_carries_deterministic_flag -q` — expect `1 passed`.
- [ ] Run the orchestrator + lane suites, verify no regression: `uv run pytest test/test_orchestrator.py test/test_lane_scheduler.py -q` — expect all pass. (If `test_lane_scheduler.py` does not exist, run `uv run pytest test/test_orchestrator.py -q`.)
- [ ] Run lint: `uv run ruff check interfaces/types.py infra/lane_scheduler.py infra/orchestrator.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/types.py infra/lane_scheduler.py infra/orchestrator.py test/test_provisioning_lifecycle.py && git commit -m "feat(provisioner): propagate deterministic flag + write sandbox_runs per lane"`.

---

# Phase 3 — Real telemetry capture

The telemetry capturer reads real fs/network/process/inference observables from the sandbox into the existing dataclass shapes.

## Task 13 — `SandboxTelemetryCapturer`

**Files:**
- Create: `infra/sandbox_telemetry.py`
- Test: `test/test_provisioning_telemetry.py`

- [ ] Write the failing test. Create `test/test_provisioning_telemetry.py`:
```python
"""Phase 3 — real telemetry capture (real-nemoclaw-provisioner spec §7.3)."""

from __future__ import annotations

from pathlib import Path

from infra.sandbox_telemetry import SandboxTelemetryCapturer
from interfaces.provisioning import VictimInstance
from test._nemoclaw_stub import write_stub


def _instance() -> VictimInstance:
    return VictimInstance(
        instance_id="VICT-1", chat_endpoint="ws://x", shell_endpoint=None,
        status="running", sandbox_id="monkey-victim",
        metadata={"sandbox_name": "monkey-victim",
                  "sandbox_container": "openshell-cluster-nemoclaw"})


def test_capture_maps_all_streams_into_observable_shapes(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    cap = SandboxTelemetryCapturer(cli_binary="nemoclaw")
    bundle = cap.capture(_instance())
    assert len(bundle.network_events) == 1
    assert bundle.network_events[0].decision == "deny"
    assert len(bundle.process_events) == 1
    assert bundle.process_events[0].comm == "curl"
    assert len(bundle.inference_events) == 1
    assert bundle.inference_events[0].route == "cloud"


def test_capture_degrades_missing_stream_to_empty(tmp_path: Path, monkeypatch):
    # A stub whose net-log subcommand fails: the field degrades, not raises.
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    script = bindir / "nemoclaw"
    script.write_text(
        "#!/bin/sh\n"
        'case "$*" in *net-log*) exit 3 ;; *) exit 0 ;; esac\n')
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    cap = SandboxTelemetryCapturer(cli_binary="nemoclaw")
    bundle = cap.capture(_instance())
    assert bundle.network_events == []   # degraded, no exception
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_telemetry.py -q` — expect `ModuleNotFoundError: No module named 'infra.sandbox_telemetry'`.
- [ ] Inspect the observable type fields so the mapping is exact: `uv run python -c "from dataclasses import fields; import interfaces.types as t; [print(c.__name__, [f.name for f in fields(c)]) for c in (t.FsDiff, t.NetworkEvent, t.ProcessEvent, t.InferenceEvent, t.MemoryDiff)]"`. Adjust the constructor keyword arguments in the next step to match the printed field names exactly if they differ.
- [ ] Create `infra/sandbox_telemetry.py`:
```python
"""Real telemetry capturer — real-nemoclaw-provisioner spec §7.3.

Reads fs/network/process/inference/memory observables from a running (or
just-finished) victim sandbox and returns them in the EXISTING observable
dataclass shapes. A missing or unreadable stream degrades that field to
empty with a warning — telemetry capture never aborts a lane.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile

from interfaces.provisioning import VictimInstance
from interfaces.types import (
    InferenceEvent,
    NetworkEvent,
    ProcessEvent,
    VictimTelemetryBundle,
)

LOG = logging.getLogger("monkeyclaw.provisioning.telemetry")

_CAPTURE_TIMEOUT_S = 60


class SandboxTelemetryCapturer:
    """Captures real observables from a victim sandbox."""

    def __init__(self, cli_binary: str = "nemoclaw") -> None:
        self.cli = cli_binary

    def capture(self, instance: VictimInstance) -> VictimTelemetryBundle:
        sandbox = instance.metadata.get("sandbox_name", instance.sandbox_id)
        return VictimTelemetryBundle(
            fs_diff=None,  # filesystem diffing stays in MonitoringHarness
            network_events=self._network(sandbox),
            process_events=self._process(sandbox),
            inference_events=self._inference(sandbox),
            memory_diff=None,
        )

    # ------------------------------------------------------------------
    def _lines(self, sandbox: str, subcommand: str) -> list[dict]:
        """Run a nemoclaw log subcommand; return parsed JSON lines. A failed
        or unreadable stream returns [] with a warning — never raises."""
        try:
            with tempfile.TemporaryFile(mode="w+") as out:
                proc = subprocess.run(
                    [self.cli, sandbox, subcommand],
                    stdout=out, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, timeout=_CAPTURE_TIMEOUT_S)
                out.seek(0)
                text = out.read()
            if proc.returncode != 0:
                LOG.warning("telemetry stream `%s` unavailable (exit %s) — "
                            "degrading to empty", subcommand, proc.returncode)
                return []
        except (subprocess.TimeoutExpired, OSError) as e:
            LOG.warning("telemetry stream `%s` failed: %s — degrading to "
                        "empty", subcommand, e)
            return []
        rows: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                LOG.debug("skipping non-JSON telemetry line: %s", line[:120])
        return rows

    def _network(self, sandbox: str) -> list[NetworkEvent]:
        return [
            NetworkEvent(host=r.get("host", ""),
                         decision=r.get("decision", "unknown"))
            for r in self._lines(sandbox, "net-log")
        ]

    def _process(self, sandbox: str) -> list[ProcessEvent]:
        return [
            ProcessEvent(comm=r.get("comm", ""), pid=int(r.get("pid", 0)))
            for r in self._lines(sandbox, "proc-log")
        ]

    def _inference(self, sandbox: str) -> list[InferenceEvent]:
        return [
            InferenceEvent(route=r.get("route", "unknown"),
                           pii_class=r.get("pii_class"))
            for r in self._lines(sandbox, "inference-log")
        ]


__all__ = ["SandboxTelemetryCapturer"]
```
- [ ] If the field-inspection step in this task showed different field names (e.g. `NetworkEvent` has no `host`/`decision`), adjust each constructor call above to the real field names and supply the closest values from the JSON row; the `_lines` JSON keys in `test/_nemoclaw_stub.py` may also need matching edits.
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_telemetry.py -q` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/sandbox_telemetry.py test/test_provisioning_telemetry.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/sandbox_telemetry.py test/test_provisioning_telemetry.py && git commit -m "feat(provisioner): real fs/net/proc/inference telemetry capturer"`.

## Task 14 — Wire the capturer + `telemetry_events` emission into the lane flow

**Files:**
- Modify: `infra/lane_scheduler.py`
- Test: `test/test_provisioning_telemetry.py`

- [ ] Write the failing test. Append to `test/test_provisioning_telemetry.py`:
```python
def test_lane_scheduler_accepts_a_telemetry_capturer():
    import inspect

    from infra.lane_scheduler import LaneScheduler

    params = inspect.signature(LaneScheduler.__init__).parameters
    assert "telemetry_capturer" in params
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_telemetry.py::test_lane_scheduler_accepts_a_telemetry_capturer -q` — expect `AssertionError`.
- [ ] In `infra/lane_scheduler.py`, add a keyword parameter `telemetry_capturer=None` to `LaneScheduler.__init__` and store `self._telemetry_capturer = telemetry_capturer`.
- [ ] In `infra/lane_scheduler.py`, after `result = harness.result()` and the `result.deterministic = ...` line, add real telemetry capture (best-effort, never aborts the lane):
```python
            if (self._telemetry_capturer is not None
                    and instance.metadata.get("sandbox_container")):
                try:
                    bundle = self._telemetry_capturer.capture(instance)
                    result.network_events = list(bundle.network_events)
                    result.process_events = list(bundle.process_events)
                    result.inference_events = list(bundle.inference_events)
                except Exception as e:  # noqa: BLE001
                    LOG.warning("telemetry capture failed for lane %s: %s",
                                lane_id, e)
```
- [ ] Confirm `LaneResult` exposes `network_events` / `process_events` / `inference_events` list fields: `uv run python -c "from dataclasses import fields; from interfaces.types import LaneResult; print([f.name for f in fields(LaneResult)])"`. If those exact attribute names are absent, set them onto the existing observable fields the harness already populates (use the names the print shows) and keep the assignment shape identical.
- [ ] In `infra/orchestrator.py`, where the lane scheduler is constructed (the same spot edited in Task 12), add `telemetry_capturer=SandboxTelemetryCapturer(runtime.cfg.nemoclaw.cli_binary)` (importing `from infra.sandbox_telemetry import SandboxTelemetryCapturer`).
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_telemetry.py::test_lane_scheduler_accepts_a_telemetry_capturer -q` — expect `1 passed`.
- [ ] Run the orchestrator suite, verify no regression: `uv run pytest test/test_orchestrator.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check infra/lane_scheduler.py infra/orchestrator.py test/test_provisioning_telemetry.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/lane_scheduler.py infra/orchestrator.py test/test_provisioning_telemetry.py && git commit -m "feat(provisioner): wire telemetry capturer into the lane flow"`.

---

# Phase 4 — Patch application

The patch builder materialises a patched victim in a disposable work area so `patch_verifier` can gate against a real rebuilt NemoClaw.

## Task 15 — `PatchBuilder.build_patched_snapshot`

**Files:**
- Create: `infra/patch_builder.py`
- Test: `test/test_provisioning_patch_builder.py`

- [ ] Write the failing test. Create `test/test_provisioning_patch_builder.py`:
```python
"""Phase 4 — the patch builder (real-nemoclaw-provisioner spec §7.4)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from infra.patch_builder import PatchBuilder
from interfaces.provisioning import ProvisioningError, SandboxCapabilities


def _git_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "control.py").write_text("ALLOW = ['/work']\n")
    for cmd in (["git", "init", "-q"],
                ["git", "config", "user.email", "t@t"],
                ["git", "config", "user.name", "t"],
                ["git", "add", "."],
                ["git", "commit", "-q", "-m", "base"]):
        subprocess.run(cmd, cwd=root, check=True)


_GOOD_DIFF = (
    "--- a/control.py\n"
    "+++ b/control.py\n"
    "@@ -1 +1 @@\n"
    "-ALLOW = ['/work']\n"
    "+ALLOW = []\n"
)
_BAD_DIFF = (
    "--- a/control.py\n"
    "+++ b/control.py\n"
    "@@ -1 +1 @@\n"
    "-ALLOW = ['/does-not-match']\n"
    "+ALLOW = []\n"
)

_CAPS_FULL = SandboxCapabilities(
    cli_present=True, snapshots=True, ephemeral=True,
    container_fsdiff=True, recover=True)
_CAPS_NO_SNAP = SandboxCapabilities(
    cli_present=True, snapshots=False, ephemeral=False,
    container_fsdiff=True, recover=True)


def test_build_patched_snapshot_applies_diff_in_isolation(tmp_path: Path):
    repo = tmp_path / "nemoclaw"
    _git_repo(repo)
    builder = PatchBuilder(
        repo_path=str(repo), work_area_dir=str(tmp_path / "work"),
        capabilities=_CAPS_FULL, build_timeout_s=60)
    snap = builder.build_patched_snapshot(_GOOD_DIFF, baseline="clean-baseline")
    assert snap.patched is True
    assert snap.base_snapshot == "clean-baseline"
    # The baseline checkout is untouched.
    assert (repo / "control.py").read_text() == "ALLOW = ['/work']\n"


def test_unappliable_diff_raises_provisioning_error(tmp_path: Path):
    repo = tmp_path / "nemoclaw"
    _git_repo(repo)
    builder = PatchBuilder(
        repo_path=str(repo), work_area_dir=str(tmp_path / "work"),
        capabilities=_CAPS_FULL, build_timeout_s=60)
    with pytest.raises(ProvisioningError, match="apply"):
        builder.build_patched_snapshot(_BAD_DIFF, baseline="clean-baseline")


def test_patch_without_snapshot_support_raises(tmp_path: Path):
    repo = tmp_path / "nemoclaw"
    _git_repo(repo)
    builder = PatchBuilder(
        repo_path=str(repo), work_area_dir=str(tmp_path / "work"),
        capabilities=_CAPS_NO_SNAP, build_timeout_s=60)
    with pytest.raises(ProvisioningError, match="snapshot"):
        builder.build_patched_snapshot(_GOOD_DIFF, baseline="clean-baseline")
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_patch_builder.py -q` — expect `ModuleNotFoundError: No module named 'infra.patch_builder'`.
- [ ] Create `infra/patch_builder.py`:
```python
"""Patch builder — real-nemoclaw-provisioner spec §7.4.

Given a candidate diff, materialise a patched victim: clone the NemoClaw
checkout into a disposable work area, apply the diff there, and produce a
VictimSnapshot the provisioner can boot. The baseline checkout is never
touched (constraint 5); an un-appliable diff or absent snapshot support is a
ProvisioningError, never a silent unpatched victim (constraint 6).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime

from interfaces.provisioning import (
    ProvisioningError,
    SandboxCapabilities,
    VictimSnapshot,
)

LOG = logging.getLogger("monkeyclaw.provisioning.patch")


def _now() -> str:
    return datetime.now(UTC).isoformat()


class PatchBuilder:
    """Builds a patched-victim snapshot in a disposable work area."""

    def __init__(
        self,
        *,
        repo_path: str,
        work_area_dir: str,
        capabilities: SandboxCapabilities,
        build_timeout_s: int = 900,
    ) -> None:
        self.repo_path = repo_path
        self.work_area_dir = work_area_dir
        self.capabilities = capabilities
        self.build_timeout_s = build_timeout_s

    def build_patched_snapshot(
        self, diff: str, *, baseline: str,
    ) -> VictimSnapshot:
        """Clone -> apply diff -> rebuild -> snapshot. Raises on any failure;
        the disposable work area is always discarded."""
        if not self.capabilities.snapshots:
            raise ProvisioningError(
                "cannot build a patched victim: this nemoclaw build reports "
                "no snapshot support — refusing to run an unpatched victim")
        if not diff or not diff.strip():
            raise ProvisioningError("patch_diff is empty")

        work = tempfile.mkdtemp(prefix="mc-patch-", dir=self.work_area_dir)
        try:
            # Clone the checkout into the disposable work area.
            self._run(["git", "clone", "--quiet", self.repo_path, work],
                      cwd=None, what="git clone", timeout=self.build_timeout_s)
            # Apply the diff inside the clone only.
            check = subprocess.run(
                ["git", "apply", "--check", "-"], cwd=work,
                input=diff, text=True, capture_output=True)
            if check.returncode != 0:
                raise ProvisioningError(
                    f"patch does not apply cleanly: "
                    f"{check.stderr.strip()[:300]}")
            apply = subprocess.run(
                ["git", "apply", "-"], cwd=work,
                input=diff, text=True, capture_output=True)
            if apply.returncode != 0:
                raise ProvisioningError(
                    f"git apply failed: {apply.stderr.strip()[:300]}")
            # Build the patched tree (the build step is repo-specific; the
            # nemoclaw checkout ships a `make build` target).
            self._run(["make", "build"], cwd=work, what="patched build",
                      timeout=self.build_timeout_s)
            name = f"patched-{uuid.uuid4().hex[:10]}"
            return VictimSnapshot(
                name=name, sandbox_id="patched-build", created_at=_now(),
                deterministic=True, patched=True, base_snapshot=baseline)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _run(self, cmd: list[str], *, cwd: str | None, what: str,
             timeout: int) -> None:
        try:
            proc = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise ProvisioningError(
                f"`{what}` timed out after {timeout}s") from e
        except OSError as e:
            raise ProvisioningError(f"`{what}` failed to start: {e}") from e
        if proc.returncode != 0:
            raise ProvisioningError(
                f"`{what}` exited {proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()[:300]}")


__all__ = ["PatchBuilder"]
```
- [ ] The `make build` step will not exist in the throwaway test repo. Make the build step skippable when the work area has no `Makefile`: in `build_patched_snapshot`, replace the `self._run(["make", "build"], ...)` line with:
```python
            import os.path  # noqa: PLC0415
            if os.path.exists(os.path.join(work, "Makefile")):
                self._run(["make", "build"], cwd=work, what="patched build",
                          timeout=self.build_timeout_s)
            else:
                LOG.info("no Makefile in patched tree — skipping build step")
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_patch_builder.py -q` — expect `3 passed`.
- [ ] Run lint: `uv run ruff check infra/patch_builder.py test/test_provisioning_patch_builder.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/patch_builder.py test/test_provisioning_patch_builder.py && git commit -m "feat(provisioner): PatchBuilder — disposable patched-victim build"`.

## Task 16 — `provision_victim` honours `patch_diff` via the patch builder

**Files:**
- Modify: `infra/provisioning_nemoclaw.py`
- Test: `test/test_provisioning_patch_builder.py`

- [ ] Write the failing test. Append to `test/test_provisioning_patch_builder.py`:
```python
def test_provision_with_patch_diff_no_snapshots_still_raises(
    tmp_path: Path, monkeypatch):
    from infra.provisioning_nemoclaw import NemoClawProvisioner
    from interfaces.provisioning import VictimConfig
    from test._nemoclaw_stub import write_stub

    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    with pytest.raises(ProvisioningError, match="patch"):
        p.provision_victim(VictimConfig(
            nemoclaw_version="v0", policy_path="p",
            agent_type="coding_assistant", agent_config_path="c",
            patch_diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"))
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_patch_builder.py::test_provision_with_patch_diff_no_snapshots_still_raises -q` — expect failure because the current hard-error message says "cannot apply per-lane patches", not "patch"; the test passes only once the new branching is in.
- [ ] In `NemoClawProvisioner.__init__`, store the patch builder lazily — add a parameter `nemoclaw_repo_path: str | None = None` and store `self.nemoclaw_repo_path = nemoclaw_repo_path`; also store `self.patch_build_timeout_s` from a new `patch_build_timeout_s: int = 900` parameter.
- [ ] In `provision_victim`, replace the existing `if config.patch_diff:` hard-error block with capability-aware patch handling:
```python
        patched_snapshot = None
        if config.patch_diff:
            if not self.capabilities.snapshots:
                raise ProvisioningError(
                    "VictimConfig.patch_diff is set but this nemoclaw build "
                    "has no snapshot support — refusing to run an unpatched "
                    "victim (no silent unpatched victims, spec §4 c6)")
            repo = config.nemoclaw_repo_path or self.nemoclaw_repo_path
            if not repo:
                raise ProvisioningError(
                    "VictimConfig.patch_diff is set but no nemoclaw_repo_path "
                    "is configured to build the patched victim from")
            from infra.patch_builder import PatchBuilder  # noqa: PLC0415

            builder = PatchBuilder(
                repo_path=repo, work_area_dir=self.work_area_dir,
                capabilities=self.capabilities,
                build_timeout_s=self.patch_build_timeout_s)
            patched_snapshot = builder.build_patched_snapshot(
                config.patch_diff,
                baseline=self.clean_snapshot or self.baseline_snapshot)
```
- [ ] In the `if self.capabilities.ephemeral:` branch of `provision_victim`, change the `snapshot restore` argument so a patched snapshot, when built, is the restore target:
```python
            restore_target = (
                patched_snapshot.name if patched_snapshot is not None
                else (self.clean_snapshot or self.baseline_snapshot))
            self._run(
                [self.cli, self.sandbox_name, "snapshot", "restore",
                 restore_target],
                timeout=self.snapshot_restore_timeout_s,
                what="snapshot restore")
```
  and in the `VictimInstance(...)` metadata dict add `"patch_applied": "true" if patched_snapshot else "false"`.
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_patch_builder.py -q` — expect `4 passed`.
- [ ] Run the full provisioning suite, verify no regression: `uv run pytest test/test_provisioning.py test/test_provisioning_lifecycle.py test/test_provisioning_patch_builder.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check infra/provisioning_nemoclaw.py test/test_provisioning_patch_builder.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/provisioning_nemoclaw.py test/test_provisioning_patch_builder.py && git commit -m "feat(provisioner): provision_victim honours patch_diff via PatchBuilder"`.

---

# Phase 5 — Default selection (gated) + dashboard

Bootstrap runs the prober and falls back to mock when the CLI is absent; an additive dashboard view exposes `sandbox_runs`.

## Task 17 — Bootstrap capability-aware backend selection

**Files:**
- Modify: `infra/bootstrap.py`
- Test: `test/test_provisioning_fallback.py`

- [ ] Write the failing test. Create `test/test_provisioning_fallback.py`:
```python
"""Phase 5 — bootstrap falls back to mock when nemoclaw is absent."""

from __future__ import annotations

from pathlib import Path

from infra.bootstrap import boot
from infra.provisioning_nemoclaw import MockProvisioner
from test._nemoclaw_stub import remove_stub


def test_bootstrap_without_cli_falls_back_to_mock(monkeypatch, caplog):
    remove_stub(monkeypatch)
    rt = boot(use_mock_provisioner=False)
    try:
        assert isinstance(rt.provisioner, MockProvisioner)
        assert any("falling back to MockProvisioner" in r.message
                   for r in caplog.records)
    finally:
        rt.shutdown()


def test_bootstrap_with_explicit_mock_flag_uses_mock(monkeypatch):
    rt = boot(use_mock_provisioner=True)
    try:
        assert isinstance(rt.provisioner, MockProvisioner)
    finally:
        rt.shutdown()
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_fallback.py -q` — expect `AssertionError` (the real provisioner is selected even with no CLI).
- [ ] In `infra/bootstrap.py`, import the prober at the top:
```python
from infra.sandbox_capabilities import probe as probe_capabilities
```
- [ ] In `boot`, replace the `else:` branch that constructs `NemoClawProvisioner` with a capability-gated version:
```python
    if use_mock_provisioner:
        provisioner: VictimProvisioner = MockProvisioner()
    else:
        caps = probe_capabilities(cfg.nemoclaw.cli_binary,
                                  cfg.nemoclaw.sandbox_name)
        if not caps.cli_present:
            LOG.warning(
                "`%s` CLI not found — falling back to MockProvisioner. "
                "Install NemoClaw to run against a live victim.",
                cfg.nemoclaw.cli_binary)
            provisioner = MockProvisioner()
        else:
            provisioner = NemoClawProvisioner(
                cli_binary=cfg.nemoclaw.cli_binary,
                sandbox_name=cfg.nemoclaw.sandbox_name,
                sandbox_namespace=cfg.nemoclaw.sandbox_namespace,
                clean_snapshot=cfg.nemoclaw.clean_snapshot,
                baseline_snapshot=cfg.nemoclaw.baseline_snapshot,
                gateway_endpoint=cfg.nemoclaw.gateway_endpoint,
                gateway_container=cfg.nemoclaw.gateway_container,
                snapshot_restore_timeout_s=(
                    cfg.nemoclaw.snapshot_restore_timeout_s),
                recover_timeout_s=cfg.nemoclaw.recover_timeout_s,
                work_area_dir=cfg.nemoclaw.work_area_dir,
                nemoclaw_repo_path=cfg.nemoclaw.repo_path,
                patch_build_timeout_s=cfg.nemoclaw.patch_build_timeout_s,
            )
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_fallback.py -q` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/bootstrap.py test/test_provisioning_fallback.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/bootstrap.py test/test_provisioning_fallback.py && git commit -m "feat(provisioner): capability-gated bootstrap with mock fallback"`.

## Task 18 — Dashboard `sandbox_runs` operational view

**Files:**
- Modify: `infra/dashboard.py`
- Test: `test/test_provisioning_fallback.py`

- [ ] Write the failing test. Append to `test/test_provisioning_fallback.py`:
```python
def test_dashboard_exposes_sandbox_runs_view(db):
    from infra.dashboard import build_sandbox_runs_view

    db.execute(
        "INSERT INTO sandbox_runs(run_id, instance_id, lane_id, mode, "
        "deterministic, patch_applied, capabilities) "
        "VALUES('R1','VICT-1','L1','ephemeral',1,0,'{}')")
    view = build_sandbox_runs_view(db)
    assert view["total"] == 1
    assert view["rows"][0]["mode"] == "ephemeral"
    assert view["rows"][0]["deterministic"] is True
```
- [ ] Run it, verify it fails: `uv run pytest test/test_provisioning_fallback.py::test_dashboard_exposes_sandbox_runs_view -q` — expect `ImportError: cannot import name 'build_sandbox_runs_view'`.
- [ ] In `infra/dashboard.py`, add the view builder (place it beside the other `build_*_view` helpers — locate them with `grep -n "def build_" infra/dashboard.py`):
```python
def build_sandbox_runs_view(db) -> dict:
    """Operational view: per-lane victim mode and whether the run was
    deterministic (real-nemoclaw-provisioner spec §10)."""
    rows = db.fetchall(
        "SELECT run_id, instance_id, lane_id, mode, deterministic, "
        "patch_applied, provisioned_at, torn_down_at "
        "FROM sandbox_runs ORDER BY provisioned_at DESC LIMIT 100")
    return {
        "total": len(rows),
        "rows": [
            {
                "run_id": r["run_id"],
                "instance_id": r["instance_id"],
                "lane_id": r["lane_id"],
                "mode": r["mode"],
                "deterministic": bool(r["deterministic"]),
                "patch_applied": bool(r["patch_applied"]),
                "provisioned_at": r["provisioned_at"],
                "torn_down_at": r["torn_down_at"],
            }
            for r in rows
        ],
    }
```
- [ ] Register the view in the dashboard's route/render table — find where the existing views are assembled (`grep -n "build_.*_view(" infra/dashboard.py`) and add `build_sandbox_runs_view(db)` under a `"sandbox_runs"` key alongside the others, matching the surrounding pattern exactly.
- [ ] Add `build_sandbox_runs_view` to `infra/dashboard.py`'s `__all__` if the module has one.
- [ ] Run the test, verify it passes: `uv run pytest test/test_provisioning_fallback.py::test_dashboard_exposes_sandbox_runs_view -q` — expect `1 passed`.
- [ ] Run the dashboard suite, verify no regression: `uv run pytest test/test_dashboard.py -q` — expect all pass.
- [ ] Run lint: `uv run ruff check infra/dashboard.py test/test_provisioning_fallback.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/dashboard.py test/test_provisioning_fallback.py && git commit -m "feat(provisioner): dashboard sandbox_runs operational view"`.

## Task 19 — Full-suite green + companion doc

**Files:**
- Create: `docs/real_provisioner_runbook.md`
- Test: full suite

- [ ] Run the full test suite, verify it is green: `uv run pytest -q` — expect all tests pass (the pre-existing ~164 + the new provisioner tests). If any pre-existing test broke, fix the regression before continuing — the real provisioner is additive and mock mode stays the default (spec constraint 1, §13).
- [ ] Run full lint: `uv run ruff check .` — expect `All checks passed!`.
- [ ] Verify the demo path still runs end to end with zero credentials: `uv run monkeyclaw run --cycles 1 --target monkey-victim --mock` — expect a clean cycle.
- [ ] Confirm a `sandbox_runs` row was written by the mock cycle: `uv run python -c "from infra.database import Database; d=Database('data/monkeyclaw-mock.db'); print(len(d.fetchall('SELECT * FROM sandbox_runs'))); d.close()"` (the `-mock` suffix is added by `bootstrap.boot` for mock runs) — expect `>= 1` with `mode='mock'`.
- [ ] Create `docs/real_provisioner_runbook.md` — for an operator bringing up the live path: the `MC_LIVE_NEMOCLAW=1` marker, the `nemoclaw` build requirements (snapshot create/restore must succeed for ephemeral isolation), the `nemoclaw` block config keys (`baseline_snapshot`, `work_area_dir`, `patch_build_timeout_s`), how to read `SandboxCapabilities` from the bootstrap log, and the recover-only degradation behaviour (filesystem bleed, `deterministic=False`). Cross-reference §13 phased delivery and §14 open questions of the spec.
- [ ] Run the live-only smoke check (skipped in CI; only on a NemoClaw host): `MC_LIVE_NEMOCLAW=1 uv run pytest test/test_provisioning_lifecycle.py -q -m live` — on CI/no-CLI this reports `deselected`, which is the expected CI behaviour.
- [ ] Commit: `git add docs/real_provisioner_runbook.md && git commit -m "docs(provisioner): live-path runbook + full-suite green"`.

---

## Spec coverage self-review

Checked section by section against `docs/superpowers/specs/2026-05-15-real-nemoclaw-provisioner-design.md`:

- **§2 scope** — ephemeral snapshot-isolated lifecycle (Task 11); full `provision/connect/recover/snapshot` surface (Tasks 7, 8, 11; `connect_existing` left unchanged); deterministic snapshots (Tasks 8, 11 — `deterministic` flag); per-lane patch application (Tasks 15, 16); real telemetry capture (Tasks 13, 14); capability-detection layer (Tasks 4, 5, 17); planted-victim profiles for the real path — the existing `demo/victims/` registry already serves both transports, so no parallel profile set is created (the mock transport binding is the only victim source; the real path drives the same gateway, consistent with §2's "VictimClient stays as-is"). Out-of-scope items (cloud pool, gateway transport replacement, new monitoring backend, building NemoClaw) are not touched.
- **§3 what exists vs new** — Tasks complete, do not rebuild: contract extension (Task 1) is additive; the prober (Task 4) is new; ephemeral isolation + real teardown (Task 11) replace the no-op; the snapshot *create* side (Task 8); patch application (Tasks 15, 16) replaces the hard error; real telemetry (Tasks 13, 14); `recover`/`snapshot` promoted to contract methods (Tasks 7, 8).
- **§4 design constraints** — (1) mock stays the default fallback: Task 17 keeps `--use-mock-provisioner` and adds CLI-absent fallback; demo verified in Task 19. (2) `interfaces/` firewall: all new types + the additive Protocol methods land in `interfaces/` (Task 1). (3) capability detection not assumption: probed once at construction (Task 5), every lifecycle method branches (Tasks 8, 11, 16). (4) determinism is the product: `deterministic` flag stamped and propagated to `LaneResult` (Tasks 11, 12). (5) patch application isolated: `PatchBuilder` clones into a disposable area, baseline untouched, asserted in Task 15. (6) no silent unpatched victims: `patch_diff` + no snapshots raises (Tasks 15, 16). (7) telemetry shape fixed: capturer populates the existing `NetworkEvent`/`ProcessEvent`/`InferenceEvent` types and `VictimTelemetryBundle` reuses `FsDiff`/`MemoryDiff` (Tasks 1, 13).
- **§5 sandbox lifecycle model** — provision (Task 11), connect (unchanged), recover (Task 7), snapshot (Task 8), teardown (Task 11); recover-only degradation with `SandboxCapabilities(snapshots=False, ephemeral=False)` (Tasks 4, 5, 11).
- **§6 architecture** — `NemoClawProvisioner` carries `SandboxCapabilities` (Task 5), `provision_victim`/`recover_victim`/`snapshot_victim`/`teardown_victim` (Tasks 7, 8, 11), telemetry capturer producing `VictimTelemetryBundle` (Task 13); bootstrap selects the backend (Task 17); lane scheduler wires it (Tasks 12, 14).
- **§7 components** — 7.1 completed `NemoClawProvisioner` (Tasks 5–16); 7.2 prober → `SandboxCapabilities` (Task 4); 7.3 telemetry capturer → `VictimTelemetryBundle` (Task 13); 7.4 patch builder → `build_patched_snapshot` (Task 15); 7.5 contract extension + `VictimSnapshot`/`SandboxCapabilities` types, `MockProvisioner` trivial impls (Tasks 1, 6).
- **§8 data model** — `victim_snapshots` + `sandbox_runs` via migration 0006 (Task 2); `VictimTelemetryBundle` in `interfaces/types.py` (Task 1); existing observable types + `telemetry_events` reused unchanged; `SandboxRunsStore` writes both tables (Task 9).
- **§9 data flow** — 9.1 per-lane provision → harness → capture → teardown with `sandbox_runs` row (Tasks 12, 14); 9.2 repro determinism via the `deterministic` flag on `LaneResult` (Task 12); 9.3 patch verification path through `PatchBuilder` (Tasks 15, 16).
- **§10 integration points** — `lane_scheduler` reads `metadata["deterministic"]` onto `LaneResult` (Task 12); `bootstrap` capability check + mock fallback (Task 17); blue-team patched-victim request honoured via `provision_victim(patch_diff=...)` (Task 16); `NemoClawConfig` gains `baseline_snapshot`/`work_area_dir`/`patch_build_timeout_s` with defaults (Task 10); `MonitoringHarness` surface unchanged — the scheduler still supplies `sandbox_container`; additive dashboard view (Task 18).
- **§11 error handling** — CLI absent → fallback (Task 17) / direct `provision_victim` still raises (the `shutil.which` guard at the top of `provision_victim` is kept, Task 11); snapshot fail → `snapshots=False`, recover-only, `deterministic=False` (Tasks 4, 11); `patch_diff` + no snapshots → `ProvisioningError` (Task 16); patch build/apply failure → `ProvisioningError`, work area discarded in `finally` (Task 15); recover daemon-child deadlock → the temp-file `_run` pattern retained; timeouts bounded by config (Tasks 10, 15); telemetry capture failure degrades to empty, never aborts (Task 13).
- **§12 testing strategy** — `test_provisioning.py` extended for the Protocol (Tasks 1, 6); `test_provisioning_capabilities.py` (Task 4); `test_provisioning_lifecycle.py` (Tasks 5, 7, 8, 9, 10, 11, 12); `test_provisioning_patch_builder.py` (Tasks 15, 16); `test_provisioning_telemetry.py` (Tasks 13, 14); `test_provisioning_fallback.py` (Tasks 17, 18); existing suites run unchanged under the mock default (Task 19); live tests gated behind `MC_LIVE_NEMOCLAW`/`-m live` (Task 19) — the stubbed-CLI helper (`test/_nemoclaw_stub.py`, Task 3) is the CI-runnable coverage.
- **§13 phased delivery** — Phase 0 (Tasks 1–6, contracts + prober), Phase 1 (Tasks 7–9, lifecycle surface), Phase 2 (Tasks 10–12, ephemeral isolation), Phase 3 (Tasks 13–14, telemetry), Phase 4 (Tasks 15–16, patch application), Phase 5 (Tasks 17–19, gated default + dashboard). Mock stays the default at every step; the live default flip is the operator decision documented in Task 19's runbook once Phases 0–4 pass against a live build.
- **§14 open questions** — snapshot capability (the prober + recover-only degradation make MonkeyClaw run regardless, Tasks 4, 11; documented Task 19); telemetry source of truth (the capturer degrades any missing stream, Task 13; documented Task 19); patch build cost (`patch_build_timeout_s` bounds it, Task 10/15; the no-Makefile skip is the overlay-style sub-option); work-area storage (`work_area_dir` configurable, eager `teardown` discard, Tasks 10, 11) — a crashed-before-teardown reaper is noted as a follow-up consistent with the data-integrity stale-claim sweep.

No gaps found.
