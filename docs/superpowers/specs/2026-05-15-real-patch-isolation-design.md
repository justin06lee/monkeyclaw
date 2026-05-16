# Real Patch Isolation — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw's blue team verifies a candidate patch through a six-gate
`PatchVerifier`. Every gate today runs against the **replay surface** — the
in-process mock replay function (`make_mock_replay_fn`). The README states the
gap plainly:

> Patch verification runs the regression tests against the replay surface
> rather than shelling into a rebuilt NemoClaw with the diff applied.

That means **the patch under test is never applied to anything**.
`default_patched_replay_factory` in `blue_team/patch_verifier.py` ignores its
`PatchCandidate` argument and returns the same mock replay used by the
replay-minimizer. `NemoClawProvisioner.provision_victim` actively *rejects* a
`VictimConfig.patch_diff` — it raises `ProvisioningError` because the
snapshot-restore model has no per-lane patch path. The verdict "all six gates
passed" therefore proves the gates pass *on the unpatched victim*, which is
either trivially true (the vuln still fires, but the mock judge is keyed to a
canned outcome) or meaningless.

A real verifier must answer one question: **with this exact diff applied to the
victim's source and the victim rebuilt, do the gates pass?** That requires
applying the diff somewhere disposable, rebuilding the victim from the patched
tree, and pointing the gate runners at *that* build. This spec covers the
disposable-worktree lifecycle, the patched-victim rebuild, the sandboxed
verification environment, and cleanup.

## 2. What already exists

Stated precisely so this spec completes rather than rebuilds:

- **`PatchVerifier` (six gates)** — `blue_team/patch_verifier.py`. The gate
  sequence, control-plane weakening detector, `VerifyOutcome`/`GateResult`
  types, and the `PatchedReplayFactory` indirection are all built. This spec
  supplies a *real* factory; it does not touch the gate logic.
- **`PatchedReplayFactory` seam** — `Callable[[PatchCandidate], ReplayFn]`
  already injected through `PatchVerifier.__init__(patched_replay_factory=...)`.
  This is the exact extension point: a real factory builds a patched victim and
  returns a replay function bound to it. No verifier API change is needed.
- **`NemoClawProvisioner`** — `infra/provisioning_nemoclaw.py`. Snapshot-restore
  provisioner; `VictimConfig` already carries `patch_diff` and
  `nemoclaw_repo_path` fields. The provisioner currently *rejects* `patch_diff`.
- **`MockProvisioner`** — same file. Plants an in-memory `MockVictim`; records
  but never applies `patch_diff`. Stays the default and the fallback.
- **`_looks_like_diff`** — `blue_team/patch_generator.py`. Loose unified-diff
  shape validator, reused by `gate_diff_applies`.
- **The real-provisioner work** — `2026-05-15-real-nemoclaw-provisioner-design.md`
  (companion spec) delivers a *rebuildable* victim: an ephemeral NemoClaw built
  from a source checkout rather than restored from a fixed snapshot. This spec
  **depends on** that capability for the live path and degrades to mock without
  it.

Nothing here re-implements gates, diff parsing, or provisioning protocol.

## 3. Scope

In scope:

- A `blue_team/patch_isolation.py` module owning the disposable-worktree
  lifecycle: clone/worktree creation, diff application, build, teardown.
- A real `PatchedReplayFactory` (`build_patched_replay_factory`) that the
  pipeline injects into `PatchVerifier` in place of
  `default_patched_replay_factory`.
- A `gate_diff_applies` upgrade from shape-check to a real `git apply --check`
  inside the worktree.
- A sandboxed verification environment contract: the patched build runs under
  the same egress/filesystem bounds MonkeyClaw applies to any victim.
- Deterministic cleanup of every worktree, build artifact, and provisioned
  victim, including on crash.
- A mock fallback: when no rebuildable victim is configured, the factory
  returns the existing mock replay and the `VerifyOutcome` is tagged
  `isolation_mode="mock"` so the verdict is never silently overclaimed.

Explicitly out of scope (YAGNI for this spec):

- Building the rebuildable NemoClaw victim itself — owned by the
  real-nemoclaw-provisioner spec.
- Caching or incremental rebuilds across patch candidates (rebuild per patch;
  optimize only if measured build time becomes the bottleneck).
- Parallel multi-worktree verification (`full_suite_concurrency` stays the
  existing placeholder).
- Container/VM-level isolation beyond what the provisioner already provides.
- Auto-PR creation or applying the verified diff to the real source tree.

## 4. Design constraints

1. **The verifier API does not change.** `PatchVerifier.verify(...)` and the
   `PatchedReplayFactory` type are the contract. This spec only supplies a real
   implementation of that callable plus a module it delegates to.
2. **Disposable means disposable.** Every worktree lives under a unique temp
   root, is never the developer's working tree, and is removed in a `finally`.
   `git worktree` operations target a throwaway checkout, never the live repo.
3. **A patch is applied exactly once, in isolation, and discarded.** The diff
   is applied to the worktree only; the victim is rebuilt from the patched
   worktree; the worktree and victim are torn down before the next candidate.
4. **Mock is the default and a first-class fallback, not an error path.** Absent
   a rebuildable victim, isolation degrades to mock and labels the outcome.
   MonkeyClaw must run end-to-end with zero NemoClaw credentials (README demo
   posture).
5. **`interfaces/` is the contract firewall.** New shared types
   (`IsolationMode`, `PatchBuild`, the schema delta) land in `interfaces/`;
   `blue_team/` imports them read-only.
6. **The patched victim is still a victim.** It runs under the same monitoring
   harness and the same egress/filesystem policy bounds as any attack target —
   a patch under test is untrusted code.

## 5. Architecture

```
   blue_team/pipeline.py
        │  injects build_patched_replay_factory(...) into PatchVerifier
        ▼
   PatchVerifier.verify(patch, package, test_pair)
        │  patched_replay_factory(patch)  ──────────────┐
        ▼                                              │
   gate_diff_applies → gate1 → gate2 → gate3 →          │
   gate_control_plane → gate_telemetry                  │
                                                        ▼
                                          blue_team/patch_isolation.py
                                          ┌──────────────────────────────┐
                                          │ PatchIsolation               │
                                          │  1. acquire worktree         │
                                          │  2. git apply --check / apply │
                                          │  3. rebuild victim from tree  │
                                          │  4. yield ReplayFn bound to   │
                                          │     the patched victim        │
                                          │  5. teardown (finally)        │
                                          └───────────────┬──────────────┘
                                                          │
                              rebuildable provisioner ◄───┤  (live path)
                              MockProvisioner       ◄──────┘  (fallback)
```

The factory is a context-managed builder: `PatchVerifier` calls it once per
candidate; the returned `ReplayFn` is valid for the duration of that
candidate's gate run; teardown happens when verification of the candidate
completes (success or failure).

## 6. Components

Each module is one file with one responsibility.

### 6.1 `blue_team/patch_isolation.py` (new)

- **Does:** Owns the disposable-worktree lifecycle. Given a `PatchCandidate` and
  a NemoClaw source root, it (1) creates a `git worktree` off a pinned base
  commit under a unique temp root, (2) runs `git apply --check` then
  `git apply`, (3) asks the rebuildable provisioner to build a victim from the
  patched worktree, (4) hands back a `ReplayFn` bound to that victim, and (5)
  tears everything down. Exposes a context manager so cleanup is structural.
- **Interface:**
  - `class PatchIsolation` — `__init__(self, provisioner, *, nemoclaw_repo_path, base_ref, cfg)`.
  - `prepare(patch: PatchCandidate) -> contextmanager[PatchBuild]` — yields a
    `PatchBuild` (worktree path, victim instance, diff-apply result); cleans up
    on exit.
  - `diff_applies(patch: PatchCandidate) -> DiffApplyResult` — runs
    `git apply --check` in a fresh worktree and returns the result without
    building, so `gate_diff_applies` gets a real answer cheaply.
- **Depends on:** the rebuildable provisioner (real-nemoclaw-provisioner spec),
  `git` on PATH, `interfaces/provisioning.py`, `interfaces/types.py`.

### 6.2 `build_patched_replay_factory` (new, in `patch_isolation.py`)

- **Does:** The real `PatchedReplayFactory`. Returns a `ReplayFn` that, when
  invoked by a gate, replays a transcript against the **patched** victim built
  by `PatchIsolation`. The factory holds the active `PatchBuild` for the
  candidate so all gates of one candidate share one build.
- **Interface:**
  `build_patched_replay_factory(isolation: PatchIsolation) -> PatchedReplayFactory`.
- **Depends on:** `PatchIsolation`, `blue_team/replay_minimizer.ReplayFn`.

### 6.3 `gate_diff_applies` upgrade (in `patch_verifier.py`)

- **Does:** Today `gate_diff_applies` calls `_looks_like_diff` — a shape check.
  The upgrade: when an isolation backend is present, the gate runs
  `PatchIsolation.diff_applies(patch)` (a real `git apply --check`) and records
  the rejected hunks in `GateResult.detail`. When isolation is mock, it keeps
  the `_looks_like_diff` shape check. The gate's name, position, and
  pass/reject semantics are unchanged.
- **Depends on:** `PatchIsolation`.

### 6.4 Pipeline wiring (in `blue_team/pipeline.py`)

- **Does:** `Pipeline.__init__` constructs a `PatchIsolation` when the runtime
  config supplies `nemoclaw_repo_path` and the provisioner is rebuildable;
  otherwise it stays `None`. The `PatchVerifier` is built with
  `patched_replay_factory=build_patched_replay_factory(isolation)` when
  isolation exists, else with `default_patched_replay_factory` (current
  behavior).
- **Depends on:** `PatchIsolation`, `PatchVerifier`.

## 7. Data model additions

All land in `interfaces/schema.sql` via the migration system. `schema_meta`
already exists (`schema_version='2'`); this spec ships
`infra/migrations/003_patch_isolation.sql` and bumps `schema_version` to `3`.

- `patch_builds` — one row per attempted isolation build:
  `build_id`, `patch_id`, `base_ref`, `worktree_path`, `diff_applied`
  (bool), `rejected_hunks` (JSON), `build_status`
  (`built` | `apply_failed` | `build_failed` | `mock`), `victim_instance_id`,
  `isolation_mode` (`live` | `mock`), `build_duration_seconds`, `created_at`,
  `torn_down` (bool).

New `interfaces/types.py` types:

- `IsolationMode` — string enum-like (`"live"` / `"mock"`), reused on
  `VerifyOutcome`.
- `DiffApplyResult` — `applied: bool`, `checked: bool`, `rejected_hunks:
  list[str]`, `stderr: str`.
- `PatchBuild` — `build_id`, `patch_id`, `worktree_path`, `victim:
  VictimInstance | None`, `diff_result: DiffApplyResult`, `isolation_mode:
  IsolationMode`, `build_status`.

`VerifyOutcome` (in `patch_verifier.py`) gains one additive field:
`isolation_mode: IsolationMode = "mock"` so every verdict states whether it was
proven against a real patched build or a mock surface. Existing callers are
unaffected (defaulted field).

## 8. Data flow

Per candidate patch, inside `PatchVerifier.verify`:

1. `verify` calls `patched_replay_factory(patch)`.
2. **Live path:** `PatchIsolation.prepare(patch)` enters its context:
   a. `git worktree add` a fresh checkout of `nemoclaw_repo_path` at `base_ref`
      under `tempfile.mkdtemp(prefix="mc-patch-")`.
   b. `git apply --check` the candidate diff. On failure, a `PatchBuild` with
      `build_status="apply_failed"` is produced and `gate_diff_applies` rejects.
   c. `git apply` the diff into the worktree.
   d. The rebuildable provisioner builds a victim from the patched worktree
      (`VictimConfig.nemoclaw_repo_path=<worktree>`); the built `VictimInstance`
      runs under the standard monitoring harness and policy bounds.
   e. A `PatchBuild` is persisted to `patch_builds`; the factory returns a
      `ReplayFn` bound to that victim.
3. **Mock path:** no worktree, no build; the factory returns
   `make_mock_replay_fn()` and a `PatchBuild` with
   `isolation_mode="mock"`, `build_status="mock"`.
4. The six gates run against the returned `ReplayFn` — unchanged gate logic.
5. When the candidate's gate run finishes (approved or rejected), the
   `PatchIsolation` context exits: victim torn down via `teardown_victim`,
   `git worktree remove --force`, temp root deleted, `patch_builds.torn_down`
   set true.
6. `verify` stamps `VerifyOutcome.isolation_mode` from the `PatchBuild`.

The pipeline's existing per-task candidate loop already iterates candidates
serially, so one build is live at a time — no concurrency to manage.

## 9. Integration points

- **`PatchVerifier`** — receives the real factory via its existing
  `patched_replay_factory` parameter; `gate_diff_applies` gains an isolation
  branch. No new constructor parameter on the public path.
- **`blue_team/pipeline.py`** — constructs `PatchIsolation` when config permits;
  one new conditional in `__init__`.
- **Rebuildable provisioner** — consumes `VictimConfig.nemoclaw_repo_path`
  pointing at the patched worktree. The current `NemoClawProvisioner` snapshot
  path is untouched; the rebuildable provisioner is the real-nemoclaw-provisioner
  spec's deliverable.
- **Config** — `configs/monkeyclaw.yaml` gains `blue_team.patch_isolation`:
  `enabled` (default false → mock), `nemoclaw_repo_path`, `base_ref` (default
  the victim's pinned commit), `build_timeout_s`, `worktree_root` (default the
  system temp dir).
- **Dashboard** — the patch panel gains an `isolation_mode` badge so a reviewer
  sees at a glance whether a verdict was proven live or on the mock surface.
  Additive.

## 10. Error handling

- **`git apply --check` fails** → `DiffApplyResult.applied=false` with
  `rejected_hunks`; `gate_diff_applies` rejects the patch with the hunk detail.
  No build is attempted. Not an isolation error — a legitimate patch rejection.
- **`git apply` fails after `--check` passed** (rare; concurrent index state) →
  `PatchBuild.build_status="apply_failed"`, the candidate is rejected at
  `gate_diff_applies`, alert logged.
- **Build fails** (compile/install error in the patched tree) →
  `build_status="build_failed"`; `verify` returns
  `approved=False, failed_gate="gate_diff_applies"` with notes
  `"patched victim failed to build"`. A patch that does not build is not a
  passing patch.
- **Build timeout** (`build_timeout_s`) → treated as `build_failed`; the
  partial build process is killed and the worktree torn down.
- **Provisioner unavailable / `git` missing / `nemoclaw_repo_path` unset** →
  isolation degrades to mock for the whole run; `VerifyOutcome.isolation_mode`
  is `"mock"`; a single startup-time warning is logged. Verification still runs;
  it is just not proven against a real build.
- **Cleanup failure** (`git worktree remove` or `rmtree` fails) → logged as an
  alert with the leaked path; `patch_builds.torn_down` stays false so a janitor
  sweep (§11) can reclaim it. A cleanup failure never fails a patch verdict.
- **Crash mid-verify** — the `PatchIsolation` context manager's `finally`
  guarantees teardown; a process-level crash leaves a row with
  `torn_down=false`, reclaimed on next startup by the janitor sweep over
  `worktree_root`.

## 11. Worktree janitor

On `Pipeline` startup, a one-shot sweep removes any `mc-patch-*` directory under
`worktree_root` whose `patch_builds` row has `torn_down=false` (or has no row at
all — orphaned by a hard crash). This bounds disk growth without a background
scheduler and keeps the design self-healing across restarts.

## 12. Testing strategy

Tests live in `test/` as `test_blue_patch_isolation_*.py`, matching the
existing `test_blue_*` convention.

- `test_blue_patch_isolation_worktree.py` — against a throwaway git repo
  fixture: `prepare` creates a worktree, applies a known-good diff, and tears it
  down; assert the worktree directory is gone and `patch_builds.torn_down` is
  true. A second case applies a deliberately-conflicting diff and asserts
  `DiffApplyResult.applied=false` with the rejected hunk.
- `test_blue_patch_isolation_mock_fallback.py` — with no `nemoclaw_repo_path`,
  assert the factory returns the mock replay and `VerifyOutcome.isolation_mode
  == "mock"`.
- `test_blue_patch_isolation_cleanup.py` — force an exception inside the
  `prepare` context and assert teardown still ran (worktree removed, victim
  torn down).
- `test_blue_patch_isolation_janitor.py` — seed an orphaned `mc-patch-*` dir,
  run the startup sweep, assert it is reclaimed.
- `test_blue_patch_verifier.py` (existing) — extended: with a fake isolation
  backend whose build "applies" the patch, assert `gate1_regression` now passes
  *because the patch took effect*, and fails when the fake build does not apply
  it. This is the test that proves the verifier is no longer testing thin air.
- All default tests run in mock mode with zero credentials. The git-repo
  fixture is a local temp repo, so the worktree tests need no NemoClaw.

## 13. Phased delivery

- **Phase 0 — contracts:** `interfaces/types.py` additions (`IsolationMode`,
  `DiffApplyResult`, `PatchBuild`), `VerifyOutcome.isolation_mode` field,
  `infra/migrations/003_patch_isolation.sql`, `schema_version` → 3. No
  behavior.
- **Phase 1 — worktree lifecycle:** `patch_isolation.py` with `prepare` /
  `diff_applies` against a local git repo; no victim build yet (`PatchBuild`
  carries `victim=None`). `gate_diff_applies` upgraded to real `git apply
  --check`.
- **Phase 2 — real build:** wire the rebuildable provisioner so `prepare`
  produces a built patched victim; `build_patched_replay_factory` returns a
  replay bound to it.
- **Phase 3 — pipeline wiring + fallback:** `Pipeline` constructs
  `PatchIsolation` from config; mock fallback and `isolation_mode` stamping;
  dashboard badge.
- **Phase 4 — janitor + hardening:** startup sweep, timeout handling, alerting
  on leaked worktrees.
- **Later (not this spec):** rebuild caching across candidates; parallel
  worktrees.

Phases 0–1 land independently of the real-nemoclaw-provisioner spec; Phases 2+
depend on it. Until Phase 2, the mock fallback is the only path and the
behavior matches today's verifier, so nothing regresses.

## 14. Open questions

1. **Base ref pinning.** `base_ref` defaults to the victim's pinned commit; if
   the live victim drifts from that commit, a patch could verify clean against
   a stale base. The real-nemoclaw-provisioner spec owns reporting the victim's
   actual build commit — this spec consumes it. Until then `base_ref` is an
   explicit config value.
2. **Build determinism.** A non-deterministic NemoClaw build (timestamps,
   dependency floats) could make `build_failed` flaky. If observed, pin the
   build with a lockfile in the rebuildable-provisioner spec; not solved here.
3. **Diff path rooting.** Patch diffs from `patch_generator.py` use `a/`…`b/`
   prefixes against the NemoClaw repo root. If a future victim layout nests the
   source, `git apply -p<n>` rooting becomes a config knob. Not needed for the
   current single-repo victim.
