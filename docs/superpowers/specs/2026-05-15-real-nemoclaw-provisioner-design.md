# Real NemoClaw Provisioner — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw's whole value proposition is *evidence*: a finding is only real when
it reproduces against a live victim and a patch is only verified when the
attack is blocked on a rebuilt, patched victim. Today the victim is
`MockProvisioner` — an in-memory planted-vulnerability agent. The README is
candid about it:

> The victim is an in-memory mock provisioner with a planted-vulnerability
> agent; a real NemoClaw provisioner is wired but not the default path. […]
> A production version adds a real NemoClaw provisioner: ephemeral,
> snapshot-isolated victims with the candidate diff actually applied in a
> disposable work area.

And the architecture report names this the single biggest risk:

> Real NemoClaw integration is the highest-risk unknown.

`NemoClawProvisioner` already exists and shells to the `nemoclaw` CLI, but it
is partial: it targets **one persistent sandbox**, resets it via
`snapshot restore` + `recover`, and `teardown_victim` is a no-op. The shipping
config runs it in *recover-only* mode (`clean_snapshot: ""`) because
`snapshot create` fails on the available CPU sandbox — so even when the real
provisioner is used, lanes are **not snapshot-isolated**: filesystem changes
from one lane bleed into the next. It cannot apply a per-lane patch
(`patch_diff` set → hard error). It captures no real fs/network/process/
inference telemetry — that comes from `MonitoringHarness` snapshotting host
paths. This spec completes `NemoClawProvisioner` into a real, snapshot-isolated,
telemetry-capturing provisioner, while keeping mock mode the default fallback
because the integration is high-risk.

## 2. Scope

In scope:

- An **ephemeral, snapshot-isolated** victim lifecycle: each lane gets a victim
  whose state is a known-clean snapshot, mutated only by that lane, and
  discarded after — so repro runs are deterministic and lanes never bleed.
- A full `provision / connect / recover / snapshot` lifecycle on the
  `VictimProvisioner` contract, with `provision_victim` and `teardown_victim`
  meaning what their names say.
- **Deterministic snapshots**: a named clean baseline snapshot, restored before
  every lane, so the same finding replays against byte-identical victim state —
  the precondition for a trustworthy repro rate.
- **Per-lane patch application**: building a patched victim snapshot in a
  disposable work area so `patch_verifier` can run its six gates against a real
  rebuilt NemoClaw, not the replay surface.
- **Real telemetry capture**: fs/network/process/inference observables read
  from the actual sandbox, populating the `FsDiff` / `NetworkEvent` /
  `ProcessEvent` / `InferenceEvent` types the harness already defines and the
  `telemetry_events` table.
- A **capability-detection** layer that probes what the local NemoClaw build
  supports (snapshots? container fs-diff?) and degrades gracefully — and
  ultimately back to mock — so a partial environment still runs.
- Planted-vulnerability victim profiles for the real path, parallel to the
  existing `demo/victims/` profiles used by the mock.

Explicitly out of scope (YAGNI for this spec):

- A cloud / multi-sandbox pool. The lane scheduler is serial-by-design today
  (`serial=True`); concurrency is retained but unused, and this spec stays
  single-sandbox. Parallel sandboxes are a later infra concern.
- Replacing the gateway WebSocket transport — `VictimClient` and the gateway
  protocol stay as-is; this spec changes how the *sandbox* is provisioned, not
  how the attacker talks to it.
- A new monitoring backend. `MonitoringHarness` stays the capture abstraction;
  this spec feeds it real sandbox handles instead of host paths.
- Building/packaging NemoClaw itself, or owning its release. MonkeyClaw
  consumes whatever `nemoclaw` CLI is installed.

## 3. What already exists vs. what is new

Already built — this spec completes, not rebuilds:

- `interfaces/provisioning.py`: the `VictimProvisioner` Protocol
  (`provision_victim`, `teardown_victim`, `list_victims`), `VictimConfig`
  (including a `patch_diff` field), `VictimInstance`, `ProvisioningError`, and
  the module singleton (`set_provisioner` / `get_provisioner`).
- `infra/provisioning_nemoclaw.py`: `NemoClawProvisioner` — shells `nemoclaw
  <sandbox> snapshot restore`, `recover`, `gateway-token`; a `connect_existing`
  path for ad-hoc probing; recover-only fallback when `clean_snapshot` is unset;
  the temp-file subprocess pattern that avoids the `recover` daemon-child pipe
  deadlock. Also `MockProvisioner` in the same file.
- `interfaces/config_schema.py` `NemoClawConfig`: `sandbox_name`,
  `sandbox_namespace`, `clean_snapshot`, `gateway_endpoint`,
  `gateway_container`, `snapshot_restore_timeout_s`, `recover_timeout_s`,
  `monitored_paths`, `allowed_paths`.
- `infra/lane_scheduler.py`: builds a `VictimConfig`, calls
  `provision_victim` / `teardown_victim` per lane, and already branches on
  `instance.metadata["sandbox_container"]` to pick container fs-diff vs.
  host-path snapshotting in `MonitoringHarness`.
- `infra/orchestrator.py` / `infra/cli.py`: the `--use-mock-provisioner` flag
  and `boot(use_mock_provisioner=...)` already select the backend.
- `demo/victims/`: planted-vulnerability profiles (`planted_filesystem`,
  `planted_pii_route`, `planted_prompt_injection`, `planted_skill_poison`) and
  a registry — bound to the mock transport today.
- `MonitoringHarness` (`HarnessConfig` with `watched_paths`, `allowed_paths`,
  `sandbox_container`, `sandbox_namespace`, `sandbox_pod`).

What is **missing** and is this spec's work:

- Real ephemeral isolation. `provision_victim` resets a *persistent* sandbox;
  `teardown_victim` is a no-op. There is no per-lane disposable work area.
- A working snapshot path. `clean_snapshot` is empty in the shipping config
  because `snapshot create` fails on the CPU sandbox — so the *create* side of
  snapshots is unimplemented and the *restore* side is config-disabled.
- Per-lane patch application — currently a hard `ProvisioningError`.
- Real telemetry capture from the sandbox (network/process/inference) — only
  filesystem diffing exists, and only via the harness.
- Capability detection / graceful degradation as a first-class layer.
- An explicit `recover` and `snapshot` surface on the provisioner contract —
  today `recover` is an internal CLI call and `snapshot` does not exist as a
  method.

## 4. Design constraints

1. **Mock mode stays the default fallback.** Because this is the highest-risk
   integration, `--use-mock-provisioner` and the auto-detect path keep mock as
   the default until the real provisioner clears its phase gates (§13). The
   demo (`demo/run_hackathon_demo.sh`, zero credentials) must keep working
   throughout.
2. **`interfaces/` stays the contract firewall.** The `VictimProvisioner`
   Protocol is *extended* — additively — with `recover_victim` and
   `snapshot_victim`. Additive Protocol methods with default-providing
   convenience wrappers keep `MockProvisioner` and any existing caller valid.
   New shared types (`VictimSnapshot`, `SandboxCapabilities`,
   `VictimTelemetryBundle`) land in `interfaces/provisioning.py` /
   `interfaces/types.py`.
3. **Capability detection, not assumption.** The provisioner probes the local
   `nemoclaw` build once at construction and records a `SandboxCapabilities`
   object. Every lifecycle method branches on capabilities; an unsupported
   capability degrades to the best available mode, and an environment that
   supports nothing falls back to mock with a loud warning.
4. **Determinism is the product.** A repro is only trustworthy if every replay
   starts from byte-identical victim state. The clean-baseline snapshot is the
   determinism anchor; if snapshots are unavailable the provisioner reports
   `deterministic=False` and the repro pipeline records reduced confidence
   rather than asserting a false repro rate.
5. **Patch application is isolated.** A candidate diff is applied in a
   disposable copy of the NemoClaw checkout / sandbox image, never in the
   baseline. A failed patch build cannot corrupt the clean baseline.
6. **No silent unpatched victims.** The current code already refuses to run
   when `patch_diff` is set but cannot be applied — that strictness is kept:
   any inability to honour the requested victim state is a `ProvisioningError`,
   never a silent fallback to a wrong state.
7. **Telemetry shape is fixed.** Real capture populates the *existing*
   `FsDiff` / `NetworkEvent` / `ProcessEvent` / `InferenceEvent` / `MemoryDiff`
   types and the `telemetry_events` table. The Tier-1 checks and the purple-team
   adapter read them unchanged.

## 5. Sandbox lifecycle model

The real provisioner manages each victim as an **ephemeral instance derived
from a deterministic baseline**:

```
   baseline image / clean snapshot   (built once, immutable)
            │  clone
            ▼
   ┌──────────────────┐  provision   ┌──────────────────┐
   │ disposable        │ ───────────► │ running victim    │
   │ work area (lane)  │  recover     │ + gateway + agent │
   └──────────────────┘              └────────┬──────────┘
            ▲                                  │ attack runs
            │ teardown (discard work area)      │ telemetry captured
            └──────────────────────────────────┘
```

- **provision** — clone the baseline into a per-lane disposable work area,
  optionally apply `patch_diff` and rebuild, start the gateway + agent,
  return a `VictimInstance` with a real `sandbox_container` so the harness
  uses container fs-diff.
- **connect** — attach to an already-running victim without resetting it
  (`connect_existing`, already implemented) — for ad-hoc probing.
- **recover** — restart the gateway + agent in place, clearing in-memory
  session/conversation state without a full reprovision (the current internal
  `recover` call, promoted to a contract method).
- **snapshot** — capture the current victim state as a named snapshot
  (`snapshot_victim`) and restore from one. This is the missing *create* side;
  it is what makes the clean baseline buildable and patched-victim snapshots
  possible.
- **teardown** — discard the disposable work area entirely. Unlike today's
  no-op, teardown actually frees the per-lane state, which is what makes the
  next lane's provision deterministic.

When the local build cannot do disposable clones (the current CPU-sandbox
reality), the provisioner degrades to the existing **recover-only** mode but
now reports `SandboxCapabilities(snapshots=False, ephemeral=False)` so callers
know isolation is not guaranteed.

## 6. Architecture

```
        infra/bootstrap.py ── selects backend by config + --use-mock-provisioner
                 │
        ┌────────┴─────────────────────────────┐
        ▼                                       ▼
  MockProvisioner                     NemoClawProvisioner  (this spec)
  (default fallback)                   ├─ SandboxCapabilities  (probed once)
                                       ├─ provision_victim   clone+patch+recover
                                       ├─ recover_victim     restart gateway/agent
                                       ├─ snapshot_victim    create / restore
                                       ├─ teardown_victim    discard work area
                                       └─ telemetry capture  ──┐
                                            │ nemoclaw CLI      │
                                            ▼                   ▼
                                  baseline snapshot      VictimTelemetryBundle
                                  + disposable work area   (fs/net/proc/inf)
                                            │                   │
        infra/lane_scheduler.py ────────────┘                   │
          provision → harness(real sandbox handle) → executor    │
          → harness.result()  ◄─────────────────────────────────┘
          → teardown
```

## 7. Components

### 7.1 `infra/provisioning_nemoclaw.py` — `NemoClawProvisioner` (completed)

- **Does:** Implements the §5 lifecycle. Construction probes capabilities
  (§7.2). `provision_victim` clones the baseline (or recover-only-degrades),
  applies `patch_diff` via the patch builder (§7.4) when set, starts the victim,
  and returns a `VictimInstance` carrying the sandbox container handle and a
  `deterministic` flag in `metadata`. `teardown_victim` discards the work area.
- **Interface:** the existing `VictimProvisioner` methods plus the two new
  contract methods (§7.5). `connect_existing` is kept unchanged.
- **Depends on:** the `nemoclaw` CLI, `interfaces/provisioning.py`,
  `interfaces/victim_client.py`, the capability prober, the patch builder, the
  telemetry capturer.

### 7.2 Capability prober (`SandboxCapabilities`)

- **Does:** Runs once at provisioner construction. Probes: is `nemoclaw` on
  PATH; does `nemoclaw <sandbox> snapshot create`/`restore` succeed on a
  throwaway snapshot; is the sandbox a container the harness can `docker exec`
  into; does `recover` work. Produces a frozen `SandboxCapabilities`
  (`cli_present`, `snapshots`, `ephemeral`, `container_fsdiff`, `recover`).
- **Interface:** `probe(cli, sandbox_name) -> SandboxCapabilities`.
- **Depends on:** the `nemoclaw` CLI. New type in `interfaces/provisioning.py`.

### 7.3 Telemetry capturer (`VictimTelemetryBundle`)

- **Does:** Reads real observables from a running/just-finished sandbox and
  returns them in the existing dataclass shapes:
  - **filesystem** — sandbox fs-diff (container `docker exec` or snapshot diff)
    → `FsDiff`. Already partially done in `MonitoringHarness`; this formalises
    it and sources it from the provisioner's sandbox handle.
  - **network** — sandbox egress log / proxy decisions → `list[NetworkEvent]`.
  - **process** — sandbox process/syscall log → `list[ProcessEvent]`.
  - **inference** — the NemoClaw inference router's local/cloud routing log →
    `list[InferenceEvent]`, with PII class and content hash/excerpt (never raw
    secrets), feeding the PRV-ROUTE / INF-ROUTE zones.
  - **memory** — agent persistent-memory key diff → `MemoryDiff`.
- **Interface:** `capture(instance) -> VictimTelemetryBundle`.
- **Depends on:** the `nemoclaw` CLI / sandbox handle; emits into
  `telemetry_events` via the telemetry emitter.

### 7.4 Patch builder

- **Does:** Given `VictimConfig.patch_diff`, materialises a *patched victim*:
  clone the NemoClaw checkout / sandbox image into a disposable work area, apply
  the diff (`git apply` / overlay), rebuild, and produce a snapshot the
  provisioner boots. Used by `patch_verifier` so its six gates run against a
  real rebuilt-and-patched NemoClaw rather than the replay surface (the README
  gap: *"Patch verification runs the regression tests against the replay
  surface rather than shelling into a rebuilt NemoClaw"*).
- **Interface:** `build_patched_snapshot(diff, baseline) -> VictimSnapshot`.
- **Depends on:** the NemoClaw checkout (`NemoClawConfig.repo_path`), the
  `nemoclaw` CLI, snapshot support. When snapshots are unavailable it raises
  `ProvisioningError` — keeping constraint 6 (no silent unpatched victim).

### 7.5 `interfaces/provisioning.py` — contract extension

- **Does:** Adds two additive methods to the `VictimProvisioner` Protocol and
  the new shared types.
- **Interface (additive):**
  ```python
  class VictimProvisioner(Protocol):
      # ... existing provision_victim / teardown_victim / list_victims ...
      def recover_victim(self, instance_id: str) -> VictimInstance:
          """Restart the gateway + agent in place, clearing session/
          conversation state without a full reprovision."""
      def snapshot_victim(
          self, instance_id: str, name: str
      ) -> "VictimSnapshot":
          """Capture current victim state as a named snapshot."""

  @dataclass
  class VictimSnapshot:
      name: str
      sandbox_id: str
      created_at: str
      deterministic: bool          # False if captured without true isolation
      patched: bool                # True for patched-victim snapshots
      base_snapshot: str | None

  @dataclass
  class SandboxCapabilities:
      cli_present: bool
      snapshots: bool
      ephemeral: bool
      container_fsdiff: bool
      recover: bool
  ```
  `MockProvisioner` gains trivial implementations (`recover_victim` returns the
  instance; `snapshot_victim` returns a `VictimSnapshot(deterministic=True)` —
  the mock victim is replanted fresh per provision, so it is already
  deterministic).

## 8. Data model additions

The provisioner is mostly schema-light — it produces in-memory telemetry the
harness and Tier-1 checks consume. Two additions, both routed through the
migration system (see the data-integrity spec — `interfaces/schema.sql` is no
longer edited in place):

- `victim_snapshots` — `snapshot_id`, `name`, `sandbox_id`, `deterministic`,
  `patched`, `base_snapshot`, `created_at`. Lets the repro pipeline pin a
  finding to the exact baseline it was found against and lets
  `patch_verifier` reference the patched snapshot it gated.
- `sandbox_runs` — `run_id`, `instance_id`, `lane_id`, `mode`
  (`ephemeral|recover_only|mock`), `deterministic`, `patch_applied`,
  `provisioned_at`, `torn_down_at`, `capabilities` (JSON snapshot of
  `SandboxCapabilities`). One row per provisioned victim — the operational
  audit trail for "what victim did this finding run against, and was it
  isolated".

`interfaces/types.py` gains `VictimTelemetryBundle` (a container of the five
existing observable types). `FsDiff` / `NetworkEvent` / `ProcessEvent` /
`InferenceEvent` / `MemoryDiff` and `telemetry_events` are reused unchanged.

## 9. Data flow

### 9.1 Per lane (lane scheduler)

```
scheduler._run_lane(idea)
  → provisioner.provision_victim(VictimConfig)
       capabilities.ephemeral?
         yes → clone baseline → (patch_diff? → patch builder) → start victim
         no  → recover-only: restore clean_snapshot if present, else recover
       → VictimInstance{ sandbox_container, metadata[deterministic] }
       → sandbox_runs row written
  → MonitoringHarness(real sandbox handle)  — container fs-diff path
  → executor runs the attack
  → telemetry capturer.capture(instance) → VictimTelemetryBundle
       → telemetry_events rows + LaneResult observable fields
  → harness.result() → LaneResult
  → provisioner.teardown_victim(instance_id)   — discard work area
```

### 9.2 Repro determinism

```
repro pipeline replays finding N times:
  each replay → provision_victim restores the SAME clean baseline snapshot
  → byte-identical victim state → trustworthy repro_rate
  if capabilities.snapshots is False:
      provision reports deterministic=False
      → repro pipeline records reduced confidence (not a false 100% rate)
```

### 9.3 Patch verification

```
patch_verifier needs a patched victim:
  → provision_victim(VictimConfig(patch_diff=candidate.diff))
       → patch builder: clone checkout → apply diff → rebuild → snapshot
       → boot patched victim
  → six gates run against the REAL rebuilt-and-patched NemoClaw
  → teardown discards the patched work area
```

## 10. Integration points

- **`infra/lane_scheduler.py`:** already calls `provision_victim` /
  `teardown_victim` and already branches on `sandbox_container`. The only
  change: it reads `instance.metadata["deterministic"]` and passes it onto the
  `LaneResult` so the repro pipeline can see whether isolation held.
- **`infra/bootstrap.py`:** backend selection gains the capability check — if
  `--use-mock-provisioner` is not set but the prober reports `cli_present=False`,
  bootstrap logs a loud warning and falls back to `MockProvisioner` rather than
  failing (constraint 1).
- **`blue_team/patch_verifier.py` / `replay_minimizer.py` / `cold_verifier.py`:**
  these already take a `provisioner`. They gain the ability to request a
  patched victim (`patch_diff` set) — which previously hard-errored — so the
  six gates run against a real patched build.
- **`interfaces/config_schema.py` `NemoClawConfig`:** gains
  `baseline_snapshot` (the immutable clean image name, distinct from
  `clean_snapshot` which is the restore target), `work_area_dir` (disposable
  clone location), and `patch_build_timeout_s`. All have defaults; existing
  configs are unaffected.
- **`MonitoringHarness`:** unchanged surface — it already accepts a sandbox
  container; this spec just ensures the real provisioner always supplies one
  when `capabilities.container_fsdiff` is true.
- **Dashboard:** a new operational view backed by `sandbox_runs` —
  per-lane victim mode and whether the run was deterministic. Additive.

## 11. Error handling

- **`nemoclaw` CLI absent** — the prober reports `cli_present=False`; bootstrap
  falls back to mock with a warning. A direct `provision_victim` on the real
  provisioner still raises `ProvisioningError` (current behaviour kept).
- **Snapshot create/restore fails** — `capabilities.snapshots=False`; the
  provisioner degrades to recover-only and stamps `deterministic=False` on
  every `VictimInstance`. The repro pipeline lowers confidence accordingly.
- **`patch_diff` set but no snapshot support** — `ProvisioningError`, never a
  silent unpatched victim (constraint 6). `patch_verifier` records the gate as
  un-runnable rather than falsely passed.
- **Patch build/apply failure** — `ProvisioningError` from the patch builder;
  the disposable work area is discarded; the baseline is untouched
  (constraint 5).
- **`recover` daemon-child pipe deadlock** — already solved by the temp-file
  subprocess pattern; retained.
- **Timeouts** — every CLI call is bounded (`snapshot_restore_timeout_s`,
  `recover_timeout_s`, `patch_build_timeout_s`); a timeout is a
  `ProvisioningError`, the lane scheduler's existing per-lane `try/except`
  isolates it, and `teardown_victim` still runs in the `finally`.
- **Telemetry capture failure** — a missing or unreadable observable stream
  degrades that field to empty (e.g. empty `network_log`) with a warning; it
  never aborts the lane. The purple-team adapter already treats missing
  telemetry conservatively.

## 12. Testing strategy

Tests live in `test/`, extending `test_provisioning.py`.

- `test_provisioning.py` (extend): `MockProvisioner` satisfies the *extended*
  `VictimProvisioner` Protocol including `recover_victim` / `snapshot_victim`;
  `runtime_checkable` Protocol conformance still holds.
- `test_provisioning_capabilities.py` — the prober, with the `nemoclaw` CLI
  stubbed (a fake script on PATH): each capability flag is set correctly for a
  full-featured stub, a snapshot-less stub, and a CLI-absent environment.
- `test_provisioning_lifecycle.py` — against a stubbed `nemoclaw` CLI:
  `provision → recover → snapshot → teardown` issues the expected CLI calls in
  order; `teardown` after an ephemeral provision discards the work area;
  recover-only mode stamps `deterministic=False`.
- `test_provisioning_patch_builder.py` — `build_patched_snapshot` applies a
  diff in a disposable area and never touches the baseline; an un-appliable
  diff raises `ProvisioningError`; `patch_diff` set with `snapshots=False`
  raises rather than running unpatched.
- `test_provisioning_telemetry.py` — the capturer maps stubbed sandbox
  fs/network/process/inference output into the correct `FsDiff` /
  `NetworkEvent` / `ProcessEvent` / `InferenceEvent` shapes; a missing stream
  degrades to an empty field, not an exception.
- `test_provisioning_fallback.py` — bootstrap with no `nemoclaw` CLI and
  without `--use-mock-provisioner` falls back to `MockProvisioner` and the
  existing e2e demo path still passes.
- Existing suites (`test_orchestrator.py`, `test_blue_pipeline_e2e.py`,
  `test_red_pipeline_e2e.py`, `test_harness.py`) run unchanged under the mock
  default — proving constraint 1.
- Live-sandbox tests are gated behind an `MC_LIVE_NEMOCLAW=1` env marker and
  skipped in CI, since CI has no `nemoclaw` install. The stubbed-CLI tests
  above are the CI-runnable coverage.

## 13. Phased delivery

Phased deliberately so mock mode remains the default fallback at every step —
this is the highest-risk integration.

- **Phase 0 — contracts & capability detection.** Extend the
  `VictimProvisioner` Protocol additively; add `VictimSnapshot`,
  `SandboxCapabilities`, `VictimTelemetryBundle` types; implement the prober;
  `MockProvisioner` satisfies the extended Protocol. `NemoClawProvisioner`
  records capabilities but behaviour is still the current recover/restore. No
  default change.
- **Phase 1 — lifecycle surface.** Promote `recover` to `recover_victim`;
  implement `snapshot_victim` (create + restore) where capabilities allow;
  write `sandbox_runs` / `victim_snapshots` rows (via migrations). Still not the
  default.
- **Phase 2 — ephemeral isolation.** Disposable per-lane work areas cloned from
  the baseline; real `teardown_victim`; `deterministic` flag propagated to
  `LaneResult`. Validated against a live NemoClaw build behind
  `MC_LIVE_NEMOCLAW`.
- **Phase 3 — real telemetry capture.** The telemetry capturer wired into the
  lane flow; `network/process/inference` observables populated from the real
  sandbox; `telemetry_events` densely populated.
- **Phase 4 — patch application.** The patch builder; `patch_verifier` runs its
  six gates against a real rebuilt-and-patched NemoClaw.
- **Phase 5 — make it the default (gated).** Only once Phases 0–4 pass against
  a live build does bootstrap default to the real provisioner *when the prober
  reports full capabilities*; otherwise it still falls back to mock. The
  `--use-mock-provisioner` flag and the credential-free demo remain forever.

Each phase is independently verifiable with the stubbed-CLI suite; the live
behaviour of Phases 2–5 is verified behind the `MC_LIVE_NEMOCLAW` marker.

## 14. Open questions

1. **NemoClaw snapshot capability.** The single largest unknown: the shipping
   config disables snapshots because `snapshot create` fails on the available
   CPU sandbox (`nemoclaw v0.0.44`). Phases 2–5 depend on a build where
   `snapshot create/restore` works. The capability prober and the recover-only
   degradation path mean MonkeyClaw runs *regardless* — but full determinism
   and per-lane patch verification require the snapshot-capable build. This is
   tracked as the gating dependency for Phase 5.
2. **Telemetry source of truth.** Whether NemoClaw exposes structured
   network/process/inference logs, or whether they must be reconstructed from
   sandbox introspection (`docker exec`, proxy logs), is unconfirmed. Phase 3
   ships whatever the live build offers; the purple-team `DerivedEvidenceAdapter`
   already covers the gap where a native stream is absent.
3. **Patch build cost.** Rebuilding NemoClaw per candidate patch may be slow.
   `patch_build_timeout_s` bounds it; if rebuild proves too expensive, an
   overlay-only "apply diff without full rebuild" mode is a Phase-4 sub-option,
   decided against measured build times.
4. **Work-area storage.** Disposable per-lane clones consume disk;
   `work_area_dir` is configurable and `teardown_victim` discards eagerly. A
   reaper for orphaned work areas (crashed before teardown) is a small Phase-2
   addition, parallel to the stale-claim sweep in the data-integrity spec.
