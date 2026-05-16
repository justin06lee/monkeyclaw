# Verifier Gate Hardening — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

The blue team's `PatchVerifier` (`blue_team/patch_verifier.py`) approves a
candidate patch only if all six gates pass. The six gates are sound in shape
but leave two exploitable holes:

1. **A patch can blind telemetry while still passing.** `gate_telemetry` checks
   that the patched run *produces* security telemetry — but "produces" is
   evaluated by the policy regression test, and a patch can satisfy that test
   while silently weakening the *detection* path the purple team relies on. The
   purple-team spec (`2026-05-15-purple-team-design.md`) introduces the
   detection oracle and the detection-as-pass quadrant: a blocked attack that
   emits no decision event is a `WEAK` quadrant — "invisible, will regress
   undetected". Nothing in the verifier asserts that a patch keeps the
   *detection* firing, only that some telemetry is emitted. A patch that fixes
   the behavior but degrades the control's observability passes today.

2. **The "vuln blocked" gate over-fits to one recorded repro.**
   `gate1_regression` replays exactly one transcript — the minimized repro
   captured by the replay-minimizer. A patch that special-cases that one
   payload (a string match, an exact-path block) passes the gate while every
   trivial variant of the same attack still works. `red_team/mutations.py`
   already contains 12 deterministic mutation operators built for exactly this
   class of transformation (paraphrase, benign framing, multi-turn split,
   instruction-in-tool-output, …). The verifier should weaponize them: a real
   fix blocks the attack *family*, not the attack *string*.

This spec hardens the verifier: it adds **gate 7 — detection still fires**, and
it strengthens the **vuln-blocked gate** to test the patch against mutated
variants of the original attack.

## 2. What already exists

Stated precisely so this spec hardens rather than rebuilds:

- **`PatchVerifier` (six gates)** — `blue_team/patch_verifier.py`. Gate
  sequence, `GateResult`/`VerifyOutcome` types, `_reject`, the
  `detect_control_plane_weakening` heuristics, the `_run_script` /
  `_run_full_suite` runners, and the `PatchedReplayFactory` seam are all built.
  The current gate ids: `gate_diff_applies`, `gate1_regression`,
  `gate2_functionality`, `gate3_full_suite`, `gate_control_plane`,
  `gate_telemetry`.
- **`gate_telemetry`** — runs `test_pair.policy_regression_test_script` (a
  `RegressionTestInput.policy_regression_test_script`, already an additive
  field in `interfaces/types.py`). It confirms *a* telemetry record exists; it
  does not confirm the *detection* path still fires.
- **`red_team/mutations.py`** — 12 named, deterministic, stdlib-only
  `MutationOperator`s in `MUTATION_OPERATORS`, plus `apply_operator(name,
  text)` and the `MutationStats` improvement tracker. Mutations are pure string
  transforms — no LLM, fully reproducible. Already consumed by
  `red_team/ideation.py` and `red_team/tournament.py`.
- **The detection oracle** — `purple_team/detection_oracle.py` and
  `interfaces/control_telemetry.py` are delivered by the purple-team spec. This
  spec *consumes* the oracle's `score(execution, telemetry) -> list[
  DetectionVerdict]` contract; it does not build it.
- **Replay/judge plumbing** — `blue_team/replay_minimizer.py` (`ReplayFn`,
  `JudgeFn`, `default_judge`) and `blue_team/test_generator.execute_test_script`
  are the existing gate execution substrate.

Nothing here re-implements gates, the control-plane detector, or the mutation
operators.

## 3. Scope

In scope:

- **Gate 7 — detection still fires** (`gate_detection`): after the patched run,
  assert the purple-team detection oracle still scores the control surface as
  observed (not `WEAK`/`FAIL` on the observability axis). A patch that blinds
  telemetry is rejected.
- **Strengthened vuln-blocked gate** (`gate1_regression` → split into the
  recorded-repro check plus a new `gate1b_mutation_robustness`): replay a
  configurable set of mutated variants of the original attack against the
  patched victim; an over-fitted patch that blocks the recorded payload but
  leaks on variants is rejected.
- New `interfaces/` types and a schema migration recording per-variant and
  per-detection gate results.
- Config knobs for the variant budget, operator selection, and the detection
  gate's strictness.

Explicitly out of scope (YAGNI for this spec):

- Building the detection oracle, telemetry adapter, or `control_telemetry.py`
  contract — owned by the purple-team spec.
- LLM-driven mutation (the 12 deterministic operators are sufficient and
  reproducible; semantic mutation is a later experiment).
- Re-deriving a fresh minimized repro from a passing variant (the variant set
  is a robustness probe, not a new finding source).
- Changing the patch isolation / rebuild path — owned by the
  real-patch-isolation spec; this spec runs *on top of* whatever replay
  surface that spec supplies.
- Auto-PR / approval-service changes.

## 4. Design constraints

1. **The gate contract is append-and-split, never reorder.** Existing gate ids
   keep their meaning. Gate 7 appends after `gate_telemetry`.
   `gate1b_mutation_robustness` runs immediately after `gate1_regression` so a
   patch that fails the recorded repro still short-circuits first (cheapest
   failure first).
2. **Mutations are deterministic.** `gate1b` uses `red_team/mutations.py`
   operators with no LLM call, so a verdict is byte-for-byte reproducible. The
   operator set and ordering are config-pinned.
3. **`red_team/mutations.py` is imported read-only.** The verifier consumes
   `apply_operator`; it does not extend or modify the operator catalogue. The
   import direction is blue → red for a pure, stateless utility — acceptable
   because mutations carry no red-team runtime state.
4. **The detection gate degrades safely.** If the detection oracle or telemetry
   adapter is unavailable (purple layer disabled by config), `gate_detection`
   is *skipped with a recorded reason*, exactly as `gate2`/`gate_telemetry`
   already skip when their input is absent. It never fabricates a pass.
5. **A stricter verifier must not silently reject historically-approved
   patches.** New gates are additive; the variant budget and detection
   strictness ship behind config with conservative defaults, and the rollout is
   phased (§13).
6. **`interfaces/` stays the contract firewall.** New shared types and the
   schema delta land in `interfaces/`; `blue_team/` imports them read-only.

## 5. Architecture

```
   PatchVerifier.verify(patch, package, test_pair)
        │   replay_fn = patched_replay_factory(patch)   (real or mock)
        ▼
   gate_diff_applies
        ▼
   gate1_regression          recorded minimized repro, patched victim
        ▼
   gate1b_mutation_robustness  ── red_team/mutations.py ──┐
        │   for op in selected operators:                 │
        │     variant = apply_operator(op, attack_text)    │
        │     replay variant → judge → must be BLOCKED     │
        ▼                                                  │
   gate2_functionality                                     │
        ▼                                                  │
   gate3_full_suite                                        │
        ▼                                                  │
   gate_control_plane                                      │
        ▼                                                  │
   gate_telemetry            policy regression test         │
        ▼                                                  │
   gate_detection  ── purple_team/detection_oracle ─────────┤
        │   score(patched execution, telemetry)            │
        │   require observability ∈ {observed}             │
        ▼                                                  │
   VerifyOutcome(approved, failed_gate, gates,             │
                 variant_results, detection_verdicts)  ◄────┘
```

## 6. Components

Each change is one file with one responsibility; no new package.

### 6.1 `gate1b_mutation_robustness` (new gate in `patch_verifier.py`)

- **Does:** After `gate1_regression` confirms the recorded repro is blocked,
  this gate derives a set of mutated attack variants from the original attack
  instruction and replays each against the patched victim. The gate **passes**
  only if *every* selected variant is judged blocked. Any variant that still
  succeeds means the patch over-fits the recorded payload → reject.
- **Variant derivation:** the original attack instruction is extracted from the
  repro package's minimal transcript (the highest-signal attacker turn). For
  each operator in the configured selection, `apply_operator(op, attack_text)`
  produces one variant; the variant is spliced back into a copy of the minimal
  transcript at the same turn position.
- **Interface:** internal `_run_mutation_robustness(patch, package, replay_fn)
  -> GateResult`; `GateResult.detail` carries a `variant_results` list
  (operator name, variant text hash, blocked bool).
- **Depends on:** `red_team/mutations.py` (`MUTATION_OPERATORS`,
  `apply_operator`), the existing `execute_test_script` / `judge_fn` substrate.

### 6.2 `gate_detection` (new gate 7 in `patch_verifier.py`)

- **Does:** After `gate_telemetry`, replays the recorded repro against the
  patched victim *with monitoring on*, materializes telemetry via the
  purple-team adapter, and calls the detection oracle. The gate **passes** only
  if the oracle scores every control surface the original attack touched with
  `observability == observed` — i.e. the patch did not move the control into a
  `WEAK` (silent) or `FAIL` quadrant on the observability axis. A patch that
  blocks the behavior but blinds the detection is rejected.
- **Distinct from `gate_telemetry`:** `gate_telemetry` asks "was *any*
  telemetry emitted?" (the policy regression test). `gate_detection` asks "does
  the *detection oracle* still recognize this attack?" — the purple-team
  detection-as-pass question. A patch can satisfy the former (emits a generic
  log line) and fail the latter (the specific decision event the oracle keys on
  is gone).
- **Interface:** internal `_run_detection_gate(patch, package, replay_fn) ->
  GateResult`; `GateResult.detail` carries the `DetectionVerdict` list.
- **Depends on:** `purple_team/detection_oracle.DetectionOracle`,
  `interfaces/control_telemetry.py`, `infra/monitoring_harness.py`.

### 6.3 `MutationVerifierConfig` / config additions

- **Does:** Carries the hardening knobs. Folded into `PatchVerifierConfig`
  (which already has `from_blue_team_cfg`):
  - `mutation_operators: list[str]` — which operators `gate1b` applies; default
    a curated subset that does not require an `extra` argument
    (`paraphrase`, `add_benign_framing`, `split_into_multi_turn`,
    `add_constraints`, `abstract_final_request`, `concretize_final_request`,
    `insert_untrusted_document`, `move_instruction_into_tool_output`).
  - `mutation_max_variants: int` — cap on variants tested (default 8).
  - `mutation_gate_enabled: bool` — default true.
  - `detection_gate_enabled: bool` — default true; auto-skips if the oracle is
    absent.
  - `detection_strictness: str` — `"observed_only"` (default — require
    `observed`) or `"allow_partial"` (accept `partial` for non-high severity).
- **Depends on:** `interfaces/config_schema.py` (blue-team config block).

### 6.4 Detection-oracle adapter binding (in `patch_verifier.py`)

- **Does:** `PatchVerifier.__init__` gains one optional injected parameter,
  `detection_oracle: DetectionOracle | None = None`. When `None`,
  `gate_detection` skips with a recorded reason. The pipeline injects the real
  oracle when the purple layer is enabled.
- **Depends on:** purple-team spec deliverables.

## 7. Data model additions

All land in `interfaces/schema.sql` via the migration system. `schema_meta`
already exists; this spec ships `infra/migrations/004_verifier_hardening.sql`
and bumps `schema_version` (sequenced after the patch-isolation migration if
both land — the migration runner reconciles by number).

- `patch_variant_results` — one row per mutated variant tested:
  `result_id`, `patch_id`, `vuln_id`, `operator`, `variant_hash`,
  `blocked` (bool), `judge_verdict`, `created_at`.
- `patch_detection_results` — one row per `gate_detection` run:
  `result_id`, `patch_id`, `vuln_id`, `zone_id`, `quadrant`
  (PASS/PARTIAL/WEAK/FAIL), `observability`, `prevention`, `passed` (bool),
  `evidence` (JSON), `created_at`.

New `interfaces/types.py` types:

- `VariantResult` — `operator: str`, `variant_hash: str`, `blocked: bool`,
  `judge_verdict: str`.

`VerifyOutcome` gains two additive fields (defaulted, so existing callers are
unaffected):

- `variant_results: list[VariantResult] = field(default_factory=list)`.
- `detection_verdicts: list[DetectionVerdict] = field(default_factory=list)`
  (`DetectionVerdict` is the purple-team type, imported read-only).

`DetectionVerdict` and `DetectionRule` are **not** redefined here — they are
the purple-team spec's types, reused.

## 8. Data flow

Inside `PatchVerifier.verify`, after the existing gates, the augmented sequence:

1. `gate_diff_applies` — unchanged.
2. `gate1_regression` — unchanged: recorded minimized repro replayed against
   the patched victim; must be blocked. Failure short-circuits (cheapest).
3. **`gate1b_mutation_robustness`** (new):
   a. Extract the attack instruction text from the repro package's minimal
      transcript.
   b. For each operator in `cfg.mutation_operators` (capped at
      `mutation_max_variants`): `variant = apply_operator(op, attack_text)`;
      splice into a transcript copy; replay against the patched victim; judge.
   c. Record each `VariantResult`. If any variant is judged *not blocked*,
      reject at `gate1b_mutation_robustness` with the leaking operator named.
4. `gate2_functionality`, `gate3_full_suite`, `gate_control_plane`,
   `gate_telemetry` — unchanged.
5. **`gate_detection`** (new gate 7):
   a. If `detection_oracle is None` → skipped `GateResult` with reason
      `"detection oracle not configured"`.
   b. Else replay the recorded repro against the patched victim with monitoring
      on; the telemetry adapter materializes `TelemetryEvent`s.
   c. `detection_oracle.score(execution, telemetry)` → `list[DetectionVerdict]`.
   d. Per `detection_strictness`, require every touched control surface to be
      `observed`. Any `WEAK`/`FAIL` on observability → reject at
      `gate_detection` with notes `"patch blinds detection on <surface>"`.
6. `VerifyOutcome` is returned with `variant_results` and `detection_verdicts`
   populated; both new result sets are persisted to the new tables.

## 9. Integration points

- **`blue_team/pipeline.py`** — constructs `PatchVerifier` with
  `detection_oracle=<purple oracle when enabled>` and the hardened
  `PatchVerifierConfig`. One conditional in `Pipeline.__init__`. When the
  purple layer is off, the verifier behaves as today plus `gate1b`.
- **`red_team/mutations.py`** — imported read-only for `apply_operator`. No
  change to that module.
- **`purple_team/detection_oracle.py`** — consumed via its `score(...)`
  contract. This spec adds no requirement to the purple-team spec beyond the
  contract it already publishes.
- **`blue_team/triage.py` / pipeline retry loop** — when `gate1b` rejects, the
  rejection reason names the leaking operator; the existing per-task candidate
  loop simply moves to the next candidate, unchanged.
- **Dashboard** — the patch panel gains a per-gate breakdown showing the
  variant pass/fail matrix and the detection quadrant. Additive.
- **Config** — `configs/monkeyclaw.yaml` gains the `blue_team` keys from §6.3.

## 10. Error handling

- **No attack text extractable** from the minimal transcript (degenerate repro)
  → `gate1b` skips with reason `"no attacker instruction to mutate"`, exactly
  like the existing `gate2` skip path. The patch is not rejected on a verifier
  shortcoming.
- **A mutation operator raises** (should not — operators are pure stdlib) → the
  individual variant is recorded `blocked=False, judge_verdict="error"` only if
  it genuinely leaked; an *operator* exception is caught, that variant is
  skipped with a logged warning, and the gate continues. An operator bug never
  fails a patch.
- **Replay of a variant explodes** → that variant's `GateResult`-equivalent is
  `blocked=False` with the error in detail — a variant that cannot be shown
  blocked is treated as not blocked (conservative; a patch must demonstrably
  hold).
- **Detection oracle raises or returns empty** → `gate_detection` is recorded
  as skipped with the error, **not** passed. The verifier never upgrades a
  verdict on missing detection evidence (mirrors the purple-team constraint
  "never upgrade on missing evidence").
- **Detection oracle absent** (purple disabled) → clean skip with reason; no
  alert, no failure.

## 11. Why these two changes and not more

The six gates plus these two close the two structural blind spots: over-fitting
(gate 1 family vs. gate 1 string) and detection blinding (gate 7 vs. gate
"telemetry exists"). Other plausible gates — performance regression, patch-size
limits, semantic-mutation robustness — are deliberately deferred: they either
need a data-collection phase (learned thresholds) or an LLM in the verifier
loop (non-deterministic verdicts), both of which violate constraint 2. The
deterministic operator set is the maximum hardening achievable without making
the verdict non-reproducible.

## 12. Testing strategy

Tests live in `test/` as `test_blue_verifier_hardening_*.py`, matching the
`test_blue_*` convention.

- `test_blue_verifier_hardening_mutation.py` — an **over-fitted patch** fixture
  (a replay function that blocks only the exact recorded string) must fail
  `gate1b_mutation_robustness`, and the failure must name the leaking operator.
  A **genuine patch** fixture (replay blocks the attack family) passes.
- `test_blue_verifier_hardening_mutation_determinism.py` — run `gate1b` twice
  on the same input; assert byte-identical `variant_results` (operators are
  deterministic).
- `test_blue_verifier_hardening_detection.py` — a fake oracle that returns
  `observability=observed` → `gate_detection` passes; one returning
  `WEAK`/silent → `gate_detection` rejects with the surface named.
- `test_blue_verifier_hardening_detection_skip.py` — with `detection_oracle=
  None`, assert `gate_detection` is a recorded skip, not a pass, and the patch
  can still be approved on the other gates.
- `test_blue_verifier_hardening_order.py` — assert gate ordering: a patch that
  fails the recorded repro fails at `gate1_regression` *before* `gate1b` runs
  (cheapest-failure-first preserved).
- `test_blue_patch_verifier.py` (existing) — extended to assert `VerifyOutcome`
  now carries `variant_results` and `detection_verdicts` and that the
  all-pass path reports eight gates.
- All tests run in mock mode, zero credentials, consistent with the repo's
  demo posture. The mutation operators need no model; the detection oracle is
  faked.

## 13. Phased delivery

- **Phase 0 — contracts:** `interfaces/types.py` additions (`VariantResult`,
  `VerifyOutcome` fields), `infra/migrations/004_verifier_hardening.sql`,
  `PatchVerifierConfig` knobs. No new gates active.
- **Phase 1 — mutation robustness:** `gate1b_mutation_robustness` implemented
  and wired after `gate1_regression`; default `mutation_gate_enabled=true` but
  the operator selection is conservative. Persist `patch_variant_results`.
- **Phase 2 — detection gate:** `gate_detection` implemented; injected
  `detection_oracle` parameter; auto-skip when absent. Persist
  `patch_detection_results`. Requires the purple-team oracle to exist; until
  then the gate is a permanent recorded skip and nothing regresses.
- **Phase 3 — pipeline + dashboard:** pipeline injects the real oracle and the
  hardened config; dashboard variant/quadrant panel.
- **Phase 4 — tuning:** widen the operator selection and tighten
  `detection_strictness` once Phase 1–2 data shows the false-rejection rate is
  acceptable.

Phase 1 lands independently of the purple-team spec. Phase 2 depends on the
purple-team detection oracle; until it ships, `gate_detection` is a clean skip,
so the verifier is strictly stronger than today (gate 1b) without ever blocking
on a missing dependency.

## 14. Open questions

1. **Variant budget vs. cost.** Eight variants × one replay each multiplies
   `gate1b` cost by 8 over a single replay. With the real patched-build
   isolation path, each replay is cheap (same victim, no rebuild). If it
   becomes a bottleneck, the operator selection shrinks or runs the variants
   against a single shared patched build — already true under the
   real-patch-isolation design. No rework needed.
2. **Operator coverage of zone families.** The curated operator subset skips
   operators needing an `extra` argument (`change_persona`,
   `combine_two_ideas`, `move_instruction_into_dependency_metadata`). A later
   iteration can synthesize a sensible `extra` per zone; not needed for the
   first hardening pass.
3. **Detection strictness for low-severity patches.** `allow_partial` exists as
   a knob but defaults off. Whether low-severity patches should be allowed to
   ship with `partial` detection is a policy call deferred to Phase 4 data.
