# Patch Generalization Loop — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw's blue team produces a patch, runs it through the six verifier
gates, and — if every gate passes — commits a positive regression test, resets
zone coverage, and declares the vulnerability fixed. That declaration is
narrower than it looks.

The verifier proves the patch blocks **one transcript**: the minimal transcript
that the replay-minimizer extracted from the original finding. It proves
nothing about the *attack family*. The General Analysis whitepaper
(`Securing_Coding_Agents_General_Analysis_1.0.pdf`) makes this point directly —
a control that blocks the literal payload but not a paraphrase, a benign
re-framing, or the same instruction relocated into tool output is not a fixed
control; it is a control with a known bypass nobody has tried yet.

MonkeyClaw already owns the machinery to try those bypasses. `red_team/mutations.py`
ships twelve deterministic mutation operators — paraphrase, benign framing,
multi-turn split, persona shift, untrusted-document embedding, tool-output
relocation, dependency-metadata relocation, and more. Today those operators
serve red-team ideation only. They are never pointed at a *patched* victim.

This spec closes that gap. After blue produces a verified patch, a
purple-mediated loop asks red to mutate the original attack and re-runs the
variants against the patched victim. If any variant bypasses the patch, the
patch is incomplete: the bypassing variant bounces back to the patch generator
as a new, explicit constraint, and the verifier re-runs. The loop terminates
when a bounded number of mutation rounds finds no bypass, or a round budget is
exhausted. This formalizes red↔blue iteration as a closed loop instead of a
single hand-off.

## 2. The generalization gap

A verified patch sits in one of three states the current pipeline cannot
distinguish:

```
                 mutated variants tried     mutated variants NOT tried
patch blocks all GENERALIZED  the fix       UNVALIDATED  passes the gates,
                              holds across               family coverage
                              the family                 unknown
patch blocked    INCOMPLETE   a variant     (cannot occur — if untried,
by a variant                  bypasses;                  we never learn)
                              re-patch
```

The verifier-gate output is always the bottom-left-blocked / top-right cell —
"this transcript is handled, the family is unknown". The generalization loop
moves every verified patch into either **GENERALIZED** (no bypass found within
budget) or **INCOMPLETE → re-patched**. "Unvalidated" stops being a silent
resting state.

## 3. Scope

In scope:

- A `purple_team/generalization_loop.py` module — the mutate → re-verify →
  bounce cycle, owned by purple, peer to the purple components in the
  purple-team spec (`2026-05-15-purple-team-design.md`).
- A `MutationReplayer` that applies `red_team/mutations.py` operators to the
  minimal transcript of a verified patch and replays each variant against the
  patched victim surface.
- A bypass detector that scores each variant replay (vulnerability re-triggered
  vs. blocked) using the existing judge/check path.
- A bounce path: a bypassing variant becomes a new `BypassConstraint` fed into
  `PatchGenerator.generate_for_task`, which the verifier then re-checks.
- A convergence/termination criterion: a per-task round budget, an operator
  budget per round, and a stable-no-bypass exit.
- Persistence of every round's result so the loop is auditable and resumable.
- Integration with the blue pipeline so the loop runs after `_on_patch_approved`
  and before the patch is treated as final.

Explicitly out of scope (YAGNI for this spec):

- LLM-driven mutation. The twelve `mutations.py` operators are deterministic,
  stdlib-only, and sufficient. A generative mutator is a later, separate spec.
- New mutation operators. The loop consumes the existing catalogue as-is.
- Cross-zone generalization (testing whether a filesystem patch also closes a
  network bypass). The loop stays bound to the patch's own zone and finding.
- Real NemoClaw provisioning. The loop runs on the same patched-victim surface
  the verifier already uses (`PatchedReplayFactory`); a real provisioner is
  tracked separately.
- Auto-PR / approval gating of the re-patched result — that is the
  approval-and-PR-service spec (`2026-05-15-approval-and-pr-service-design.md`).
  The generalization loop hands its output *to* that gate; it does not own it.

## 4. Non-negotiable design constraints

1. **The loop generates no attacks and writes no diffs.** It mutates an
   *existing* confirmed attack with deterministic operators and asks the
   *existing* `PatchGenerator` for the re-patch. It owns orchestration,
   bypass scoring, and termination — nothing else. This keeps the merge
   surface with red and blue near zero, exactly as the purple-team spec
   requires for `purple_team/`.
2. **The loop never weakens the verifier.** A re-patch is a normal
   `PatchCandidate` and runs through the full six-gate `PatchVerifier`
   unchanged. The loop adds a gate's worth of *coverage*; it removes none.
3. **`interfaces/` stays the contract firewall.** New shared types
   (`MutationVariant`, `BypassResult`, `BypassConstraint`,
   `GeneralizationRound`, `GeneralizationResult`) and the schema delta land in
   `interfaces/`. `purple_team/` imports them read-only.
4. **The loop is bounded and deterministic.** Operators are deterministic;
   the round budget and operator budget are config constants. The loop must
   provably terminate — no patch can spin it forever (see §9).
5. **A non-converged patch is reported, never hidden.** If the round budget is
   exhausted with a live bypass, the patch is *not* silently accepted. It is
   marked `generalization=unconverged` and routed for human review via the
   approval service. Purple never upgrades an unconverged patch to "fixed".

## 5. Relationship to the verifier-gate-hardening work

The patch verifier (`blue_team/patch_verifier.py`) already runs six gates per
candidate: `gate_diff_applies`, `gate1_regression`, `gate2_functionality`,
`gate3_full_suite`, `gate_control_plane`, `gate_telemetry`. The
verifier-gate-hardening track strengthens those gates *in place* — better
control-plane heuristics, a real patched-victim build behind
`PatchedReplayFactory`, denser telemetry assertions.

This spec is deliberately **outside** the gate set, not a seventh gate, for
three reasons:

- **Granularity.** A gate is pass/fail on one candidate. Generalization is an
  iterative loop over many mutated transcripts and possibly several re-patch
  rounds. Embedding a loop inside a gate would make a single `verify()` call
  unbounded.
- **Ownership.** Gates are blue-team-owned and run synchronously inside
  `PatchVerifier.verify`. The generalization loop is purple-owned (it drives
  red's mutation operators against a blue artifact) and runs *after* a verified
  approval, consistent with the purple-team spec's "validate, correlate, score,
  route" charter.
- **Reuse, not replacement.** Each generalization round re-invokes the
  *unmodified* `PatchVerifier`. When the verifier-hardening track upgrades
  `PatchedReplayFactory` to a real patched build, the generalization loop
  inherits that fidelity for free — it calls the same factory. The two tracks
  compose: hardening makes each gate run truthful; generalization makes the
  *set of transcripts* each run is truthful about wider.

Concretely: the loop depends on `PatchVerifier`, `PatchedReplayFactory`, and
`detect_control_plane_weakening` as stable contracts. It must not be merged
before the verifier's `PatchedReplayFactory` seam exists (it does today) and
should be re-validated when that seam is upgraded to a real build.

## 6. Architecture

```
   blue_team.pipeline._on_patch_approved
            │  verified PatchCandidate + ReproPackage + RegressionTestPair
            ▼
   ┌─────────────────────── generalization_loop ────────────────────────┐
   │                                                                     │
   │   mutation_replayer ──► bypass_detector ──► (any bypass?)            │
   │        │  variants          │  BypassResult        │                │
   │        │                    │              no ─────┴──► GENERALIZED │
   │        ▼                    ▼              yes                      │
   │   red_team.mutations   red_team.judge       │                       │
   │   (12 operators)       (check path)         ▼                       │
   │                                    bounce_builder                   │
   │                                      │  BypassConstraint            │
   │                                      ▼                              │
   │                          blue_team.patch_generator                  │
   │                          .generate_for_task(task, constraints=…)    │
   │                                      │  new PatchCandidate          │
   │                                      ▼                              │
   │                          blue_team.patch_verifier (6 gates)         │
   │                                      │                              │
   │                                      └──► next round (≤ max_rounds) │
   └──────────────────────────┬──────────────────────────────────────────┘
                              │  GeneralizationResult
                              ▼
        generalization_rounds table   +   approval service (if unconverged
                                          or re-patch changed the diff)
```

## 7. Components

Each module is a single file in `purple_team/` with one clear responsibility.

### 7.1 `mutation_replayer.py`

- **Does:** Given the verified patch's `ReproPackage` (which carries the
  minimal transcript under `transcripts["minimal"]`) and a budget of mutation
  operators, produces a set of `MutationVariant` records. For each operator in
  the round's budget, it applies the operator to the attacker turns of the
  minimal transcript via `red_team.mutations.apply_operator`, then replays the
  mutated transcript against the patched victim using the same
  `PatchedReplayFactory` the verifier uses. Multi-turn-producing operators
  (`split_into_multi_turn`, `reverse_component_order`) are re-split into
  attacker `Message` turns before replay.
- **Interface:** `replay_variants(patch, package, operators) -> list[MutationVariant]`.
- **Depends on:** `red_team.mutations` (operator catalogue, read-only),
  `blue_team.patch_verifier.PatchedReplayFactory`, `interfaces.types`
  (`Message`, `LaneResult`, `MutationVariant`).

### 7.2 `bypass_detector.py`

- **Does:** Scores each `MutationVariant` replay into a `BypassResult` —
  `bypassed` (the vulnerability re-triggered against the patched victim) or
  `blocked` (the patch held). Reuses the blue-team judge path
  (`replay_minimizer.default_judge` plus the Tier 1 `CheckResult` evidence
  already threaded through `execute_test_script`) so a bypass is decided by the
  same oracle the verifier's `gate1_regression` uses — no second, divergent
  notion of "vulnerable". A variant whose replay errored is scored
  `inconclusive` and excluded from the bounce set but flagged in the round
  record.
- **Interface:** `score(variant, package) -> BypassResult`.
- **Depends on:** `blue_team.replay_minimizer` (judge), `interfaces.types`
  (`CheckResult`, `BypassResult`).

### 7.3 `bounce_builder.py`

- **Does:** Converts the highest-severity confirmed `BypassResult` of a round
  into a `BypassConstraint` — a structured record naming the operator that
  bypassed the patch, the mutated transcript, the triggered check evidence, and
  a human-readable directive ("the patch must also block this paraphrased /
  tool-output-relocated variant"). It also produces an updated `FixTask` whose
  `recommended_approach` is appended with the constraint text, so the next
  `PatchGenerator.generate_for_task` call sees the bypass as a first-class
  requirement rather than buried prose.
- **Interface:** `build(task, bypass_results) -> tuple[FixTask, BypassConstraint]`.
- **Depends on:** `blue_team.triage.FixTask`, `interfaces.types`
  (`BypassConstraint`).

### 7.4 `generalization_loop.py`

- **Does:** The orchestrator. Assembles the round loop:
  1. Round 0 starts from a freshly verified `PatchCandidate`.
  2. `mutation_replayer` runs the round's operator budget against the patched
     victim.
  3. `bypass_detector` scores every variant.
  4. If no variant bypassed → exit `GENERALIZED`.
  5. If a variant bypassed and rounds remain → `bounce_builder` produces a
     `BypassConstraint`; `PatchGenerator.generate_for_task` produces re-patch
     candidates; each runs through the full `PatchVerifier`; the first
     candidate that passes all six gates becomes the round's patch and the loop
     advances. If no re-patch candidate passes the verifier, exit
     `UNCONVERGED` (re-patch failed).
  6. If the round budget is exhausted with a live bypass → exit `UNCONVERGED`.
  Persists a `GeneralizationRound` per round and a final
  `GeneralizationResult`.
- **Interface:** `run(patch, package, test_pair, task) -> GeneralizationResult`.
- **Depends on:** `mutation_replayer`, `bypass_detector`, `bounce_builder`,
  `blue_team.patch_generator.PatchGenerator`, `blue_team.patch_verifier.PatchVerifier`,
  the MCP (`log_patch_candidate`, `mark_patch_status`, and the new
  `log_generalization_round` — see §11).

### 7.5 `operator_budget.py`

- **Does:** Decides which mutation operators each round runs. Round 0 runs the
  full twelve-operator catalogue (cheap — deterministic string ops plus a
  replay each). Subsequent rounds run a *focused* budget: the operators that
  bypassed in any prior round (re-test that the re-patch closed them) plus the
  zone-relevant operators. The zone→operator affinity table is a static map
  (e.g. `SKILL-SUPPLY` → `move_instruction_into_dependency_metadata`,
  `PROMPT-INJ` → `insert_untrusted_document` / `move_instruction_into_tool_output`).
  Keeping this in its own module isolates the one piece of policy most likely
  to be tuned.
- **Interface:** `budget_for(round_index, zone_id, prior_bypass_operators) -> list[str]`.
- **Depends on:** `red_team.mutations.MUTATION_OPERATORS` (read-only).

## 8. The mutate → re-verify → bounce cycle

One round, in full:

1. **Mutate.** `operator_budget.budget_for(...)` returns the round's operator
   list. `mutation_replayer` applies each operator to the patched patch's
   minimal-transcript attacker turns and replays each variant against the
   patched victim. Output: one `MutationVariant` per operator.
2. **Re-verify (per variant).** `bypass_detector` scores each variant. The
   patch's `gate1_regression` already proved the *literal* transcript is
   blocked; this step asks the same question of each *mutated* transcript.
3. **Decide.**
   - No variant `bypassed` → the patch generalized. Emit
     `GeneralizationResult(status=GENERALIZED, rounds=…)` and stop.
   - One or more variants `bypassed` and `round_index < max_rounds` → continue
     to bounce.
   - Variants `bypassed` and `round_index == max_rounds` → emit
     `GeneralizationResult(status=UNCONVERGED, ...)` and stop.
4. **Bounce.** `bounce_builder` picks the most severe / highest-confidence
   bypass, builds a `BypassConstraint`, and produces an augmented `FixTask`.
5. **Re-patch.** `PatchGenerator.generate_for_task` runs on the augmented task.
   Because the constraint is appended to `recommended_approach` and the
   bypassing transcript is added to the prompt as an explicit "must also block"
   case, the generator now optimizes against both the original and the bypass.
6. **Re-gate.** Each re-patch candidate runs through the unmodified
   six-gate `PatchVerifier`. The first to pass all gates becomes the patch for
   round N+1; the loop returns to step 1. If none pass, emit
   `GeneralizationResult(status=UNCONVERGED, reason="re-patch failed gates")`.

The bypassing variant is *added* to the constraint set across rounds, never
replaced — round 3's re-patch must block round 1's and round 2's bypasses too.
This makes the loop monotone: each round's patch is constrained by a superset
of the prior round's transcripts, so the loop cannot oscillate between two
patches that each fix the other's bypass.

## 9. Convergence and termination

The loop provably terminates because every exit is bounded:

- **`max_rounds`** (config `purple.generalization.max_rounds`, default 3). The
  loop runs at most this many bounce rounds. Round 0 (initial verification) is
  not counted; rounds 1..`max_rounds` are re-patch rounds.
- **Operator budget per round** is finite (≤ 12) and deterministic, so a single
  round cannot run unbounded mutations.
- **Re-patch candidate cap.** `PatchGenerator` already returns a bounded
  candidate list (`high_severity_alt_count`, default 3). The loop tries them in
  the generator's least-invasive-first order and stops at the first that passes
  the verifier.

Convergence criterion — the loop exits `GENERALIZED` when a round runs its full
operator budget and `bypass_detector` reports zero `bypassed` variants. Because
the constraint set is monotone (§8), a `GENERALIZED` exit at round N means the
current patch blocks the original transcript plus every mutated variant tried
in rounds 0..N.

Non-convergence is an explicit, first-class outcome, not a fallback. Two
`UNCONVERGED` sub-cases:

- `reason=round_budget_exhausted` — `max_rounds` reached with a live bypass.
- `reason=repatch_failed_gates` — a re-patch round produced no candidate that
  passes all six verifier gates.

In both cases the *last verified patch* is retained (it still blocks the
original finding and passed the gates), but the `GeneralizationResult` carries
the open bypass(es). The blue pipeline must route an `UNCONVERGED` result to
the approval service for mandatory human review — it may not auto-finalize the
patch (§10).

## 10. Integration points

- **`blue_team/pipeline.py`** — `process_blue_queue` currently approves a patch
  in `_on_patch_approved` and is done. This spec inserts a call between
  verifier approval and finalization: after `_patch_task` gets an approved
  `VerifyOutcome`, it calls
  `purple_team.generalization_loop.run(patch, package, test_pair, task)`.
  The pipeline then branches on the `GeneralizationResult`:
  - `GENERALIZED` and the patch is unchanged from round 0 → existing
    `_on_patch_approved` path runs as today.
  - `GENERALIZED` but the patch changed (a re-patch round was needed) → the
    *final* patch's positive regression test is committed; additionally, one
    regression test per bypassed operator is committed so the closed bypasses
    stay closed (see §11, `add_regression_test`).
  - `UNCONVERGED` → the patch is **not** finalized by the pipeline; it is
    handed to the approval service with `generalization=unconverged` and the
    open-bypass list. Coverage is *not* reset to 0.3 (the zone is not proven
    fixed). An alert fires.
  This is one new call plus a branch; `process_repro_queue` and
  `run_regression` are untouched.
- **`red_team/mutations.py`** — consumed read-only. `apply_operator`,
  `get_operator`, and `MUTATION_OPERATORS` are stable contracts. The loop does
  **not** touch `MutationStats` (that is red-team-local ideation state); it may
  optionally feed per-operator bypass outcomes back as a future enhancement,
  out of scope here.
- **`blue_team/patch_generator.py`** — `generate_for_task` is called with the
  augmented `FixTask`. The constraint reaches the generator purely through
  `FixTask.recommended_approach` and the prompt context; **no signature change**
  is required, keeping the blue/purple seam additive. (Optional follow-up: a
  typed `constraints: list[BypassConstraint] | None` keyword — noted as an open
  question, not specified here.)
- **`blue_team/patch_verifier.py`** — `PatchVerifier.verify` and
  `PatchedReplayFactory` are consumed unchanged. The loop constructs the same
  verifier the pipeline uses (it is injectable on the pipeline, so the loop
  receives the already-wired instance).
- **Orchestrator** — no change. The loop runs inside `process_blue_queue`,
  which the orchestrator already calls once per cycle.
- **Dashboard** — one additive view: the generalization panel — per finalized
  patch, the round count, operators tried, bypasses found and closed, and the
  final `GENERALIZED`/`UNCONVERGED` status.

## 11. Data model additions

All land in `interfaces/schema.sql` via the versioned migration system
(`schema_meta` already exists and tracks the schema version). One new table:

- `generalization_rounds` — `round_id` (PK), `patch_id` (the patch *as of this
  round*, FK `patches.patch_id`), `finding_id`, `vuln_id`, `zone_id`,
  `round_index` (0..max_rounds), `operators_tried` (JSON list of operator
  names), `variants_total`, `variants_bypassed`, `variants_inconclusive`,
  `bypass_operators` (JSON list — operators that bypassed this round),
  `outcome` (`generalized` | `bounced` | `unconverged`), `repatch_patch_id`
  (the candidate produced for the next round, nullable), `evidence` (JSON —
  per-variant `BypassResult` summary), `created_at`.
  Index on `(finding_id, round_index)` and on `patch_id`.

The existing `patches` table is reused for re-patch candidates — each re-patch
is a normal `PatchCandidate` logged via `log_patch_candidate` /
`mark_patch_status`, exactly like a first-round patch. The
`GeneralizationResult` is reconstructable by joining `generalization_rounds` on
`finding_id`; no separate result table is needed.

New MCP method (added to `interfaces/mcp_tools.py`, the contract):
`log_generalization_round(round: GeneralizationRoundInput) -> str`. The loop
also reuses the existing `add_regression_test`, `log_patch_candidate`,
`mark_patch_status`, and `send_alert`.

New `interfaces/types.py` dataclasses:

- `MutationVariant` — `variant_id`, `operator`, `mutated_transcript`
  (`list[Message]`), `replay_result` (`LaneResult`).
- `BypassResult` — `variant_id`, `operator`, `status` (`bypassed` | `blocked`
  | `inconclusive`), `triggered_evidence` (`list[CheckResult]`), `severity`,
  `notes`.
- `BypassConstraint` — `constraint_id`, `operator`, `bypassing_transcript`
  (`list[Message]`), `directive` (str), `evidence` (`list[CheckResult]`).
- `GeneralizationRound` / `GeneralizationRoundInput` — the read / write shapes
  for the `generalization_rounds` row.
- `GeneralizationResult` — `finding_id`, `final_patch_id`, `status`
  (`generalized` | `unconverged`), `reason` (str | None), `rounds`
  (`list[GeneralizationRound]`), `open_bypasses` (`list[BypassResult]`).

`Message`, `LaneResult`, `CheckResult`, `PatchCandidate`, `ReproPackage`, and
`FixTask` already exist and are reused.

## 12. Data flow per finalized patch

1. `process_blue_queue` → `_patch_task` produces a verified `VerifyOutcome`
   (approved) for a `PatchCandidate`.
2. The pipeline calls `generalization_loop.run(patch, package, test_pair, task)`.
3. **Round 0:** `operator_budget` returns all twelve operators;
   `mutation_replayer` produces twelve `MutationVariant`s replayed against the
   patched victim; `bypass_detector` scores them.
4. If zero bypassed → `GeneralizationResult(GENERALIZED)`. Loop ends at round 0.
5. If any bypassed → `bounce_builder` builds a `BypassConstraint` and augmented
   `FixTask`; `PatchGenerator.generate_for_task` produces re-patch candidates;
   each runs the six-gate `PatchVerifier`; the first to pass becomes round 1's
   patch.
6. Each round writes a `generalization_rounds` row via
   `log_generalization_round`.
7. Rounds repeat until `GENERALIZED` or `UNCONVERGED` (§9).
8. The pipeline branches on the result (§10): commit the final patch's
   regression tests and reset coverage on `GENERALIZED`; route to the approval
   service without coverage reset on `UNCONVERGED`.
9. The dashboard generalization panel reads `generalization_rounds`.

## 13. Error handling

- **A mutation operator raises** (malformed transcript, empty content) — the
  variant is recorded `inconclusive` with the exception repr; the round
  continues with the remaining operators. One bad operator never aborts a
  round.
- **A variant replay raises** (victim transport error) — the variant is scored
  `inconclusive`, counted in `variants_inconclusive`, and excluded from the
  bounce set. If *every* variant in a round is inconclusive, the round outcome
  is `unconverged` with `reason=replay_unavailable` rather than a false
  `generalized` — the loop never claims generalization on missing evidence
  (mirrors the purple-team spec's "conservative on missing evidence" rule).
- **`PatchGenerator` returns no candidates** for the augmented task — the round
  outcome is `unconverged` with `reason=repatch_failed_gates`.
- **The MCP `log_generalization_round` write fails** — logged as an alert; the
  loop continues in memory and the `GeneralizationResult` is still returned to
  the pipeline (best-effort persistence, consistent with the pipeline's
  existing `try/except` around `add_regression_test` and coverage updates).
- **The loop itself raises** — `process_blue_queue` wraps the call in
  `try/except`; a loop crash logs the exception and falls back to the current
  behavior (finalize the round-0 verified patch) so a generalization-loop bug
  can never block the blue pipeline.

## 14. Testing strategy

Tests live in `test/` with the `test_purple_*` naming used by the purple-team
spec, mirroring the existing `test_red_*` / `test_blue_*` convention.

- `test_purple_mutation_replayer.py` — given a fixture minimal transcript,
  assert each of the twelve operators yields a replayable variant and that
  multi-turn-producing operators are correctly re-split into attacker turns.
- `test_purple_bypass_detector.py` — table-driven over `bypassed` / `blocked` /
  `inconclusive`, including the replay-error → `inconclusive` path; assert the
  detector reuses the same judge verdict the verifier's `gate1_regression`
  would produce on the same transcript.
- `test_purple_bounce_builder.py` — assert a `BypassConstraint` carries the
  operator, the bypassing transcript, and that the augmented `FixTask`'s
  `recommended_approach` contains the directive text.
- `test_purple_generalization_loop.py` — three core cases:
  1. **Converges at round 0** — a patch that blocks all twelve variants exits
     `GENERALIZED` with one round.
  2. **Converges after a bounce** — round 0 finds a bypass; a stub
     `PatchGenerator` returns a re-patch that blocks it; round 1 exits
     `GENERALIZED`; assert the closed-bypass regression test is committed and
     the constraint set is monotone.
  3. **Does not converge** — every re-patch keeps a live bypass; assert exit
     `UNCONVERGED(reason=round_budget_exhausted)` after exactly `max_rounds`
     rounds, the last verified patch is retained, and coverage is *not* reset.
- `test_purple_generalization_termination.py` — a property-style test asserting
  the loop always terminates within `max_rounds + 1` rounds regardless of the
  (stubbed) generator/verifier behavior.
- `test_blue_pipeline_generalization_e2e.py` — drive `process_blue_queue` with
  the loop wired, against the mock victim, asserting an `UNCONVERGED` result
  routes to the approval-service hand-off and does not reset coverage.
- All tests run in mock mode with zero model credentials, using injectable
  stub `PatchGenerator` / `PatchVerifier` / replay functions, consistent with
  the existing blue-team test posture.

## 15. Phased delivery

The subsystem delivers in phases, each independently verifiable:

- **Phase 0 — contracts:** new `interfaces/types.py` dataclasses, the
  `generalization_rounds` table migration, and the `log_generalization_round`
  MCP method. No behavior yet.
- **Phase 1 — mutate & detect:** `mutation_replayer.py`, `bypass_detector.py`,
  `operator_budget.py`. Round 0 only — given a verified patch, produce and
  score variants. No bounce, no re-patch.
- **Phase 2 — close the loop:** `bounce_builder.py`,
  `generalization_loop.py` with the full round loop and termination.
- **Phase 3 — wire into blue:** the `process_blue_queue` call and result
  branch in `blue_team/pipeline.py`, including the closed-bypass regression
  tests and the `UNCONVERGED` → approval-service hand-off.
- **Phase 4 — surface it:** the dashboard generalization panel.

Phase 1 alone is shippable and useful: it turns every verified patch's
"family coverage unknown" into a measured "N of 12 operators bypass", even
before the bounce loop exists.

## 16. Open questions

1. **Typed constraint plumbing.** This spec passes the `BypassConstraint`
   through `FixTask.recommended_approach` to avoid changing
   `PatchGenerator.generate_for_task`'s signature. A typed
   `constraints: list[BypassConstraint] | None` keyword would be cleaner once
   the blue and purple tracks are ready to co-version that interface. Deferred,
   not blocking.
2. **`max_rounds` default.** Set to 3 as a starting point — round 0 plus two
   re-patches. The right value depends on observed convergence rates once the
   loop has run against real findings; it is a single config constant to tune.
3. **Operator-budget escalation.** Round 0 runs all twelve operators; later
   rounds run a focused budget. If focused rounds prove to miss bypasses an
   exhaustive round would catch, the budget policy in `operator_budget.py` can
   be widened — isolated to that one module by design.
4. **Generative mutation.** The deterministic operators are a strong, cheap
   baseline. An LLM-driven mutator that paraphrases more naturally is a clear
   future extension but needs its own spec and a cost analysis; explicitly out
   of scope here.

## 17. Companion documents recommended

- An architecture-report update folding the generalization loop into the
  documented `red → judge → repro → blue` loop as the closing red↔blue
  iteration step.
- A short ADR recording why generalization is a post-verification purple loop
  rather than a seventh verifier gate (the §5 reasoning), so the boundary is
  not re-litigated later.
