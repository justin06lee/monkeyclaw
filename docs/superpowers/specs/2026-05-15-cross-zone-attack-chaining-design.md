# Cross-Zone Attack Chaining — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

Real security incidents are not single-zone events. An attacker injects an
instruction through an untrusted document (`PROMPT-INJ`), uses the foothold to
read a credential file (`PRV-LEAK`), and exfiltrates it over an allowlisted
domain (`SBX-NET`). Each step, considered alone, may look survivable: the
injection is "just" a refused odd request, the file read is "just" reading a
file, the network call is "just" a permitted egress. The breach is the
*composition*. The General Analysis whitepaper makes the same point — its
adversarial corpus describes multi-step kill chains, not isolated probes.

MonkeyClaw already has a `red_team/strategist.py` and the
`execution_agent.py` v4 "deep-dive" prompt talks about an "attack chain." But
what it builds today is **not a multi-zone kill chain** — it is a multi-*step*
plan that still has exactly **one** primary zone, scored against that one zone
(see §2 for precisely what exists). Nothing in MonkeyClaw composes a sequence
of single-zone primitives across zone boundaries, executes that sequence as a
unit, or attributes a chained breach back across the zones it traversed.

This spec adds a true cross-zone composer: it sequences single-zone attack
primitives — including archive elites from different zones — into multi-zone
kill chains, executes them as ordered units against the live victim, and
attributes the resulting finding across every zone the chain touched, so
coverage credit is shared correctly.

## 2. What `red_team/strategist.py` does today (precise statement)

The current `Strategist.synthesize(ideas, zones_by_id, cycle_id, n_chains)`:

- Takes the cycle's batch of raw `IdeaObject`s (from the three ideation modes).
- Makes **one** LLM call that asks the model to fuse them into `n_chains`
  distinct "attack chains."
- Each output object has a `steps` list (3–7 free-text strings), a
  `builds_on` list of raw-idea indices, and — critically — **one**
  `primary_zone`. The schema blurb states this explicitly: *"has ONE primary
  target zone — the zone whose defense it ultimately breaks (this is how the
  result is scored)."*
- Returns each chain as a plain `IdeaObject` whose `approach` is the rendered
  step list. The pipeline then runs one deep-dive lane per chain
  (`pipeline.py::generate_ideas` → `execute_lane`), and `judge()` scores it
  against that single `primary_zone`.

So today: **the strategist produces multi-step, single-zone plans.** The steps
may *mention* other zones, but the chain is one `IdeaObject`, runs in one lane,
is judged once, and credits coverage to one zone. It also does not draw on the
MAP-Elites archive (`red_team/archive.py`) — it only sees the current cycle's
raw ideas. There is no chain grammar, no per-step zone attribution, no notion
of a step's *output* feeding the next step's *precondition*.

This spec keeps the strategist's batch-synthesis call and its `n_chains`
shape, and extends it: a chain becomes a typed, multi-zone object with
per-step zone attribution and inter-step data dependencies, drawn from archive
elites as well as cycle ideas.

## 3. Scope

In scope:

- A **chain grammar** — a typed representation of a kill chain as an ordered
  list of `ChainStep`s, each bound to a zone, with declared `produces` /
  `requires` capability tokens linking a step's output to the next step's
  precondition.
- A **`red_team/chain_composer.py`** module that builds `AttackChain`s by
  sequencing primitives drawn from (a) the cycle's ideas and (b) archive
  elites from `red_team/archive.py`, across zone boundaries.
- Extension of `red_team/strategist.py` to emit `AttackChain`s instead of
  single-zone `IdeaObject` plans, reusing its existing batch LLM call.
- **Multi-zone execution** — a `ChainExecutionAgent` that runs an ordered chain
  against one victim, carrying state (the captured `produces` tokens) between
  steps, and stops a chain when a step's precondition is unmet.
- **Cross-zone attribution** — a `chain_attribution.py` module that, given a
  chained finding, distributes coverage credit and finding records across the
  zones the chain traversed.
- Schema + `interfaces/` types for chains, steps, and chain findings.

Explicitly out of scope (YAGNI for this spec):

- Branching / conditional chains (a DAG of steps). Chains are linear ordered
  sequences in this spec; a tree is a later extension and the grammar leaves
  room for it (§4).
- Learned chain ranking — chain priority is heuristic here; predicting which
  chains are worth running is the learned-ranking-model spec
  (`2026-05-15-learned-ranking-model-design.md`).
- Cross-*victim* chains (a chain that spans two sandboxes). One chain, one
  victim instance.
- Replacing single-zone ideation. Single-zone primitives remain the unit of
  ideation; chaining composes them.
- Repro-side handling of multi-zone findings beyond emitting one finding per
  traversed zone — blue-team chain triage is a follow-on.

## 4. The chain grammar

A kill chain is an `AttackChain`: an ordered, linear list of `ChainStep`s plus
chain-level metadata. The grammar's job is to make "the output of step *k*
enables step *k+1*" explicit and machine-checkable, so execution can verify a
chain is still on-track and attribution knows which zones genuinely
participated.

```
AttackChain
  chain_id           : str            CHAIN-<uuid>
  cycle_id           : int
  title              : str
  zones              : list[str]      every zone the chain traverses, in order
  primary_zone       : str            the zone of the terminal breach step
  steps              : list[ChainStep]  ordered, linear
  builds_on          : list[str]      source idea_ids / archive entry ids
  estimated_turns    : int
  rationale          : str

ChainStep
  step_index         : int            0-based position
  zone_id            : str            the single zone this step attacks
  objective          : str            what this step must achieve
  primitive_ref      : str            idea_id or archive cell key it came from
  approach           : str            the step's attack instruction
  requires           : list[str]      capability tokens this step needs first
  produces           : list[str]      capability tokens this step yields on success
  success_signal     : str            observable that confirms the step landed
```

**Capability tokens** are short controlled strings naming what a step yields or
needs — e.g. `foothold.instruction_executed`, `secret.value_captured`,
`egress.channel_open`. The composer guarantees the **chain invariant**: for
every step *k*, every token in `steps[k].requires` appears in the union of
`produces` over `steps[0..k-1]`. The first step `requires` nothing. A chain
that fails the invariant is rejected at compose time.

A small **token vocabulary** is committed (`red_team/chain_tokens.py`) so
composer, executor, and tests share one set; unknown tokens are a compose-time
`ValueError`. The vocabulary is deliberately coarse (~15 tokens) — it expresses
*dependency*, not a full attack ontology.

This linear-with-tokens grammar is a deliberate subset of a step DAG. A future
branching extension adds `requires` satisfaction across multiple parents
without changing the `ChainStep` shape — which is why `requires`/`produces` are
lists, not scalars.

## 5. Design constraints

1. **A chain is composed from primitives; it does not invent new single-zone
   attacks.** Every `ChainStep.approach` traces to an existing `IdeaObject` or
   an `ArchiveEntry`. Ideation still owns single-zone attack invention. This
   keeps the composer's failure modes bounded and its provenance auditable.
2. **`interfaces/` stays the contract firewall.** `AttackChain`,
   `ChainStep`, `ChainFinding` and the schema delta land in `interfaces/`;
   `red_team/` imports them read-only.
3. **A chain still runs in one lane against one victim.** The lane scheduler,
   provisioner, and `MonitoringHarness` are unchanged — a chain is submitted as
   one unit, exactly as a deep-dive `IdeaObject` is today. The
   `ChainExecutionAgent` is selected by the same attribute-sniffing pattern
   `ExecutionAgent` already uses for playbooks (`execution_agent.py` line 244).
4. **The chain invariant is enforced before execution, not discovered during
   it.** A malformed chain never reaches a lane.
5. **Backward compatible.** Single-zone `IdeaObject` lanes keep working
   unchanged; a cycle can mix chain lanes and plain idea lanes. If the composer
   produces nothing, the pipeline falls back to today's strategist behaviour —
   the same fallback `pipeline.py::generate_ideas` already has.

## 6. Architecture

```
   ideation modes ──raw IdeaObject[]──┐
                                      │
   red_team/archive.py ──elites_for_zone()──┐
   (MAP-Elites, cross-zone)                 │
                                      ▼     ▼
                            red_team/strategist.py
                              (batch LLM synthesis call)
                                      │  candidate chain skeletons
                                      ▼
                            red_team/chain_composer.py
                              · binds steps to zone primitives
                              · assigns requires/produces tokens
                              · enforces the chain invariant
                              · heuristic chain priority
                                      │  AttackChain[]
                                      ▼
                            pipeline.generate_ideas → one lane per chain
                                      │
                            red_team/chain_executor.py
                              ChainExecutionAgent — ordered, stateful
                                      │  LaneResult (+ per-step records)
                                      ▼
                            judge / judge_ensemble
                                      │  JudgmentResult
                                      ▼
                            red_team/chain_attribution.py
                              · one ChainFinding (the kill chain)
                              · per-zone finding records
                              · per-zone coverage credit
                                      │
                            routing → repro queue / MAP-Elites archive
```

## 7. Components

Each module is a single file with one clear responsibility.

### 7.1 `red_team/chain_tokens.py`

- **Does:** Defines the committed capability-token vocabulary and a
  `validate_tokens(list[str])` helper. Pure data + one function, stdlib only —
  the counterpart of `MUTATION_OPERATORS` in `red_team/mutations.py`.
- **Interface:** `CAPABILITY_TOKENS: tuple[str, ...]`, `validate_tokens(...)`.

### 7.2 `red_team/strategist.py` — extended (EXTENDS existing module)

- **Currently:** synthesizes raw ideas into `n_chains` single-zone multi-step
  `IdeaObject`s via one batch LLM call (§2).
- **Change:** the same batch call is re-prompted to emit *chain skeletons* —
  each skeleton names an ordered list of `(zone, objective)` pairs and which
  raw idea / archive elite each pairs with. The schema blurb drops the single
  `primary_zone` constraint and instead asks for a `zones` sequence and a
  terminal breach step. The strategist now also receives archive elites for the
  candidate zones (`archive.elites_for_zone`) as additional source primitives —
  closing the gap noted in §2. Its output is handed to the composer, not
  returned directly. Its never-raises, salvage-what-you-can contract is kept.
- **Interface:** `synthesize_chains(ideas, archive, zones_by_id, cycle_id,
  n_chains) -> list[ChainSkeleton]`. The old `synthesize` is retained for the
  fallback path.

### 7.3 `red_team/chain_composer.py`

- **Does:** Turns each `ChainSkeleton` into a fully-typed, validated
  `AttackChain`. For each skeleton step it binds a concrete primitive (the raw
  `IdeaObject` or `ArchiveEntry` the strategist referenced), copies its
  `approach`, and assigns `requires` / `produces` tokens from a per-zone
  default token map plus the skeleton's stated objective. It then **enforces
  the chain invariant** (§4): a step whose `requires` are not satisfied by an
  earlier step's `produces` causes the composer either to reorder (if a valid
  ordering exists) or to drop the chain with a logged reason. It assigns a
  heuristic chain priority (sum of source-primitive priority scores, discounted
  by chain length and by count of distinct zones — longer chains are riskier
  but more valuable).
- **Interface:** `compose(skeletons, ideas_by_id, archive, cycle_id) ->
  list[AttackChain]`.
- **Depends on:** `red_team/chain_tokens.py`, `red_team/archive.py`,
  `interfaces/types.py`.

### 7.4 `red_team/chain_executor.py`

- **Does:** `ChainExecutionAgent.execute(chain, victim, harness, lane_cfg)` —
  runs an `AttackChain` against one victim as an ordered, stateful sequence.
  It walks `chain.steps` in order; for each step it runs a bounded deep-dive
  sub-conversation (reusing the `execution_agent.py` turn loop and the
  `MonitoringHarness`) focused on that step's `objective` and `zone_id`. After
  a step, it checks the step's `success_signal` against harness evidence: if
  the step **produced** its tokens, those tokens enter the chain's live
  capability set and execution advances; if a step fails to produce a token a
  later step `requires`, the chain stops early with `termination=chain_broken`
  and records how far it got. The captured outputs (e.g. a secret value read in
  step *k*) are carried forward verbatim into step *k+1*'s context — this is
  what makes it a chain rather than three unrelated lanes.
- **Interface:** same `execute(idea, victim, harness, lane_cfg)` signature as
  `ExecutionAgent`, selected by sniffing `idea`'s chain attribute — the exact
  pattern `execution_agent.py` uses for `idea.playbook`.
- **Depends on:** `infra/monitoring_harness.py`, `interfaces/victim_client.py`,
  `red_team/execution_agent.py` (reuses its turn loop helpers).
- **Per-step records:** the harness records each `ChainStep`'s turn span,
  produced tokens, and pass/fail, so attribution and the dashboard can show the
  chain's progression. These ride on the `LaneResult` as a `chain_trace`.

### 7.5 `red_team/chain_attribution.py`

- **Does:** Given a completed chain `LaneResult` + its `JudgmentResult`,
  produces cross-zone attribution. The chain yields:
  - **One `ChainFinding`** — the kill chain itself: ordered zones, the steps
    that landed, the terminal breach, overall severity (the max over
    contributing steps, escalated one level if ≥3 zones chained, because a
    multi-zone chain is materially worse than its worst single step).
  - **Per-zone finding records** — one `FindingRecord` per zone that had a
    *landed* step, each carrying that zone's contribution and a back-reference
    to the `chain_id`. A zone whose step did not land gets no finding but is
    still recorded as *attempted* for coverage.
  - **Coverage credit** — every traversed zone receives coverage credit via
    `update_zone_coverage`; the terminal breach zone receives the confirmed
    credit, intermediate landed zones receive partial credit, attempted-only
    zones receive the standard "tested" increment. This prevents a chain from
    starving the coverage of the zones it merely passed through.
- **Interface:** `attribute(chain, lane_result, judgment) -> ChainAttribution`
  (the `ChainFinding` + the per-zone `FindingRecord`s + the coverage deltas).
- **Depends on:** `interfaces/types.py`, `red_team/progress.py` (per-step
  progress is scored with the existing `score_progress`).

### 7.6 `red_team/routing.py` — extended

- **Change:** `route_judgment` learns to accept a `ChainAttribution`. It logs
  the `ChainFinding` and each per-zone `FindingRecord`, pushes the chain to the
  repro queue once (keyed on the `ChainFinding`, priority from chain severity),
  applies the per-zone coverage deltas, and feeds each landed step into the
  MAP-Elites archive as its own `ArchiveEntry` — so a successful chain enriches
  every traversed zone's elite cells, not just one. Single-zone routing is
  unchanged.

## 8. Data model additions

All land in `interfaces/schema.sql` via the migration system. New tables:

- `attack_chains` — `(chain_id TEXT PRIMARY KEY, cycle_id INTEGER, title TEXT,
  zones TEXT, primary_zone TEXT, steps TEXT, builds_on TEXT, estimated_turns
  INTEGER, created_at TEXT)`. `zones` and `steps` are JSON.
- `chain_findings` — `(chain_finding_id TEXT PRIMARY KEY, chain_id TEXT,
  cycle_id INTEGER, zones_traversed TEXT, terminal_zone TEXT, severity TEXT,
  verdict TEXT, landed_steps TEXT, evidence TEXT, repro_status TEXT,
  created_at TEXT)`.
- `chain_step_results` — `(chain_id TEXT, step_index INTEGER, zone_id TEXT,
  landed INTEGER, produced_tokens TEXT, turn_span TEXT, progress_score REAL)`,
  primary key `(chain_id, step_index)`. The per-step trace for the dashboard
  and attribution.

`findings` gains one nullable column via migration — `chain_id TEXT` — the
back-reference from a per-zone finding to its parent chain. A plain
single-zone finding leaves it null. This is the only change to an existing
table and it is additive.

New `interfaces/types.py` dataclasses: `ChainStep`, `AttackChain`,
`ChainSkeleton`, `ChainFinding`, `ChainAttribution`, `ChainStepResult`. The
chain rides into a lane on `idea.chain` exactly as a playbook rides on
`idea.playbook` today — the lane scheduler's `IdeaObject` contract is unchanged.

The migration bumps `schema_meta.schema_version`.

## 9. Data flow per cycle

1. Ideation produces single-zone raw ideas (unchanged).
2. The strategist's batch call emits `ChainSkeleton`s, now also drawing on
   archive elites for the candidate zones.
3. `chain_composer.compose` binds primitives, assigns tokens, enforces the
   invariant, and ranks — yielding validated `AttackChain`s.
4. `pipeline.generate_ideas` submits each chain as one lane (chains and plain
   ideas may be mixed in a cycle, capped at `n_lanes`). If the composer
   produced nothing, the pipeline falls back to the legacy single-zone
   strategist path.
5. `chain_executor.ChainExecutionAgent` runs each chain as an ordered, stateful
   sequence, recording a `chain_trace` and stopping early on a broken
   precondition.
6. The judge / judge-ensemble scores the lane result (unchanged interface).
7. `chain_attribution.attribute` produces the `ChainFinding`, the per-zone
   findings, and the coverage deltas.
8. `routing.route_judgment` logs them, pushes one repro entry, applies per-zone
   coverage, and feeds each landed step into the MAP-Elites archive.

## 10. Cross-zone attribution rules (summary)

- A zone is **traversed** if a `ChainStep` targeting it ran.
- A zone is **landed** if that step produced its declared `produces` tokens.
- The **terminal zone** is the zone of the last landed step; the
  `ChainFinding.verdict` is the judge verdict for the chain as a whole.
- Severity = max single-step severity, escalated one level if the chain landed
  in ≥3 distinct zones.
- Coverage: terminal zone → confirmed-equivalent credit; other landed zones →
  partial credit; traversed-only zones → standard "tested" increment.
- Every per-zone `FindingRecord` carries `chain_id`, so the dashboard and repro
  pipeline can always reconstruct the full kill chain from a single-zone
  finding.

## 11. Integration points

- **`red_team/strategist.py`:** extended (new `synthesize_chains`, old
  `synthesize` kept for fallback).
- **`red_team/pipeline.py`:** `generate_ideas` calls the composer and may emit
  chain lanes; `execute_lane` is unchanged (the chain executor is selected by
  attribute sniffing); `judge()` calls `chain_attribution` when the lane's idea
  carried a chain.
- **`red_team/routing.py`:** extended to accept a `ChainAttribution`.
- **`red_team/archive.py`:** unchanged; the composer reads it and routing
  writes each landed step into it.
- **`infra/` (lane scheduler, provisioner, harness):** unchanged — a chain is
  one lane unit.
- **`interfaces/`:** new types + additive schema migration.
- **Dashboard:** one new view — the kill-chain timeline (a chain's steps,
  zones, and which landed), additive.

## 12. Error handling

- A `ChainSkeleton` that references a primitive the composer cannot resolve, or
  whose steps cannot be ordered to satisfy the chain invariant, is dropped with
  a logged reason — never executed.
- A chain that breaks mid-execution (a step fails to produce a required token)
  terminates cleanly with `termination=chain_broken`; attribution still credits
  the zones that landed. A partial chain is a useful near-miss, not a failure
  to discard.
- A composer that produces zero valid chains is not an error: the pipeline
  falls back to the legacy single-zone strategist path, identical to the
  fallback already in `pipeline.py::generate_ideas`.
- `chain_attribution` failures are isolated per lane in `judge()`, matching the
  orchestrator's existing per-lane judge isolation (`orchestrator.py` lines
  185–190).
- Token-vocabulary violations are compile-time `ValueError`s in the composer —
  a bad token never reaches a lane.

## 13. Testing strategy

Tests live in `test/`, `test_chain_*.py`, matching the existing
`test_<area>_*.py` convention.

- `test_chain_grammar.py` — `AttackChain` / `ChainStep` construction; the chain
  invariant accepts a valid token sequence and rejects an unsatisfiable one;
  unknown tokens raise.
- `test_chain_composer.py` — a fixture skeleton set composes into valid chains;
  a skeleton with an out-of-order dependency is reordered when possible and
  dropped when not; chain priority orders longer multi-zone chains above
  trivial ones.
- `test_chain_executor.py` — against the mock victim: a chain whose steps all
  land runs to the terminal step and carries a captured token forward; a chain
  with a step that cannot produce its token stops with `chain_broken` and
  records the landed prefix.
- `test_chain_attribution.py` — table-driven: a 3-zone chain that fully lands
  produces one `ChainFinding` (severity escalated), one finding per landed
  zone, and the expected per-zone coverage deltas; a partially-landed chain
  attributes only the landed zones.
- `test_chain_routing.py` — a `ChainAttribution` produces one repro-queue entry
  and feeds every landed step into the archive.
- `test_chain_pipeline_e2e.py` — one full cycle with a composed chain against
  the mock victim, matching the existing red e2e pattern.
- All runs in mock mode, zero model credentials.

## 14. Phased delivery

- **Phase 0 — grammar + contracts:** `chain_tokens.py`, the `interfaces/`
  types, the schema migration. No behaviour.
- **Phase 1 — composer:** `chain_composer.py` and the strategist extension —
  produces validated `AttackChain`s from skeletons + archive elites. Fully
  unit-tested, not yet executed.
- **Phase 2 — execution:** `chain_executor.py` — runs chains statefully against
  the mock victim, records the `chain_trace`.
- **Phase 3 — attribution:** `chain_attribution.py` and the `routing.py`
  extension — cross-zone findings and coverage credit.
- **Phase 4 — wiring:** `pipeline.py` emits chain lanes; mixed chain/idea
  cycles; the kill-chain dashboard view.
- **Later (not this spec):** branching chains (the step DAG), learned chain
  ranking, blue-team chain triage.

## 15. Open questions

1. **Token vocabulary scope.** ~15 coarse tokens are enough to express step
   dependency. If chains grow long and the invariant becomes too permissive,
   the vocabulary can be refined; the grammar (lists, not scalars) does not
   change.
2. **Chain turn budget.** A chain's `estimated_turns` is the sum of its steps'
   budgets. Whether a chain lane needs a higher hard cap than a single-zone
   lane (`LaneConfig.max_turns`) is a tuning question for Phase 2; the executor
   reads the cap, it does not assume one.
3. **Repro of multi-zone findings.** This spec emits one repro-queue entry per
   `ChainFinding`. Whether the repro pipeline should minimise a chain
   step-wise (find the shortest sub-chain that still breaches) is a valuable
   follow-on left to a blue-team chain-repro spec.
