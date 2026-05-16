# Mutation Operator Learning — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw's red team generates attack ideas from three ideation modes, then
executes them once. When an attack fails — or nearly succeeds — the system has
no principled way to **transform** it into a stronger variant. The General
Analysis whitepaper and the architecture report both call for this directly:

> Score mutation operators: paraphrase, benign framing, multi-turn split,
> persona shift, combine ideas, sequence reversal, abstraction/concretization.
> (`docs/monkeyclaw_full_architecture_report.md`, Source Document Synthesis)

A mutation operator is a named transformation of an attack-instruction string
— "rephrase this", "wrap it in a fake document", "split it across turns". Some
operators reliably turn near-misses into confirmed findings; others rarely
help. Today MonkeyClaw applies operators (the 12-operator catalogue in
`red_team/mutations.py` already exists) but it neither **records which operator
produced which outcome** nor **uses that history to choose** the next operator.
Every mutation is therefore a uniform guess, and the `mutation_operator_stats`
table — which exists in `interfaces/schema.sql` — is never written.

This spec closes that gap: it makes operator selection a learned, evidence-
driven policy. Each operator accumulates an observed *lift* (does it improve
attacks?), and a bandit / Thompson-sampling policy selects operators in
proportion to their posterior success while still exploring under-sampled ones.
The result is a red team that gets measurably better at strengthening its own
attacks over time, and a dashboard signal showing which transformations work.

## 2. What already exists vs. what is new

This spec **completes partial work**. It does not rebuild the operator
catalogue.

### Already built (`red_team/mutations.py`, current working-tree state)

- **`MUTATION_OPERATORS`** — a frozen tuple of exactly **12 operator names**:
  `paraphrase`, `add_benign_framing`, `split_into_multi_turn`,
  `change_persona`, `add_constraints`, `combine_two_ideas`,
  `reverse_component_order`, `abstract_final_request`,
  `concretize_final_request`, `insert_untrusted_document`,
  `move_instruction_into_tool_output`,
  `move_instruction_into_dependency_metadata`.
- **`MutationOperator`** — a frozen dataclass wrapping a name, a description,
  and a deterministic, stdlib-only, **no-LLM** transform of an attack string.
  `apply(idea_text, *, extra=None) -> str`.
- **`OPERATORS`** / `get_operator()` / `apply_operator()` — the operator
  registry and lookup helpers.
- **`MutationStats`** — an **in-memory, process-local** accumulator. Per
  operator it tracks `uses`, `successes`, `avg_score`, derives a blended
  `improvement` score (0.6·success_rate + 0.4·avg_score), gives unused
  operators an optimistic neutral prior (0.5), and exposes `record()`,
  `stats_for()`, `snapshot()`, `rank()` (best-first, deterministic tie-break),
  and `pick(k)` (top-k by rank).
- **`mutation_operator_stats` table** — schema columns `operator` (PK),
  `uses`, `successes`, `avg_score`, `updated_at`. Already in `schema.sql`.

The module's own docstring states the current limitation precisely: *"There is
a `mutation_operator_stats` DB table in the schema, but no MCP method to write
it — so `MutationStats` stays a process-local accumulator."* `MutationStats`
is therefore reset to zero on every process start, and `rank()` is a pure
greedy ordering with no exploration beyond the static neutral prior.

### New in this spec

1. An **MCP method pair** (`get_mutation_operator_stats`,
   `update_mutation_operator_stats`) so `MutationStats` can persist to and
   load from the `mutation_operator_stats` table. Operator learning becomes
   durable across cycles and process restarts.
2. A **mutation lift signal**: a defined, computed measure of whether a
   mutation *improved* an attack relative to its parent, replacing today's
   caller-supplied boolean `improved`.
3. A **`mutation_policy.py` module**: a bandit / Thompson-sampling selection
   policy over operators, replacing the static greedy `rank()` for selection
   while keeping `rank()` for display.
4. A **`mutation_engine.py` module**: the orchestration glue that selects an
   operator, applies it, tracks the parent→child lineage, computes lift after
   judgment, and writes the result back through the MCP.
5. Two **schema columns** on `mutation_operator_stats` (`squared_score`,
   `last_lift`) and one **new table** `mutation_attempts` recording each
   individual mutated execution for offline analysis and the future learned
   ranking model.

## 3. Scope

In scope:

- Durable, persisted per-operator statistics via the MCP / database.
- A defined mutation-lift signal computed from judge output.
- A Thompson-sampling selection policy over the 12 existing operators, with a
  greedy and an epsilon-greedy fallback selectable by config.
- A mutation engine that wires selection → application → outcome recording
  into the red-team pipeline as an explicit, optional stage.
- Per-zone operator stats (some operators help in `PROMPT-INJ` but not
  `SBX-NET`), in addition to a global rollup.
- Dashboard exposure of operator performance.

Explicitly out of scope (YAGNI for this spec):

- **Training a learned ranking model.** The architecture report is explicit:
  collect hundreds-to-thousands of attempts first, then train offline. This
  spec only *produces the dataset* (`mutation_attempts`); it does not consume
  it with an ML model.
- **LLM-driven mutation operators.** All 12 operators are deterministic
  stdlib transforms and stay that way. Adding a "have a model rewrite this"
  operator is a separate decision with cost implications.
- **Contextual bandits** (operator choice conditioned on a feature vector of
  the idea). The per-zone split is the only context this spec models;
  full contextual bandits wait for the learned ranking model.
- **Mutating non-string attack structure** (tool-call graphs, victim
  configuration). Operators transform the attack-instruction string only.

## 4. Non-negotiable design constraints

1. **Operators stay deterministic and LLM-free.** The catalogue's value is
   that mutation is cheap and reproducible. The selection *policy* learns; the
   *operators* do not. No operator may call an LLM.
2. **`interfaces/` is the contract firewall.** The two new MCP methods, the
   new shared types, and the schema delta land in `interfaces/`. `red_team/`
   imports them read-only. `red_team/` never writes the database directly.
3. **Schema changes go through the migration system.** `schema_meta` already
   carries `schema_version` (currently `2`). The new columns and table bump
   it to `3` via the version-gated migration runner in `infra/database.py`;
   `CREATE TABLE IF NOT EXISTS` and additive `ALTER TABLE` keep a fresh DB and
   existing rows both valid.
4. **The pipeline must run with mutation disabled.** Mutation is an optional
   pipeline stage behind `red_team.mutation.enabled` (default `true` for the
   learning value, but a single flag flip restores today's behaviour). A
   disabled mutation stage is a strict no-op.
5. **One module, one responsibility.** `mutations.py` owns operators + stats;
   `mutation_policy.py` owns selection; `mutation_engine.py` owns
   orchestration. No file gains a second job.

## 5. The mutation lift signal

Today `MutationStats.record()` takes a caller-supplied `improved: bool`. No
caller computes it from evidence, so it is effectively unused. This spec
defines lift concretely.

A mutated attack has a **parent** (the original idea/attempt) and a **child**
(the mutated attempt). Both are judged by the existing red-team `Judge`
(`red_team/judge.py`) — Tier 1 programmatic checks plus, on semantic zones,
the Tier 2 / ensemble judge. Each produces a scalar **attack score** in
`[0, 1]`:

- For a `confirmed` verdict: score `1.0`.
- For a `suspicious` verdict: the judge / ensemble `confidence` (the ensemble
  already returns a calibrated confidence; the single Tier 2 judge returns
  one too).
- For a `clean` verdict: `0.0`.

**Lift** is `child_score - parent_score`, clamped to `[-1, 1]`. The operator
is credited with:

- `improved = lift > improvement_epsilon` (config, default `0.05`) — a
  meaningful positive movement, not noise.
- `score = child_score` — folded into the operator's running `avg_score`
  exactly as `MutationStats.observe()` already does.

A `confirmed` child from a `clean` parent is the maximum lift (`+1.0`); a
mutation that breaks a working attack records negative lift and depresses the
operator's posterior. This makes the recorded signal a real,
evidence-grounded measure rather than a guess.

## 6. Architecture

```
   red_team/pipeline.py
        │  (a near-miss / parent idea + its LaneResult + JudgmentResult)
        ▼
   mutation_engine.py ──────────────────────────────────────────────┐
        │                                                            │
        │  1. select operator(s)                                     │
        ▼                                                            │
   mutation_policy.py  ◄── posterior from ──┐                        │
   (Thompson sampling)                      │                        │
        │  operator name(s)                 │                        │
        ▼                                   │                        │
   mutations.py:apply_operator()            │                        │
        │  mutated attack string            │                        │
        ▼                                   │                        │
   (re-enters pipeline: execute_lane + judge the child)              │
        │  child JudgmentResult                                      │
        ▼                                   │                        │
   compute lift (§5) ──────────────────────►│                        │
        │                                   │                        │
        ▼                                   │                        │
   MutationStats.record()  ──persist──► MCP.update_mutation_operator_stats
        │                                          │                 │
        └──────────────► MCP.log_mutation_attempt ──┴─────────────────┘
                                                    │
                          mutation_operator_stats  ─┤  (durable)
                          mutation_attempts        ─┘
        ▲
        └── on pipeline start: MutationStats.load_from(MCP.get_mutation_operator_stats())
```

## 7. Components

Each module is a single file in `red_team/` with one responsibility.

### 7.1 `red_team/mutations.py` (existing — extended)

- **Does:** Owns the operator catalogue (unchanged — 12 deterministic
  operators) and `MutationStats`. **Extended** so `MutationStats` is durable:
  - `MutationStats.load_from(rows: list[MutationOperatorStat])` — seed the
    in-memory records from persisted rows on pipeline construction.
  - `MutationStats.to_rows() -> list[MutationOperatorStat]` — serialize
    current records for persistence.
  - `_OpRecord` gains `squared_score` (running sum of score², needed for the
    Thompson-sampling variance estimate in §7.2) and `last_lift`.
  - `record()` keeps its signature; callers now always pass an
    evidence-derived `improved`/`score` (the engine computes them, §5).
  - A `MutationStats` may be **scoped to a zone** via an optional
    `zone_id` constructor argument; the engine holds one global instance plus
    one per active zone.
- **Interface:** existing public surface, plus `load_from`, `to_rows`, and a
  `posterior(operator) -> (alpha, beta)` accessor used by the policy.
- **Depends on:** `interfaces/types.py` (`MutationOperatorStat`). No LLM, no
  DB, no other red-team module.

### 7.2 `red_team/mutation_policy.py` (new)

- **Does:** Selects which operator(s) to apply next. Treats each operator as
  an arm of a multi-armed bandit. The default policy is **Thompson sampling**
  over a Beta posterior per operator: `Beta(1 + successes, 1 + (uses −
  successes))` seeded from `MutationStats`. To pick, draw one sample per
  operator and take the arm(s) with the highest draws. Under-sampled operators
  have a wide posterior and are naturally explored; consistently strong
  operators are exploited. Two alternative policies are selectable by config
  for ablation: `greedy` (delegate to `MutationStats.rank()`, today's
  behaviour) and `epsilon_greedy` (rank with probability `1 − ε`, uniform
  random otherwise).
- **Interface:**
  - `MutationPolicy(stats: MutationStats, kind="thompson", *, seed=None, epsilon=0.1)`
  - `select(k: int = 1, *, exclude: set[str] = frozenset()) -> list[str]` —
    returns `k` operator names; `exclude` lets the engine avoid re-applying an
    operator already used on this lineage.
  - `explain() -> dict[str, float]` — per-operator sampled value from the last
    `select()`, for the dashboard and tests.
- **Depends on:** `red_team/mutations.py` (`MutationStats`,
  `MUTATION_OPERATORS`). `random` only — no numpy dependency; the Beta draw
  uses `random.betavariate`. Deterministic when `seed` is set (required for
  tests).

### 7.3 `red_team/mutation_engine.py` (new)

- **Does:** Orchestrates one mutation round. Given a parent idea, its
  `LaneResult`, and its `JudgmentResult`:
  1. Decides whether the parent is a **mutation candidate** — a `suspicious`
     verdict, or a `clean` verdict whose progress/ensemble confidence exceeds
     `near_miss_threshold` (config). `confirmed` attacks are not mutated (no
     headroom); deeply `clean` attacks are not mutated (mutation rarely
     rescues them — wasted budget).
  2. Calls `MutationPolicy.select(k)` (k = `red_team.mutation.children_per_parent`,
     default `2`), scoped to the parent's zone.
  3. Applies each selected operator via `apply_operator()` to the parent's
     attack-instruction string, producing child `IdeaObject`s with
     `source_mode="mutation"`, a `parent_idea_id`, and the operator recorded
     in `mutation_lineage` (a red-team-local field, §8).
  4. Hands children back to the pipeline for execution + judgment.
  5. On child judgment, computes lift (§5), calls
     `MutationStats.record()` for the global and per-zone instances, and
     persists via the MCP (`update_mutation_operator_stats`,
     `log_mutation_attempt`).
- **Interface:**
  - `MutationEngine(policy, stats_by_zone, mcp, cfg)`
  - `mutation_candidates(judged) -> list[IdeaObject]` — filter parents.
  - `mutate(parent_idea, parent_lane, parent_judgment) -> list[IdeaObject]` —
    produce child ideas.
  - `record_outcome(child_idea, child_judgment, parent_judgment) -> MutationAttempt`
    — compute lift, update stats, persist, return the attempt record.
- **Depends on:** `red_team/mutations.py`, `red_team/mutation_policy.py`,
  `interfaces/mcp_tools.py`, `interfaces/types.py`. Best-effort MCP writes —
  a persistence failure logs an alert and never aborts the cycle.

### 7.4 `red_team/pipeline.py` (existing — integration only)

- **Does:** Gains an optional mutation stage. After the first judgment pass
  over a zone's executed ideas, if `red_team.mutation.enabled`, the pipeline
  asks `MutationEngine.mutation_candidates()` for parents worth mutating,
  calls `mutate()` to get children, executes and judges the children through
  the existing `execute_lane` / `judge` path, and calls `record_outcome()`
  for each. Children are subject to the existing dedup and lane-budget caps so
  mutation cannot blow the cycle's token budget. No new public method.
- **Depends on:** `red_team/mutation_engine.py`. On pipeline construction it
  loads persisted stats once via `MutationStats.load_from(...)`.

## 8. Data model additions

All land in `interfaces/schema.sql` via the migration system; `schema_version`
bumps `2 → 3`.

### Altered table — `mutation_operator_stats`

Two additive columns (`ALTER TABLE ... ADD COLUMN`, both with defaults so
existing rows stay valid):

- `squared_score REAL NOT NULL DEFAULT 0.0` — running sum of score², the
  variance input the Thompson-sampling policy needs.
- `last_lift REAL NOT NULL DEFAULT 0.0` — the most recent observed lift, a
  cheap dashboard signal.

A per-zone breakdown is stored by making the existing single-column primary
key a **composite** in a new sibling table rather than mutating the PK of the
shipped table:

### New table — `mutation_operator_stats_by_zone`

```sql
CREATE TABLE IF NOT EXISTS mutation_operator_stats_by_zone (
    operator      TEXT NOT NULL,
    zone_id       TEXT NOT NULL,
    uses          INTEGER NOT NULL DEFAULT 0,
    successes     INTEGER NOT NULL DEFAULT 0,
    avg_score     REAL NOT NULL DEFAULT 0.0,
    squared_score REAL NOT NULL DEFAULT 0.0,
    last_lift     REAL NOT NULL DEFAULT 0.0,
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (operator, zone_id)
);
```

The shipped `mutation_operator_stats` table stays the global rollup.

### New table — `mutation_attempts`

One row per mutated execution — the dataset the future learned ranking model
will train on:

```sql
CREATE TABLE IF NOT EXISTS mutation_attempts (
    attempt_id       TEXT PRIMARY KEY,
    cycle_id         INTEGER NOT NULL,
    zone_id          TEXT NOT NULL,
    operator         TEXT NOT NULL,
    parent_idea_id   TEXT NOT NULL,
    child_idea_id    TEXT NOT NULL,
    parent_score     REAL NOT NULL,
    child_score      REAL NOT NULL,
    lift             REAL NOT NULL,
    improved         INTEGER NOT NULL DEFAULT 0,
    child_verdict    TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mutation_attempts_op
    ON mutation_attempts(operator, zone_id, created_at);
```

### New `interfaces/` types

- `MutationOperatorStat` — `operator`, `zone_id` (`""` for the global
  rollup), `uses`, `successes`, `avg_score`, `squared_score`, `last_lift`.
  Used by `get/update_mutation_operator_stats`.
- `MutationAttempt` — mirrors the `mutation_attempts` row; returned by
  `MutationEngine.record_outcome()` and `log_mutation_attempt`.

`IdeaObject` is **not** changed (it is Person A's contract). The
`parent_idea_id` and `mutation_lineage` (the ordered list of operators applied
to reach this idea) ride on the idea instance as red-team-local attributes,
the same pattern `red_team/ideation.py` already uses for `idea.tactics` and
`idea.model_label`. The durable record of lineage is the `mutation_attempts`
table.

### New MCP methods (`interfaces/mcp_tools.py`)

- `get_mutation_operator_stats(zone_id: str | None = None) -> list[MutationOperatorStat]`
  — returns the global rollup, or the per-zone rows for one zone.
- `update_mutation_operator_stats(stat: MutationOperatorStat) -> None` —
  upsert into the global table and, when `zone_id` is non-empty, the per-zone
  table.
- `log_mutation_attempt(attempt: MutationAttempt) -> str` — insert one
  `mutation_attempts` row, returns `attempt_id`.

Implemented in both `infra/mcp_server.py` (real, SQLite) and
`infra/mock_mcp.py` (in-memory), matching every other MCP method.

## 9. Data flow per cycle

1. Pipeline runs ideation → dedup → priority → execution → judgment as today.
2. If `red_team.mutation.enabled`: `MutationEngine.mutation_candidates()`
   selects parents (suspicious + high-confidence-clean near-misses).
3. For each parent, `MutationPolicy.select(k)` draws operators from the
   per-zone Thompson posterior; `mutate()` applies them to the parent's
   attack string, yielding `k` child ideas.
4. Children are deduplicated and executed through the existing
   `execute_lane` path, then judged by the existing `Judge`.
5. For each child, `record_outcome()` computes lift (§5), updates the global
   and per-zone `MutationStats`, and persists via
   `update_mutation_operator_stats` + `log_mutation_attempt`.
6. Children that reach `confirmed`/`suspicious` route to the repro queue
   through the existing `red_team/routing.py` path — they are ordinary
   findings whose provenance happens to be a mutation.
7. On the next pipeline construction, `MutationStats.load_from()` rehydrates
   the posteriors from the database, so learning compounds across cycles.

## 10. Integration points

- **`red_team/pipeline.py`** — one optional stage, gated by config; disabled
  is a strict no-op restoring today's behaviour.
- **`red_team/routing.py`** — unchanged; mutated children are routed exactly
  like any other judged idea.
- **`red_team/judge.py`** — unchanged; reused as-is to score parent and
  child. The lift signal is computed *from* its output, not inside it.
- **MCP / `infra/`** — three new methods on the existing protocol; one
  schema migration. No other infra change.
- **Dashboard** — one additive panel: per-operator `uses` / `success_rate` /
  `avg_lift`, global and per-zone, sourced from `mutation_operator_stats*`.
  The architecture report's "Mutation operator success" dashboard item.
- **`configs/monkeyclaw.yaml`** — a new `red_team.mutation` block:
  `enabled`, `policy` (`thompson` | `greedy` | `epsilon_greedy`), `epsilon`,
  `children_per_parent`, `near_miss_threshold`, `improvement_epsilon`,
  `max_lineage_depth`. Read red-team-locally (the `tournament.py` precedent),
  so `interfaces/config_schema.py` need not change.

## 11. Error handling

- **MCP persistence failure** (`update_mutation_operator_stats` /
  `log_mutation_attempt` raises): logged as an alert, swallowed. The in-memory
  `MutationStats` still holds the cycle's learning; only durability across
  restarts is lost for that write. The cycle never aborts.
- **`get_mutation_operator_stats` failure on startup**: `MutationStats`
  starts empty — exactly today's behaviour — and a warning is logged. The
  policy still works from the neutral prior.
- **A child execution or judgment fails**: handled by the existing pipeline
  error path; `record_outcome()` is simply not called for that child, so no
  stats are corrupted. No partial lift is recorded.
- **An operator produces a degenerate string** (e.g. `split_into_multi_turn`
  on a one-word idea): the operators already handle this defensively
  (fallback splits). The engine additionally drops a child whose mutated
  string is byte-identical to its parent.
- **Runaway mutation depth**: `max_lineage_depth` (default `2`) caps how many
  operators may be chained onto one lineage; the engine refuses to mutate a
  child past that depth, bounding both cost and the `exclude` set.

## 12. Testing strategy

Tests live in `test/` under the `test_<area>_*.py` convention.

- `test_mutations_stats.py` — `load_from` / `to_rows` round-trip;
  `squared_score` and `last_lift` accumulation; per-zone scoping; the
  optimistic prior for unused operators is preserved.
- `test_mutation_policy.py` — with a fixed `seed`, Thompson sampling is
  deterministic; an operator with many successes is selected more often than
  an unsampled one across N draws; the `exclude` set is honoured; `greedy`
  matches `MutationStats.rank()`; `epsilon_greedy` explores at the configured
  rate.
- `test_mutation_lift.py` — table-driven over (parent verdict, child verdict,
  confidences) → expected lift and `improved`, including the negative-lift
  (broke a working attack) and `improvement_epsilon` boundary cases.
- `test_mutation_engine.py` — `mutation_candidates` selects suspicious and
  high-confidence-clean parents and rejects confirmed/deep-clean ones;
  `mutate` stamps `parent_idea_id` / `mutation_lineage` / `source_mode`;
  identical-string children are dropped; `max_lineage_depth` is enforced;
  `record_outcome` writes the global and per-zone stats and one
  `mutation_attempts` row through the mock MCP.
- `test_mutation_pipeline_e2e.py` — one full red cycle in mock mode with
  mutation enabled: a planted near-miss is mutated, the child is executed and
  judged, stats persist, and a disabled-mutation run is byte-for-byte the
  pre-mutation pipeline behaviour.
- `test_contracts.py` (existing) — extended to assert both MCP
  implementations satisfy the three new method signatures.

All tests run in mock mode with zero model credentials, consistent with the
repo's demo posture.

## 13. Phased delivery

- **Phase 0 — contracts:** `MutationOperatorStat` / `MutationAttempt` types,
  the three MCP methods on the protocol + both implementations, the schema
  migration (`2 → 3`). No behaviour change yet.
- **Phase 1 — durable stats:** extend `MutationStats` with `load_from` /
  `to_rows` / `squared_score` / `last_lift` and per-zone scoping. The
  existing `rank()` now persists across restarts.
- **Phase 2 — selection policy:** `mutation_policy.py` with the Thompson,
  greedy, and epsilon-greedy policies.
- **Phase 3 — engine + lift:** `mutation_engine.py`, the §5 lift signal,
  `record_outcome` persistence.
- **Phase 4 — pipeline wiring:** the optional mutation stage in
  `red_team/pipeline.py`, the config block, the dashboard panel.
- **Later (not this spec):** train the learned ranking model on the
  accumulated `mutation_attempts` dataset; contextual-bandit selection.

## 14. Open questions

1. **Children-per-parent budget.** `children_per_parent` defaults to `2`.
   Whether the right number is fixed, or proportional to the parent's
   near-miss confidence (mutate promising parents harder), is left to tune
   once there is real attempt data — the engine isolates the decision.
2. **Cold-start exploration window.** Thompson sampling explores naturally,
   but with 12 operators × 18 zones the per-zone tables are sparse early.
   Whether to fall back to the global rollup until a zone has ≥ N samples, or
   trust the wide per-zone posterior immediately, is an ablation question;
   the per-zone-then-global fallback is the conservative default.
3. **Lift for programmatic zones.** On Tier-1-only zones the attack score is
   effectively binary (`1.0`/`0.0`), so lift is coarse. This is acceptable —
   mutation is most valuable on the semantic zones where the ensemble gives a
   graded confidence — but a future progress-rubric score (architecture
   report, "staged progress scoring") would sharpen it.
