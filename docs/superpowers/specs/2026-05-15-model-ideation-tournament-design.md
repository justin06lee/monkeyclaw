# Model Ideation Tournament — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw's red team generates attack ideas from a single configured model
(`nvidia/nemotron-3-super-120b-a12b`). One model has one prior: it favours
certain attack families, phrasings, and tactic vocabularies, and it is blind in
the same places every cycle. The architecture report calls for breaking that
monoculture:

> Multi-model ideation tournament for selected zones [...] different models
> generate ideas for the same zone, judged head-to-head, route future ideation
> by win-rate per zone.
> (`docs/monkeyclaw_full_architecture_report.md`, Red Team / Target pipeline)

The report's model-routing analysis is the reason this matters: Nemotron Super
is a strong general workhorse, but a frontier creative model and a
cyber-specialised open model bring genuinely different idea distributions, and
*which* generator is best is **zone-dependent** — a code-grounded filesystem
zone rewards a frontier coding model; a social-engineering zone may reward a
high-temperature creative model. There is no universally best ideation model;
there is a best model *per zone*, discoverable only by competition.

MonkeyClaw already has the tournament *mechanism* (`red_team/tournament.py`
exists, in an in-progress state). What it lacks is the part that makes a
tournament a tournament: **head-to-head judging of the ideas different models
produced**, and a **per-zone win-rate that routes future ideation**. Today the
tournament merges every entrant's ideas into one pool and tracks raw
confirmed-finding counts; it never compares entrants on equal footing and never
feeds results back into entrant selection. This spec completes that loop.

## 2. What already exists vs. what is new

This spec **completes partial work**. It does not rebuild the tournament hook.

### Already built (`red_team/tournament.py`, current working-tree state)

- **`Entrant`** — one model in the tournament: a `role` (keying into the
  models config), optional `provider`/`model` overrides, an `optional` flag
  (auto-set when the role name contains "optional"), and a `label` property.
- **`ModelTournamentConfig`** — `enabled` (default `false`) plus a list of
  `Entrant`s.
- **`_coerce_config()` / `load_tournament_config()`** — parse the
  `red_team.model_tournament` block from a dict, a YAML path, or the default
  `configs/monkeyclaw.yaml`; a missing section yields a disabled config (the
  safe default). Read red-team-locally, deliberately not through the Pydantic
  schema.
- **`ModelTournament`** — the runner:
  - `enabled` — true only when the config is enabled and has entrants.
  - `generate(generate_fn)` — runs `generate_fn` for every entrant, tags each
    produced idea with `idea.model_label = entrant.label`, swallows an
    optional entrant's failure (so the demo never breaks), and returns the
    **merged** idea pool.
  - `record_outcome(model_label, verdict, tokens)` — bumps per-model
    `confirmed` / `suspicious` / `tokens` counters when an idea's outcome is
    judged.
  - `leaderboard()` / `summary()` — per-model snapshot for logging.
  - `_bump()` — the internal counter store keyed by model label.
- **`red_team/ideation.py:tournament_ideas()`** — runs the normal 3-mode
  ideation per entrant via a `generate_fn`, returns the merged pool, or `[]`
  when the tournament is disabled so the caller falls back to the single-model
  path.
- **`red_team/pipeline.py`** — constructs a `ModelTournament` from
  `load_tournament_config()`, has a `_llm_for_entrant()` resolver, and calls
  `tournament_ideas(...)` inside `generate_ideas()`; a disabled tournament is
  a no-op.

So the **fan-out** half exists: many models generate, ideas are tagged and
merged, raw outcomes are counted. The wired pipeline integration from commit
`4e63710` ("wire the model tournament into the pipeline") is in place.

### What is missing — the actual tournament

- **No head-to-head judging.** Entrants' ideas are merged and run through the
  ordinary pipeline; two entrants' ideas for the same zone are never compared
  directly. `record_outcome` counts confirmed findings, but a confirmed
  finding depends on execution and judging luck, not just idea quality, and
  the count is not normalised by ideas attempted.
- **No per-zone win-rate.** The leaderboard is global. Entrant strength is
  zone-dependent (§1) and the data model has no per-zone dimension.
- **No routing feedback.** `enabled` and the entrant list are static config;
  results never change which entrants run, or with what weight, next time.
- **No persistence.** `_stats` is process-local and lost on restart, like
  `MutationStats` before its own learning spec. The architecture report's
  required `model_runs` table exists but the tournament does not write a
  per-zone result anywhere.
- **No dependency on model routing.** Entrants carry a `role`, but
  `_llm_for_entrant()` must resolve it; this is exactly the per-role model
  config from the Person A infrastructure spec, and the tournament's entrant
  roles should be those role labels.

### New in this spec

1. A **head-to-head ideation judge** (`ideation_tournament.py`): for a zone,
   it compares the *idea sets* two entrants produced and scores which entrant
   contributed the stronger, more novel, more zone-relevant ideas — before
   expensive execution.
2. A **per-zone win-rate table** (`model_zone_winrate`): each head-to-head
   result updates an entrant's win-rate for that zone.
3. **Win-rate-driven routing**: future ideation for a zone draws entrants in
   proportion to their per-zone win-rate, with an exploration floor so a new
   or weak entrant is never permanently shut out.
4. **Persistence** of tournament results and win-rates through the MCP, so
   routing compounds across cycles and survives restarts.
5. A formal **dependency on the model-routing spec**: entrant `role`s are the
   `models:` config role labels, and `_llm_for_entrant()` resolves them via
   `make_llm(role)`.

## 3. Scope

In scope:

- Head-to-head judging of the idea sets two entrant models produced for the
  same zone, run before execution.
- A per-zone, per-entrant win-rate accumulated from those head-to-heads.
- Routing future ideation by per-zone win-rate, with an exploration floor.
- Persistence of tournament rounds and win-rates through the MCP / database.
- Per-cycle budget control — the tournament fans out across N models, so the
  number of zones it runs on and the entrants it draws are bounded.
- Dashboard exposure of per-zone model performance.

Explicitly out of scope (YAGNI for this spec):

- **The model-routing config itself.** The `models:` block, `ModelRouteConfig`,
  and `make_llm(role)` are owned by the Person A infrastructure spec. This
  spec *depends on* them and *consumes* them; it does not define them.
- **Training a learned model-selection policy.** The win-rate table is the
  routing signal; a learned policy over zone/idea features is a later step
  once the `model_tournament_rounds` dataset is large enough.
- **Tournament for execution or judging models.** This spec is about
  *ideation* model competition only. Execution-agent and judge-model selection
  are separate concerns (the judge ensemble has its own spec).
- **Running the tournament every cycle on every zone.** The tournament is
  selective by design (cost) — it runs on a bounded set of zones per cycle.
- **Cross-zone model ranking.** Win-rate is per zone; a global "best model"
  is not a meaningful or computed quantity.

## 4. Non-negotiable design constraints

1. **Disabled is a strict no-op.** `red_team.model_tournament.enabled`
   defaults `false`; with it off, ideation runs exactly as today on the single
   configured model. This is already true and must stay true — the
   tournament's docstring promise that "the demo is not fragile" is a hard
   requirement.
2. **An optional entrant's failure never breaks a cycle.** Already enforced in
   `ModelTournament.generate()`; the new judging and routing code must hold
   the same line — a missing model, a failed call, or an empty idea set
   degrades gracefully.
3. **`interfaces/` is the contract firewall.** New shared types and the
   schema delta land in `interfaces/`; `red_team/` imports them read-only.
   The tournament config stays red-team-local (the existing deliberate
   choice), but the *persisted* win-rate and round records are an
   `interfaces/` contract because the dashboard and MCP touch them.
4. **Schema changes go through the migration system.** `schema_meta`
   (`schema_version` `2`) bumps to `3` via the version-gated migration
   runner; additive tables only.
5. **Depends on model routing.** Entrant `role`s are the `models:` config role
   labels; `_llm_for_entrant()` resolves them through `make_llm(role)`. This
   spec is sequenced *after* the model-routing work lands.
6. **One module, one responsibility.** `tournament.py` keeps the runner +
   config; `ideation_tournament.py` owns head-to-head judging and routing. No
   file gains a second job.

## 5. The head-to-head ideation judge

The current `record_outcome` credits an entrant when one of its ideas becomes
a confirmed finding. That conflates idea quality with execution and judging
outcomes and is expensive (every idea must be fully executed before it counts).
This spec adds a cheaper, more direct signal that runs *before* execution.

For a zone, each entrant produces its idea set via the normal 3-mode ideation.
The **ideation judge** then runs pairwise comparisons between entrants: given
two entrants' idea sets for the same zone (titles, approaches, novelty notes,
tactic tags), one LLM call asks a single question — *which entrant's idea set
is the stronger basis for attacking this zone: more genuinely distinct
approaches, more zone-relevant exploitation, fewer textbook repeats?* It
returns a winner, a margin, and per-entrant strengths.

This is the same pairwise principle the judge-ensemble spec uses for attack
ranking, applied one level earlier — to *idea sets* rather than executed
attacks — and for the same reason: a direct comparison is more reliable than
two absolute scores. With more than two entrants, the judge runs a round-robin
(at three entrants, three comparisons) and each comparison contributes a
win/loss.

A second, cheaper **execution-outcome signal** is retained: after a zone's
ideas are executed and judged, `record_outcome` still credits entrants by the
verdicts their ideas earned. The two signals are combined into the win-rate
update (§8) — the ideation-judge signal is available immediately and cheaply;
the execution signal is slower but grounded in real attack outcomes.

## 6. Architecture

```
   red_team/pipeline.py : generate_ideas()
        │  (a tournament-selected zone)
        ▼
   tournament.py : ModelTournament.generate(generate_fn)
        │  per entrant: make_llm(role) → 3-mode ideation
        │  → per-entrant idea sets, each idea tagged model_label
        ▼
   ideation_tournament.py
        │  1. head-to-head judge: round-robin pairwise compare
        │     entrant idea sets  ──make_llm("semantic_judge")──► winner/margin
        │  2. update per-zone win-rate
        ▼
   model_zone_winrate table  ◄── persist ──► MCP.update_model_zone_winrate
        │
        │  (merged idea pool continues through the normal pipeline:
        │   dedup → priority → execute → judge)
        ▼
   record_outcome(model_label, verdict)   ── execution-outcome signal
        │
        └──► win-rate update (§8) ──► routing for the NEXT cycle:
                 entrant_selection.py picks entrants ∝ per-zone win-rate
                 (with an exploration floor)

   MCP: log_tournament_round · get/update_model_zone_winrate
        │
        ▼
   model_tournament_rounds · model_zone_winrate   (durable)
```

## 7. Components

### 7.1 `red_team/tournament.py` (existing — extended)

- **Does:** Keeps the runner + config (`Entrant`, `ModelTournamentConfig`,
  `load_tournament_config`, `ModelTournament`) unchanged in its existing
  responsibilities — fan-out, idea tagging, optional-entrant safety. **Extended**:
  - `ModelTournament._stats` gains a **per-zone** dimension: counters keyed
    `(model_label, zone_id)` rather than `model_label` alone. `_bump`,
    `record_outcome`, and `leaderboard` carry a `zone_id`.
  - `ModelTournament` gains `load_winrates(rows)` / `winrate(zone_id,
    model_label)` so routing decisions read persisted state.
  - `leaderboard()` / `summary()` keep a global rollup for logging, derived
    from the per-zone counters.
- **Interface:** existing public surface, with `record_outcome` and
  `leaderboard` taking an optional `zone_id`, plus `load_winrates` and
  `winrate`.
- **Depends on:** `interfaces/types.py` (`ModelZoneWinrate`), `yaml`. No LLM.

### 7.2 `red_team/ideation_tournament.py` (new)

- **Does:** Owns head-to-head judging and the win-rate update.
  - `judge_round(zone, idea_sets) -> TournamentRound`: given a mapping of
    `model_label → list[IdeaObject]` for one zone, runs the round-robin
    pairwise comparisons (§5), one LLM call per pair, and produces a
    `TournamentRound` recording each pairwise winner and per-entrant
    strengths.
  - `update_winrate(round, execution_outcomes) -> list[ModelZoneWinrate]`:
    folds the round's pairwise wins and the cycle's execution verdicts (§8)
    into the per-zone, per-entrant win-rate, returning the updated rows.
  - Never raises: a failed pairwise call drops that pair; an empty idea set
    for an entrant counts as a forfeit, not a crash.
- **Interface:**
  - `IdeationTournamentJudge(llm, mcp=None)` — `llm` resolved via
    `make_llm("semantic_judge")`.
  - `judge_round(zone, idea_sets) -> TournamentRound`
  - `update_winrate(round, execution_outcomes) -> list[ModelZoneWinrate]`
- **Depends on:** `interfaces/llm.py`, `interfaces/mcp_tools.py`,
  `interfaces/types.py`. Best-effort MCP writes.

### 7.3 `red_team/entrant_selection.py` (new)

- **Does:** Routes future ideation. Given a zone and the persisted per-zone
  win-rates, selects which entrants run this cycle and with what weight. The
  policy: draw entrants in proportion to their per-zone win-rate, but every
  configured entrant retains an **exploration floor** probability
  (`exploration_floor`, config) so a new or currently-weak entrant is sampled
  often enough to discover a zone where it is actually strong. A zone with no
  win-rate history yet runs all entrants (cold start = full competition).
- **Interface:**
  - `select_entrants(zone_id, all_entrants, winrates, *, seed=None) -> list[Entrant]`
  - `weights(zone_id, winrates) -> dict[str, float]` — the routing weights,
    for the dashboard and tests.
- **Depends on:** `red_team/tournament.py` (`Entrant`), `interfaces/types.py`.
  `random` only; deterministic under `seed`.

### 7.4 `red_team/pipeline.py` (existing — integration only)

- **Does:** `generate_ideas()` is extended so that, for a tournament-selected
  zone, it: asks `entrant_selection.select_entrants()` which entrants run;
  passes them to `ModelTournament.generate()` (which already fans out and
  tags); calls `IdeationTournamentJudge.judge_round()` on the resulting
  per-entrant idea sets; and after the zone's ideas are executed and judged,
  calls `update_winrate()` with the execution outcomes. The merged idea pool
  still flows through the existing dedup → priority → execute → judge path
  unchanged. `_llm_for_entrant()` resolves entrant roles via `make_llm(role)`.
  No new public method.
- **Depends on:** `red_team/ideation_tournament.py`,
  `red_team/entrant_selection.py`.

## 8. The win-rate update

A `ModelZoneWinrate` row holds, per `(zone_id, model_label)`: an ideation-judge
record (`h2h_wins`, `h2h_comparisons`) and an execution record
(`confirmed`, `suspicious`, `ideas_executed`). The combined **win-rate** is:

```
h2h_rate   = h2h_wins / max(h2h_comparisons, 1)
exec_rate  = (confirmed + 0.5·suspicious) / max(ideas_executed, 1)
winrate    = h2h_weight · h2h_rate + (1 − h2h_weight) · exec_rate
```

`h2h_weight` (config, default `0.6`) leans on the cheap, immediate
ideation-judge signal while still grounding the rate in real execution
outcomes. An entrant with no history at all gets a neutral prior (`0.5`) so
`entrant_selection` treats it optimistically — the same starvation-avoidance
principle the mutation-operator stats use. The win-rate is stored, not
recomputed, so it accumulates across cycles.

## 9. Data model additions

All land in `interfaces/schema.sql` via the migration system; `schema_version`
bumps `2 → 3`.

### New table — `model_zone_winrate`

```sql
CREATE TABLE IF NOT EXISTS model_zone_winrate (
    zone_id          TEXT NOT NULL,
    model_label      TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT '',
    h2h_wins         INTEGER NOT NULL DEFAULT 0,
    h2h_comparisons  INTEGER NOT NULL DEFAULT 0,
    confirmed        INTEGER NOT NULL DEFAULT 0,
    suspicious       INTEGER NOT NULL DEFAULT 0,
    ideas_executed   INTEGER NOT NULL DEFAULT 0,
    winrate          REAL NOT NULL DEFAULT 0.5,
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (zone_id, model_label)
);
CREATE INDEX IF NOT EXISTS idx_model_zone_winrate_zone
    ON model_zone_winrate(zone_id, winrate);
```

### New table — `model_tournament_rounds`

One row per head-to-head round (one zone, one cycle), for offline analysis and
the future learned model-selection policy:

```sql
CREATE TABLE IF NOT EXISTS model_tournament_rounds (
    round_id      TEXT PRIMARY KEY,
    cycle_id      INTEGER NOT NULL,
    zone_id       TEXT NOT NULL,
    entrants      TEXT NOT NULL DEFAULT '[]',
    pairwise      TEXT NOT NULL DEFAULT '[]',
    winner_label  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_model_tournament_rounds_zone
    ON model_tournament_rounds(zone_id, cycle_id);
```

`entrants` and `pairwise` are JSON-text — the list of entrant labels and the
list of `{a, b, winner, margin}` comparison records — consistent with the
JSON-text-for-flexible-structures convention the schema already uses.

The existing `model_runs` table (per-LLM-call accounting) is reused unchanged:
every entrant's ideation calls already land there via the standard LLM path,
so per-model token/cost is already accounted for and the tournament need not
duplicate it.

### New `interfaces/` types

- `ModelZoneWinrate` — mirrors the `model_zone_winrate` row; returned by
  `get_model_zone_winrate` and `update_winrate`.
- `TournamentRound` — `round_id`, `cycle_id`, `zone_id`, entrant labels, the
  pairwise comparison records, the round winner; mirrors
  `model_tournament_rounds` and is returned by `judge_round`.
- `PairwiseIdeaSetResult` — one head-to-head comparison: `zone_id`,
  `winner_label`, `loser_label`, `margin`, `reasoning`.

`IdeaObject` is **not** changed; `idea.model_label` already rides on the idea
instance as a red-team-local attribute (set by `ModelTournament.generate()`).

### New MCP methods (`interfaces/mcp_tools.py`)

- `get_model_zone_winrate(zone_id: str | None = None) -> list[ModelZoneWinrate]`
  — all rows, or one zone's rows, for routing decisions.
- `update_model_zone_winrate(row: ModelZoneWinrate) -> None` — upsert.
- `log_tournament_round(round: TournamentRound) -> str` — insert one
  `model_tournament_rounds` row, returns `round_id`.

Implemented in both `infra/mcp_server.py` and `infra/mock_mcp.py`.

## 10. Data flow per cycle

1. The orchestrator steers the cycle to the lowest-coverage zone (unchanged).
2. If `red_team.model_tournament.enabled` and the zone is tournament-eligible
   (within the per-cycle tournament-zone budget): `entrant_selection.select_entrants()`
   reads persisted `model_zone_winrate` and picks the entrants for this zone.
3. `ModelTournament.generate()` fans out — `make_llm(role)` per entrant, the
   normal 3-mode ideation — and returns the merged, model-tagged idea pool.
4. `IdeationTournamentJudge.judge_round()` runs the round-robin pairwise
   comparison of the per-entrant idea sets and persists a `TournamentRound`
   via `log_tournament_round`.
5. The merged pool flows through the existing dedup → priority → execute →
   judge path unchanged.
6. As ideas are judged, `ModelTournament.record_outcome(label, verdict,
   zone_id)` accumulates the execution-outcome counters.
7. After the zone's ideas are judged, `update_winrate()` folds the round's
   head-to-head wins and the execution counters into the per-zone win-rate
   (§8) and persists via `update_model_zone_winrate`.
8. Next time the orchestrator returns to this zone, step 2 reads the updated
   win-rates and routes ideation toward the entrant that won here before — the
   feedback loop closes.

## 11. Integration points

- **`red_team/pipeline.py`** — `generate_ideas()` extended with entrant
  selection, the head-to-head judging call, and the post-judgment win-rate
  update. Tournament disabled → today's single-model path exactly.
- **Model routing (Person A infra spec)** — hard dependency. Entrant `role`s
  are `models:` role labels; `_llm_for_entrant()` resolves them via
  `make_llm(role)`. The architecture report's recommended entrants map to
  roles: `red_ideation` (Nemotron Super, the default workhorse), a
  `frontier_creative_optional` role (a frontier creative model), and a
  `cyber_specialist_optional` role (a cyber-specialised open model, run only
  in an isolated red lane per the report's caveat). The optional roles are
  already modelled by the existing `Entrant.optional` flag.
- **MCP / `infra/`** — three new methods; one schema migration; `model_runs`
  reused unchanged. No other infra change.
- **Dashboard** — one additive panel: per-zone model win-rate (the
  architecture report's "Model performance by role" item, sharpened to per
  zone), plus the most recent tournament rounds.
- **`configs/monkeyclaw.yaml`** — the existing `red_team.model_tournament`
  block gains: `tournament_zones_per_cycle`, `h2h_weight`,
  `exploration_floor`. The `enabled`/`entrants` shape is unchanged.

## 12. Error handling

- **Tournament disabled** — `ModelTournament.enabled` is false; the entire
  tournament path is skipped and ideation runs single-model. Already true.
- **An optional entrant's ideation fails** — already swallowed by
  `ModelTournament.generate()`; that entrant simply contributes no ideas, is
  treated as a forfeit in the head-to-head round, and the cycle proceeds.
- **A required entrant fails** — logged as an alert; if at least one entrant
  produced ideas the cycle continues with what it has; if none did, ideation
  falls back to the single configured model exactly as a disabled tournament
  would. The cycle never aborts on a model failure.
- **A pairwise ideation-judge call fails** — that comparison is dropped; the
  round records the remaining comparisons; an entrant with no completed
  comparisons keeps its prior win-rate (no update on missing evidence).
- **MCP persistence failure** — logged and swallowed; the in-memory
  per-zone stats still steer this cycle's logging. Only durability of the
  win-rate / round record is lost for that write; the cycle never aborts.
- **A zone with one entrant** — no head-to-head is possible; the round is
  skipped, only the execution-outcome signal updates the win-rate, and an
  exploration-floor draw still re-introduces other entrants on a later cycle.

## 13. Testing strategy

Tests live in `test/` under the `test_<area>_*.py` convention.

- `test_tournament.py` (existing — extended) — per-zone counters in
  `_bump` / `record_outcome` / `leaderboard`; `load_winrates` / `winrate`
  round-trip; existing disabled-tournament and optional-entrant-failure tests
  stay green.
- `test_ideation_tournament.py` — `judge_round` runs the right number of
  round-robin comparisons for 2 and 3 entrants, parses winner/margin, treats
  an empty idea set as a forfeit, and survives a failed pairwise call;
  `update_winrate` folds h2h and execution signals per the §8 formula,
  including the neutral prior for a no-history entrant.
- `test_entrant_selection.py` — with a fixed `seed`, selection is
  deterministic; a high-win-rate entrant is selected more often than a
  low-win-rate one across N draws; the `exploration_floor` guarantees every
  configured entrant a minimum sampling rate; a no-history zone runs all
  entrants.
- `test_tournament_pipeline_e2e.py` — one full red cycle in mock mode with
  the tournament enabled on a planted zone: multiple entrants generate, the
  head-to-head round is judged and persisted, win-rates update, and a
  disabled-tournament run reproduces the single-model pipeline byte-for-byte.
- `test_contracts.py` (existing) — extended for the three new MCP method
  signatures on both implementations.

All entrant LLM clients and the ideation judge are mocked; every test runs in
mock mode with zero model credentials, consistent with the repo's demo posture.

## 14. Phased delivery

This spec is sequenced **after** the model-routing work (the `models:` config
and `make_llm(role)`) lands, per constraint 5.

- **Phase 0 — contracts:** `ModelZoneWinrate` / `TournamentRound` /
  `PairwiseIdeaSetResult` types, the three MCP methods on the protocol + both
  implementations, the schema migration (`2 → 3`).
- **Phase 1 — per-zone stats + persistence:** extend `ModelTournament` with
  the per-zone counters, `load_winrates`, `winrate`; wire `model_runs` token
  accounting confirmation.
- **Phase 2 — head-to-head judging:** `ideation_tournament.py`,
  `judge_round`, `log_tournament_round`.
- **Phase 3 — win-rate + routing:** the §8 win-rate update,
  `entrant_selection.py`, the per-zone routing draw.
- **Phase 4 — pipeline wiring:** `generate_ideas()` integration, the config
  additions, the dashboard panel.
- **Later (not this spec):** train a learned model-selection policy on the
  accumulated `model_tournament_rounds` dataset, conditioned on zone and idea
  features rather than win-rate alone.

## 15. Open questions

1. **Tournament-zone budget.** `tournament_zones_per_cycle` bounds cost — the
   tournament fans out across N models, so running it on every zone every
   cycle is expensive. Whether the eligible zones should be the
   lowest-detection-coverage zones, the zones with the most win-rate
   uncertainty, or a fixed rotation is left to tune; the config isolates the
   decision.
2. **h2h vs. execution weighting.** `h2h_weight` defaults to `0.6`, leaning on
   the cheap ideation-judge signal. The right balance — how much to trust a
   judge's read of an idea set versus real executed outcomes — is an ablation
   question answerable once `model_tournament_rounds` has enough history.
3. **Entrant churn.** Adding or removing an entrant role mid-deployment leaves
   stale `model_zone_winrate` rows. They are simply never selected again; a
   row for an entrant no longer in the config is inert. Whether to prune such
   rows is a housekeeping question deferred until it matters.
