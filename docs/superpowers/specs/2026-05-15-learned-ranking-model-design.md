# Learned Ranking Model — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw spends LLM tokens generously on *pre-execution* decisions: the
ideation engine runs three prompt modes per zone, the strategist makes a
synthesis call, and — most expensively — the judge ensemble runs five LLM calls
per lane (`red_team/judge_ensemble.py`). Many of those calls exist only to
*rank*: to decide which ideas are worth executing, which mutation operator to
apply next, and how interesting an attempt was. The architecture report
(`docs/monkeyclaw_full_architecture_report.md`, "Should MonkeyClaw Train Its
Own Small Model?") names the fix directly:

> A small ranking/preference model or LoRA adapter that predicts
> idea/component usefulness from structured traces. … A small model can replace
> expensive LLM calls for pre-ranking and mutation selection. This directly
> improves token efficiency and exploration quality.

And, just as directly, the report names the trap:

> Do not train first. Collect at least hundreds to thousands of attempts,
> build the structured dataset, then train/evaluate offline. Until then, use
> heuristics plus pairwise judge comparisons.

This spec is therefore structured around that warning. Its **first and
load-bearing deliverable is a data-collection layer**, not a model. The model
is a later phase that only begins once the dataset crosses a stated size and
quality bar. Until then a deterministic heuristic ranker — already most of what
`red_team/priority.py` and `red_team/progress.py` compute — plus pairwise
judge comparisons stand in, behind the exact same interface the future model
will implement.

## 2. What this depends on, and what already exists

This spec sits on top of two other specs and several existing modules. It does
not duplicate them.

- **Trajectory scoring** — `red_team/progress.py` already exists and produces a
  rich, deterministic `ProgressScore` per `LaneResult`: `risk_stage`,
  `progress_delta`, `refusal_strength`, `boundary_erosion`, `steerability`,
  `transfer_likelihood`, `robustness`, costs, `failure_mode`, and
  `useful_components`. These are the **trajectory features** the ranking model
  consumes. This spec depends on `progress.py` and the trajectory-scoring spec;
  it does not re-derive trajectory features.
- **Judge ensemble** — `red_team/judge_ensemble.py` already exists and produces
  five role votes (`safety`, `progress`, `novelty`, `robustness`, `forensics`)
  with scores and confidences, persisted in `judge_votes`. These are the
  **judge-ensemble score** inputs, and the judge ensemble's pairwise mode is
  the labelling oracle for Phase 0. This spec depends on the judge-ensemble
  spec; it does not modify the ensemble.
- **Priority** — `red_team/priority.py` already computes
  `novelty × impact × coverage_gap × severity_weight`. This is the current
  heuristic ranker; this spec wraps it behind a stable interface and, later,
  swaps the implementation.
- **Mutation operators** — `red_team/mutations.py` already defines 12 operators
  and an in-memory `MutationStats` accumulator that ranks operators by observed
  improvement. The learned model's "likely mutation operators" output replaces
  `MutationStats.rank()` once trained; until then `MutationStats` *is* the
  heuristic.
- **MAP-Elites archive** — `red_team/archive.py` defines the niche grid
  (`zone × interaction_style × response_movement`). The model's "archive niche"
  output predicts which cell an attempt will land in.
- **model_runs table** — already in `interfaces/schema.sql`; per-LLM-call
  accounting (tokens, cost) exists and feeds the model's `token_cost` input.

So the genuinely *new* work here is: (a) a trace-collection layer that
assembles labelled training rows from data the loop already produces, (b) a
stable `Ranker` interface, (c) a heuristic implementation of it that ships
immediately, and (d) — gated behind the dataset bar — an offline training
pipeline and a learned implementation.

## 3. Scope

In scope:

- A **structured trace dataset**: `red_team/trace_collector.py` assembles one
  labelled row per attack attempt from the `LaneResult`, the `IdeaObject`, the
  `ProgressScore`, the judge-ensemble votes, the repro outcome, and the
  mutation operator used. Rows persist in a new `attempt_traces` table.
- A **`Ranker` contract** in `interfaces/` — the stable interface the
  pre-ranking and mutation-selection call sites depend on, with a `predict`
  that returns a `RankerOutput` (usefulness score, likely mutation operators,
  archive niche, likely failure mode).
- A **`HeuristicRanker`** — the day-one implementation, composed from
  `priority.py`, `progress.py`, and `MutationStats`. Ships immediately; no
  training, no new model.
- A **pairwise labelling path** — using the judge ensemble in pairwise mode to
  generate preference labels (A-better-than-B) while absolute scores are noisy.
- A **dataset-readiness gate** — explicit, measured criteria that must be met
  before any training run.
- An **offline training pipeline** (`scripts/train_ranker.py`) and a
  **`LearnedRanker`** implementation — a LoRA adapter or a lightweight ranking
  head — both gated behind the readiness gate.
- Offline evaluation: the learned ranker must beat the heuristic ranker on a
  held-out split before it is allowed to serve.

Explicitly out of scope (YAGNI for this spec):

- Training a model in the hackathon timeframe. The dataset will not be large
  enough; Phases 0–2 (collection + heuristic + pairwise labels) are what ships.
- Replacing the judge ensemble's *verdict*. The ranker predicts *usefulness for
  search steering*; the judge ensemble remains the authority on whether an
  attack succeeded. The ranker never decides a finding.
- Online / continual learning. Training is strictly offline, batch, versioned.
- Replacing patch generation or root-cause analysis with a learned model — the
  architecture report explicitly scopes the small model to ranking only.
- A model registry / serving infrastructure — the learned ranker is a single
  versioned artifact loaded from disk, like the embedding model already is.

## 4. Design constraints

1. **Data collection first; do not train prematurely.** No training run happens
   before the §8 readiness gate passes. Phases 0–2 are independently valuable
   (the heuristic ranker improves token efficiency on its own and the dataset
   is built regardless).
2. **The `Ranker` interface is stable across implementations.** `HeuristicRanker`
   and `LearnedRanker` are interchangeable. Swapping them is a config change,
   not a code change at the call sites.
3. **The ranker is advisory and reversible.** It steers *which ideas execute
   first* and *which mutation to try* — it never gates a finding and never
   discards an idea outright. A bad ranker wastes some token budget on
   ordering; it cannot cause a missed vulnerability or a false finding.
4. **`interfaces/` stays the contract firewall.** `RankerInput`, `RankerOutput`,
   the `Ranker` protocol, and the schema delta land in `interfaces/`;
   `red_team/` imports them read-only.
5. **Labels are cheap and concrete; favour them over expensive ones.** The
   primary label — repro success, progress delta, Tier 1/Tier 2 verdict — is
   already produced by the loop for free. Pairwise judge comparisons are the
   secondary label, used only where absolute scores are too noisy. No human
   labelling is required or assumed.
6. **Training is offline, batch, and versioned.** The learned artifact carries
   the dataset snapshot id, the feature schema version, and an evaluation
   report. A learned ranker that has not beaten the heuristic on a held-out
   split never serves.

## 5. Architecture

```
   PHASE 0–2  (ships now — collection + heuristic)
   ───────────────────────────────────────────────
   judge_ensemble ─votes─┐
   progress.py ─ProgressScore─┐
   priority.py ─components─┐  │
   routing/repro ─outcome─┐│  │
   mutations.py ─operator─┐││ │
                          ▼▼▼▼▼
              red_team/trace_collector.py
                · assembles one labelled row per attempt
                · writes attempt_traces table
                          │
                          │   (the dataset accumulates)
                          ▼
   pre-ranking call site ──► Ranker (interface, interfaces/ranker.py)
   mutation-select site ──►   │
                              ├── HeuristicRanker   (serves now)
                              └── LearnedRanker     (serves after §8 gate)

   PHASE 3+  (gated behind the dataset-readiness gate)
   ───────────────────────────────────────────────────
   attempt_traces ──► scripts/train_ranker.py ──► ranker artifact
                            │  (offline, batch)        │
                       judge pairwise labels           ▼
                                              offline eval vs HeuristicRanker
                                                        │  must win
                                                        ▼
                                              LearnedRanker serves
```

## 6. Components

### 6.1 `interfaces/ranker.py` — the contract (NEW, in `interfaces/`)

- **Does:** Defines `RankerInput`, `RankerOutput`, and the `Ranker` Protocol.
  This is the firewall: every consumer imports only this.
- **`RankerInput`** — exactly the model inputs the architecture report names:
  `idea_summary` (str), `tactic_tags` (list[str]), `zone_id` (str),
  `trajectory_features` (the `ProgressScore` dimensions, when an attempt has
  run; absent for a not-yet-executed idea), `judge_scores` (the five ensemble
  role scores, when available), `repro_outcome` (str | None), `token_cost`
  (int), `mutation_operator` (str | None).
- **`RankerOutput`** — exactly the outputs the report names: `usefulness`
  (float 0–1), `likely_mutation_operators` (list[str], ranked, from
  `MUTATION_OPERATORS`), `archive_niche` (a `zone × interaction_style ×
  response_movement` cell key), `likely_failure_mode` (one of
  `progress.FAILURE_MODES`).
- **`Ranker` Protocol** — `predict(input: RankerInput) -> RankerOutput` and
  `rank(inputs: list[RankerInput]) -> list[int]` (the argsort by usefulness).

### 6.2 `red_team/trace_collector.py` — the dataset layer (the first deliverable)

- **Does:** After each judged attempt, assembles **one `AttemptTrace` row**
  from data the loop already produced — the `IdeaObject` (summary, tactics,
  zone, mutation operator), the `LaneResult`, the `ProgressScore` from
  `progress.py`, the five judge-ensemble votes, the repro outcome once the
  repro pipeline reports back, and the `token_cost` from `model_runs`. It
  writes the row to `attempt_traces`. The trace is the *features* plus the
  *label*; the label fields are filled in two passes (the repro outcome lands
  later than the judge verdict — the row is updated when it does).
- **Interface:** `record(idea, lane_result, progress, ensemble_outcome) ->
  trace_id`; `attach_repro_outcome(trace_id, outcome)`;
  `export(split, schema_version) -> list[AttemptTrace]` (for the trainer).
- **Depends on:** `interfaces/types.py`, `interfaces/ranker.py`, the
  `attempt_traces` table. Called from `red_team/routing.py` — one more
  best-effort write alongside the existing finding/coverage/archive writes.

### 6.3 `red_team/pairwise_labels.py` — the secondary labelling path

- **Does:** Where absolute usefulness is too noisy to label cleanly (two
  attempts both "suspicious", both with mid `search_score`), this module asks
  the judge ensemble in **pairwise mode** — "is attempt A more useful to the
  search than attempt B?" — and records the preference. Pairwise comparisons
  are cheaper to make reliable than absolute scores and are exactly what the
  architecture report recommends as the interim signal. Pairs are sampled
  within a `(zone, failure_mode)` bucket so comparisons are meaningful.
- **Interface:** `compare(trace_a, trace_b) -> Preference`;
  `sample_pairs(traces, budget) -> list[tuple[AttemptTrace, AttemptTrace]]`.
- **Depends on:** `red_team/judge_ensemble.py`, the `pairwise_labels` table.
- **Note:** this runs on a budget (a small number of comparisons per cycle) so
  it does not reintroduce the LLM cost the learned ranker is meant to remove.
  It is interim scaffolding: once the `LearnedRanker` serves, pairwise sampling
  drops to a low background rate used only to keep validating the model.

### 6.4 `red_team/heuristic_ranker.py` — the day-one `Ranker`

- **Does:** Implements the `Ranker` protocol with **no learned model**. It
  composes existing deterministic logic: `usefulness` blends
  `priority.py`'s priority components (for not-yet-run ideas) and
  `progress.search_score` (for run attempts) into 0–1; `likely_mutation_operators`
  delegates to `MutationStats.rank()` from `red_team/mutations.py`;
  `archive_niche` maps `IdeaTactics.interaction_style` plus the predicted
  `failure_mode` to a cell key; `likely_failure_mode` reuses `progress.py`'s
  classifier on the trajectory features when present, else a tactic-tag
  heuristic. It ships in Phase 1 and is the permanent fallback if a learned
  ranker is ever withdrawn.
- **Interface:** the `Ranker` Protocol.
- **Depends on:** `red_team/priority.py`, `red_team/progress.py`,
  `red_team/mutations.py`, `red_team/archive.py`.

### 6.5 `scripts/train_ranker.py` — offline training (gated)

- **Does:** A standalone, human-run script (never invoked by the loop). It
  reads `attempt_traces` (plus `pairwise_labels`), checks the §8 readiness
  gate, builds train/val/test splits, trains the learned ranker, runs the §9
  offline evaluation against `HeuristicRanker`, and writes a versioned artifact
  + an evaluation report. It refuses to produce a servable artifact if the gate
  fails or the model loses to the heuristic.
- **Interface:** CLI — `python scripts/train_ranker.py [--dry-run]`.

### 6.6 `red_team/learned_ranker.py` — the learned `Ranker` (gated)

- **Does:** Implements the `Ranker` protocol by loading a trained artifact. The
  artifact is one of two forms, decided at training time and recorded in the
  artifact metadata:
  - **A lightweight ranking head** — a small MLP / gradient-boosted model over
    the structured features. Preferred default: it is tiny, fast, CPU-friendly,
    needs the fewest examples, and the inputs are already structured.
  - **A LoRA adapter** — over a small base (e.g. a Nemotron Nano), used only if
    the `idea_summary` free text turns out to carry signal the structured
    features miss. Heavier; chosen only if the head plateaus and evaluation
    justifies it.
- It carries its dataset snapshot id and feature-schema version; on a feature
  schema mismatch it refuses to load and the runtime falls back to
  `HeuristicRanker`.
- **Interface:** the `Ranker` Protocol, plus `load(artifact_path)`.

## 7. The structured trace (data model)

`attempt_traces` — one row per judged attack attempt — in
`interfaces/schema.sql` via migration:

- **Identity:** `trace_id`, `idea_id`, `finding_id` (nullable), `cycle_id`,
  `zone_id`, `feature_schema_version`, `created_at`.
- **Features (the `RankerInput`):** `idea_summary`, `tactic_tags` (JSON),
  `mutation_operator`, `interaction_style`, plus the flattened `ProgressScore`
  dimensions, the five judge-ensemble role scores + confidences (JSON), and
  `token_cost`.
- **Labels:** `repro_outcome` (`reproduced` | `flaky` | `not_reproduced` |
  `pending`), `judge_verdict` (`confirmed` | `suspicious` | `clean`),
  `search_score` (the `progress.search_score` scalar), `archive_niche` (the
  cell the attempt actually landed in), `usefulness_label` (the derived 0–1
  target — see below).
- The `usefulness_label` is a deterministic function of the cheap signals
  (confirmed repro is high, clean hard-refusal is low, near-miss with boundary
  erosion is mid). It is computed by `trace_collector`, not hand-labelled.

`pairwise_labels` — `(pair_id, trace_a, trace_b, preferred, judge_confidence,
created_at)` — the preference labels from `pairwise_labels.py`.

New `interfaces/` types: `RankerInput`, `RankerOutput`, `AttemptTrace`,
`Preference`, and the `Ranker` Protocol (`interfaces/ranker.py`).

The migration bumps `schema_meta.schema_version` and records the initial
`feature_schema_version` as a `schema_meta` row, so a trained artifact can
detect a feature-schema drift.

## 8. The dataset-readiness gate

Training does not begin until **all** of these measured criteria hold. They are
checked by `scripts/train_ranker.py`, which aborts with a clear report if any
fails:

1. **Volume.** At least **800** `attempt_traces` rows with a non-`pending`
   `repro_outcome` (the architecture report's "hundreds to thousands"; 800 is
   the floor, more is better).
2. **Label balance.** Each `judge_verdict` class is at least 10% of the
   dataset, and the dataset spans at least 12 of the 18 zones — a ranker
   trained on three zones will not generalise.
3. **Failure-mode spread.** At least four of the six `progress.FAILURE_MODES`
   are represented with ≥30 rows each.
4. **Pairwise coverage.** At least **300** `pairwise_labels` rows, sampled
   across at least 8 zones.
5. **Feature stability.** No `feature_schema_version` change in the most recent
   300 rows — i.e. the feature definition has stopped moving.

Until the gate passes, `HeuristicRanker` serves and the dataset keeps
accumulating. The gate state is surfaced on the dashboard (a simple
"dataset readiness" panel) so the operator knows when training is viable.

## 9. Offline evaluation

`scripts/train_ranker.py` evaluates a candidate `LearnedRanker` on a held-out
test split (chronologically the most recent 15% of traces — a time-based split,
not random, so evaluation reflects future performance):

- **Ranking quality:** the learned ranker's idea ordering vs. the heuristic's,
  scored by how often the top-ranked idea was the one that actually produced
  the best `search_score` / a confirmed finding (top-1 and NDCG@5).
- **Mutation prediction:** accuracy of `likely_mutation_operators[0]` against
  the operator that actually improved an attempt.
- **Niche / failure-mode prediction:** classification accuracy against the
  observed `archive_niche` and `failure_mode`.
- **Cost model:** estimated LLM tokens saved — the pre-ranking and
  mutation-selection calls the learned ranker displaces, from `model_runs`.

**Promotion rule:** the `LearnedRanker` is allowed to serve only if it strictly
beats `HeuristicRanker` on ranking quality on the held-out split *and* does not
regress mutation/niche accuracy. Otherwise the artifact is rejected and the
heuristic keeps serving. This is the same evidence-before-assertion posture the
purple-team spec applies to its report card (constraint §4.3 there).

## 10. Integration points

- **`red_team/routing.py`:** one new best-effort call —
  `trace_collector.record(...)` — alongside the existing finding / coverage /
  archive writes. A trace-write failure logs and never aborts routing.
- **Pre-ranking call site (`red_team/priority.py` / `pipeline.py`):** the idea
  ordering step calls `Ranker.rank(...)` instead of (or composed with) the raw
  `score_ideas` sort. With `HeuristicRanker` this is behaviour-equivalent to
  today; with `LearnedRanker` it is the learned ordering.
- **Mutation-selection call site (`red_team/mutations.py` consumers):** the
  "which operator next" decision calls `Ranker.predict(...).
  likely_mutation_operators` instead of `MutationStats.rank()` directly —
  `HeuristicRanker` simply delegates back to `MutationStats`, so the swap is
  transparent until a learned ranker lands.
- **Repro pipeline:** when a repro completes it calls
  `trace_collector.attach_repro_outcome(...)` — closing the label.
- **`interfaces/`:** new `interfaces/ranker.py`, new types, schema migration.
- **Dashboard:** one new view — dataset-readiness + (once a learned ranker
  serves) the offline-evaluation summary. Additive.
- **Config:** one new key, `red_team.ranker` (`heuristic` | `learned`), default
  `heuristic`. Switching to `learned` with no servable artifact falls back to
  `heuristic` with a logged warning.

## 11. Error handling

- A `trace_collector` write failure is best-effort: logged, never
  cycle-aborting — consistent with the archive-update handling in
  `routing.py`.
- A `LearnedRanker` artifact that is missing, corrupt, or has a mismatched
  `feature_schema_version` causes a logged fallback to `HeuristicRanker` —
  the loop never stops for a ranker problem.
- `pairwise_labels.py` runs on a strict per-cycle budget; if the judge LLM is
  unavailable the comparison is skipped, not retried into a cost spike.
- `scripts/train_ranker.py` aborts loudly (non-zero exit, clear report) if the
  readiness gate fails or the candidate loses the offline evaluation — it never
  emits a servable artifact in those cases.
- Because the ranker is advisory (constraint §4.3), every failure mode degrades
  to "ranking is slightly worse," never to a missed or false finding.

## 12. Testing strategy

Tests live in `test/`, `test_ranker_*.py` / `test_trace_*.py`, matching the
existing `test_<area>_*.py` convention.

- `test_trace_collector.py` — `record` assembles a row with the right features
  from a hand-built `LaneResult` + `ProgressScore` + ensemble outcome;
  `attach_repro_outcome` updates the label; `export` honours the split.
- `test_heuristic_ranker.py` — the `HeuristicRanker` satisfies the `Ranker`
  protocol; `rank` orders a fixture idea set by composed priority/progress;
  `likely_mutation_operators` matches `MutationStats.rank()`.
- `test_ranker_interface.py` — `HeuristicRanker` and a stub `LearnedRanker` are
  interchangeable behind `Ranker`; a missing learned artifact falls back to
  heuristic.
- `test_pairwise_labels.py` — pair sampling stays within `(zone, failure_mode)`
  buckets; a mock judge produces a recorded `Preference`.
- `test_dataset_readiness.py` — the gate passes on a fixture dataset that meets
  all five criteria and fails (with the specific failing criterion named) on
  datasets that miss each one.
- `test_train_ranker_gate.py` — `train_ranker.py --dry-run` against an
  insufficient dataset aborts without emitting an artifact.
- All runs in mock mode, zero model credentials.

## 13. Phased delivery

The phasing is the spec's central discipline: collection ships first, the model
is gated, and every phase is independently valuable.

- **Phase 0 — contracts + trace schema:** `interfaces/ranker.py`, the
  `AttemptTrace` / `Preference` types, the `attempt_traces` and
  `pairwise_labels` tables, the schema migration. No behaviour change.
- **Phase 1 — collection + heuristic:** `red_team/trace_collector.py` wired
  into `routing.py`; `red_team/heuristic_ranker.py`; the pre-ranking and
  mutation-selection call sites routed through the `Ranker` interface. From
  here the dataset accumulates on every cycle, and the ranker indirection is in
  place — with zero behaviour change, because `HeuristicRanker` reproduces
  today's logic.
- **Phase 2 — pairwise labels:** `red_team/pairwise_labels.py`; the
  dataset-readiness panel on the dashboard. The dataset now gains preference
  labels.
- **Phase 3 — training (gated):** `scripts/train_ranker.py` and the offline
  evaluation. **Only runs once the §8 gate passes** — likely well after the
  hackathon. Produces a candidate artifact + report.
- **Phase 4 — learned serving (gated):** `red_team/learned_ranker.py`; the
  `red_team.ranker=learned` config path. **Only serves once the candidate
  beats `HeuristicRanker`** on the held-out split (§9).
- **Continuous:** pairwise sampling drops to a low background rate; the trained
  ranker is periodically re-evaluated against fresh traces, and a regression
  against the heuristic reverts serving to `heuristic`.

Phases 0–2 are this spec's committed deliverable. Phases 3–4 are designed now
but deliberately deferred behind measured gates — exactly the
"do not train first" instruction from the architecture report.

## 14. Open questions

1. **Head vs. LoRA adapter.** Phase 3 decides empirically. The structured
   features alone may be sufficient, in which case a gradient-boosted / small
   MLP head is the clear choice (cheaper, fewer examples, CPU-friendly). The
   LoRA adapter is held in reserve for the case where `idea_summary` free text
   carries signal the structured features miss. The `Ranker` interface is
   identical either way.
2. **Usefulness-label formula.** The deterministic `usefulness_label`
   (§7) needs calibration once real traces exist — the relative weight of
   "confirmed repro" vs. "high boundary erosion near-miss" is a judgement the
   first 800 traces will inform.
3. **Pairwise vs. absolute as the primary training signal.** If absolute
   `usefulness_label` proves too noisy even at 800 rows, the trainer can switch
   to a pairwise-ranking objective (learning from `pairwise_labels` directly).
   Both label sources are collected from Phase 1/2 onward, so the choice can be
   made at training time without re-collecting data.
4. **Re-training cadence.** Once a learned ranker serves, how often to
   re-train against accumulated traces is a tuning question for the
   continuous phase; the time-based eval split (§9) makes a stale model
   detectable before it is re-trained.
