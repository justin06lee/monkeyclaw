# Ranking model notes

Companion to the learned-ranking-model spec. The ranking layer is
**data-collection-first**: the dataset accrues on every cycle, but a learned
model is gated behind measured criteria and never trains prematurely.

## What ships today

- `interfaces/ranker.py` — the stable `Ranker` Protocol (`RankerInput`,
  `RankerOutput`). Every pre-ranking / mutation-selection call site imports
  only this contract.
- `red_team/trace_collector.py` — assembles one labelled `AttemptTrace` per
  judged attempt and writes it to `attempt_traces`. This is the load-bearing
  deliverable; it runs whether or not a learned ranker is ever trained.
- `red_team/heuristic_ranker.py` — `HeuristicRanker`, the day-one `Ranker`.
  No learned model: it composes `progress.search_score` and
  `MutationStats.rank()`. It is also the permanent fallback.
- `red_team/pairwise_labels.py` — the secondary labelling path: judge-ensemble
  pairwise comparisons within `(zone, judge_verdict)` buckets, on a strict
  per-cycle budget.

## The model is gated

- `scripts/train_ranker.py` is human-run and offline — never invoked by the
  loop. It checks the dataset-readiness gate and aborts (non-zero exit) if the
  dataset is not ready.
- `red_team/learned_ranker.py` (`LearnedRanker`) loads a versioned artifact and
  falls back to `HeuristicRanker` on a missing, corrupt, or
  feature-schema-mismatched artifact — a ranker problem never stops a cycle.

## Dataset-readiness gate

Training does not begin until all five measured criteria hold. Thresholds are
defined authoritatively in `red_team/dataset_readiness.py`:

- **Volume** — `MIN_TRACES` (800) traces with a non-`pending` repro outcome.
- **Zone spread** — at least `MIN_ZONES` (12) distinct zones.
- **Label balance** — each judge verdict class is at least
  `MIN_VERDICT_FRACTION` (10%) of settled traces.
- **Failure-mode spread** — at least `MIN_FAILURE_MODES` (4) failure modes with
  `MIN_PER_FAILURE_MODE` (30) rows each.
- **Pairwise coverage** — at least `MIN_PAIRWISE` (300) pairwise labels.
- **Feature stability** — the most recent `FEATURE_STABLE_WINDOW` (300) traces
  share one `feature_schema_version`.

The gate is surfaced on the dashboard (`render_dataset_readiness`) so an
operator can see when training becomes viable.

## Offline-evaluation promotion rule

A trained candidate is evaluated against `HeuristicRanker` on the chronological
held-out test split (`TraceCollector.export(split="test")`). A learned ranker
that has not strictly beaten the heuristic on that split **never serves** — the
trainer refuses to emit a servable artifact.

## Config switch

`red.ranker` in `configs/monkeyclaw.yaml` (`RankerConfig`):

- `mode` — `heuristic` (default) or `learned`.
- `artifact_path` — versioned learned-ranker artifact location.
- `pairwise_budget` — max judge pairwise comparisons per cycle.

Swapping `mode` is a config change, not a code change at the call sites.

## Deferred (spec §14)

Head vs. LoRA, `usefulness_label` calibration, pairwise-vs-absolute as the
primary training signal, and re-training cadence are all deferred. Both label
sources (`usefulness_label` and `pairwise_labels`) are collected from Phase 1/2
onward, so the training-time choice needs no re-collection.
