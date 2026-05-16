# MonkeyClaw Upgrade Roadmap

Date: 2026-05-15
Status: Draft for review

This roadmap sequences the 17 design specs in `docs/superpowers/specs/` into
dependency-ordered waves. Each spec gets its own implementation plan (via the
writing-plans process) and is executed independently; this document only fixes
the **order** and the **cross-spec coordination rules**.

## The 17 specs

| Spec | Area | One-line scope |
|---|---|---|
| data-integrity-and-migrations | Arch | Queue FSMs + atomic transitions; versioned migration runner |
| model-routing | Arch | Per-role model routing, fallback chains, token/cost accounting |
| real-nemoclaw-provisioner | Arch | Ephemeral snapshot-isolated victim sandboxes |
| purple-team | Purple | Detection-as-pass scoring, coverage, validation, report card, self-governance |
| map-elites-archive | Red | Diversity-preserving elite archive of attack ideas |
| trajectory-and-progress-scoring | Red | Staged rubric + multi-turn trajectory scoring + near-misses |
| mutation-operator-learning | Red | Bandit selection over mutation operators |
| judge-ensemble | Red | Multi-judge voting, disagreement, frontier appeal, Elo |
| model-ideation-tournament | Red | Head-to-head model ideation, win-rate routing |
| corpus-driven-ideation | Red | MITRE ATLAS / OWASP-LLM-seeded ideation + tagging |
| cross-zone-attack-chaining | Red | Compose single-zone primitives into kill chains |
| learned-ranking-model | Red | Data-collection-first learned idea ranker |
| real-patch-isolation | Blue | Apply diffs in disposable worktree + rebuilt victim |
| verifier-gate-hardening | Blue | Gate 7 (detection fires) + mutation-variant robustness |
| real-root-cause-analysis | Blue | Executed-path tracer over a real code graph |
| patch-generalization-loop | Blue | Mutate→re-verify→bounce loop for incomplete patches |
| approval-and-pr-service | Blue | Severity-gated approval + audit + optional auto-PR |

## Dependency graph

```
data-integrity-and-migrations ──► (every spec that adds a table or queue state)
model-routing ──► model-ideation-tournament, judge-ensemble (frontier appeal)
real-nemoclaw-provisioner ──► real-patch-isolation
purple-team ──► verifier-gate-hardening (gate 7), patch-generalization-loop
map-elites-archive ──► cross-zone-attack-chaining
trajectory-and-progress-scoring ──┐
judge-ensemble ────────────────────┼──► learned-ranking-model
mutation-operator-learning ────────┘
mutation-operator-learning + verifier-gate-hardening ──► patch-generalization-loop
```

## Execution waves

Specs inside a wave have no dependency on each other and can be executed in
parallel; each later wave depends on earlier waves.

### Wave 0 — Foundation (strictly first)

- **data-integrity-and-migrations** — the migration runner is a hard
  prerequisite for every spec that adds a table; the queue FSMs prevent the
  lost/stranded-item bugs the spec audit already found.
- **model-routing** — small, unblocks the tournament and the ensemble appeal
  path; landing it early avoids retrofitting role plumbing.

### Wave 1 — Enablers (parallel after Wave 0)

- **purple-team**
- **real-nemoclaw-provisioner**
- **map-elites-archive**
- **trajectory-and-progress-scoring**
- **mutation-operator-learning**
- **judge-ensemble**
- **corpus-driven-ideation**
- **real-root-cause-analysis**

### Wave 2 — Depend on a Wave 1 spec (parallel after their dependency)

- **model-ideation-tournament** (needs model-routing — Wave 0 — so it may also
  start in Wave 1; placed here only because it shares `tournament.py` with the
  in-flight mutation work)
- **cross-zone-attack-chaining** (needs map-elites-archive)
- **verifier-gate-hardening** (needs purple-team's detection oracle)
- **real-patch-isolation** (needs real-nemoclaw-provisioner)

### Wave 3 — Top of the dependency tree

- **patch-generalization-loop** (needs mutation-operator-learning +
  verifier-gate-hardening)
- **learned-ranking-model** (needs trajectory-scoring + judge-ensemble, and a
  data-collection period — start collecting traces in Wave 1, train in Wave 3)
- **approval-and-pr-service** (independent; scheduled last so the human gate
  wraps a fully hardened blue pipeline)

## Cross-spec coordination rules

These prevent the parallel work from colliding:

1. **Migration versions are assigned at execution time, not in the specs.**
   Several specs say "bump schema_version 2→3". Whichever spec lands first takes
   3, the next takes 4, and so on. The migration runner from Wave 0 enforces
   ordered, idempotent files under `infra/migrations/`; spec authors must renum
   their migration to the next free version when their plan is executed.
2. **`interfaces/` is the single merge point.** All new shared types and schema
   deltas land in `interfaces/`. When two Wave 1 specs both touch
   `interfaces/types.py` or `schema.sql`, execute them on separate branches and
   merge through `interfaces/` deliberately, not by parallel edit.
3. **Shared vocabulary lives in one place.** The harm ladder / response-movement
   vocabulary used by both map-elites-archive and trajectory-and-progress-scoring
   must be defined once in `interfaces/` (per those specs) before either is
   executed — promote it in whichever of the two lands first.
4. **Purple's `telemetry_events` producer is shared.** purple-team's derived
   evidence adapter is the dense producer of `telemetry_events`;
   verifier-gate-hardening's gate 7 consumes the same table. Land purple-team
   first.
5. **Each spec keeps mock mode working.** real-nemoclaw-provisioner,
   real-patch-isolation, and the purple validator must all preserve the
   zero-credential mock path as the default until their real path clears every
   gate — consistent with the current repo posture.

## Per-spec plans

Each spec is taken through the writing-plans process to produce an
implementation plan with review checkpoints, then executed. The purple-team
implementation plan is produced first (Wave 1, and the centerpiece); the
remaining plans are produced wave by wave so each plan reflects the merged
state of its dependencies.
