# MonkeyClaw Full Architecture Report

Date: 2026-05-16
Status: As-built — reflects the system after the 17-spec upgrade program.

## Executive Summary

MonkeyClaw is a continuous adversarial security-hardening system for
NemoClaw / OpenClaw. It runs a perpetual **red → judge → repro → blue →
purple** loop: it generates attacks, executes them against victim sandboxes,
verifies outcomes with evidence, minimizes confirmed repros, produces patch
candidates and regression tests, verifies the fixes through eight gates, then
checks — through a dedicated purple-team layer — that the defense is not only
*effective* but *observable*. Everything folds back into a coverage-driven
SQLite knowledge base that steers the next cycle at the weakest zone.

An earlier version of this report (2026-05-15) described MonkeyClaw as "a
strong scaffold, not a finished security product" and laid out a seven-phase
build spec to close the gap. **That program has been executed.** It was
sequenced as 17 design specs across four dependency-ordered waves and is
complete: the migration runner, queue state machines, per-role model routing,
the purple team, MAP-Elites search, trajectory scoring, mutation-operator
learning, the judge ensemble, corpus-driven ideation, cross-zone chaining, the
learned-ranker data path, real root-cause analysis, real patch isolation, the
hardened eight-gate verifier, the patch-generalization loop, and the approval
& PR service all landed. This report documents the system as built.

The single design decision that most distinguishes MonkeyClaw is
**detection-as-pass**: a control that blocks an attack but emits no telemetry
is not treated as a passing control. The purple team scores defense on two
independent axes — prevention and observability — and a `PASS` requires both.

## System Overview

```text
red_team/    attack generation, execution, judgment, search memory
blue_team/   repro pipeline + patch generation, verification, regression
purple_team/ detection scoring, coverage, validation, report card, generalization
infra/       orchestrator, MCP server, migrations, routing, provisioning, dashboard
interfaces/  the contract layer — schema, types, MCP signatures, model router
```

The orchestrator (`infra/orchestrator.py`) runs cycles. Each cycle picks the
lowest-coverage zones, runs a red batch, judges results, drains the repro and
blue queues, and runs one purple pass. Coverage is dual-axis — an *attack*
coverage score and a *detection* coverage score per zone — and purple's
detection-gap signal is fed back into red's idea-priority scoring, so the loop
hunts both undefended and undetected zones.

## The Attack-Surface Registry

MonkeyClaw probes **18 NemoClaw attack-surface zones**, seeded in
`interfaces/schema.sql`:

| Group | Zones |
|---|---|
| Sandbox | `SBX-FS`, `SBX-NET`, `SBX-PROC`, `SBX-IPC` |
| Privacy | `PRV-ROUTE`, `PRV-LEAK` |
| Permissions | `PERM-MODEL`, `PERM-RUNTIME` |
| Skills | `SKILL-INSTALL`, `SKILL-EXEC`, `SKILL-SUPPLY` |
| Memory | `MEM-STATE`, `MEM-SHARED` |
| Inference | `INF-ROUTE`, `INF-LOCAL` |
| Agent / human | `AGENT-COMM`, `PROMPT-INJ`, `SOCIAL-ENG` |

Each zone carries a severity weight and a coverage decay rate — coverage
erodes over time so a zone tested long ago resurfaces for re-testing. The
zone → failure-class map is in `docs/zone_failure_class_mapping.md`; the
zone → detection-signature map is in `docs/zone_detection_mapping.md`.

## 1. Control Plane (`infra/`)

### Configuration

`infra/config.py` is a layered loader: `defaults → configs/monkeyclaw.yaml →
--config file → MC_* env vars`, with double-underscore nesting for env
overrides. The schema lives in `interfaces/config_schema.py`.

### Model routing

`interfaces/model_router.py` `ModelRouter` resolves a **role** (e.g.
`red_ideation`, `semantic_judge`, `patch_generation`, `cold_verification`) to
a routed client. `client_for(role)` builds an ordered fallback chain:
explicit per-role route → policy-tier route (`cheap` / `workhorse` / `heavy`
/ `frontier`) → local backend → an unconditional mock terminal. A model
outage degrades quality but never halts the loop. Every model attempt writes
a `model_runs` row — role, model, tokens, latency, USD cost from the
per-Mtok `pricing` table — and the orchestrator surfaces a per-role cost
rollup in each cycle summary.

The default routing puts high-volume agent work on Nemotron 3 Super (120B
total / 12B active MoE), cheap extraction / summarization / cold-verification
on Nemotron 3 Nano, content-safety judging on
`nemotron-content-safety-reasoning-4b`, and code-heavy work
(root cause, patch generation, code-grounded ideation) on a frontier coding
route.

### Migrations

`infra/migrations/` is a forward-only, ordinal-validated runner. Files are
`NNNN_name.sql` or `NNNN_name.py`; `.sql` runs via `executescript` in a
transaction, `.py` exports `migrate(conn)`. Each applied migration records a
`migration:NNNN` row in `schema_meta` and bumps `schema_version`; migrations
are applied on `Database` open and never re-run. **19 migrations** ship:

| # | Adds |
|---|---|
| 0001 | Baseline ledger entry for schema.sql-bootstrapped DBs |
| 0002 | FSM covering indexes on the queue tables |
| 0003 | `queue_transitions` status-transition audit table |
| 0004 | `regression_tests.run_state` column + backfill |
| 0005 | Purple-team detection tables |
| 0006 | Real-provisioner snapshot / sandbox-run tables |
| 0007 | MAP-Elites `niche_descriptors` column |
| 0008 | Trajectory-score + near-miss tables |
| 0009 | Mutation-operator stats (per-zone) + attempt tables |
| 0010 | Judge-ensemble appeal + attack-Elo tables |
| 0011 | `idea_techniques` (ATLAS/OWASP tagging) |
| 0012 | `code_symbols` / `code_edges` / `executed_paths` code graph |
| 0013 | Model-ideation-tournament win-rate tables |
| 0014 | `attack_chains` / `chain_findings` / step results |
| 0015 | Patch variant + detection result hardening tables |
| 0016 | `patch_builds` worktree-build audit table |
| 0017 | `generalization_rounds` table |
| 0018 | `attempt_traces` learned-ranking feature tables |
| 0019 | `approval_events` append-only approval audit table |

### Queue state machines

`infra/state_machine.py` defines five frozen FSMs; every status change goes
through `TransitionEngine`, which performs an atomic status `UPDATE` plus a
`queue_transitions` audit row inside `BEGIN IMMEDIATE`. No code outside this
module issues raw status updates — this is what eliminates the
lost/stranded-item bugs the prior report flagged.

| FSM | Column | States |
|---|---|---|
| `REPRO_QUEUE_FSM` | `repro_queue.status` | queued → processing → completed/failed/queued |
| `REPRO_PKG_FSM` | `repro_packages.blue_team_status` | queued → triaged → patching → verified/stuck |
| `FINDING_FSM` | `findings.patch_status` | open → in_progress → patched → verified → open |
| `PATCH_FSM` | `patches.status` | proposed → testing → approved/rejected |
| `REGRESSION_FSM` | `regression_tests.run_state` | untested → passing/failing ↔ quarantined |

### Provisioning

`infra/provisioning_nemoclaw.py` ships both `NemoClawProvisioner` (real) and
`MockProvisioner` (in-memory). The real provisioner uses a snapshot-restore
strategy against a persistent sandbox: it restores, recovers, fetches the
gateway token, and capability-probes the build to branch `ephemeral`
(deterministic per-lane disposable work area) vs `recover_only` (snapshots
unavailable). At bootstrap (`infra/bootstrap.py`) the real provisioner is the
default, with automatic fallback to the mock when the `nemoclaw` CLI is not
on `PATH`. The `demo` and `blue-team` paths always use the mock.

### Approval & PR service

`infra/approval_service.py` `ApprovalService` is stateless beyond the
append-only `approval_events` table. `request()` resolves a posture via
`GatePolicy.posture_for` (default-deny: unknown severity or an unconverged
generalization → `require_approval`). Default postures: critical/high →
`require_approval`, medium/low → `auto_allow`. `require_approval` logs an
`ask` row with an expiry, dispatches a notification, and returns `PENDING`;
the blue pipeline stashes the patch and polls the audit log each cycle.
`PRGenerator` (`infra/pr_generator.py`) optionally opens a draft PR via the
`gh` CLI — branch, apply, commit, push, `gh pr create --draft` — when
`approvals.auto_pr` is enabled (off by default).

## 2. Data Plane

SQLite + sqlite-vec is the MVP backend. Beyond the original tables
(surface zones, findings, ideas, cycle log, repro queue/packages, regression
tests, patches, code chunks, alerts), the upgrade program added:

- `idea_archive_cells` + `idea_components` — MAP-Elites archive.
- `trajectory_scores` + near-miss tables.
- `mutation_operator_stats` (+ per-zone) + `mutation_attempts`.
- `judge_votes` (ensemble), `appeal_verdicts`, `attack_elo`.
- `idea_techniques` — ATLAS/OWASP technique tags.
- `code_symbols` / `code_edges` / `executed_paths` — the root-cause graph.
- `model_zone_winrate` — ideation-tournament results.
- `attack_chains` / `chain_findings` / `chain_step_results`.
- `detection_rules` / `detection_results` / `detection_coverage` /
  `control_validation_runs` / `report_cards` — purple team.
- `patch_variant_results` / `patch_detection_results` / `patch_builds`.
- `generalization_rounds`, `attempt_traces`, `model_runs`, `approval_events`,
  `queue_transitions`, `telemetry_events`.

A production deployment migrates to PostgreSQL + pgvector for cross-lane
concurrency, object storage for transcripts/artifacts, and signed immutable
audit logs.

## 3. Red Team (`red_team/`)

`red_team/pipeline.py` `Pipeline` exposes `generate_ideas`, `execute_lane`,
and `judge` to the orchestrator.

### Ideation — four modes

`IdeationEngine` runs three prompt modes — creative (high-temp), code-grounded
(reads NemoClaw source), history-informed (queries past findings) — plus
**Mode D**, a deterministic systematic walk over the least-covered MITRE
ATLAS / OWASP-LLM techniques for the zone (`taxonomy.py`,
`technique_coverage.py`). The corpus is vendored under `red_team/corpora/`
(ATLAS v5.4.0 + OWASP LLM Top 10); a malformed corpus aborts startup. Every
idea is tagged with `atlas_technique_ids` / `owasp_category_ids`. Mode D is
additionally seeded by a preloaded 33-skill attack corpus
(`red_team/attack_skills/`, loaded via `attack_skills_loader.py` and seeded
into the `attack_skills` table at bootstrap).

### MAP-Elites archive

`red_team/archive.py` keeps a diversity-preserving archive keyed by the
3-tuple `(zone, interaction_style, response_movement)` — 18 zones × 6 styles
× 6 movements = 648 cells. `EliteArchive.consider` keeps only the
single best-scoring entry per cell, and only on a strictly higher score, so a
strong attack in one niche can never displace a different niche.
`archive_seed.py` renders a per-zone seed into the ideation prompts: elite
recall, cross-cell recombination pairs, and explicit empty-niche targets.

### Dedup, priority, chaining

Embedding similarity drops duplicates (`dedup.py`); `priority.py` scores kept
ideas as `novelty × impact × coverage_gap × severity_weight`, then applies a
detection-gap boost (`1.0 + 0.5 × det_gap`, so a fully-blind zone multiplies
priority by 1.5) and a per-zone attack-Elo signal. `strategist.py` +
`chain_composer.py` compose single-zone primitives into multi-zone kill
chains with capability-token preconditions (every required token must be
produced by an earlier step); each chain runs in its own lane.

### Execution

`execution_agent.py` drives a multi-turn attack against a live victim over
the OpenClaw gateway WebSocket; `chain_executor.py` walks chain steps,
carrying produced capability tokens and step output into the next step.

### Judgment

`judge.py` is the Tier 1 + Tier 2 dispatcher. **Tier 1** is six pure
programmatic checks in `checks.py` — filesystem breach, network violation,
process escape, permission escalation, PII-in-cloud-route, policy
modification; any trigger yields a `confirmed` verdict at confidence 1.0.
**Tier 2** fires only when Tier 1 is clean and the zone is in
`{PROMPT-INJ, SOCIAL-ENG, MEM-STATE, MEM-SHARED}`: a **five-role judge
ensemble** (`judge_ensemble.py`) — safety, progress, novelty, robustness,
forensics. `confirmed` requires the safety judge to vote confirmed above
threshold; `suspicious` requires progress and forensics to both see movement.
A contested case (high disagreement or low aggregate confidence) can escalate
to a single frontier model via `appeal_judge.py` (gated off by default).
`judge_ranking.py` runs pairwise Elo for same-zone attacks whose absolute
scores are too close to separate.

### Search memory

Every judged attempt feeds `trajectory.py` (a per-turn harm-ladder staged
rubric — stages 0–5 — replacing binary success/failure), `progress.py` (a
multi-dimensional progress score: refusal strength, specificity, boundary
erosion, steerability, novelty, transferability, robustness, cost), and
`near_miss.py` (extracts mutation-worthy near-misses). The
mutation-operator bandit (`mutation_engine.py`, `mutation_policy.py`) selects
from **12 deterministic operators** — paraphrase, benign framing, multi-turn
split, persona shift, add constraints, combine ideas, reverse order,
abstract/concretize, inject untrusted document, move-instruction-into-tool-
output, move-instruction-into-dependency-metadata — using a Thompson-sampling
policy by default and learning per-operator utility from judged lift.
`trace_collector.py` writes a labelled `AttemptTrace` per attempt;
`dataset_readiness.py` gates the offline learned-ranker trainer on a
five-criterion readiness check. `heuristic_ranker.py` ships day one;
`learned_ranker.py` falls back to it until a trained artifact passes the gate.

## 4. Repro Pipeline (`blue_team/`)

`Pipeline.process_repro_queue` processes confirmed/suspicious findings:

1. **Replay + minimize** (`replay_minimizer.py`) — provision N=5 fresh
   victims, replay the transcript; `repro_rate < 0.5` downgrades to
   suspicious and parks the item. Otherwise delta-debug drops turns and
   simplifies payloads (capped at 30 iterations).
2. **Root cause** (`root_cause.py`), severity-gated to `>= high`. When the
   code graph is enabled, `path_tracer.py` runs a real four-stage executed-
   path trace — anchor (triggered checks + victim-log identifiers → entry
   symbols), seed (semantic search → sink symbols), walk (bounded BFS over
   `code_symbols`/`code_edges`), rank (`0.5·proximity + 0.35·centrality +
   0.15·evidence_touch`). The LLM may cite only files on the traced path;
   it degrades to semantic-search-only when the graph is empty.
3. **Repro document** (`repro_writer.py`) — a fixed-section markdown vuln doc.
4. **Cold verify** (`cold_verifier.py`) — a fresh, context-free agent
   reproduces the vuln from the document alone, up to 3 attempts.
5. **Publish** — push the repro package, bump zone coverage, alert.

## 5. Blue Team (`blue_team/`)

`Pipeline.process_blue_queue` patches verified repro packages: triage →
patch generation → test generation (positive, negative, policy) →
verification → optional generalization loop → approval gate → finalize
(commit a regression test, reset coverage, alert, optional auto-PR).

### The eight verifier gates

`patch_verifier.py` runs eight gates in order; the first failure rejects:

1. **Diff applies** — real `git apply --check` in a worktree when isolation
   is enabled, else a shape check.
2. **Regression** — the positive test passes: the vulnerability no longer
   triggers on the patched victim.
3. **Mutation robustness** — replays ≤8 deterministically-mutated attack
   variants; passes only if *every* variant is blocked.
4. **Functionality** — the negative test passes: legitimate adjacent
   functionality still works.
5. **Full suite** — every active regression test still passes.
6. **Control plane** — the diff is scanned for seven weakening classes
   (deleted tests, skip markers, removed asserts/checks, loosened path lists,
   new egress, removed telemetry, MCP allowlist or CI/deploy edits).
7. **Telemetry** — the policy test passes: the patched run still emits Tier 1
   decision records — no silent bypass.
8. **Detection** — the recorded repro is replayed against a monitored
   patched victim and scored by the purple-team detection oracle; the gate
   passes only if every touched surface is still `observed`. Auto-skips when
   purple is disabled.

### Real patch isolation

`patch_isolation.py` (gated on `blue_team.patch_isolation.enabled`) does a
real `git worktree add --detach` off a pinned base ref, applies the diff,
rebuilds the victim against the worktree, and yields a `PatchBuild` to the
verifier — then tears the worktree and victim down. Disabled by default; the
verifier runs against the mock replay surface as a first-class fallback. A
startup janitor reclaims orphaned `mc-patch-*` worktrees.

## 6. Purple Team (`purple_team/`)

Purple is neither attacker nor patcher — it scores defense behavior.
`PurplePipeline.run` executes once per cycle:

1. **Derived-evidence adapter** (`derived_adapter.py`) — infers
   `TelemetryEvent` and `ControlDecision` records from monitoring-harness
   side-effects (network/fs/process/inference logs). It is the dense producer
   of the `telemetry_events` table.
2. **Detection oracle** (`detection_oracle.py`) — the core of
   detection-as-pass. It scores each execution on two axes:
   - **prevention** — `blocked` vs `succeeded` (derived from the red verdict).
   - **observability** — `observed` / `silent` / `unknown` (derived from
     control-decision records).

   The 2×2 quadrant:

   | | observed | silent / unknown |
   |---|---|---|
   | **blocked** | `PASS` | `WEAK` |
   | **succeeded** | `PARTIAL` | `FAIL` |

   Blocking an attack alone yields only `WEAK` — "works today, regresses
   tomorrow undetected." Missing or malformed telemetry degrades to
   `observability=unknown` and is never upgraded to `PASS`.
3. **Coverage model** (`coverage_model.py`) — folds verdicts into per-zone
   detection coverage and produces a joint attack × detection heatmap.
4. **Control validator** (`control_validator.py`) — re-runs the policy corpus
   against the live victim build (inline every cycle, full sweep every
   `full_sweep_every` cycles) and flags cases that regressed from a prior
   `PASS`.
5. **Detection synthesizer** (`detection_synthesizer.py`) — turns confirmed
   findings into reusable `DetectionRule`s in the whitepaper Appendix D shape.
6. **Report card** (`report_card.py`) — a measured score across seven
   whitepaper rubric dimensions (secret protection, network governance,
   approval precision, MCP governance, prompt-injection handling, audit
   completeness, developer usability). Targets are stated policy goals,
   explicitly flagged aspirational — never asserted as verified fact.
7. **Self-governance** (`self_governance.py`) — on full sweeps, points the
   detection machinery at MonkeyClaw's *own* agents (attacker, cold-verifier,
   patch-generator, judge), checking bounded egress, sandboxed execution, no
   secret-path reads, and a complete audit trail.
8. **Feedback router** (`feedback_router.py`) — routes `FAIL`/`WEAK` zones
   into the red detection-gap signal and `PARTIAL`/regressed cases into the
   blue queue.

`correlator.py` joins per-session findings, telemetry, decisions, patches,
and detection rules into the dashboard's evidence timeline.

### The generalization loop

`generalization_loop.py` runs *after* blue verifies a patch. Per round
(round 0 + up to `max_rounds` re-patch rounds, default 3):
`operator_budget.py` picks mutation operators, `mutation_replayer.py` mutates
the minimal transcript and replays each variant against the *patched* victim,
and `bypass_detector.py` scores each replay `bypassed` / `blocked` /
`inconclusive`. No bypass → `GENERALIZED`. A surviving bypass →
`bounce_builder.py` turns the worst bypass into a `BypassConstraint`, augments
the fix task, and re-runs patch generation + the eight-gate verifier. Out of
budget with an open bypass → `unconverged` (and the patch is held for
approval). The loop is provably bounded.

## 7. Monitoring, Telemetry, and the Dashboard

`infra/monitoring_harness.py` captures sandbox observables (fs diff via the
gateway, network/process/inference logs); `infra/telemetry.py` and
`sandbox_telemetry.py` normalize them. The purple derived-evidence adapter
turns these into the structured telemetry/decision records the detection
oracle consumes.

`infra/dashboard.py` serves an eleven-panel single-page dashboard:

1. Run status / pipeline flow
2. Coverage heatmap (all 18 zones)
3. Ideas & finding timeline
4. Repro queue & packages
5. Patch candidates & regression suite
6. Search intelligence — MAP-Elites archive, mutation operators, judge ensemble
7. Judge appeals & attack Elo
8. Evidence (telemetry) timeline & cycle history
9. Provisioned sandbox runs
10. Model usage & cost per role
11. Detection coverage & the security report card

## 8. Security Posture of MonkeyClaw Itself

Because MonkeyClaw is an intentionally adversarial agent system, it obeys the
same controls it tests. `infra/guardrails.py` enforces a denied-host-path
list (`~/.ssh`, `~/.aws`, gcloud config, `/etc/shadow`), a phased network
allowlist (default / analysis / setup), a model-route allowlist, an MCP-tool
allowlist, and per-cycle lane/token caps with an emergency stop. The
purple-team self-governance audit runs the detection machinery against
MonkeyClaw's own agents. Patch isolation confines diff application to
disposable worktrees. The approval service gates high-severity patches behind
a human decision recorded in an append-only audit log.

## 9. Provenance — the 17-Spec Upgrade Program

The upgrade roadmap (`docs/superpowers/specs/2026-05-15-upgrade-roadmap.md`)
sequenced 17 design specs into four waves. Each spec was taken through a
plan-and-execute process with review checkpoints; each implementation plan
and design spec is preserved under `docs/superpowers/`.

| Wave | Specs |
|---|---|
| **0 — Foundation** | data-integrity & migrations; model-routing |
| **1 — Enablers** | purple-team; real-nemoclaw-provisioner; map-elites-archive; trajectory-and-progress-scoring; mutation-operator-learning; judge-ensemble; corpus-driven-ideation; real-root-cause-analysis |
| **2 — Dependents** | model-ideation-tournament; cross-zone-attack-chaining; verifier-gate-hardening; real-patch-isolation |
| **3 — Top of tree** | patch-generalization-loop; learned-ranking-model; approval-and-pr-service |

Cross-spec coordination rules (migration versions assigned at execution time,
`interfaces/` as the single merge point, shared vocabulary defined once,
purple landing before its consumers, and every spec preserving the
zero-credential mock path) kept the parallel work from colliding.

## 10. Mock vs. Real — What Ships in the Demo

The demo runs with zero model credentials and a deterministic mock path; the
real paths are implemented and gated:

| Capability | Default | Real path |
|---|---|---|
| Victim provisioner | Mock (auto-fallback) | `NemoClawProvisioner`, default when `nemoclaw` CLI present |
| Patch isolation | Mock replay surface | Worktree build + rebuilt victim (`patch_isolation.enabled`) |
| Model-ideation tournament | Off | `model_tournament.enabled` + entrants |
| Frontier judge appeal | Off | `red_team.judge.appeal.enabled` |
| Learned ranker | Heuristic | Trained artifact behind a dataset-readiness gate |
| Auto-PR | Off | `gh`-CLI draft PR (`approvals.auto_pr`) |

## 11. Tests

The repository ships a comprehensive automated suite — 1000+ tests across
red, purple, blue, infra, the migration runner (including a schema-parity
check between `schema.sql` and the migration ledger), and the dashboard. Run
`uv run pytest` and `uv run ruff check .`.

## 12. Remaining Production Work

- PostgreSQL + pgvector backend for cross-lane concurrency.
- Object storage for transcripts/artifacts; signed immutable audit logs.
- A trained learned ranker once enough labelled traces accumulate.
- SIEM/telemetry export and a hardened external approval service.
- A persistent event store behind the evidence timeline (today it is derived
  from telemetry events + finding evidence).

## External References

- NVIDIA Nemotron model families: https://blogs.nvidia.com/blog/nemotron-model-families/
- NVIDIA Nemotron 3 Super: https://research.nvidia.com/labs/nemotron/Nemotron-3-Super/
- NVIDIA Nemotron content-safety reasoning 4B: https://build.nvidia.com/nvidia/nemotron-content-safety-reasoning-4b/modelcard
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release/
- Microsoft PyRIT: https://github.com/microsoft/PyRIT
