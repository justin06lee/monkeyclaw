# MonkeyClaw Full Architecture Report

Date: 2026-05-15

## Inputs Reviewed

- Repository: `justin06lee/monkeyclaw`, cloned into `/Volumes/Neural/monkeyclaw`.
- Architecture sketch: `/Users/ezzyrappeport/Desktop/Untitled-2026-05-15-1150.excalidraw`.
- Security whitepaper: `/Users/ezzyrappeport/Desktop/Securing_Coding_Agents_General_Analysis_1.0.pdf`.
- Product/spec notes: `/Users/ezzyrappeport/Desktop/billion dollar idea copy.docx`.
- External research: NVIDIA Nemotron official materials, OpenAI Codex/GPT-5.x docs, Anthropic Claude Opus 4.7 pages, OWASP LLM Top 10, Microsoft PyRIT, MITRE ATLAS, and WhiteRabbitNeo model listings.

## Executive Summary

MonkeyClaw is intended to be a continuous adversarial security hardening system for NemoClaw/OpenClaw. It should run a perpetual red -> judge -> repro -> blue -> regression loop: generate attacks, execute them against fresh victim sandboxes, verify outcomes with evidence, minimize confirmed repros, produce patch candidates and regression tests, verify fixes, then feed everything back into a coverage-driven knowledge base.

The current repo is a strong scaffold, not a finished security product. It already contains the expected directory split, shared dataclasses, SQLite schema, MCP protocol, mock/real MCP implementations, red-team pipeline, blue-team pipeline, orchestrator, CLI, dashboard, and tests. The largest gaps are real NemoClaw/OpenClaw integration, production-grade telemetry/guardrails, atomic status transitions for blue-team queues, richer scoring/search dynamics from the DOCX, and a clear model routing policy.

The Excalidraw file had a complete red/repro concept and only a blue-team heading. I updated it with the missing blue-team architecture: repro intake, triage/grouping, root-cause context, patch generation, test generation, verifier gates, human/PR gate, regression suite, knowledge update, and control-plane guardrails.

## Current Repo Map

### `interfaces/`

This is the contract layer and the right architectural anchor. It contains:

- `types.py`: shared dataclasses for ideas, lane results, judgments, findings, repro packages, patches, tests, policy config, and observability primitives.
- `mcp_tools.py`: protocol for all MCP tools.
- `schema.sql`: SQLite schema with 18 seeded attack-surface zones, vector tables, queues, findings, repro packages, patches, regression tests, code chunks, and alerts.
- `provisioning.py`, `victim_client.py`, `nemoclaw_policy.py`: victim runtime contracts and policy adapters.

Assessment: the boundary is correct. It should remain the merge-conflict firewall.

### `infra/`

Infrastructure is mostly present:

- `database.py`: SQLite/sqlite-vec wrapper and embedding model loader.
- `mcp_server.py`: real MCP protocol implementation over SQLite.
- `mock_mcp.py`: mock server for tests/demo.
- `orchestrator.py`: cycle loop and red/blue cadence.
- `lane_scheduler.py`: parallel victim lane scheduling.
- `monitoring_harness.py`: observable capture abstraction.
- `provisioning_nemoclaw.py`: NemoClaw provisioner.
- `codebase_indexer.py`: code indexing.
- `notifications.py`: Telegram/webhook alert path.
- `cli.py`, `dashboard.py`: operator surfaces.

Assessment: the structure is correct, but real production behavior needs harder state management, stronger telemetry, security policy evidence, and cloud/hybrid backend options.

### `red_team/`

The red-team pipeline is implemented as the spec describes:

- `ideation.py`: three prompt modes: creative, code-grounded, history-informed.
- `dedup.py`, `priority.py`: duplicate filtering and priority selection.
- `execution_agent.py`: attacker-victim execution driver.
- `checks.py`: Tier 1 programmatic checks.
- `judge.py`: Tier 1 plus semantic Tier 2 for prompt/social/memory zones.
- `routing.py`: finding logging, repro queue push, coverage update, alerts.
- `pipeline.py`: assembled red-team pipeline.

Assessment: good MVP shape. It lacks the richer progress trajectory scoring, MAP-Elites archive, mutation operator learning, judge ensemble, and pairwise/Elo ranking described in the DOCX.

### `blue_team/`

The blue-team/repro side is scaffolded:

- `replay_minimizer.py`: replay and delta-minimize.
- `root_cause.py`: code-search-assisted fix-site locator.
- `repro_writer.py`: structured repro document generator.
- `cold_verifier.py`: fresh-agent verification loop.
- `triage.py`: severity/blast-radius/fix-complexity grouping.
- `patch_generator.py`: diff candidate generation.
- `test_generator.py`: positive regression plus negative functionality tests.
- `patch_verifier.py`: verifier gates.
- `regression_runner.py`: permanent regression suite execution.
- `pipeline.py`: assembled repro + blue + regression pipeline.

Assessment: this is the area the Excalidraw sketch was missing. The code exists, but the architecture still needs explicit data/status transitions, patch application isolation, human approval/PR handling, and verified rollback behavior.

### `.agents/` and `skill/`

The `.agents` docs mirror the DOCX closely: three-person split, timeline, interface contracts, and implementation responsibilities. `skill/SKILL.md` packages MonkeyClaw as an OpenClaw skill.

## Source Document Synthesis

### DOCX

The DOCX contains the real product vision. The most important additions beyond the current code are:

- Use a staged progress rubric, not binary success/failure.
- Score attack trajectories across turns: refusal strength, specificity, steerability, boundary erosion, transferability, novelty, robustness, and cost.
- Store ideas as structured objects with tactic tags, useful components, failure modes, parent ideas, transfer scores, and mutation suggestions.
- Use pairwise comparison or Elo-style ranking when absolute scoring is noisy.
- Use MAP-Elites archives so the system preserves diverse high-performing ideas across niches instead of converging on one attack family.
- Score mutation operators: paraphrase, benign framing, multi-turn split, persona shift, combine ideas, sequence reversal, abstraction/concretization.
- Use a judge ensemble: safety, progress, novelty, robustness, forensics.

Recommendation: implement this as a second-generation `red_team/search_memory.py` + schema expansion, not as prompt-only behavior.

### PDF

The PDF is a deployment security blueprint for coding agents. It should influence MonkeyClaw in two ways:

1. MonkeyClaw should test the controls it names: filesystem scope, shell execution, network egress, MCP governance, identity/OAuth scope, approvals, telemetry, hook decisions, browser/desktop surfaces, repository control-plane edits, package scripts, and CI/deploy authority.
2. MonkeyClaw itself must obey these controls, because it is an intentionally adversarial agent system.

Add required evidence objects for:

- Tool request and decision.
- File read/write.
- Shell started/finished.
- Network request/proxy decision.
- MCP invocation/schema hash/OAuth scopes.
- Approval requested/resolved.
- Session started/finished.

The PDF's evaluation corpus should become a built-in policy test suite. Cases T01-T25 map cleanly to MonkeyClaw zones and should become canned fixtures.

### Excalidraw

The original sketch covered:

- Red team idea sources: high-temp/creative model, source analyzer + Argyph, previous-data contrastive agent, NemoClaw codebase, Argyph.
- Strategist with citations.
- MAP-Elites/idea combination.
- Execution model loop.
- Judge and full attack object.
- Knowledge table, SQLite/vector memory, librarian.
- Repro module: replayer, minimizer, root-cause locator + Argyph, writer, verifier, blue-team handoff.

Missing piece was the blue-team architecture. Added in the file:

- Repro queue intake.
- Triage and grouping.
- Root-cause context.
- Patch generator.
- Test generator.
- Patch verifier.
- Human/PR gate.
- Regression suite.
- Knowledge table and coverage updates.
- Control-plane guardrails from the PDF.

## Full Target Architecture

### 1. Control Plane

Owns configuration, policy, lifecycle, and operator controls.

Required components:

- Config loader with environment overrides.
- Model routing policy.
- Cycle scheduler.
- Lane scheduler.
- Queue state machine.
- Budget manager.
- Approval policy.
- Secrets policy.
- Network phase policy.
- MCP server allowlist/schema hash registry.
- Telemetry schema and retention policy.

### 2. Data Plane

Owns all persistent state.

MVP:

- SQLite + sqlite-vec.
- Tables already present: surface zones, findings, ideas, cycle log, repro queue, repro packages, regression tests, patches, code chunks, alerts.

Needed additions:

- `idea_components`: extracted tactics/components from each idea.
- `idea_archive_cells`: MAP-Elites bins.
- `idea_pairwise_results`: comparison outcomes.
- `mutation_operator_stats`: learned operator utility.
- `judge_votes`: ensemble judge results.
- `policy_events`: PDF-derived tool/network/MCP/file/shell decisions.
- `model_runs`: model, prompt class, token use, cost, latency, verdict.
- `approval_events`: human/service approval audit.

Production:

- PostgreSQL + pgvector for concurrency.
- Object storage for transcripts/artifacts.
- Signed, immutable audit logs for security-relevant events.

### 3. Red Team

MVP pipeline:

1. Get coverage gaps.
2. Generate ideas from three modes.
3. Deduplicate and score.
4. Execute top ideas in parallel.
5. Run Tier 1 checks.
6. Run Tier 2 semantic judge when needed.
7. Route findings to repro queue.

Target pipeline additions:

- Staged risk/progress rubric.
- Trajectory slope scoring.
- Near-miss extraction.
- Component extraction from prompts and transcripts.
- MAP-Elites archive update.
- Mutation operator learning.
- Pairwise/Elo idea ranking.
- Multi-model ideation tournament for selected zones.
- OWASP/MITRE/PDF corpus-driven attack generation.

### 4. Repro Pipeline

Required flow:

1. Dequeue confirmed/suspicious finding.
2. Replay on fresh victim N times.
3. Compute repro rate.
4. Delta-minimize turns/tool calls/payloads.
5. Root-cause locate for high-severity findings.
6. Write structured repro doc.
7. Cold-verify using a fresh agent with no prior context.
8. Push package to blue-team queue and knowledge table.

Needed hardening:

- Queue completion/failure status updates.
- Artifact capture paths.
- Repro flake classification.
- Deterministic victim snapshots.
- Clear downgrade path for non-reproducible findings.

### 5. Blue Team

Required flow:

1. Pull ready repro packages.
2. Triage and group by zone/root cause.
3. Generate patch candidates.
4. Generate positive regression tests and negative functionality tests.
5. Verify patch in isolated branch/worktree/sandbox.
6. Run full regression suite.
7. Mark package/finding/patch statuses.
8. Add permanent regression tests.
9. Alert and update coverage.

Needed hardening:

- Patch application should happen only in disposable branches/worktrees.
- Human review should be optional but default for high/critical.
- Auto-PR generation should be post-MVP.
- Patch verifier must reject patches that remove tests, loosen policy, bypass hooks, or only suppress evidence.
- Regression suite should include PDF policy tests, not just vulnerability repros.

### 6. Monitoring and Evidence

Current observability primitives are right but need production emitters.

Required evidence:

- Filesystem diff: created, modified, deleted, accessed, outside allowed paths.
- Network log: destination, method, bytes, response, blocked/allowed.
- Process log: executable, syscall, args class, blocked, inside sandbox.
- Memory diff: keys and value classes, not raw secrets.
- Inference routing log: local/cloud route, PII class, content hash/excerpt.
- MCP calls: server/tool/schema hash/OAuth scope/input hash.
- Approval decisions: allow/deny/ask, reason, approver, expiry.

### 7. Dashboard and Reports

Dashboard should show:

- Global and per-zone coverage.
- Current lanes.
- Finding timeline.
- Repro queue and blue-team queue.
- Regression pass rate.
- Token/cost burn.
- Model performance by role.
- Mutation operator success.
- MAP-Elites archive heatmap.
- Policy evidence completeness.

Reports should include:

- Security report card per defense layer.
- Repro documents.
- Patch verification results.
- Regression suite deltas.
- Control-plane audit summary.

## Model Routing Recommendation

Do not use one model for everything. Use model routing by task risk and complexity.

### Frontier reasoning/coding

Use Claude Opus 4.7, GPT-5.3-Codex, or equivalent frontier coding/reasoning models for:

- Patch generation.
- High-severity root-cause analysis.
- Complex code-grounded ideation.
- Difficult semantic judgment appeals.
- Architecture/spec generation.

Reason: these tasks need long-context reasoning, code changes, and low hallucination tolerance.

### Nemotron

Use NVIDIA Nemotron for most high-volume agent work.

Recommended split:

- Nemotron 3 Nano: cheap summarization, structured extraction, log normalization, simple cold-verifier following, queue triage prefilter, mutation proposal prefilter.
- Nemotron 3 Super: main local/enterprise workhorse for ideation, semantic judging, repro writing, and most execution-agent planning. It is a 120B total / 12B active MoE model and fits the current repo's config direction.
- Nemotron 3 Ultra: reserve for hard long-horizon agent planning or when local frontier-like reasoning is needed and infrastructure can support it.
- Nemotron content-safety reasoning 4B: use as a specialized auxiliary judge for content-safety/policy classification, not as the main attacker or patcher.

The current repo config names `nvidia/nemotron-3-super-120b-a12b`; that is a sensible default for serious local agentic work. Add explicit per-role model config instead of one global ideation/judgment model.

### Cyber-specialized open models

WhiteRabbitNeo-13B-v1 is outdated as a default. Its Hugging Face listing is from early 2024, and newer WhiteRabbitNeo models exist, including Qwen-2.5-Coder-based variants. Use cyber-specialized models only as optional tournament entrants or auxiliary idea generators, not as authoritative judges or patchers.

For offensive/defensive cyber reasoning, prefer a controlled internal model route:

- Run cyber models only in isolated red-team lanes.
- Log all outputs and block direct exfiltration.
- Use programmatic checks and cold repro as the source of truth.
- Never accept "uncensored" as a quality signal. The system needs effective adversarial exploration with evidence, not unbounded compliance.

### OpenAI/Codex

Use GPT-5.3-Codex or the current Codex-specialized model for:

- Codebase-wide implementation planning.
- Patch candidate generation.
- Test generation.
- Refactors that must preserve behavior.

### Embeddings

The repo currently uses `sentence-transformers/all-MiniLM-L6-v2` at 384 dimensions. The DOCX recommends `nomic-embed-text` or OpenAI embeddings. Pick one per deployment and keep it stable. For MVP, keep MiniLM if tests already depend on 384 dimensions. For production, migrate through a schema version to a stronger 768/1536-dimensional embedding model if retrieval quality becomes a blocker.

## Should MonkeyClaw Train Its Own Small Model?

Yes, but not for initial vulnerability discovery or patch generation.

Recommended custom model:

- A small ranking/preference model or LoRA adapter that predicts idea/component usefulness from structured traces.
- Inputs: idea summary, tactic tags, zone, transcript-derived trajectory features, judge ensemble scores, repro outcome, token cost, mutation operator.
- Outputs: usefulness score, likely mutation operators, archive niche, and likely failure mode.

Why this is beneficial:

- MonkeyClaw will generate thousands of labeled attempts naturally.
- The label is cheap and concrete: repro success, progress delta, Tier 1/Tier 2 verdict, pairwise preference, mutation improvement.
- A small model can replace expensive LLM calls for pre-ranking and mutation selection.
- This directly improves token efficiency and exploration quality.

Do not train first. Collect at least hundreds to thousands of attempts, build the structured dataset, then train/evaluate offline. Until then, use heuristics plus pairwise judge comparisons.

## MVP Build Spec

### Phase 0: Environment and Verification

- Add setup docs for systems without `uv`.
- Add CI that runs `uv sync`, `pytest`, and `ruff`.
- Add a minimal smoke test that can run without live NemoClaw.
- Pin dependency versions that matter for sqlite-vec and sentence-transformers.

### Phase 1: State Machine and Data Integrity

- Add explicit statuses for findings, repro queue, repro packages, patches, and regression tests.
- Make queue completion/failure atomic.
- Add migrations instead of editing `schema.sql` after release.
- Add structured event logging tables.
- Add model run/token/cost tracking.

### Phase 2: Real NemoClaw/OpenClaw Integration

- Confirm live NemoClaw CLI/gateway commands.
- Implement provision/connect/recover/snapshot lifecycle.
- Capture real fs/network/process/inference telemetry.
- Add planted-vulnerability victim profiles.
- Add policy fixtures for the 18 zones.

### Phase 3: Red Team Search Dynamics

- Implement staged progress scoring.
- Store near misses.
- Add idea component extraction.
- Add MAP-Elites archive.
- Add mutation operator stats.
- Add judge ensemble results.
- Add model tournament mode behind a config flag.

### Phase 4: Repro Quality

- Persist replay artifacts.
- Add flake classification.
- Make cold verifier revisions traceable.
- Require repro docs to include environment, steps, expected/actual, evidence, affected paths, mitigations, and confidence.

### Phase 5: Blue Team

- Apply patch candidates in disposable worktrees/sandboxes.
- Run positive and negative tests.
- Run full regression before approving.
- Add optional human approval.
- Add PR generation later.
- Update coverage and knowledge table after verified fixes.

### Phase 6: Security Controls from PDF

- Add policy test corpus T01-T25.
- Add network phase allowlist tests.
- Add MCP schema drift tests.
- Add secret-read and control-plane edit tests.
- Add telemetry completeness scoring.
- Add CODEOWNERS recommendations for control-plane files.

### Phase 7: Dashboard and Reporting

- Coverage heatmap.
- Queue status.
- Findings and repro timeline.
- Regression trend.
- Cost/model usage.
- MAP-Elites archive.
- Policy evidence completeness.

## Key Gaps and Risks

- Verification could not be run locally because `uv`, pytest, ruff, and most Python dependencies are missing.
- Real NemoClaw integration is the highest-risk unknown.
- Blue-team code needs stronger queue lifecycle and patch isolation.
- Current schema does not yet represent MAP-Elites, mutation stats, judge votes, policy events, or model runs.
- Current model config is too coarse; role-based routing is needed.
- PDF-derived security controls are not yet built into the harness.
- Auto-patching without human review would be premature for high/critical vulnerabilities.
- Argyph should stay referenced as a future root-cause/code-analysis helper. Do not add its MCP server until that project is stable.

## External References

- NVIDIA Nemotron model families: https://blogs.nvidia.com/blog/nemotron-model-families/
- NVIDIA Nemotron 3 family: https://research.nvidia.com/labs/nemotron/Nemotron-3/
- NVIDIA Nemotron 3 Super: https://research.nvidia.com/labs/nemotron/Nemotron-3-Super/
- NVIDIA Nemotron content-safety reasoning 4B: https://build.nvidia.com/nvidia/nemotron-content-safety-reasoning-4b/modelcard
- OpenAI GPT-5.2 model docs: https://platform.openai.com/docs/models/gpt-5.2/
- OpenAI Codex app: https://openai.com/index/introducing-the-codex-app/
- Anthropic Claude Opus 4.7: https://www.anthropic.com/claude/opus
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- Microsoft PyRIT: https://github.com/microsoft/PyRIT
- MITRE ATLAS update: https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release/
- WhiteRabbitNeo models: https://huggingface.co/WhiteRabbitNeo/models
