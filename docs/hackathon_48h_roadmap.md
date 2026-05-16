# MonkeyClaw 48-Hour Hackathon Roadmap

Date: 2026-05-15

## Goal

Build MonkeyClaw into a convincing end-to-end autonomous red-team/blue-team hardening system for NemoClaw/OpenClaw: it should discover or simulate security failures, record evidence, reproduce them, generate fixes/tests, verify defenses, and present the result in a demo-ready dashboard/report.

The winning demo is not "we have a lot of agents." The winning demo is:

1. MonkeyClaw runs a red-team cycle against a target victim.
2. It finds a security failure with concrete evidence.
3. It minimizes and cold-verifies the reproduction.
4. It sends the package to blue team.
5. Blue team generates a patch candidate and regression test.
6. Verification shows the vulnerability is blocked and normal behavior still works.
7. The dashboard/report shows coverage, finding, repro, patch, and regression status.

## Final Fully Built Repo

At the end, the repo should have these production-shaped subsystems:

```text
monkeyclaw/
├── interfaces/                 Shared contracts, schemas, types, policy/event models
├── infra/                      MCP server, DB, orchestration, config, telemetry, provisioning
├── red_team/                   Ideation, execution, judgment, search memory, routing
├── blue_team/                  Repro, minimization, patch/test generation, verification
├── demo/                       Planted vulnerable victims, demo scripts, sample policies
├── data/                       Runtime DB/logs/artifacts, ignored by git
├── docs/                       Roadmap, specs, architecture report, demo narrative
├── skill/                      OpenClaw skill package
├── test/                       Unit, contract, mock E2E, policy corpus, demo-path tests
├── configs/                    Runtime profiles and model-routing config
└── README.md                   Install, quickstart, demo instructions
```

## Three-Person Ownership Model

This split is designed to allow parallel Git work without conflicts.

| Person | Workstream | Primary Directories | Shared Files Policy |
|---|---|---|---|
| Person A | Infrastructure, control plane, contracts, telemetry | `interfaces/`, `infra/`, `configs/`, `test/test_contracts.py`, `test/test_mcp_real.py` | Owns shared interfaces. B/C request changes from A instead of editing contracts directly. |
| Person B | Red team, search intelligence, judges, attack corpus | `red_team/`, `test/test_red_*.py`, `demo/attacks/` | Does not edit `infra/` or `blue_team/`; calls MCP protocol only. |
| Person C | Repro, blue team, regression, dashboard, final demo | `blue_team/`, `infra/dashboard.py`, `test/test_blue_*.py`, `demo/`, final docs | Does not edit `red_team/`; consumes findings/repro packages through MCP. |

Recommended branch names:

- `person-a-infra-control-plane`
- `person-b-red-team-search`
- `person-c-blue-demo`

Merge order:

1. Person A lands interface/schema/config changes first.
2. Person B lands red-team work against A's contracts.
3. Person C lands blue/demo/dashboard work against A's contracts.
4. Final integration branch merges all three, resolves only import/config/test wiring.

## 48-Hour Critical Path

### Hours 0-3: Environment and Contract Freeze

Owner: Person A

- Make `uv sync`, `pytest`, and `ruff` work on a fresh machine.
- Add or update `docs/dev_setup.md`.
- Freeze the interface additions needed by all three streams:
  - telemetry event dataclasses
  - model routing config
  - queue status enums
  - policy test result objects
  - optional MAP-Elites/search-memory objects
- Seed demo DB path and artifact directory rules.

Acceptance:

- `uv run pytest test/test_contracts.py -q` passes.
- B and C can import the new dataclasses without touching A's files.

### Hours 3-10: Mock End-to-End Spine

Owners: A, B, C in parallel

- A: reliable mock MCP + deterministic planted-vulnerability provisioner.
- B: red-team cycle can produce at least one confirmed finding against the planted victim.
- C: repro/blue pipeline can consume that finding and produce a verified repro package plus candidate patch/test.

Acceptance:

- One command runs a mock E2E cycle:

```bash
uv run monkeyclaw run --cycles 1 --target planted-filesystem --mock
uv run monkeyclaw findings
uv run monkeyclaw blue-team --mock
```

### Hours 10-18: Security Evidence and Policy Corpus

Owners: A and B, C consumes output

- Add PDF-derived telemetry events:
  - session started/finished
  - policy loaded
  - tool requested/decision
  - file read/write
  - shell started/finished
  - network request
  - MCP invoked
  - approval requested/resolved
- Add policy corpus cases derived from the provided PDF:
  - secret read
  - unknown upload
  - package postinstall egress
  - MCP schema drift
  - untrusted prompt injection
  - control-plane edit
  - cloud CLI mutation
  - unregistered MCP server
  - base64 decode/execution pattern

Acceptance:

- The demo finding includes structured evidence, not just transcript prose.
- The policy corpus can be run as tests.

### Hours 18-28: Intelligence Layer

Owner: Person B

- Add staged progress scoring.
- Add near-miss capture.
- Add idea component extraction.
- Add MAP-Elites archive table/logic if A's schema supports it.
- Add judge ensemble outputs:
  - safety judge
  - progress judge
  - novelty judge
  - robustness judge
  - forensics judge
- Add model tournament hooks behind config.

Acceptance:

- Demo shows not only "vuln found" but "why this idea was selected" and "how prior attempts influenced the next idea."

### Hours 18-32: Blue Team Loop

Owner: Person C

- Make repro package generation polished and readable.
- Make cold verifier status explicit.
- Generate patch candidates as diffs.
- Generate positive regression and negative functionality tests.
- Verify patch candidates in disposable work area.
- Add regression result objects to DB/dashboard.

Acceptance:

- One planted vuln produces:
  - repro markdown
  - patch candidate
  - regression test
  - verifier result
  - dashboard entry

### Hours 28-40: Demo Dashboard and Narrative

Owner: Person C, with data from A/B

- Dashboard views:
  - coverage heatmap
  - active cycle
  - findings table
  - repro queue
  - blue-team queue
  - regression status
  - model/cost stats
  - MAP-Elites/search archive summary
  - telemetry/evidence timeline
- Add a scripted demo path.
- Add sample DB fixture for a backup demo if live run fails.

Acceptance:

- `uv run monkeyclaw dashboard` opens a useful live demo.
- `demo/run_hackathon_demo.sh` or equivalent walks through the full story.

### Hours 40-48: Polish, Reliability, Pitch

Owners: all

- Fix flaky tests.
- Make README short and demo-focused.
- Add screenshots or terminal transcript.
- Add final architecture diagram notes.
- Prepare two demo modes:
  - live mode
  - pre-seeded fallback mode

Acceptance:

- A judge can clone, run setup, run mock demo, and understand why the project matters in under 10 minutes.

## Model Strategy

Use role-based model routing instead of one global model.

### Recommended Defaults

| Role | Default | Why |
|---|---|---|
| Cheap summarization/extraction | Nemotron 3 Nano or local small model | High-volume, low-risk, cheap. |
| Main red-team ideation/execution planning | Nemotron 3 Super 120B-A12B | Strong local/open model path, aligned with repo config. |
| Complex root-cause/patch generation | Claude Opus 4.7 or GPT-5.3-Codex | Highest reasoning/code quality matters. |
| Code edits/tests | GPT-5.3-Codex or Claude Opus 4.7 | Better code reliability and context handling. |
| Safety/policy classification | Nemotron content-safety reasoning 4B plus programmatic checks | Specialized auxiliary signal. |
| Cyber-specialist tournament entrant | newer WhiteRabbitNeo/Qwen-based variant, optional | Useful for idea diversity only; not authoritative. |

WhiteRabbitNeo-13B-v1 should not be the main model. Treat cyber-specialized open models as optional red-team idea generators in isolated lanes. The source of truth remains evidence, replay, and verifier gates.

## Small Custom ML Model Recommendation

Do not train during the first 48 hours unless everything else is done.

The best future small model is a ranking/preference model for idea/component usefulness:

- Inputs: idea summary, tactic tags, zone, transcript trajectory features, judge ensemble scores, repro result, mutation operator, token cost.
- Outputs: expected usefulness, best mutation operator, likely archive niche, likely failure mode.
- Training signal: replay success, progress delta, pairwise comparison, mutation improvement.

Why this is worth doing later:

- MonkeyClaw naturally produces labeled data.
- A small model can cheaply pre-rank ideas and reduce frontier-model spend.
- It improves search efficiency without becoming a risky autonomous attacker or judge.

## Full Feature Backlog

### Must Have for Hackathon Demo

- Working setup.
- Mock/planted victim.
- Full red -> repro -> blue loop.
- Structured evidence.
- Dashboard/report.
- Regression test generation.
- Clear model routing config.
- README quickstart.

### Should Have

- Policy corpus tests from PDF.
- MAP-Elites archive.
- Judge ensemble.
- Mutation operator stats.
- Telegram/webhook alert demo.
- Pre-seeded fallback DB.
- Demo video or screenshots.

### Stretch

- Real NemoClaw/OpenClaw live integration.
- Auto PR creation.
- Multi-model tournament.
- Formal verification hooks for Landlock/seccomp rules.
- Cross-agent attack chains.
- Adversarial skill marketplace fixture pack.
- Custom preference/ranking model training pipeline.

## Demo Story

The pitch:

"NemoClaw gives agents a sandbox. MonkeyClaw tells you whether the sandbox, policy, privacy router, skill pipeline, and agent behavior actually survive adversarial pressure over time. It is Chaos Monkey for AI-agent security: it attacks, proves, patches, and remembers."

Live demo flow:

1. Show coverage map with low coverage.
2. Run one cycle.
3. Show red team selecting a zone and generating ideas.
4. Show evidence that a planted target violated policy.
5. Show repro minimization and cold verification.
6. Show blue-team patch/test generation.
7. Show regression passes.
8. Show coverage and knowledge base updated.

## Research References

- NVIDIA Nemotron model families: https://blogs.nvidia.com/blog/nemotron-model-families/
- NVIDIA Nemotron 3: https://research.nvidia.com/labs/nemotron/Nemotron-3/
- NVIDIA Nemotron 3 Super: https://research.nvidia.com/labs/nemotron/Nemotron-3-Super/
- NVIDIA Nemotron content-safety reasoning 4B: https://build.nvidia.com/nvidia/nemotron-content-safety-reasoning-4b/modelcard
- OpenAI GPT-5.2 docs: https://platform.openai.com/docs/models/gpt-5.2/
- OpenAI Codex app: https://openai.com/index/introducing-the-codex-app/
- Anthropic Claude Opus: https://www.anthropic.com/claude/opus
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- Microsoft PyRIT: https://github.com/microsoft/PyRIT
- MITRE ATLAS secure AI release: https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release/
- WhiteRabbitNeo models: https://huggingface.co/WhiteRabbitNeo/models
