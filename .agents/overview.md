# MonkeyClaw — Workload Split Overview

**3-person parallel development plan · Merge-conflict-free architecture**

---

## The Split Principle

Each person owns a vertical slice of the pipeline. They never edit each other's code. All communication between slices flows through the MCP server's tool interface and the shared database schemas. As long as all three agree on the interface contracts (the MCP tool signatures and the database table schemas), they can develop in complete isolation and merge with zero conflicts.

---

## The Three Roles

### Person 1 — Infrastructure & Orchestration

The foundation everything else plugs into.

**Owns:**
- MCP server (mock + real implementation)
- Database (SQLite + sqlite-vec)
- Attack surface map (zone registry + coverage mechanics)
- Orchestrator (cycle loop, red/blue cadence)
- Lane scheduler (provision, dispatch, teardown, recycle)
- Monitoring harness (fs, network, process, memory, inference captures)
- Notification layer (Telegram, webhooks)
- Configuration system (YAML loader)
- NemoClaw codebase indexing (vector search over source)
- Victim provisioning API

### Person 2 — Red Team Pipeline

Everything from "generate an attack idea" to "verdict: confirmed/clean."

**Owns:**
- Ideation engine (3 prompt modes: creative, code-grounded, history-informed)
- Deduplication check (embedding + cosine similarity)
- Priority scoring (novelty × impact × coverage_gap × severity_weight)
- Execution agent (the OpenClaw agent that performs attacks)
- Tier 1 judgment (6 programmatic checks — filesystem, network, process, permission, PII, policy)
- Tier 2 judgment (LLM semantic judge for prompt injection, social engineering, memory corruption)
- Post-judgment routing (log finding, push to repro queue, update coverage, alert)

### Person 3 — Repro + Blue Team + Regression

Everything from "confirmed finding lands in the repro queue" to "patch is verified and regression test is permanent."

**Owns:**
- Replay-minimizer agent (replay N times + delta-debug to minimal chain)
- Root-cause locator (conditional, severity ≥ high only)
- Repro writer agent (structured markdown vulnerability document)
- Cold verifier agent (fresh agent follows doc with zero context)
- Triage agent (prioritize + group related vulns)
- Patch generator agent (candidate diffs with alternatives for high-severity)
- Test generator agent (positive regression test + negative functionality test)
- Patch verifier (three-gate validation: regression, functionality, full suite)
- Regression runner (execute full suite, compute coverage delta)

---

## Why This Split Works

Person 1 builds the shared infrastructure that Persons 2 and 3 consume as a service. Person 2's red team pipeline OUTPUTS findings to the database. Person 3's repro/blue pipeline INPUTS findings from the database. They never touch the same files. The only shared artifacts are the MCP tool signatures and database schemas — which Person 1 owns and publishes first.

---

## Directory Structure (Zero-Conflict Guarantee)

Each person works in their own directory. No file is ever edited by two people.

```
monkeyclaw/
├── interfaces/          ← Person 1 writes, Persons 2 & 3 read-only
│   ├── schema.sql       ← Database schema
│   ├── mcp_tools.py     ← MCP tool signatures with type hints
│   ├── types.py         ← Shared data objects (IdeaObject, LaneResult, etc.)
│   └── provisioning.py  ← Victim provisioning API
├── infra/               ← Person 1 ONLY
│   ├── mcp_server.py
│   ├── database.py
│   ├── orchestrator.py
│   ├── lane_scheduler.py
│   ├── monitoring_harness.py
│   ├── codebase_indexer.py
│   ├── notifications.py
│   └── config.py
├── red_team/            ← Person 2 ONLY
│   ├── ideation.py
│   ├── dedup.py
│   ├── priority.py
│   ├── execution_agent.py
│   ├── checks.py        ← Tier 1 checks (importable by Person 3)
│   ├── judge.py
│   └── routing.py
└── blue_team/           ← Person 3 ONLY
    ├── replay_minimizer.py
    ├── root_cause.py
    ├── repro_writer.py
    ├── cold_verifier.py
    ├── triage.py
    ├── patch_generator.py
    ├── test_generator.py
    ├── patch_verifier.py
    └── regression_runner.py
```

---

## Critical Path

Person 1's interface contracts (MCP tool signatures + DB schemas) are the only blocker. Once those are published (day 1-2), Persons 2 and 3 can develop against mocks indefinitely. Person 1 then implements the real backend while 2 and 3 build their agents.

- **Day 1-2:** Person 1 publishes interface contracts. Persons 2 & 3 review and negotiate any changes.
- **Day 2+:** All three develop in parallel. Person 1 provides mock MCP server that returns dummy data so 2 & 3 can test immediately.
- **Day 8:** Integration — swap mock MCP for real MCP. Everything connects because it was built against the same contracts.

---

## The One Cross-Person Code Dependency

Person 2 writes the 6 Tier 1 programmatic check functions as a standalone module: `red_team/checks.py`. Person 3 imports this module in the replay-minimizer and patch verifier. This is the ONLY cross-directory import in the entire codebase.

Rules for this module:
- Single file with pure functions
- No imports from the rest of `red_team/`
- No side effects
- Person 2 publishes the function signatures on Day 3
- Person 3 can mock them until the real implementation is ready
