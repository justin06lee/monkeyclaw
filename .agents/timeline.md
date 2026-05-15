# MonkeyClaw — Development Timeline

**Assumptions:** 7-10 day build sprint. All three working roughly full-time. Adjust proportionally if part-time. NemoClaw SDK access available from day 1.

---

## Day-by-Day Schedule

### Day 1

| Person 1 | Person 2 | Person 3 |
|----------|----------|----------|
| **DB schema + MCP tool signatures + shared types** | Reviewing P1's contracts | Reviewing P1's contracts |

Person 1 spends the entire day on interface contracts. No implementation. Get the schemas and tool signatures right. Persons 2 & 3 review and negotiate changes by end of day. This is the most important day of the sprint.

### Day 2

| Person 1 | Person 2 | Person 3 |
|----------|----------|----------|
| **Mock MCP server + provisioning API** | **Ideation Mode A + B + C prompts** | **Replay-minimizer agent** |

Person 1 delivers the mock MCP so Persons 2 & 3 can start testing. Persons 2 & 3 begin building their core components against the mock.

### Day 3

| Person 1 | Person 2 | Person 3 |
|----------|----------|----------|
| **Real DB + vector setup + codebase indexing** | **Dedup + priority scoring + execution agent** | **Root-cause locator + repro writer** |

Person 2 publishes Tier 1 check function signatures (stubs) by end of day so Person 3 can import them.

### Day 4

| Person 1 | Person 2 | Person 3 |
|----------|----------|----------|
| **Real MCP tools (search, log, queue ops)** | **Execution agent (cont.) + Tier 1 checks** | **Cold verifier + triage agent** |

Person 2 implements real Tier 1 check functions. Person 3 has been using the stubs from Day 3 and can now switch to real imports.

### Day 5

| Person 1 | Person 2 | Person 3 |
|----------|----------|----------|
| **Monitoring harness (fs, net, proc)** | **Tier 2 judge + post-judgment routing** | **Patch generator + test generator** |

### Day 6

| Person 1 | Person 2 | Person 3 |
|----------|----------|----------|
| **Lane scheduler + orchestrator** | **E2E red team test (mock MCP)** | **Patch verifier + regression runner** |

Persons 2 & 3 should be running end-to-end tests of their respective pipelines against the mock MCP by end of day.

### Day 7

| Person 1 | Person 2 | Person 3 |
|----------|----------|----------|
| **Config system + notifications** | **E2E red team test (cont.)** | **E2E blue team test (mock MCP)** |

Person 1 runs integration smoke tests against the real MCP using sample data. Prepares for the Day 8 switchover.

### Day 8 — INTEGRATION DAY

| All Three |
|-----------|
| **Swap mock MCP → real MCP. Connect all pieces.** |

This is the moment of truth. If the contracts were followed, this is a config change (point to real server instead of mock). If someone deviated, this is where you find out.

Tasks:
- Person 1: Final real MCP readiness check with sample data
- Person 2: Switch to real MCP, run red team pipeline against a real NemoClaw victim
- Person 3: Switch to real MCP, test repro pipeline against a real finding
- All three: Debug any interface mismatches (type errors, missing fields, unexpected nulls)

### Day 9 — FULL PIPELINE TEST

| All Three |
|-----------|
| **End-to-end: red team → repro → blue team → regression** |

Run the complete cycle:
1. Person 2's red team generates ideas, executes attacks, judges results
2. Confirmed findings flow to Person 3's repro pipeline
3. Repro packages flow to Person 3's blue team
4. Blue team generates patches, tests them, adds regression tests
5. Regression suite runs to verify everything holds
6. Surface map updates, ideation adjusts for next cycle

Fix any remaining integration issues.

### Day 10 — POLISH

| All Three |
|-----------|
| **Bug fixes, demo prep, documentation** |

- Fix remaining bugs discovered during full pipeline test
- Prepare demo: set up a victim agent with known vulnerabilities for a live demo run
- Write README and setup instructions
- Record a demo video if needed

---

## Critical Path Analysis

```
                    Day 1          Day 2          Day 3-7         Day 8
                    ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
   Person 1         │ Contracts│──▶│ Mock MCP │──▶│Real infra│──▶│Integration│
                    └──────┬───┘   └──────────┘   └──────────┘   └──────────┘
                           │
                    ┌──────▼───┐   ┌─────────────────────────┐
   Person 2         │ Review   │──▶│ Build red team pipeline  │──────────────▶
                    └──────────┘   └─────────────────────────┘
                           │
                    ┌──────▼───┐   ┌─────────────────────────┐
   Person 3         │ Review   │──▶│ Build repro + blue team  │──────────────▶
                    └──────────┘   └─────────────────────────┘
```

**The only blocking dependency:** Person 1's interface contracts (Day 1). Everything after Day 2 is fully parallel.

**Secondary dependency:** Person 2's Tier 1 check function signatures (Day 3). Person 3 needs these to build the replay-minimizer and patch verifier. If Person 2 is late on this, Person 3 can mock the functions and integrate later.

---

## Risk Mitigation

### Risk: Interface contracts have errors
**Impact:** Discovered on Day 8, causes rework.
**Mitigation:** Persons 2 & 3 review contracts thoroughly on Day 1. Any uncertainty → ask immediately. Person 1 runs integration smoke tests on Day 7 using sample data to catch issues before the full switchover.

### Risk: Person 1's mock MCP is too simplistic
**Impact:** Persons 2 & 3 build against unrealistic behavior, integration fails.
**Mitigation:** The mock should return realistic data shapes, not just empty arrays. Include edge cases: empty results for `search_findings`, high similarity results for `check_duplicate`, empty repro queues. Person 1 should pair with Persons 2 & 3 briefly on Day 2 to verify the mock is usable.

### Risk: NemoClaw SDK is harder to integrate than expected
**Impact:** Monitoring harness and victim provisioning take longer than planned.
**Mitigation:** Person 1 starts investigating the NemoClaw SDK on Day 1 (while writing contracts). If it's more complex than expected, flag it immediately and adjust the timeline. The mock MCP buys the team time — Persons 2 & 3 can keep developing even if the real infrastructure is delayed.

### Risk: Execution agent system prompt doesn't produce good attacks
**Impact:** Red team pipeline technically works but finds nothing useful.
**Mitigation:** Person 2 should start prompt iteration early (Day 3) and test against planted-vulnerability victims. Budget at least 2-3 full prompt rewrites. This is the most craft-dependent part of the project.

### Risk: SQLite write contention under parallel lanes
**Impact:** Lane results get lost or corrupted when multiple lanes finish simultaneously.
**Mitigation:** Use SQLite WAL mode from the start. If contention is still an issue, Person 1 implements a write queue (buffer lane results in memory, flush to DB sequentially). If that's still not enough, migrate to PostgreSQL + pgvector.

---

## Daily Sync Protocol

15-minute standup, every day, all three people. Each person answers:

1. **What I shipped** — specific deliverables completed
2. **What's blocked** — any dependency on another person
3. **Interface changes needed** — any MCP tool signature, type definition, or schema change request

**Rules:**
- Interface change requests must be raised same-day and resolved within hours. Never let a contract disagreement linger overnight.
- If you discover that a tool signature doesn't have a field you need, tell Person 1 immediately. Adding a field to a type is trivial on Day 3. Adding it on Day 8 means everyone has to update.
- If your end-to-end test reveals that the mock MCP needs to return different data shapes, tell Person 1 immediately.
