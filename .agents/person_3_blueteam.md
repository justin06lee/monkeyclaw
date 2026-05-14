# Person 3 — Repro + Blue Team + Regression

**Role:** Everything from "confirmed finding lands in the repro queue" to "patch is verified and regression test is permanent."

---

## Scope Boundaries

You consume findings from the database (via MCP), produce repro packages, generate patches, and build the regression suite. You never touch ideation, execution, or judgment — those are Person 2. You never touch the database directly — you call MCP tools that Person 1 built.

Your code lives entirely in `monkeyclaw/blue_team/`. You import shared types from `interfaces/types.py` (owned by Person 1). The one exception: you import `red_team/checks.py` (Person 2's Tier 1 checks) for replay verification. This is the only cross-directory import.

---

## Phase A — Repro Pipeline (Day 2-5)

### Deliverable 1: Replay-Minimizer Agent

**File:** `blue_team/replay_minimizer.py`

Single agent, two sequential phases (spec §8.2). Merging replay and minimize into one agent eliminates inter-agent communication overhead — the minimizer re-invokes replay on every delta-debugging step.

**Replay Phase:**
1. Pull a finding from the repro queue via `get_repro_queue()` MCP tool
2. Retrieve the full lane result (transcript, harness data) from the finding record
3. Provision N fresh victim instances (default N=5) using Person 1's provisioning API (`provision_victim` from `interfaces/provisioning.py`)
4. Replay the exact attack transcript against each victim — send each attacker message in sequence, capture victim responses
5. After each replay, run Person 2's Tier 1 checks (imported from `red_team/checks.py`) and, for semantic zones, run a simplified Tier 2 check
6. Compute reproducibility rate: `reproduced_count / N`
7. If repro rate < threshold (default 0.5): downgrade the finding to `suspicious`, log it, park it. Do NOT proceed to minimize.
8. If repro rate >= threshold: proceed to minimize phase

**Minimize Phase (Delta Debugging):**
1. Start with the full attack transcript (all turns)
2. For each turn in the transcript (iterating from earliest to latest):
   a. Remove the turn
   b. Replay the shortened transcript against a fresh victim
   c. Run judgment checks
   d. If the vulnerability still reproduces → keep the shorter version (this turn was unnecessary)
   e. If the vulnerability no longer reproduces → restore the turn (it's necessary)
3. After all turns have been tested, attempt payload simplification within remaining turns:
   a. For each remaining attacker message, try replacing complex content with simplified versions
   b. Re-replay to verify the vuln still triggers
   c. Keep the simplest version that still works
4. Output: the minimal attack chain — fewest turns, simplest content
5. Cap at 30 replay iterations total to prevent runaway delta-debugging

**Output:** Updated finding record with `repro_rate`, `minimal_transcript`, and `minimized=true`. Pass to root-cause locator (if severity >= high) or repro writer (if severity < high).

**Cross-person dependency:** You import `run_all_tier1_checks` from `red_team/checks.py`. If Person 2 hasn't published this yet, mock it as a function that always returns `[]` (no triggers) until the real implementation is ready. Person 2 commits to publishing function signatures by Day 3.

### Deliverable 2: Root-Cause Locator (Conditional Agent)

**File:** `blue_team/root_cause.py`

Fires ONLY for findings with severity >= high (configurable via `root_cause_severity_threshold` in config). For medium/low, skip entirely — the token cost and hallucination risk aren't justified.

**Process:**
1. Receive the minimized attack chain + monitoring harness data (which syscalls failed, which paths were accessed, which network requests were made)
2. Query `search_codebase` MCP tool for source files relevant to the affected zone. Use the zone description + evidence signals as the search query — NOT "search the entire codebase"
3. Provide the model with: minimized transcript, harness evidence, relevant source files
4. Ask the model to trace the execution path from the triggered check to the suspect code
5. Rank candidate fix sites: specific files, functions, and line ranges

**Hallucination mitigation:**
- Require the model to assign a confidence score (0-1) to each candidate fix site
- Sites with confidence < 0.5 are marked as "speculative" in the output
- The repro package explicitly warns the blue team not to trust low-confidence analysis without manual verification
- If the model can't identify any candidate with confidence >= 0.3, output "root cause could not be determined" rather than guessing

**Output:**
```python
RootCauseResult(
    root_cause_confidence: float,  # overall confidence
    candidate_fix_sites: list[FixSite],  # file, function, line_range, explanation, confidence
    execution_trace: str  # narrative of how the attack traversed the system
)
```

### Deliverable 3: Repro Writer Agent

**File:** `blue_team/repro_writer.py`

Generates the structured markdown vulnerability document (spec §8.4).

**Input:** Minimized transcript, repro rate, root-cause data (if available), original idea citations, monitoring harness evidence.

**Document template (must follow this structure exactly):**

```markdown
# [VULN_ID] - [Title]

## Severity
[Score] - [critical | high | medium | low]

## Summary
2-3 sentence description.

## Environment
- NemoClaw version: X.Y.Z
- OpenClaw version: X.Y.Z
- OpenShell runtime version: X.Y.Z
- Target agent type: [type]
- Policy configuration: [details]

## Reproduction Steps
1. [Exact step with exact input]
2. [Expected observation after each step]
3. [Steps written for a fresh agent with no prior context]

## Expected Behavior
What SHOULD happen.

## Actual Behavior
What DOES happen.

## Indicators of Compromise
Observable signals.

## Reproducibility
Rate: X/Y
Notes on conditions affecting reproducibility.

## Root Cause Analysis (if available)
Suspected code paths. Confidence: [level].

## Ideas Used
- [idea_id] from [source_mode] targeting [zone]

## Suggested Mitigations
Potential fix approaches (non-authoritative).

## Raw Artifacts
- Minimal attack transcript
- Relevant harness data
```

**Key requirement:** Reproduction Steps must be detailed enough that a fresh agent with ZERO context about MonkeyClaw can follow them and trigger the vulnerability. This is verified by the cold verifier (Deliverable 4).

### Deliverable 4: Cold Verifier Agent

**File:** `blue_team/cold_verifier.py`

The quality gate (spec §8.5). Its purpose is to ensure the repro document is followable by someone/something with zero prior context.

**Process:**
1. Provision a fresh agent instance with NO knowledge of MonkeyClaw, no access to prior findings, no memory of the attack
2. Give this agent ONLY the repro document (the markdown from Deliverable 3)
3. The agent follows the reproduction steps exactly as written
4. After execution, run Person 2's Tier 1 checks + a simplified Tier 2 check to evaluate whether the vulnerability was reproduced

**Outcome routing:**
- **PASS:** Vulnerability reproduced by a cold agent following only the document. Push the completed repro package via `push_repro_package` MCP tool with `cold_verified=true, ready_for_blue=true`.
- **FAIL:** Could not reproduce. Generate diagnostic notes:
  - Which step failed?
  - What was unclear or ambiguous?
  - What information was missing?
  - Send notes back to repro writer agent for revision

**Loop:** PASS/FAIL loop runs up to 3 iterations (configurable via `cold_verify_max_attempts`). If the document fails all 3 attempts, flag for human review with a note: "automated reproduction documentation was unable to produce a followable document after 3 attempts."

---

## Phase B — Blue Team System (Day 4-7)

### Deliverable 5: Triage Agent

**File:** `blue_team/triage.py`

Consumes repro packages from the blue team queue.

**Process:**
1. Pull repro packages via `get_blue_team_queue()` MCP tool
2. Score each by: `severity × blast_radius × (1 / fix_complexity)`
   - **Blast radius:** How many zones/features are affected. Parse from the repro package: a permission model vuln might affect all zones (high blast radius); a specific prompt injection might only affect one agent config (low).
   - **Fix complexity:** Estimated from the root-cause analysis if available. One-line boundary check = low complexity. Redesigning the privacy router = high. If no root-cause data, estimate from the failure class.
3. Group related vulnerabilities: If multiple repro packages trace back to the same zone AND similar root cause (check via vector similarity on the repro summaries), group them as one fix task. Fixing the root cause should resolve all grouped vulns.
4. Output: A prioritized fix queue where each entry is a single repro package or a grouped set, with a priority score and recommended fix approach.
5. Update each repro package's `blue_team_status` to `triaged` via the MCP.

### Deliverable 6: Patch Generator Agent

**File:** `blue_team/patch_generator.py`

Produces candidate code patches for each fix task.

**Process:**
1. Receive a fix task from triage (one or more repro packages)
2. Retrieve relevant source files via `search_codebase` MCP tool, using the root-cause data (if available) or the zone description as the query
3. Provide the model with: repro package details, minimal reproduction steps, relevant source code, root-cause analysis (if available)
4. Ask the model to generate a proposed patch in unified diff format
5. For severity >= high: generate 2-3 alternative approaches ranked by invasiveness (least invasive first). Each approach should include:
   - A label (e.g., "Symlink pre-resolution before policy check")
   - An invasiveness rating (low/medium/high)
   - The diff
   - An explanation of what it changes and why
   - Side effects analysis

**Constraint:** The patch generator does NOT auto-apply patches. It produces candidates. The patch verifier (Deliverable 8) tests them. In human-in-the-loop mode (configurable), a human reviews candidates before verification.

**Output:** `PatchCandidate` objects stored via a new finding update or logged directly.

### Deliverable 7: Test Generator Agent

**File:** `blue_team/test_generator.py`

From each repro package + proposed patch, generates two types of tests:

**Positive regression test:**
- A minimal script (shell or Python) that reproduces the vulnerability
- Uses the minimal reproduction steps from the repro document
- Uses Person 2's Tier 1 check functions to verify the outcome programmatically
- Expected behavior on UNPATCHED NemoClaw: vulnerability triggers (test "fails")
- Expected behavior on PATCHED NemoClaw: vulnerability does NOT trigger (test "passes")

**Negative test (functionality preservation):**
- A script that exercises the legitimate functionality adjacent to the fix
- Example: if the patch prevents symlink resolution outside the sandbox, the negative test verifies that symlinks WITHIN the sandbox still work correctly
- Expected behavior on BOTH unpatched and patched: legitimate operation succeeds
- This catches overly aggressive patches that break valid use cases

**Output:** `RegressionTest` objects ready for the patch verifier and eventual addition to the permanent suite.

### Deliverable 8: Patch Verifier

**File:** `blue_team/patch_verifier.py`

Three-gate validation (spec §9.5):

**Setup:** Provision a fresh NemoClaw instance. Apply the proposed patch.

**Gate 1 — Regression test:** Run the new positive regression test against the patched instance. Expected: vulnerability no longer triggers. If it still triggers → patch rejected, the fix doesn't work.

**Gate 2 — Functionality test:** Run the new negative test against the patched instance. Expected: legitimate operations still work. If they break → patch rejected, the fix is too aggressive.

**Gate 3 — Full regression suite:** Pull the entire regression suite via `get_regression_suite()` MCP tool. Run every test. Expected: all previously-fixed vulnerabilities remain fixed. If any regress → patch rejected, the fix introduced a regression.

**Outcome routing:**
- **All 3 pass:** Patch approved.
  - Add the new regression test to the permanent suite via `add_regression_test` MCP tool
  - Mark the vulnerability as `patched` in the findings table
  - Update the surface map: reset zone coverage to 0.3 via `update_zone_coverage`
  - If `auto_commit_patches` is true, commit the patch to the staging branch
  - Send alert via `send_alert`
- **Any gate fails:** Patch rejected.
  - Log which gate failed and why
  - Send failure details back to patch generator for revision
  - Loop up to `patch_verify_max_attempts` (default 3) per patch approach
  - If all approaches fail all attempts: escalate for human review

---

## Phase C — Regression Suite (Day 5-7)

### Deliverable 9: Regression Runner

**File:** `blue_team/regression_runner.py`

The engine that executes the full regression suite (spec §10).

**Process:**
1. Pull all active (non-deprecated) tests from `get_regression_suite()` MCP tool
2. Provision a NemoClaw instance with the current state (current patches applied)
3. Run every test sequentially (or in parallel if tests are independent):
   - Execute the test script
   - Record pass/fail for each test
   - Update `last_run_at` and `last_run_result` for each test
   - Track `consecutive_passes` — a test that has passed 50 times in a row is very stable
4. Compute suite-level metrics:
   - Total tests, passing, failing
   - Any newly failing tests (were passing last run, failing now)
   - Tests by zone coverage
5. Compute coverage delta between this run and the previous run:
   - Zones where new patches were applied since last run
   - Zones with decaying coverage (no activity)
   - Any regressions (tests that were passing but now fail)
6. Feed coverage delta back to the surface map via `update_zone_coverage` MCP tool

**Trigger points:**
- **Post-patch:** Called by the patch verifier (Deliverable 8) as Gate 3. In this mode, it runs against a specific patched instance.
- **Pre-red-team-batch:** Called by Person 1's orchestrator before each new red team batch begins. In this mode, it runs against the current production state to establish a baseline and generate the coverage delta that informs ideation.

**Output:**
```python
RegressionRunResult(
    total_tests: int,
    tests_passing: int,
    tests_failing: int,
    newly_failing: list[str],  # test_ids that regressed
    coverage_delta: dict[str, float],  # zone_id → coverage change
    new_tests_since_last_run: int,
    run_duration_seconds: int
)
```

---

## Phase D — Integration (Day 7+)

### Deliverable 10: End-to-End Blue Team Test + Integration

**Test with planted vulnerability:**
1. Manually create a fake "confirmed finding" in the mock MCP with a known vulnerability (e.g., a sandbox escape via a specific command sequence)
2. Run the full pipeline: replay-minimize it → write the repro doc → cold-verify it → triage it → generate a patch → generate tests → verify the patch → add the regression test
3. Verify every step produces correct output and makes the right MCP calls

**Integration with real system:**
- Swap mock MCP for Person 1's real implementation
- Run against real confirmed findings from Person 2's red team pipeline
- Debug any type mismatches in the repro package format
- Verify cold verifier works against real NemoClaw instances (not just mocks)
- End-to-end test: Person 2's red team finds a vulnerability → your pipeline reproduces it, documents it, patches it, verifies the fix, and adds a regression test
- Verify the regression runner works at scale: run the full suite (may have 10-50 tests after initial cycles) and confirm it completes within reasonable time
