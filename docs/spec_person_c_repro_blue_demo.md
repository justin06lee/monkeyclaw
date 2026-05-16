# Person C Spec: Repro, Blue Team, Regression, Dashboard, Demo

## Mission

Person C owns the proof and the show. Your job is to turn findings into reproducible vulnerability packages, generate fixes and tests, verify them, and make the result demo-ready.

You own:

- `blue_team/`
- `test/test_blue_*.py`
- `infra/dashboard.py`
- `demo/` orchestration scripts and sample outputs, in coordination with A/B
- final demo docs and screenshots

You should not edit:

- `interfaces/` directly. Ask Person A.
- `red_team/` directly. Ask Person B.
- most of `infra/` except `infra/dashboard.py` and demo-facing read-only additions after coordination.

## Hackathon Outcome

By the end, a judge should see:

1. A finding enters the repro queue.
2. MonkeyClaw replays it several times.
3. MonkeyClaw minimizes the repro.
4. A cold verifier confirms the repro doc is usable.
5. Blue team triages it.
6. Blue team generates patch candidates.
7. Blue team generates regression and functionality tests.
8. Verifier approves or rejects the patch.
9. Dashboard shows the full red-to-blue lifecycle.

## Core Blue Flow

```text
repro queue
-> replay N times
-> compute repro rate
-> delta minimize
-> root cause locate
-> write repro package
-> cold verify
-> blue queue
-> triage/group
-> patch candidates
-> tests
-> patch verification
-> regression suite
-> knowledge/coverage/dashboard update
```

## Deliverable C1: Repro Package Quality

### Goal

Produce a repro document that is good enough for a fresh agent or human to follow.

### Required Repro Sections

- Vulnerability ID
- Title
- Severity
- Affected zone
- Environment and prerequisites
- Minimal reproduction steps
- Expected behavior
- Actual behavior
- Evidence
- Indicators of compromise
- Affected paths/functions if known
- Ideas used
- Repro rate
- Suggested mitigations
- Confidence and caveats

### Files

- Modify: `blue_team/repro_writer.py`
- Modify: `test/test_blue_repro_writer.py`

### Acceptance

- Repro markdown includes every required section.
- Minimal steps are structured and machine-readable.
- Low-confidence root-cause info is labeled speculative.

## Deliverable C2: Replay and Minimization Reliability

### Goal

Make replay evidence convincing.

### Behavior

- Replay original transcript N times.
- Run Tier 1 checks after each replay.
- Store success/failure per replay.
- If repro rate below threshold, mark as parked/suspicious.
- If above threshold, delta-minimize:
  - remove turns
  - remove tool calls
  - shrink payload
  - preserve trigger semantics

### Files

- Modify: `blue_team/replay_minimizer.py`
- Modify: `test/test_blue_replay_minimizer.py`

### Acceptance

- A planted filesystem finding minimizes to the smallest trigger.
- Repro rate is computed correctly.
- Failed repros do not proceed to patch generation.

## Deliverable C3: Cold Verifier Loop

### Goal

A repro doc that cannot be followed is not a repro.

### Behavior

- Start fresh victim/agent context.
- Give only the repro document.
- Execute steps exactly.
- Run checks.
- PASS means `cold_verified=true`.
- FAIL produces diagnostic notes and sends them back to writer.
- Max attempts defaults to 3.

### Files

- Modify: `blue_team/cold_verifier.py`
- Modify: `test/test_blue_cold_verifier.py`

### Acceptance

- Cold verifier can pass a good doc.
- Cold verifier rejects an ambiguous doc.
- Diagnostic rewrite improves the doc on retry.

## Deliverable C4: Triage and Grouping

### Goal

Blue team should fix root causes, not individual symptoms.

### Triage Score

```text
priority = severity_weight * blast_radius * repro_rate / fix_complexity
```

### Grouping Criteria

Group repro packages when:

- same affected zone
- overlapping affected paths/functions
- similar root-cause text
- similar failure class

### Files

- Modify: `blue_team/triage.py`
- Modify: `test/test_blue_triage.py`

### Acceptance

- Related filesystem findings group into one fix task.
- Unrelated prompt-injection and PII findings stay separate.

## Deliverable C5: Patch Candidate Generation

### Goal

Generate patch candidates that are reviewable and testable.

### Candidate Requirements

Each candidate must include:

- patch ID
- vulnerability IDs addressed
- zone
- approach label
- invasiveness
- unified diff
- explanation
- side effects
- expected tests
- confidence

For high/critical severity, generate 2-3 approaches:

- least invasive
- moderate architectural fix
- stronger policy-level fix

### Files

- Modify: `blue_team/patch_generator.py`
- Modify: `test/test_blue_patch_generator.py`

### Acceptance

- Candidate diffs are valid unified diff text.
- High severity produces multiple approaches.
- Side effects are explicit.

## Deliverable C6: Test Generation

### Goal

Every verified vuln creates permanent tests.

### Required Tests

Positive regression:

- reproduces the vulnerability on unpatched target
- passes after patch blocks the vulnerability

Negative functionality:

- exercises legitimate nearby behavior
- must pass before and after patch

Policy regression:

- confirms required telemetry/policy decision exists
- catches silent bypasses where behavior is blocked but evidence is missing

### Files

- Modify: `blue_team/test_generator.py`
- Modify: `test/test_blue_test_generator.py`

### Acceptance

- Generated tests include expected result.
- Tests reference minimal repro steps.
- Functionality preservation test is not empty.

## Deliverable C7: Patch Verification

### Goal

No patch is approved unless it blocks the vulnerability and preserves normal behavior.

### Verification Gates

1. Patch applies cleanly in disposable work area.
2. Positive regression passes.
3. Negative functionality test passes.
4. Full regression suite passes.
5. No control-plane weakening detected.
6. Telemetry evidence exists.

### Control-Plane Weakening Checks

Reject patch if it:

- deletes or skips tests
- disables checks
- loosens allowed paths
- opens unknown network egress
- suppresses telemetry instead of fixing behavior
- changes MCP allowlists without approval
- modifies CI/deploy workflows unexpectedly

### Files

- Modify: `blue_team/patch_verifier.py`
- Modify: `test/test_blue_patch_verifier.py`

### Acceptance

- Bad patch is rejected.
- Good planted-vuln patch is approved.
- Verification result is stored through Person A's MCP methods.

## Deliverable C8: Regression Runner

### Goal

Regression suite makes security improve over time instead of oscillating.

### Behavior

- Run all active tests.
- Record pass/fail/error.
- Update consecutive pass counts.
- Mark flaky tests.
- Produce summary for dashboard.

### Files

- Modify: `blue_team/regression_runner.py`
- Modify: `test/test_blue_regression_runner.py`

### Acceptance

- Suite result is deterministic in mock mode.
- Failed regression updates DB status.
- Passing post-patch regression updates coverage signal.

## Deliverable C9: Dashboard

### Goal

Make the project understandable in 30 seconds.

### Views

Add dashboard sections:

- Overview:
  - cycles completed
  - confirmed/suspicious findings
  - open/verified patches
  - regression pass rate
  - mean coverage
- Coverage heatmap:
  - 18 zones
  - coverage score
  - open vulns
  - last tested
- Finding timeline:
  - idea
  - zone
  - verdict
  - evidence
  - repro status
  - patch status
- Repro package view:
  - minimal steps
  - repro rate
  - cold verifier status
  - affected paths
- Blue team view:
  - fix tasks
  - patch candidates
  - verifier gates
  - regression tests
- Evidence timeline:
  - tool requests
  - file/network/process events
  - MCP events
  - approvals
- Search intelligence:
  - MAP-Elites cell count
  - top mutation operators
  - judge ensemble vote summary
- Cost/model stats:
  - tokens by role
  - model success rates
  - cost estimate

### Files

- Modify: `infra/dashboard.py`
- Create: `test/test_dashboard.py` if feasible

### Acceptance

- `uv run monkeyclaw dashboard` starts successfully.
- Dashboard works with empty DB.
- Dashboard works with pre-seeded demo DB.
- Dashboard makes the full red-to-blue path visible.

## Deliverable C10: Demo Assets

### Goal

Make the final presentation robust even if live APIs or live NemoClaw fail.

### Files

- Create: `demo/run_hackathon_demo.sh`
- Create: `demo/seed_demo_db.py`
- Create: `demo/README.md`
- Create: `docs/demo_script.md`
- Create: `docs/judge_quickstart.md`

### Demo Modes

Live mode:

```bash
uv run monkeyclaw run --cycles 1 --target planted-filesystem --mock
uv run monkeyclaw blue-team --mock
uv run monkeyclaw dashboard
```

Fallback mode:

```bash
uv run python demo/seed_demo_db.py
uv run monkeyclaw dashboard
```

### Acceptance

- A judge can run the fallback demo without model credentials.
- The live demo path is one command or a short sequence.

## Deliverable C11: Final README and Pitch Support

Coordinate with everyone, but you own the final demo-facing docs.

README should include:

- What MonkeyClaw is.
- Why agent security needs continuous red/blue testing.
- Quickstart.
- Demo commands.
- Architecture diagram or text diagram.
- What works now.
- What is mocked for hackathon.
- What production version adds.

Pitch script should include:

- Problem.
- Insight.
- Demo flow.
- Technical architecture.
- Why this wins.
- Future path.

## Person C Timeline

### Hours 0-3

- Review A's contracts.
- Confirm repro package and status fields.
- Coordinate dashboard read APIs.

### Hours 3-12

- Make replay/minimize reliable for planted findings.
- Improve repro writer.
- Cold verifier pass/fail loop.

### Hours 12-24

- Triage grouping.
- Patch generation.
- Test generation.
- Patch verifier gates.

### Hours 24-36

- Regression runner.
- Dashboard core views.
- Demo DB seed.

### Hours 36-44

- Demo script.
- README and pitch docs.
- Dashboard polish.

### Hours 44-48

- Integration.
- Fallback demo rehearsal.
- Final screenshots/logs.

## Final Acceptance Checklist

- Confirmed finding becomes repro package.
- Repro package cold-verifies.
- Blue team generates patch and tests.
- Patch verifier rejects bad patches and approves good planted fix.
- Regression suite records results.
- Dashboard shows full lifecycle.
- Demo works live or from seeded DB.
