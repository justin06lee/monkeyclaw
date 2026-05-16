# MonkeyClaw demo script

A guided ~4-minute walkthrough for presenting MonkeyClaw to judges. It
assumes the fallback demo (`demo/run_hackathon_demo.sh`) is running and
the dashboard is open.

The goal: show the **full red-to-blue lifecycle** — a vulnerability is
found, reproduced, proven, patched, and regression-locked — on one
screen.

---

## 0. Setup (before the judges arrive)

```bash
uv sync
demo/run_hackathon_demo.sh        # seeds the DB, opens the dashboard
```

Keep a terminal open for the optional live commands in step 6.

---

## 1. The problem (30s)

> "Coding agents are privileged developer runtimes. They read source,
> run shell commands, call MCP tools, and reach the network. An injected
> or mistaken action can read a secret and exfiltrate it with ordinary
> commands. The risk surface is real and it is not tested continuously."

MonkeyClaw is an autonomous red/blue loop that **continuously attacks an
agent, proves the findings, patches them, and locks them with
regression tests** — across 18 attack zones.

---

## 2. Overview panel (20s)

Point at the top stat row:

- cycles run, confirmed vs. suspicious findings
- open vs. verified patches
- regression pass rate and mean coverage

> "This is the state of the whole system at a glance — it is meant to be
> understandable in 30 seconds."

---

## 3. Coverage heatmap (20s)

> "Eighteen attack zones — sandbox filesystem, network, the permission
> model, prompt injection, MCP supply chain, memory. Red is untested,
> green is covered. The loop spends its budget on the red cells."

---

## 4. Finding timeline — the red team (45s)

Walk one row left to right:

> "Here is finding FND-0001: a poisoned README told the agent to print
> `.env` into the test log. The red team generated the idea, the victim
> fell for it, a programmatic Tier 1 check fired — `secret_file_read` —
> and it was confirmed at a 100% repro rate."

Note the lifecycle columns: **verdict -> repro status -> patch status.**

> "Findings drawn from the General Analysis 'Securing Coding Agents'
> adversarial corpus: indirect prompt injection, terminal exfiltration,
> symlink escape, MCP tool poisoning, control-plane edits."

---

## 5. The blue team — repro, patch, verify (60s)

**Repro packages panel:**

> "A finding is not a vulnerability until it reproduces. MonkeyClaw
> replays the attack on fresh victims, computes a repro rate, minimizes
> the transcript to the smallest trigger, and writes a repro document.
> A *cold verifier* — a fresh agent given only that document — then
> tries to follow it. The green check means a cold agent could
> reproduce the bug from the doc alone."

**Blue team panel:**

> "Triage scores and groups the packages. The patch generator proposes
> candidate diffs — least invasive first. Then the patch verifier runs
> six gates: the diff applies, the vulnerability is blocked, normal
> functionality still works, the full regression suite still passes,
> the patch does not weaken the control plane, and security telemetry
> is still produced. Only then is a patch approved."

Point at a rejected patch:

> "This patch was *rejected* — the control-plane gate caught it widening
> the allowed-path list. A fix that quietly weakens a guardrail is not a
> fix."

---

## 6. Evidence, search, cost (30s)

> "Evidence timeline — every triggered check and alert. Search
> intelligence — how the red team is exploring the zone space and which
> ideation modes are productive. Cost panel — token spend and an
> estimate, because continuous testing has to be affordable."

---

## 7. Optional — run it live (45s)

In the spare terminal:

```bash
uv run monkeyclaw run --cycles 1 --target monkey-victim --mock
uv run monkeyclaw blue-team
```

> "That is one real cycle: ideate, attack, judge, then the blue-team
> pipeline. Refresh the dashboard — the new finding flows through the
> same lifecycle."

---

## 8. Close (20s)

> "MonkeyClaw turns agent security from a one-time audit into a
> continuous loop. Red finds it, blue proves and fixes it, regression
> tests keep it fixed. Security improves over time instead of
> oscillating."

---

## If something breaks

- The fallback demo never needs network or credentials. If the live
  path fails, re-run `demo/run_hackathon_demo.sh` (fallback mode) and
  present from the seeded DB.
- Re-seed at any time: `uv run python demo/seed_demo_db.py`.
- The dashboard tolerates an empty DB — it will simply show "no data"
  panels until a cycle or the seed runs.
