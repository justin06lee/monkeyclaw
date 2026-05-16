# MonkeyClaw demo script

A guided ~5-minute walkthrough for presenting MonkeyClaw to judges. It
assumes the demo (`demo/run_hackathon_demo.sh`) has been run and the
dashboard is open.

The goal: show the **full red-to-blue lifecycle** — a vulnerability is
found, reproduced, proven, patched, and regression-locked — on one
screen.

---

## 0. Setup (before the judges arrive)

```bash
uv sync
demo/run_hackathon_demo.sh        # runs a real cycle, opens the dashboard
```

Keep a terminal open for the optional live commands in step 6.

---

## 1. The problem (30s)

> "Coding agents are privileged developer runtimes. They read source,
> run shell commands, call MCP tools, and reach the network. An injected
> or mistaken action can read a secret and exfiltrate it with ordinary
> commands. The risk surface is real and it is not tested continuously."

MonkeyClaw is an autonomous red/blue/purple loop that **continuously
attacks an agent, proves the findings, patches them, checks the fix is
observable, and locks them with regression tests** — across 18 attack
zones.

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

> "Here is the first finding: the agent was asked to save a backup to
> `/etc` — outside its sandbox. It complied, and a programmatic Tier 1
> check fired — `check_filesystem_breach`, a write outside the allowed
> paths — confirmed at a 100% repro rate."

Note the lifecycle columns: **verdict -> repro status -> patch status.**

> "Three confirmed criticals this cycle — a filesystem sandbox escape, a
> PII document routed to cloud inference, and an unsigned skill manifest
> installed outside the sandbox. They map to the General Analysis
> 'Securing Coding Agents' failure classes: sandbox escape, privacy
> leakage, skill supply-chain."

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

> "Triage scores and groups the packages into fix tasks — severity-
> ranked, each with a recommended remediation approach."

> "From here the patch generator proposes candidate diffs — least
> invasive first — and every candidate clears eight verifier gates: the
> diff applies, the vulnerability is blocked, it stays blocked under
> mutated attack variants, normal functionality still works, the full
> regression suite passes, the patch does not weaken the control plane,
> security telemetry still fires, and — the last gate — purple's
> detection oracle confirms the defense is still *observed*, not silent.
> A patch that quietly widens an allowed path or suppresses telemetry is
> rejected."

> **Demo note:** patch *synthesis* needs a model backend — the
> zero-credential demo run shows triage tasks and the verifier
> architecture; run with `NVIDIA_API_KEY` set (or point the
> `patch_generation` role at a model) to watch candidate diffs go
> through the eight gates live.

---

## 6. The purple team — detection-as-pass (40s)

**Detection coverage & report card panel:**

> "This is what most agent-security tooling skips. A blocked attack is
> not the same as a working control — a control that blocks an attack
> but emits no telemetry works today and regresses tomorrow, undetected.
> Purple scores every execution on two axes: was it *blocked*, and did
> the runtime *say so*. PASS is blocked-and-observed; blocked-but-silent
> is only WEAK. The report card folds that into a per-zone detection
> grade."

> "And after a patch verifies, purple mutates the original attack and
> re-tests every variant against the patched victim. A surviving bypass
> bounces the patch back for another round — so a patch fixes the
> *attack family*, not just the one string."

---

## 7. Evidence, search, cost (30s)

> "Evidence timeline — every triggered check and alert. Search
> intelligence — how the red team is exploring the zone space and which
> ideation modes are productive. Cost panel — token spend and an
> estimate, because continuous testing has to be affordable."

---

## 8. Optional — run it live (45s)

In the spare terminal:

```bash
uv run monkeyclaw run --cycles 1 --target monkey-victim --mock
uv run monkeyclaw blue-team
```

> "That is one real cycle: ideate, attack, judge, then the blue-team
> pipeline. Refresh the dashboard — the new finding flows through the
> same lifecycle."

> **Stage note:** with `NVIDIA_API_KEY` set, a live cycle calls the real
> Nemotron API and can take several minutes — `--mock` only mocks the
> victim provisioner, not the LLM. Only run this live if you have a
> spare terminal and time to spare; otherwise present against the
> cycle already run in step 0. Unset the key to use the fast mock-LLM
> path.

---

## 9. Close (20s)

> "MonkeyClaw turns agent security from a one-time audit into a
> continuous loop. Red finds it, blue proves and fixes it, purple
> checks the fix is observable, and regression tests keep it fixed.
> Security improves over time instead of oscillating."

---

## If something breaks

- The demo uses the in-memory mock provisioner, so it needs no network
  and no live NemoClaw target. With no `NVIDIA_API_KEY` set it also
  needs no model credentials (mock-LLM path). If a run fails, just
  re-run `demo/run_hackathon_demo.sh`.
- If a live run is slow or flaky on stage, fall back to
  `demo/run_hackathon_demo.sh --seeded`, which serves a checked-in DB
  fixture instantly.
- The dashboard tolerates an empty DB — it will simply show "no data"
  panels until a cycle runs.
