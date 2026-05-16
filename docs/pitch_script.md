# MonkeyClaw pitch script

A ~3-minute spoken pitch. Pair it with `docs/demo_script.md` for the
live walkthrough.

---

## Problem

Coding agents — Claude Code, Codex, Cursor, NemoClaw — are privileged
developer runtimes. They read source, edit files, run shell commands,
call MCP tools, and reach the network. That power is the product. It is
also the attack surface.

The dangerous pattern is simple: hostile content enters the model's
context — a poisoned README, an MCP tool description, a webpage — and
once an approved tool reads a file or runs a command, the injected
instruction becomes a real action. A secret gets read; `curl` ships it
out.

Today this is checked, if at all, by a one-time audit. But the agent,
its tools, and its prompts change every week. A point-in-time audit is
stale the day after it ships.

## Insight

Security for agents has to be **continuous and adversarial**, and it has
to **close the loop** — finding a bug is not enough; you have to prove
it, fix it, and keep it fixed.

And there is a second insight that drives our purple layer: **a blocked
attack is not the same as a working control.** A control that blocks an
attack but emits no telemetry works today and regresses tomorrow,
undetected. So we score defense on two axes — *was the attack blocked*
**and** *did the runtime say so* — and a control passes only when both
are true. We call it **detection-as-pass**.

So we built MonkeyClaw as a standing red, blue *and* purple team for
NemoClaw: it attacks across 18 mapped attack zones, every confirmed
finding flows through reproduction, patching, and regression-locking —
automatically — and purple checks the fix is observable and stays fixed.

## Demo flow

1. A red-team cycle generates attack ideas for the lowest-coverage zone
   and runs them against a victim agent.
2. A confirmed finding — say, a poisoned README that makes the agent
   print `.env` — enters the repro queue.
3. MonkeyClaw replays it on fresh victims, computes a repro rate, and
   minimizes the transcript to the smallest trigger.
4. A *cold verifier* — a fresh agent given only the repro document —
   confirms the document is actually reproducible.
5. The blue team triages, generates candidate patches, generates three
   regression tests, and runs the patch through eight verifier gates —
   including a purple-team gate that confirms the defense is *observable*.
6. After the patch verifies, purple mutates the original attack and
   re-tests every variant; a surviving bypass bounces the patch back.
7. The dashboard shows the whole red → blue → purple lifecycle on one
   screen.

The demo runs all of this from one real pipeline cycle against a planted
victim via the in-memory mock provisioner — no model credentials and no
live API needed.

## Technical architecture

A continuous **red → judge → repro → blue → purple** loop:

- **Red** — five-mode Nemotron ideation (creative, code-grounded,
  history-informed, corpus-driven, and a systematic MITRE ATLAS / OWASP-LLM
  technique walk), a MAP-Elites archive, embedding dedup, cross-zone attack
  chaining, multi-turn execution, and tiered judgment (six programmatic
  checks + a five-role semantic judge ensemble).
- **Repro** — replay-minimization, executed-path root-cause location, a
  structured repro document, and a cold-verifier quality gate.
- **Blue** — triage and grouping, multi-approach patch generation,
  three-test generation, and an eight-gate patch verifier that also rejects
  patches which weaken the control plane.
- **Purple** — a detection oracle that scores every execution on a
  prevention × observability quadrant, a coverage model, a 7-dimension
  security report card, and a post-patch generalization loop.
- **Infra** — an MCP server over a SQLite knowledge base, a victim
  provisioner, the monitoring harness, and a live multi-panel dashboard.

Everything is contract-first: a frozen `interfaces/` layer (schema, MCP
signatures, dataclasses) lets the red, blue, and infra tracks move
independently.

## Why this wins

- **It closes the loop.** Most agent-security tooling stops at "found a
  problem." MonkeyClaw proves it, patches it, and locks it with a
  permanent regression test.
- **The blue team is honest.** The verifier rejects a patch that blocks
  the behavior but emits no telemetry, or that quietly loosens a path or
  disables a check. A fix that weakens a guardrail is not a fix.
- **It is grounded.** The 18 zones map to recognized failure classes
  from the General Analysis "Securing Coding Agents" guide — coverage
  means something.
- **It demos without luck.** The mock-provisioner path needs no network
  and no credentials, yet every dashboard panel is real pipeline output.

## Future path

- A custom Nemotron red-team model — a finetune that ideates structured
  attacks without refusing, scored against the stock-Nemotron baseline by
  confirmed-vulnerability rate. It drops in via per-role model routing.
- A PostgreSQL + pgvector backend for cross-lane concurrency, and object
  storage for transcripts with signed, immutable audit logs.
- SIEM / telemetry export behind the evidence timeline.
- The verified-outcome signal as a preference label — DPO today, online
  RL with MonkeyClaw as the live environment tomorrow.
