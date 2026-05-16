# Red-Team Model Buildbook

Date: 2026-05-16
Target: a custom Nemotron red-team attack-generation model for MonkeyClaw.
Constraint: ~24h. Build in a separate Brev GPU session with Claude Code.

## 0. Locked decisions

- **Base model:** Nemotron-3-Nano. Small enough to QLoRA-finetune in hours,
  iterate several times, and serve cheaply via vLLM. (Super 120B is too heavy
  to finetune + serve well inside 24h. The pipeline below is size-agnostic —
  re-run on Super after the hackathon.)
- **Method:** QLoRA SFT is the must-ship. DPO is a stretch, only if SFT
  finishes with hours to spare. No online RL.
- **Data:** cold start — public datasets + synthetic generation. Optionally
  harvest a little MonkeyClaw self-play data in parallel, but do NOT depend on
  it.

## 1. What the model must do

Input: a MonkeyClaw ideation instruction — "generate N attack ideas for zone
`<ZONE_ID>` targeting failure class `<X>`", with context (codebase excerpts,
prior findings, tactic hints).

Output: a JSON array of structured **attack-idea objects** in MonkeyClaw's
`IdeaObject` schema — NOT prose, NOT a refusal.

Three things the model must reliably do that frontier models currently refuse
or do badly:
1. **Not refuse.** It runs inside an authorized red-team harness against the
   project's own NemoClaw victim sandboxes. It should treat the operator
   instruction as the task.
2. **Emit valid structured output** — the exact `IdeaObject` JSON, every time.
3. **Cover the 18 zones with diverse tactics** — filesystem/network/process/IPC
   sandbox escapes, privacy routing, permission model, skill supply chain,
   memory poisoning, inference routing, agent comms, prompt injection, social
   engineering — multi-turn where relevant.

BEFORE writing any training data: pull the exact target format from the repo —
`interfaces/types.py` (`IdeaObject`, `IdeaInput`) and `red_team/ideation.py`
(the three ideation prompt modes + the new taxonomy mode). Every training
example's output must match `IdeaObject` field-for-field, or MonkeyClaw can't
parse it.

## 2. Data plan (this is the bottleneck — spend most effort here)

Target: ~3,000-8,000 SFT examples, all reformatted to
`instruction -> IdeaObject-JSON`. Three streams:

### 2a. Public datasets (HuggingFace) — breadth, real attacks

Pull and adapt (verify exact HF IDs before downloading):
- Prompt injection: `deepset/prompt-injections`, `TrustAIRLab/in-the-wild-jailbreak-prompts`,
  `JailbreakBench/JBB-Behaviors`, `walledai/HarmBench`.
- Agent/tool-specific injection: AgentDojo, InjecAgent (agent prompt-injection
  benchmarks) — closest to MonkeyClaw's threat model.
- Multi-turn jailbreaks: multi-turn / Crescendo-style attack datasets — teaches
  boundary erosion across turns.
- Red-team attempts: the red-team subset of `Anthropic/hh-rlhf`.
Adapt each: take the raw attack, classify it into one of the 18 zones + a
tactic, wrap it as a populated `IdeaObject`. Keep provenance in metadata.

### 2b. Taxonomy-grounded synthetic — coverage, structure

- MITRE ATLAS techniques + OWASP LLM Top 10 are already vendored in
  `red_team/corpora/`. For each technique x each relevant zone, generate
  several structured attack ideas.
- Use a strong cooperating model (Claude/GPT cooperate for generating
  *structured security test cases* when the framing is explicit: authorized
  red-team harness, own victim sandbox, structured-object output, educational).
  Bulk-generate `instruction -> IdeaObject[]` pairs across all 18 zones x
  tactics x ATLAS techniques. This is the main volume lever.
- Generate multi-turn trajectories explicitly (turn-by-turn attack plans), not
  just single-shot prompts.

### 2c. Format / negative examples — reliability

- Many examples of perfectly-formed `IdeaObject` JSON so the model locks the
  schema.
- Examples that turn an ambiguous/loaded instruction into a clean structured
  attack object (anti-refusal: the right behavior is "produce the test case,"
  not "decline").
- A few hard cases: novel zone combinations, sparse-context zones.

### 2d. (Parallel, optional) MonkeyClaw self-play harvest

If someone can run `monkeyclaw run --perpetual --mock` for a few hours, mine
the SQLite KB (`ideas`, transcripts, `judgments`, repro outcomes) into
`instruction -> IdeaObject` pairs — these are the highest-quality, format-exact
examples. Bonus, not a dependency.

### Data hygiene
- Dedup (embedding similarity) so the model doesn't overfit repeated jailbreaks.
- Hold out ~10% as an eval split, stratified across the 18 zones.
- Balance zones — don't let prompt-injection drown the rare zones.

## 3. Training (Brev GPU)

- Environment: Brev instance, vLLM + a QLoRA trainer (axolotl or trl/peft).
  Claude Code in that session sets up the env.
- **QLoRA** on Nemotron-3-Nano: 4-bit base, LoRA adapters (r=16-32, alpha 32,
  dropout 0.05, target all attention + MLP projections). Full finetune is
  unnecessary and slower.
- Instruction format: match MonkeyClaw's actual ideation prompt exactly
  (system + user). Train on completion only (mask the prompt).
- Hyperparams (starting point, ~1 epoch over a few-thousand examples):
  lr 1e-4 to 2e-4 cosine, batch + grad-accum to fit VRAM, max_seq_len long
  enough for multi-turn examples, bf16, 1-3 epochs (watch eval-loss overfit).
- Checkpoint every N steps; keep the best by eval loss.
- Time-box: one clean SFT run + one corrective re-run. Don't chase perfection.

## 4. Eval (do not skip — it's the demo proof)

Two layers:
1. **Static held-out set:** on the 10% holdout, measure — valid-JSON rate
   (must be ~100%), schema-conformance, zone-coverage, refusal rate (must be
   ~0), diversity.
2. **In-harness eval (the real metric):** point MonkeyClaw's red ideation role
   at the finetuned model, run cycles against the mock/planted victims, measure
   **confirmed-vulnerability rate** and **zone coverage** vs the stock-Nemotron
   baseline. "Custom model finds N% more confirmed vulns" is your headline
   number.

## 5. Integration with MonkeyClaw

- Serve the finetuned model (merged adapter or adapter-on-base) with **vLLM**,
  OpenAI-compatible endpoint.
- MonkeyClaw already has per-role **model routing**. Point the `red_ideation`
  (and `red_code_ideation`) roles at the new endpoint via config — a
  `configs/monkeyclaw.yaml` / env change, no code change.
- Keep stock Nemotron as the fallback in the route chain.

## 6. 24-hour timeline (hour-boxed)

- H0-2: pull `IdeaObject` schema + ideation prompt format; stand up the Brev
  env; smoke-test base Nemotron-3-Nano inference + the QLoRA trainer.
- H2-9: DATA. Pull public datasets, run synthetic generation, reformat
  everything to `IdeaObject` JSON, dedup, build train/eval splits. Most of the
  budget goes here.
- H9-13: SFT run #1. Watch eval loss.
- H13-15: static eval + fixes; SFT run #2 if needed.
- H15-18: serve via vLLM; wire into MonkeyClaw; in-harness eval vs baseline.
- H18-22: STRETCH — DPO if SFT is solid and time remains (see section 7);
  otherwise iterate data + re-SFT.
- H22-24: freeze, capture the headline eval numbers, demo prep.

## 7. Stretch — DPO (only if SFT lands early)

MonkeyClaw produces a verified outcome signal — use it as a preference label.
Preference pairs: for the same instruction, an attack idea that the judge/repro
pipeline **confirmed a vulnerability** > an idea that did not (or that the model
refused/mis-formatted). Sources of pairs: the in-harness eval run, or synthetic
(well-formed structured attack > refusal/prose). Run DPO on top of the SFT
adapter. This is the start of the flywheel — post-hackathon it becomes online
GRPO with MonkeyClaw as the live RL environment.

## 8. Risks / guardrails

- **Scope:** this model is a component of an authorized agent-security testing
  harness — it generates structured test cases run against the project's own
  victim sandboxes. Keep that boundary: cyber model only in red-team lanes, all
  outputs logged, programmatic checks + cold repro remain the source of truth.
- **Don't optimize for "uncensored."** Optimize for: valid structured output +
  task-following + attacks the judge/repro pipeline actually confirms. An
  incoherent compliant model is worse than a refusing one.
- **Schema drift** is the #1 integration failure — every training example must
  match the live `IdeaObject` schema; re-check it before training.
- **24h risk:** if data takes longer than H9, cut synthetic volume and ship SFT
  on whatever clean data exists. A working small model > an unfinished one.

## 9. First actions in the new Brev + Claude Code session

1. `git pull` this repo; read `interfaces/types.py` (`IdeaObject`),
   `red_team/ideation.py`, `red_team/corpora/` (vendored ATLAS/OWASP).
2. Stand up the Brev env: GPU, vLLM, QLoRA trainer, Nemotron-3-Nano weights.
3. Build the data pipeline (section 2) — this is the long pole, start it first.
4. Then SFT -> eval -> serve -> wire in -> measure.
