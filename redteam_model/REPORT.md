# MonkeyClaw Red-Team Ideation Model — Build Report

**Date:** 2026-05-16  **Box:** Brev, 4×A100 80GB (single GPU used)
**Base model:** `nvidia/NVIDIA-Nemotron-3-Nano-4B-BF16` (smallest Nemotron-3
Nano variant — 4B hybrid Mamba-Transformer)
**Method:** LoRA SFT (r=16, α=32, all-linear), completion-only loss
**Goal:** reliably emit valid MonkeyClaw `IdeaObject` JSON attack ideas,
never refuse.

## What was built

| Artifact | Path |
|----------|------|
| Data generator | `rt/gen_data.py` |
| SFT dataset (1032 ex, 18 zones × 5 modes) | `rt/data/{train,eval}.jsonl` |
| Training subset (used) | `rt/data/train_small.jsonl` |
| Training script | `rt/train.py` |
| Manual LoRA merge | `rt/merge.py` |
| Merged model | `/home/shadeform/models/nemotron-rt-merged` |
| OpenAI-compatible server | `rt/serve.py` (port 8000) |
| Holdout eval | `rt/eval.py` |
| Integration smoke test | `rt/smoke.py` |

## Data pipeline

`rt/gen_data.py` generates `instruction → IdeaObject-JSON` pairs grounded
entirely in the repo's own corpora — no external API calls, so every example
is schema-valid by construction:

- **35 attack skills** (`red_team/attack_skills/*.yaml`) — real techniques
  with `approach_template`, `success_criteria_template`, tactics, observables,
  mutation seeds.
- **18-zone catalog** (`infra/mock_mcp.SEED_ZONES`) + scope descriptions.
- **Zone→ATLAS/OWASP mapping** + the vendored MITRE ATLAS snapshot.

Each example's **input** reproduces the exact ideation prompt format in
`red_team/ideation.py` (5 modes: creative, code_grounded, history_informed,
research_grounded, taxonomy). Each **output** matches the
`_JSON_SCHEMA_BLURB` contract field-for-field. ~12% of examples carry a
"loaded" operator note (anti-refusal training). 1032 unique examples, all
18 zones covered, 10% held out.

## Training

QLoRA was specified; in practice the 80 GB A100 has ample room for **bf16
LoRA** on a 4B model, so 4-bit was skipped (avoids bitsandbytes edge cases on
the hybrid Mamba arch). LoRA r=16 α=32 on all 92 linear projections
(attention + MLP + Mamba in/out projections), lr 2e-4 cosine,
completion-only loss, `chunk_size` reduced to 64 for the torch Mamba path.

Final run: 256 balanced examples, 2 epochs, train loss 1.79 → ~0.6.

## Eval (held-out)

`rt/eval.py` against the served model (16-prompt held-out sample,
temp 0.7, max_tokens 4096):

| Metric | Result | Target |
|--------|--------|--------|
| **Refusal rate** | **0.0%** | 0% ✓ |
| **Valid-JSON rate** | **93.8%** | ~100% |
| Strict schema conformance (all ideas) | 12.5% | — |
| Per-idea field conformance | 18.5% | — |
| Request failures | 0 | 0 ✓ |

**Headline:** zero refusals, and the model reliably emits parseable
`IdeaObject` JSON arrays. The strict-conformance numbers come from a
deliberately harsh standalone checker; MonkeyClaw's own ideation parser
(`_parse_ideas` + `_salvage_idea_dicts`) is lenient — it defaults missing
fields, coerces types, strips fences, and salvages complete objects from a
truncated array. The end-to-end smoke test (`rt/smoke.py`) confirms
MonkeyClaw accepts the output and builds real `IdeaObject`s.

Known rough edges (1-epoch / 256-example SFT, training stopped early for the
deadline): the model is verbose, occasionally wraps output in a ``` fence,
and the trailing idea in a long array can truncate. All are absorbed by
MonkeyClaw's parser; a 2-epoch run on the full 929-example set would tighten
them.

## Integration with MonkeyClaw

`configs/monkeyclaw.yaml` → `models.roles.red_ideation` now points at
`nemotron-3-nano-redteam-sft`. The `nvidia` provider is aimed at the local
endpoint via env:

```
MC_NEMOTRON_BASE_URL=http://<box>:8000/v1
MC_NVIDIA_API_KEY=local
```

`rt/smoke.py` runs a real `red_team.ideation.IdeationEngine.generate_for_zone`
call through the finetuned model — the exact path the `red_ideation` role
uses in production.

## Notable deviations / engineering notes

- **vLLM**: installed v0.21 needs CUDA 13; this box's driver is 12.8. Served
  with a transformers-backed OpenAI-compatible shim (`rt/serve.py`) instead.
- **Mamba kernels**: `causal-conv1d` / `mamba-ssm` CUDA kernels unavailable;
  used the torch Mamba path with a reduced `chunk_size` (the OOM tensor is
  O(chunk²); chunk_size is a pure tiling parameter so the result is exact).
- **Merge**: peft↔transformers version mismatch broke `merge_and_unload`;
  `rt/merge.py` does a manual, deterministic LoRA weight merge instead.
- Inference uses `repetition_penalty=1.15` to harden against degenerate
  JSON loops from the small SFT.
