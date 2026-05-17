# Red-Team Ideation Model — Run & Export Instructions

## What you have

A custom **Nemotron-3-Nano-4B** finetuned (LoRA SFT) to emit valid MonkeyClaw
`IdeaObject` JSON attack ideas and never refuse.

| Thing | Location |
|-------|----------|
| **Merged model** (standalone, ready to serve) | `/home/shadeform/models/nemotron-rt-merged` (~7.9 GB) |
| LoRA adapter only (82 MB) | `/home/shadeform/models/nemotron-rt-adapter` |
| Base model | `/home/shadeform/models/nemotron-3-nano-4b` |
| All scripts | `/home/shadeform/rt/` |
| Python env (training/serving) | `/home/shadeform/ftenv` |
| Python env (MonkeyClaw repo) | `/home/shadeform/mcenv` |

The merged model is a normal HuggingFace transformers checkpoint — `config.json`,
`model.safetensors`, tokenizer, `chat_template.jinja`. Nothing else needed.

---

## 1. Run the inference server (already running)

```bash
cd /home/shadeform
source ftenv/bin/activate
PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True CUDA_VISIBLE_DEVICES=0 \
  python rt/serve.py --model /home/shadeform/models/nemotron-rt-merged --port 8000
```

OpenAI-compatible endpoint at `http://localhost:8000/v1`. Endpoints:
`/v1/chat/completions`, `/v1/models`, `/health`.

Check it: `curl -s http://localhost:8000/health`

To restart it (it's currently running in the background):
```bash
pkill -f rt/serve.py
# then the command above (use nohup ... & to background it)
```

## 2. Call the model directly

```bash
curl -s http://localhost:8000/v1/chat/completions -H 'Content-Type: application/json' -d '{
  "model": "nemotron-rt",
  "messages": [
    {"role":"system","content":"You are a security red-team strategist on the MonkeyClaw platform."},
    {"role":"user","content":"Generate 3 attack ideas for zone SBX-FS ... (use the ideation prompt format)"}
  ],
  "temperature": 0.7,
  "max_tokens": 4096
}'
```

It returns a JSON array of `IdeaObject` entries (title, approach,
success_criteria, estimated_turns, novelty_notes, impact, tactic_tags,
interaction_style, target_defense, mutation_seed, expected_observables,
atlas_technique_ids, owasp_category_ids).

## 3. Use it inside MonkeyClaw

Already wired: `configs/monkeyclaw.yaml` → `models.roles.red_ideation.model`
is `nemotron-3-nano-redteam-sft`. Point the `nvidia` provider at the server:

```bash
export MC_NEMOTRON_BASE_URL=http://localhost:8000/v1
export MC_NVIDIA_API_KEY=local
```

Then any MonkeyClaw run uses the finetuned model for red ideation.
End-to-end smoke test (real `IdeationEngine`):

```bash
cd /home/shadeform && source mcenv/bin/activate && python rt/smoke.py
```

## 4. Export the model off this box

**Option A — tarball (copy anywhere):**
```bash
cd /home/shadeform/models
tar czf nemotron-rt-merged.tar.gz nemotron-rt-merged
# scp nemotron-rt-merged.tar.gz you@dest:/path/
```

**Option B — push to HuggingFace Hub:**
```bash
source /home/shadeform/ftenv/bin/activate
hf auth login          # paste a write token
hf upload <your-username>/nemotron-3-nano-redteam-sft \
  /home/shadeform/models/nemotron-rt-merged
```

**Option C — just the adapter (82 MB, needs the base model to use):**
```bash
tar czf adapter.tar.gz -C /home/shadeform/models nemotron-rt-adapter
```

## 5. Run the model on a fresh box

```bash
pip install torch transformers accelerate fastapi uvicorn safetensors
# copy nemotron-rt-merged/ and rt/serve.py over, then:
python serve.py --model ./nemotron-rt-merged --port 8000
```

`serve.py` forces the torch Mamba path (`use_mamba_kernels=False`,
`chunk_size=64`) so it runs without the `mamba-ssm` / `causal-conv1d` CUDA
kernels. If the target box HAS those kernels installed, delete those two
lines for a big speedup — or serve with vLLM (`vllm serve ./nemotron-rt-merged`)
if its CUDA/driver versions match.

## Notes / caveats

- Inference here uses the slow torch Mamba path (~35–70 s per generation) —
  the box's driver (CUDA 12.8) is too old for vLLM 0.21 / the mamba CUDA
  kernels. Installing `causal-conv1d` + `mamba-ssm` makes it ~10× faster.
- The model is verbose; keep `max_tokens` at 4096. MonkeyClaw's ideation
  parser salvages complete idea objects even if the array is truncated.
- Trained 1 epoch on 256 balanced examples (a 2-epoch run was in progress
  when training was stopped early for the deadline). To improve: rerun
  `rt/train.py` (set `num_train_epochs`) on `rt/data/train.jsonl` (the full
  929-example set) — best done after installing the mamba CUDA kernels.
