"""QLoRA SFT for the MonkeyClaw red-team ideation model.

Base : nvidia/NVIDIA-Nemotron-3-Nano-4B (hybrid Mamba-Transformer, BF16)
Method: 4-bit QLoRA (falls back to bf16 LoRA if bitsandbytes cannot quantize
        the hybrid arch), LoRA r=16 alpha=32 on all linear projections,
        completion-only loss, lr 2e-4 cosine, 2 epochs.
"""
from __future__ import annotations

import json
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (AutoConfig, AutoModelForCausalLM, AutoTokenizer,
                          BitsAndBytesConfig, Trainer, TrainingArguments)

BASE = "/home/shadeform/models/nemotron-3-nano-4b"
DATA = Path("/home/shadeform/rt/data")
ADAPTER_OUT = "/home/shadeform/models/nemotron-rt-adapter"
MERGED_OUT = "/home/shadeform/models/nemotron-rt-merged"
MAX_LEN = 3072

print(">> loading tokenizer")
tok = AutoTokenizer.from_pretrained(BASE)
# Native transformers nemotron_h class; force the torch Mamba path (no
# mamba-ssm CUDA kernels needed for finetuning).
CFG = AutoConfig.from_pretrained(BASE)
CFG.use_mamba_kernels = False
# The torch Mamba path materializes an O(chunk_size^2) intermediate; the
# stock 256 OOMs. chunk_size is a pure SSD tiling parameter (result is
# mathematically invariant), so shrink it to fit memory.
CFG.chunk_size = 64
if tok.pad_token is None:
    tok.pad_token = tok.unk_token

# --------------------------------------------------------------------------
# Tokenize: completion-only loss. Prompt = chat up to (and including) the
# assistant generation prompt; labels are masked over the common prefix.
# --------------------------------------------------------------------------
def build(path: Path) -> Dataset:
    rows = []
    too_long = 0
    for line in path.open():
        ex = json.loads(line)
        msgs = ex["messages"]
        prompt_text = tok.apply_chat_template(
            msgs[:-1], tokenize=False, add_generation_prompt=True,
            enable_thinking=False)
        full_text = tok.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=False,
            enable_thinking=False)
        if not full_text.startswith(prompt_text):
            # Boundary merge — fall back to prefix-by-tokens below anyway.
            pass
        p_ids = tok(prompt_text, add_special_tokens=False)["input_ids"]
        f_ids = tok(full_text, add_special_tokens=False)["input_ids"]
        # common token prefix length
        n = 0
        for a, b in zip(p_ids, f_ids):
            if a != b:
                break
            n += 1
        if len(f_ids) > MAX_LEN:
            too_long += 1
            f_ids = f_ids[:MAX_LEN]
        labels = [-100] * min(n, len(f_ids)) + f_ids[min(n, len(f_ids)):]
        if all(x == -100 for x in labels):
            continue
        rows.append({"input_ids": f_ids, "labels": labels,
                     "attention_mask": [1] * len(f_ids)})
    print(f"   {path.name}: {len(rows)} rows, {too_long} truncated")
    return Dataset.from_list(rows)


train_ds = build(DATA / "train_small.jsonl")
import numpy as np
lens = [len(r) for r in train_ds["input_ids"]]
print(f">> seq len: mean={np.mean(lens):.0f} p95={np.percentile(lens,95):.0f} "
      f"max={max(lens)}")

# --------------------------------------------------------------------------
# Model — try 4-bit QLoRA, fall back to bf16 LoRA.
# --------------------------------------------------------------------------
# bf16 LoRA — the 80GB A100 has ample headroom for a 4B model, so skip
# 4-bit (avoids bitsandbytes edge cases on the hybrid Mamba arch).
quant = False
print(">> loading base in bf16")
model = AutoModelForCausalLM.from_pretrained(
    BASE, config=CFG, torch_dtype=torch.bfloat16, device_map={"": 0})
model.gradient_checkpointing_enable()

model.config.use_cache = False
lora = LoraConfig(
    r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
    task_type="CAUSAL_LM", target_modules="all-linear")
model = get_peft_model(model, lora)
model.print_trainable_parameters()


def collate(batch):
    m = max(len(b["input_ids"]) for b in batch)
    pad = tok.pad_token_id
    ids, lbl, att = [], [], []
    for b in batch:
        d = m - len(b["input_ids"])
        ids.append(b["input_ids"] + [pad] * d)
        lbl.append(b["labels"] + [-100] * d)
        att.append(b["attention_mask"] + [0] * d)
    return {"input_ids": torch.tensor(ids), "labels": torch.tensor(lbl),
            "attention_mask": torch.tensor(att)}


args = TrainingArguments(
    output_dir="/home/shadeform/rt/ckpt",
    per_device_train_batch_size=2,
    gradient_accumulation_steps=8,
    num_train_epochs=2,
    learning_rate=2e-4,
    lr_scheduler_type="cosine",
    warmup_ratio=0.03,
    bf16=True,
    logging_steps=5,
    eval_strategy="no",
    save_strategy="no",
    report_to=[],
    gradient_checkpointing=True,
    gradient_checkpointing_kwargs={"use_reentrant": False},
    optim="paged_adamw_8bit" if quant else "adamw_torch",
)

trainer = Trainer(
    model=model, args=args, train_dataset=train_ds, data_collator=collate)
print(">> training")
trainer.train()

print(">> saving adapter")
model.save_pretrained(ADAPTER_OUT)
tok.save_pretrained(ADAPTER_OUT)

# --------------------------------------------------------------------------
# Merge adapter into bf16 base for vLLM serving.
# --------------------------------------------------------------------------
print(">> merging adapter into bf16 base")
del model, trainer
torch.cuda.empty_cache()
from peft import PeftModel
base = AutoModelForCausalLM.from_pretrained(
    BASE, config=CFG, torch_dtype=torch.bfloat16, device_map={"": 0})
merged = PeftModel.from_pretrained(base, ADAPTER_OUT)
merged = merged.merge_and_unload()
# native transformers/vLLM resolve nemotron_h by model_type — drop the
# remote-code pointer so no load path needs the repo's modeling file.
if getattr(merged.config, "auto_map", None):
    merged.config.auto_map = None
merged.config.use_mamba_kernels = True  # vLLM has its own mamba kernels
merged.save_pretrained(MERGED_OUT, safe_serialization=True)
tok.save_pretrained(MERGED_OUT)
import shutil
src = Path(BASE) / "chat_template.jinja"
if src.exists():
    shutil.copy(src, Path(MERGED_OUT) / "chat_template.jinja")
print(">> done. merged model at", MERGED_OUT)
