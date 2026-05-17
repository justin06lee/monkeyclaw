"""Manual LoRA merge — applies the trained adapter to the bf16 base by hand.

Bypasses peft's PeftModel.from_pretrained / transformers weight-conversion
path, which crashes on this peft<->transformers version pair.
"""
import json
import shutil
from pathlib import Path

import torch
from safetensors.torch import load_file
from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

BASE = "/home/shadeform/models/nemotron-3-nano-4b"
ADAPTER = "/home/shadeform/models/nemotron-rt-adapter"
MERGED = "/home/shadeform/models/nemotron-rt-merged"

cfg_a = json.loads((Path(ADAPTER) / "adapter_config.json").read_text())
r = cfg_a["r"]
alpha = cfg_a["lora_alpha"]
scaling = alpha / (r ** 0.5) if cfg_a.get("use_rslora") else alpha / r
print(f">> r={r} alpha={alpha} scaling={scaling}")

print(">> loading base bf16")
CFG = AutoConfig.from_pretrained(BASE)
CFG.use_mamba_kernels = True  # vLLM/native kernels at serve time
model = AutoModelForCausalLM.from_pretrained(
    BASE, config=CFG, torch_dtype=torch.bfloat16)
tok = AutoTokenizer.from_pretrained(BASE)

sd = load_file(str(Path(ADAPTER) / "adapter_model.safetensors"))
# pair lora_A / lora_B by their shared module path
pairs = {}
for k in sd:
    if ".lora_A." in k:
        pairs.setdefault(k.replace(".lora_A.", ".lora_B."), k)

base_sd = dict(model.named_parameters())
merged_n = 0
for kb, ka in pairs.items():
    A = sd[ka].float()                       # (r, in)
    B = sd[kb].float()                       # (out, r)
    # base_model.model.<path>.lora_A.weight -> <path>.weight
    path = ka.replace("base_model.model.", "").replace(".lora_A.weight", ".weight")
    if path not in base_sd:
        print(f"   !! no base weight for {path}")
        continue
    delta = (B @ A) * scaling                # (out, in)
    with torch.no_grad():
        base_sd[path] += delta.to(base_sd[path].dtype)
    merged_n += 1
print(f">> merged {merged_n} LoRA modules into base weights")

Path(MERGED).mkdir(parents=True, exist_ok=True)
if getattr(model.config, "auto_map", None):
    model.config.auto_map = None
# transformers 5.x rejects top_p without do_sample on save
try:
    model.generation_config.do_sample = True
except Exception:
    pass
model.save_pretrained(MERGED, safe_serialization=True)
tok.save_pretrained(MERGED)
src = Path(BASE) / "chat_template.jinja"
if src.exists():
    shutil.copy(src, Path(MERGED) / "chat_template.jinja")
print(">> merged model saved to", MERGED)
