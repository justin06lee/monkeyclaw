"""OpenAI-compatible inference server for the finetuned red-team model.

Backed by transformers (native nemotron_h, torch Mamba path). vLLM 0.21 is
installed but compiled for CUDA 13; this box's driver is 12.8, so we serve
with transformers instead. Exposes /v1/chat/completions and /v1/models so
MonkeyClaw's NVIDIA/OpenAI provider can route the `red_ideation` role here.

  python rt/serve.py --model /home/shadeform/models/nemotron-rt-merged --port 8000
"""
from __future__ import annotations

import argparse
import time
import uuid

import torch
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="/home/shadeform/models/nemotron-rt-merged")
ap.add_argument("--port", type=int, default=8000)
ap.add_argument("--served-name", default="nemotron-rt")
ARGS = ap.parse_args()

print(f">> loading {ARGS.model}")
CFG = AutoConfig.from_pretrained(ARGS.model)
CFG.use_mamba_kernels = False
CFG.chunk_size = 64  # torch Mamba path — keep the O(chunk^2) tensor small
TOK = AutoTokenizer.from_pretrained(ARGS.model)
MODEL = AutoModelForCausalLM.from_pretrained(
    ARGS.model, config=CFG, torch_dtype=torch.bfloat16, device_map={"": 0})
MODEL.eval()
EOS = TOK.convert_tokens_to_ids("<|im_end|>")
print(">> ready")

app = FastAPI()


class ChatReq(BaseModel):
    model: str | None = None
    messages: list[dict]
    temperature: float = 0.7
    max_tokens: int = 2048
    top_p: float = 0.95
    chat_template_kwargs: dict | None = None


@app.get("/v1/models")
def models():
    return {"object": "list", "data": [
        {"id": ARGS.served_name, "object": "model", "owned_by": "monkeyclaw"}]}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat/completions")
def chat(req: ChatReq):
    ctk = req.chat_template_kwargs or {}
    enable_thinking = bool(ctk.get("enable_thinking", False))
    prompt = TOK.apply_chat_template(
        req.messages, tokenize=False, add_generation_prompt=True,
        enable_thinking=enable_thinking)
    ids = TOK(prompt, return_tensors="pt", add_special_tokens=False).to(MODEL.device)
    do_sample = req.temperature and req.temperature > 0
    with torch.no_grad():
        out = MODEL.generate(
            **ids, max_new_tokens=req.max_tokens, do_sample=do_sample,
            temperature=req.temperature if do_sample else None,
            top_p=req.top_p if do_sample else None,
            repetition_penalty=1.15,  # break degenerate JSON repetition loops
            eos_token_id=EOS, pad_token_id=TOK.pad_token_id or 0)
    gen = out[0][ids["input_ids"].shape[1]:]
    text = TOK.decode(gen, skip_special_tokens=True).strip()
    p, c = ids["input_ids"].shape[1], gen.shape[0]
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model or ARGS.served_name,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": "stop"}],
        "usage": {"prompt_tokens": p, "completion_tokens": int(c),
                  "total_tokens": p + int(c)},
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=ARGS.port, log_level="warning")
