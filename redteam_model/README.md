# Red-Team Ideation Model

A custom **Nemotron-3-Nano-4B** finetuned (LoRA SFT) to reliably emit valid
MonkeyClaw `IdeaObject` JSON attack ideas and never refuse — the
`red_ideation` model role.

- **REPORT.md** — full build report (data, training, eval, deviations)
- **INSTRUCTIONS.md** — run / call / export / redeploy
- **gen_data.py** — synthetic SFT data generator (grounded in `red_team/attack_skills/`)
- **train.py** — LoRA SFT trainer · **merge.py** — adapter merge
- **serve.py** — OpenAI-compatible inference server
- **eval.py** — held-out evaluator · **smoke.py** — MonkeyClaw integration test
- **data/** — SFT train/eval splits · **logs/** — training + eval logs

Merged model weights (~7.5 GB) are NOT in git — see INSTRUCTIONS.md to
rebuild or download. Headline eval: **0% refusals, 93.8% valid JSON**.
