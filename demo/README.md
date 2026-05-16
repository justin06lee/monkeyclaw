# MonkeyClaw demo

This directory holds the one-command hackathon demo (spec C10).

## Files

| File | Purpose |
|------|---------|
| `run_hackathon_demo.sh` | One-command demo runner. Runs a real red-team cycle, the blue-team pipeline, then opens the dashboard. |
| `victims/` | Planted-vulnerability victims — OpenClaw-agent-shaped targets with known flaws the pipeline exercises, plus `registry.py` mapping profile names to victim classes. |
| `attacks/` | YAML attack playbooks (deterministic, scripted turns) and the policy corpus the red team can replay without a model. |

## Running the demo

```bash
demo/run_hackathon_demo.sh
```

This runs one full pipeline cycle against a planted-vulnerability victim
using the in-memory mock provisioner (no live NemoClaw target or model
credentials required), runs the blue-team pipeline, then serves the
dashboard at <http://127.0.0.1:8787>.

Every dashboard panel is populated by this real pipeline run — there is
no fabricated or pre-seeded data.

## What the judge sees

After the run, all eight dashboard views have content: confirmed and
suspicious findings, cold-verified repro packages, patch candidates,
regression tests, and the alert stream. See `docs/demo_script.md` for
the guided walkthrough and `docs/judge_quickstart.md` for the shortest
path.
