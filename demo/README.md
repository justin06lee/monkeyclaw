# MonkeyClaw demo

This directory makes the MonkeyClaw demo robust even when live model
APIs or a live NemoClaw target are unavailable (spec C10).

## Files

| File | Purpose |
|------|---------|
| `seed_demo_db.py` | Builds a fully-populated knowledge base — cycles, findings, repro packages, patches, regression tests, alerts. Findings are drawn from the General Analysis "Securing Coding Agents" adversarial corpus and detection catalog, mapped onto MonkeyClaw's 18 attack zones. |
| `run_hackathon_demo.sh` | One-command demo runner. Seeds the DB (or runs a live cycle) and opens the dashboard. |

## Two modes

### Fallback mode — no credentials required

```bash
demo/run_hackathon_demo.sh
# equivalently:
uv run python demo/seed_demo_db.py
uv run monkeyclaw dashboard
```

The seed script wipes and rebuilds `data/monkeyclaw.db`, then the
dashboard serves the full red-to-blue lifecycle at
<http://127.0.0.1:8787>. This path always works — it needs no API key
and no network.

### Live mode — needs `NVIDIA_API_KEY`

```bash
export NVIDIA_API_KEY=...
demo/run_hackathon_demo.sh live
```

Live mode runs one real red-team cycle with the mock provisioner, runs
the blue-team pipeline, then opens the dashboard. If `NVIDIA_API_KEY`
is not set, the runner automatically degrades to fallback mode.

## Re-running

`seed_demo_db.py` is idempotent — every run deletes and recreates the
DB, so the demo state is deterministic. Pass `--db PATH` to seed a
different location.

## What the judge sees

The seeded DB is designed so all eight dashboard views have content:
confirmed and suspicious findings, cold-verified repro packages,
approved and rejected patches, passing and failing regression tests,
and a critical-severity alert stream. See `docs/demo_script.md` for the
guided walkthrough and `docs/judge_quickstart.md` for the shortest path.
