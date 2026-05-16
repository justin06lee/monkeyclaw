# MonkeyClaw demo

This directory holds the one-command hackathon demo (spec C10).

## Files

| File | Purpose |
|------|---------|
| `run_hackathon_demo.sh` | One-command demo runner. Live mode runs a real red-team cycle + blue-team pipeline; `--seeded` mode serves a checked-in fixture. |
| `build_seed_db.sh` | Regenerates the pre-seeded fallback fixture (`fixtures/seed.db`). |
| `fixtures/seed.db` | Pre-seeded database fixture for the backup demo — a real pipeline run captured to disk. |
| `victims/` | Planted-vulnerability victims — OpenClaw-agent-shaped targets with known flaws the pipeline exercises. |

## Running the demo

### Live mode (default)

```bash
demo/run_hackathon_demo.sh
```

This runs one full pipeline cycle against a planted-vulnerability victim
using the in-memory mock provisioner (no live NemoClaw target or model
credentials required), runs the blue-team pipeline, then serves the
dashboard at <http://127.0.0.1:8787>.

Every dashboard panel is populated by this real pipeline run.

### Pre-seeded fallback mode

```bash
demo/run_hackathon_demo.sh --seeded
```

If a live run fails on stage, this is the backup: it skips the pipeline
and serves the dashboard against `fixtures/seed.db`, a committed database
fixture captured from a real pipeline run. No live target, model
credentials, or pipeline execution required.

Regenerate the fixture whenever the schema or demo pipeline changes:

```bash
demo/build_seed_db.sh
```

## What the judge sees

After the run, all eight dashboard views have content: confirmed and
suspicious findings, cold-verified repro packages, patch candidates,
regression tests, and the alert stream. See `docs/demo_script.md` for
the guided walkthrough and `docs/judge_quickstart.md` for the shortest
path.
