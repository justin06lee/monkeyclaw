# Judge quickstart

The shortest path to seeing MonkeyClaw work. No model credentials, no
network, ~30 seconds.

## 1. Install dependencies

```bash
uv sync
```

## 2. Run the fallback demo

```bash
demo/run_hackathon_demo.sh
```

This seeds a pre-built knowledge base and starts the dashboard. Open
the printed URL (default <http://127.0.0.1:8787>).

That is the whole demo. Everything below is optional.

## Optional — drive it from the CLI

```bash
uv run python demo/seed_demo_db.py     # (re)build the demo DB
uv run monkeyclaw status               # coverage + findings summary
uv run monkeyclaw findings             # list confirmed/suspicious vulns
uv run monkeyclaw dashboard            # live web dashboard
```

## Optional — run it live

Needs an NVIDIA API key for the Nemotron backend:

```bash
export NVIDIA_API_KEY=...
demo/run_hackathon_demo.sh live
```

Live mode runs one real red-team cycle, the blue-team pipeline, then
the dashboard. Without the key the runner falls back to the seeded DB
automatically.

## What to look for

The dashboard shows the full red-to-blue lifecycle on one page:

1. **Overview** — cycles, confirmed/suspicious findings, patch counts,
   regression pass rate, mean coverage.
2. **Coverage heatmap** — all 18 attack zones, red (untested) to green
   (covered).
3. **Finding timeline** — each finding from idea -> verdict -> repro ->
   patch.
4. **Repro packages** — minimal steps, repro rate, cold-verifier status.
5. **Blue team** — patch candidates and regression tests.
6. **Evidence timeline** — triggered Tier 1 checks and alerts.
7. **Search intelligence** — ideation cells, source modes, judge tiers.
8. **Cost / model stats** — tokens and estimated cost.

## Verify the test suite

```bash
uv run pytest -q
```

All tests should pass.
