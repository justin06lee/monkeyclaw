"""Person 3 — Repro + Blue Team + Regression.

Owns everything from "confirmed finding lands in the repro queue" to "patch
is verified and regression test is permanent."

Public surface for the orchestrator:

- `blue_team.pipeline.Pipeline` — orchestrator entrypoint (`BluePipeline`
  Protocol). Drives the repro queue, the blue team queue, and the regression
  suite from a single `Runtime`.

The only cross-directory dependency is `red_team.checks` — pure functions
that Person 2 published. Imported in `replay_minimizer` and `patch_verifier`
for Tier 1 evaluation of replayed transcripts.
"""

__all__: list[str] = []
