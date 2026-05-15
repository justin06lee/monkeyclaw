"""Person 2 — Red Team Pipeline.

Owns everything from "generate an attack idea" to "verdict: confirmed/clean."

Public surface for the orchestrator and for Person 3:

- `red_team.pipeline.Pipeline`        — orchestrator entrypoint (RedTeamPipeline Protocol)
- `red_team.checks.run_all_tier1_checks` + the 6 individual check functions
  — cross-person dependency Person 3 imports for replay verification and
  patch testing.

Everything else is internal to this directory.
"""
