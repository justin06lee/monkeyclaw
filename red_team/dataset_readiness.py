"""The dataset-readiness gate (learned-ranking-model spec §8).

Training does not begin until all five measured criteria hold. The gate is
shared by scripts/train_ranker.py (which aborts if it fails) and the
dashboard (which surfaces the gate state so the operator knows when training
is viable).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from interfaces.types import AttemptTrace, Preference

# The five thresholds, straight from spec §8.
MIN_TRACES = 800              # non-pending repro_outcome rows
MIN_ZONES = 12                # of the 18 zones
MIN_VERDICT_FRACTION = 0.10   # each judge_verdict class
MIN_PAIRWISE = 300            # pairwise_labels rows
MIN_FAILURE_MODES = 4         # failure modes with >= MIN_PER_FAILURE_MODE rows
MIN_PER_FAILURE_MODE = 30
FEATURE_STABLE_WINDOW = 300   # most-recent rows that must share one version


@dataclass
class GateResult:
    """The outcome of the readiness gate — ready, plus any failing criteria."""

    ready: bool
    failures: list[str] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)


def _failure_mode(trace: AttemptTrace) -> str:
    return str(trace.progress_dims.get("failure_mode_key", "")) \
        or trace.archive_niche.split("|")[-1]


def evaluate_readiness(
    traces: list[AttemptTrace], pairs: list[Preference]
) -> GateResult:
    """Check all five criteria; never raises (spec §8)."""
    failures: list[str] = []
    metrics: dict[str, float] = {}

    # 1 — volume: non-pending repro outcomes.
    settled = [t for t in traces if t.repro_outcome != "pending"]
    metrics["settled_traces"] = len(settled)
    if len(settled) < MIN_TRACES:
        failures.append(
            f"volume: {len(settled)} settled traces < {MIN_TRACES}")

    # 2 — label balance: verdict spread + zone spread.
    zones = {t.zone_id for t in settled}
    metrics["zones"] = len(zones)
    if len(zones) < MIN_ZONES:
        failures.append(f"zone spread: {len(zones)} zones < {MIN_ZONES}")
    if settled:
        for verdict in ("confirmed", "suspicious", "clean"):
            frac = sum(1 for t in settled
                       if t.judge_verdict == verdict) / len(settled)
            if frac < MIN_VERDICT_FRACTION:
                failures.append(
                    f"label balance: '{verdict}' is {frac:.0%} "
                    f"< {MIN_VERDICT_FRACTION:.0%}")

    # 3 — failure-mode spread.
    mode_counts: dict[str, int] = {}
    for t in settled:
        mode_counts[_failure_mode(t)] = mode_counts.get(_failure_mode(t), 0) + 1
    well_covered = sum(1 for c in mode_counts.values()
                       if c >= MIN_PER_FAILURE_MODE)
    metrics["failure_modes_covered"] = well_covered
    if well_covered < MIN_FAILURE_MODES:
        failures.append(
            f"failure-mode spread: {well_covered} modes with "
            f">={MIN_PER_FAILURE_MODE} rows < {MIN_FAILURE_MODES}")

    # 4 — pairwise coverage.
    metrics["pairwise_labels"] = len(pairs)
    if len(pairs) < MIN_PAIRWISE:
        failures.append(
            f"pairwise coverage: {len(pairs)} labels < {MIN_PAIRWISE}")

    # 5 — feature stability: most-recent rows share one feature version.
    recent = sorted(traces, key=lambda t: t.created_at,
                    reverse=True)[:FEATURE_STABLE_WINDOW]
    if recent and len({t.feature_schema_version for t in recent}) > 1:
        failures.append(
            "feature stability: feature_schema_version changed within the "
            f"most recent {FEATURE_STABLE_WINDOW} traces")

    return GateResult(ready=not failures, failures=failures, metrics=metrics)


__all__ = [
    "GateResult",
    "MIN_PAIRWISE",
    "MIN_TRACES",
    "MIN_ZONES",
    "evaluate_readiness",
]
