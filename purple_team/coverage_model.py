"""coverage_model — purple-team spec §7.2.

Maintains DETECTION coverage per zone: a 0..1 score answering "when we
attack this zone, does the defense reliably see and decide?" This is a
second axis alongside the existing attack-coverage score on surface_zones.
Produces the joint heatmap (attack coverage x detection coverage).

Detection-coverage credit: an execution counts as "detected" when its
quadrant is observed (PASS or PARTIAL). WEAK and FAIL are silent and
score zero. The running score is observed_samples / total_samples.
"""

from __future__ import annotations

from datetime import UTC, datetime

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import DetectionCoverage, DetectionVerdict, ZoneCoverage

# Quadrants where the defense observed the execution.
_OBSERVED_QUADRANTS = {"PASS", "PARTIAL"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class CoverageModel:
    """Detection-coverage tracking + the joint heatmap."""

    def __init__(self, mcp: MonkeyClawMCP) -> None:
        self.mcp = mcp

    def update(self, zone_id: str, verdicts: list[DetectionVerdict]) -> None:
        """Fold new verdicts into the zone's running detection coverage."""
        if not verdicts:
            return
        prior = self.mcp.get_detection_coverage(zone_id)
        prior_observed = (
            round(prior.coverage_score * prior.sample_count)
            if prior else 0
        )
        prior_total = prior.sample_count if prior else 0
        new_observed = sum(
            1 for v in verdicts if v.quadrant in _OBSERVED_QUADRANTS)
        total = prior_total + len(verdicts)
        observed = prior_observed + new_observed
        self.mcp.upsert_detection_coverage(DetectionCoverage(
            zone_id=zone_id,
            coverage_score=observed / total if total else 0.0,
            sample_count=total,
            updated_at=_now(),
        ))

    def coverage(self, zone_id: str) -> DetectionCoverage:
        """The zone's detection coverage; a zeroed row if never updated."""
        cov = self.mcp.get_detection_coverage(zone_id)
        if cov is None:
            return DetectionCoverage(
                zone_id=zone_id, coverage_score=0.0,
                sample_count=0, updated_at=_now())
        return cov

    def heatmap(self) -> list[ZoneCoverage]:
        """The joint attack-coverage x detection-coverage heatmap, one
        cell per registered zone."""
        cells: list[ZoneCoverage] = []
        for gap in self.mcp.get_coverage_gaps(top_n=999):
            cov = self.mcp.get_detection_coverage(gap.zone_id)
            cells.append(ZoneCoverage(
                zone_id=gap.zone_id,
                zone_name=gap.zone_name,
                attack_coverage=gap.coverage_score,
                detection_coverage=cov.coverage_score if cov else 0.0,
                detection_samples=cov.sample_count if cov else 0,
            ))
        return cells


__all__ = ["CoverageModel"]
