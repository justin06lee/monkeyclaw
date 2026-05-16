"""Phase 1 — coverage_model maintains detection coverage per zone."""

from __future__ import annotations

from interfaces.types import DetectionVerdict
from purple_team.coverage_model import CoverageModel


def _verdict(zone: str, quadrant: str) -> DetectionVerdict:
    prevention = "blocked" if quadrant in ("PASS", "WEAK") else "succeeded"
    observability = "observed" if quadrant in ("PASS", "PARTIAL") else "silent"
    return DetectionVerdict(
        execution_id="L1", session_id="L1", zone_id=zone, quadrant=quadrant,
        prevention=prevention, observability=observability,
        rule_id=None, evidence="{}")


def test_all_pass_yields_full_detection_coverage(server):
    model = CoverageModel(server)
    model.update("SBX-FS", [_verdict("SBX-FS", "PASS"),
                            _verdict("SBX-FS", "PASS")])
    cov = model.coverage("SBX-FS")
    assert cov.coverage_score == 1.0
    assert cov.sample_count == 2


def test_all_fail_yields_zero_detection_coverage(server):
    model = CoverageModel(server)
    model.update("SBX-NET", [_verdict("SBX-NET", "FAIL")])
    assert model.coverage("SBX-NET").coverage_score == 0.0


def test_partial_observed_counts_toward_detection(server):
    # PARTIAL = detection fired (observed) even though prevention failed.
    model = CoverageModel(server)
    model.update("PROMPT-INJ", [_verdict("PROMPT-INJ", "PARTIAL"),
                                _verdict("PROMPT-INJ", "FAIL")])
    # one of two executions was observed -> 0.5
    assert model.coverage("PROMPT-INJ").coverage_score == 0.5


def test_update_is_cumulative_across_calls(server):
    model = CoverageModel(server)
    model.update("SBX-FS", [_verdict("SBX-FS", "PASS")])
    model.update("SBX-FS", [_verdict("SBX-FS", "FAIL")])
    cov = model.coverage("SBX-FS")
    assert cov.sample_count == 2
    assert cov.coverage_score == 0.5


def test_coverage_unknown_zone_is_zero(server):
    model = CoverageModel(server)
    cov = model.coverage("NEVER-TOUCHED")
    assert cov.coverage_score == 0.0
    assert cov.sample_count == 0


def test_heatmap_joins_attack_and_detection_coverage(server):
    model = CoverageModel(server)
    model.update("SBX-FS", [_verdict("SBX-FS", "PASS")])
    cells = model.heatmap()
    fs = next(c for c in cells if c.zone_id == "SBX-FS")
    assert fs.detection_coverage == 1.0
    assert 0.0 <= fs.attack_coverage <= 1.0
    assert fs.zone_name  # populated from surface_zones
