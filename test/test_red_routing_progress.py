"""B8 — routing with progress scores + the MAP-Elites archive.

Verifies the four routing rules: confirmed / suspicious / clean-near-miss /
clean-no-progress, and that every judged attempt maps into the archive.
"""

from __future__ import annotations

import json

from infra.mock_mcp import MockMCP
from interfaces.types import CheckResult, IdeaObject, JudgmentResult
from red_team.archive import EliteArchive
from red_team.ideation import IdeaTactics
from red_team.progress import ProgressScore, search_score
from red_team.routing import NEAR_MISS_THRESHOLD, route_judgment


def _idea(zone: str = "SBX-FS", style: str = "multi_turn") -> IdeaObject:
    idea = IdeaObject(
        idea_id="IDEA-1", cycle_id=1, zone_id=zone, source_mode="creative",
        title="t", approach="a", success_criteria="s", estimated_turns=2,
        novelty_notes="")
    idea.tactics = IdeaTactics(interaction_style=style, tactic_tags=["x"])
    return idea


def _judgment(verdict: str, *, zone: str = "SBX-FS", severity: str = "high",
              tier: str = "programmatic") -> JudgmentResult:
    return JudgmentResult(
        lane_id="LANE-1", idea_id="IDEA-1", zone_id=zone, verdict=verdict,
        tier_that_caught=tier, failure_class="sandbox_escape",
        severity=severity, confidence=0.9,
        evidence=[CheckResult("c", verdict != "clean", severity, {})],
        reasoning="r", tokens_used_judgment=10, timestamp="t")


def _progress(**kw) -> ProgressScore:
    base = dict(
        risk_stage=0, progress_delta=0, refusal_strength=0, specificity=0,
        boundary_erosion=0, steerability=0, novelty=0, transfer_likelihood=0,
        robustness=0, turn_cost=0, token_cost=0, failure_mode="clean",
        useful_components=[], mutation_suggestions=[])
    base.update(kw)
    return ProgressScore(**base)


class _SpyMCP(MockMCP):
    """MockMCP that records repro pushes, alerts, and logged findings."""

    def __init__(self):
        super().__init__(seed=0, verbose=False)
        self.repro_pushes: list[tuple[str, str]] = []
        self.alerts: list[tuple[str, str]] = []
        self.findings: list = []

    def push_to_repro_queue(self, finding_id, priority):
        self.repro_pushes.append((finding_id, priority))
        return super().push_to_repro_queue(finding_id, priority)

    def send_alert(self, message, severity):
        self.alerts.append((message, severity))
        return super().send_alert(message, severity)

    def log_finding(self, finding):
        self.findings.append(finding)
        return super().log_finding(finding)


# ---------------------------------------------------------------------------


def test_confirmed_routes_high_repro_and_archives():
    mcp = _SpyMCP()
    archive = EliteArchive()
    fid = route_judgment(
        _judgment("confirmed"), _idea(), mcp,
        progress=_progress(risk_stage=5, failure_mode="programmatic_violation"),
        archive=archive, alert_severity_floor="high")
    assert (fid, "high") in mcp.repro_pushes
    assert mcp.alerts                       # critical/high cleared the floor
    assert archive.cell_count() == 1        # mapped into a MAP-Elites cell


def test_suspicious_stores_progress_score_and_low_repro():
    mcp = _SpyMCP()
    fid = route_judgment(
        _judgment("suspicious", severity="medium", tier="semantic"),
        _idea(), mcp,
        progress=_progress(risk_stage=3, progress_delta=2, steerability=2),
        archive=EliteArchive())
    assert mcp.repro_pushes == [(fid, "low")]
    # The progress score is persisted on the finding's evidence JSON.
    evidence = json.loads(mcp.findings[-1].evidence)
    assert any(item.get("check_name") == "progress_score" for item in evidence)


def test_clean_near_miss_is_archived_without_repro():
    mcp = _SpyMCP()
    archive = EliteArchive()
    prog = _progress(risk_stage=3, progress_delta=2, steerability=3, novelty=2,
                     failure_mode="partial_compliance", turn_cost=3)
    assert search_score(prog) >= NEAR_MISS_THRESHOLD   # genuinely a near-miss
    route_judgment(_judgment("clean", severity="low", tier="none"),
                   _idea(), mcp, progress=prog, archive=archive)
    assert mcp.repro_pushes == []           # clean never pushes repro
    assert archive.cell_count() == 1        # but the near-miss is preserved


def test_clean_no_progress_logs_summary_only():
    mcp = _SpyMCP()
    route_judgment(
        _judgment("clean", severity="low", tier="none"), _idea(), mcp,
        progress=_progress(refusal_strength=5, failure_mode="hard_refusal"),
        archive=EliteArchive())
    assert mcp.repro_pushes == []
    assert mcp.alerts == []
    assert len(mcp.findings) == 1


def test_every_attempt_maps_to_a_distinct_archive_cell():
    mcp = _SpyMCP()
    archive = EliteArchive()
    route_judgment(_judgment("confirmed"), _idea(style="direct"), mcp,
                   progress=_progress(risk_stage=5,
                                      failure_mode="programmatic_violation"),
                   archive=archive)
    route_judgment(_judgment("clean", tier="none"),
                   _idea(style="multi_turn"), mcp,
                   progress=_progress(risk_stage=2,
                                      failure_mode="partial_compliance"),
                   archive=archive)
    # Distinct interaction-style niches -> two cells, neither erased.
    assert archive.cell_count() == 2
