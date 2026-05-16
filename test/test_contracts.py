"""Verify the interface contracts hold: every method exists, types import,
mock and real MCP both conform to the Protocol."""

from __future__ import annotations

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.provisioning import VictimProvisioner
from interfaces.types import (
    CoverageGap,
    DupResult,
    IdeaObject,
    JudgmentResult,
    LaneResult,
)


def test_types_importable():
    """Smoke-construct every dataclass to catch field-rename breaks early."""
    iobj = IdeaObject(idea_id="x", cycle_id=0, zone_id="PROMPT-INJ",
                      source_mode="creative", title="t", approach="a",
                      success_criteria="s", estimated_turns=1, novelty_notes="n")
    assert iobj.priority_score == 0.0
    gap = CoverageGap(zone_id="x", zone_name="X", coverage_score=0.1,
                      priority_score=0.9, vulns_open=0, last_tested_at=None)
    assert gap.severity_weight == 1.0
    dup = DupResult(False, 0.0, None)
    assert dup.matching_idea_id is None


def test_mcp_protocol_methods_present():
    expected = {
        "get_coverage_gaps", "update_zone_coverage",
        "log_finding", "search_findings",
        "get_recent_summaries", "log_cycle_summary",
        "check_duplicate", "log_idea",
        "push_to_repro_queue", "get_repro_queue",
        "push_repro_package", "get_blue_team_queue",
        "get_regression_suite", "add_regression_test",
        "search_codebase", "send_alert",
    }
    actual = {m for m in dir(MonkeyClawMCP) if not m.startswith("_")}
    assert expected <= actual, f"missing: {expected - actual}"


def test_mock_conforms_to_protocol():
    from infra.mock_mcp import MockMCP
    mock = MockMCP(verbose=False)
    assert isinstance(mock, MonkeyClawMCP)


def test_real_server_conforms_to_protocol(real_mcp):
    assert isinstance(real_mcp, MonkeyClawMCP)


def test_provisioner_protocol():
    from infra.provisioning_nemoclaw import MockProvisioner
    p = MockProvisioner()
    assert isinstance(p, VictimProvisioner)


def test_new_dataclasses_importable_and_constructible():
    from interfaces.types import (
        ArchiveCell, IdeaComponent, JudgeVote, JudgeVoteInput, ModelRunInput,
        ModelRunRecord, PatchCandidateInput, PolicyCorpusCase, PolicyCorpusResult,
        PolicyCorpusResultInput, PolicyDecision, QueueState, TelemetryEvent,
        TelemetryEventInput,
    )
    ev = TelemetryEventInput(
        session_id="S1", event_type="agent.session.started", actor="orchestrator",
        action_class="session", target=None, decision=None, reason_code=None,
        data_class=None, content_hash=None, excerpt=None, metadata={},
    )
    assert ev.session_id == "S1"
    vote = JudgeVoteInput(
        lane_id="L1", judge_role="semantic", verdict="confirmed", score=0.9,
        confidence=0.8, reasoning="r", evidence_turns=[1, 2],
    )
    assert vote.evidence_turns == [1, 2]
    run = ModelRunInput(
        role="red_ideation", model="m", provider="nvidia", input_tokens=10,
        output_tokens=20, latency_ms=100, cost_usd=None, success=True, error=None,
    )
    assert run.success is True


def test_protocol_declares_new_methods():
    from interfaces.mcp_tools import MonkeyClawMCP
    for name in (
        "log_telemetry_event", "get_session_timeline", "log_model_run",
        "log_judge_vote", "log_policy_corpus_result", "get_policy_corpus_results",
        "mark_repro_queue_status", "mark_repro_package_status",
        "log_patch_candidate", "mark_patch_status",
    ):
        assert hasattr(MonkeyClawMCP, name), f"protocol missing {name}"


def test_protocol_declares_archive_methods():
    from interfaces.mcp_tools import MonkeyClawMCP
    for name in (
        "update_archive_cell", "get_archive_cells",
        "store_idea_components", "get_idea_components",
    ):
        assert hasattr(MonkeyClawMCP, name), f"protocol missing {name}"


def test_mock_mcp_archive_roundtrip():
    from infra.mock_mcp import MockMCP
    from interfaces.types import ArchiveUpdateInput, IdeaComponentInput
    m = MockMCP(verbose=False)
    cell = m.update_archive_cell(ArchiveUpdateInput(
        zone_id="PROMPT-INJ", interaction_style="direct",
        response_movement="refusal", idea_id="IDEA-1", score=0.4))
    assert cell.occupancy == 1
    assert cell.best_idea_id == "IDEA-1"
    # Lower score does not displace the elite, but occupancy still grows.
    cell2 = m.update_archive_cell(ArchiveUpdateInput(
        zone_id="PROMPT-INJ", interaction_style="direct",
        response_movement="refusal", idea_id="IDEA-2", score=0.1))
    assert cell2.occupancy == 2
    assert cell2.best_idea_id == "IDEA-1"
    # Higher score displaces it.
    cell3 = m.update_archive_cell(ArchiveUpdateInput(
        zone_id="PROMPT-INJ", interaction_style="direct",
        response_movement="refusal", idea_id="IDEA-3", score=0.9))
    assert cell3.best_idea_id == "IDEA-3"
    assert cell3.occupancy == 3
    cells = m.get_archive_cells("PROMPT-INJ")
    assert len(cells) == 1
    assert m.get_archive_cells("SBX-FS") == []
    ids = m.store_idea_components("IDEA-1", [
        IdeaComponentInput("IDEA-1", "interaction_style", "direct")])
    assert len(ids) == 1
    comps = m.get_idea_components("IDEA-1")
    assert len(comps) == 1 and comps[0].content == "direct"


def test_mock_mcp_model_run_and_judge_vote_roundtrip():
    from infra.mock_mcp import MockMCP
    from interfaces.types import JudgeVoteInput, ModelRunInput
    m = MockMCP(verbose=False)
    rid = m.log_model_run(ModelRunInput(
        role="red_ideation", model="m", provider="nvidia",
        input_tokens=5, output_tokens=7, latency_ms=42))
    assert isinstance(rid, str) and rid
    vid = m.log_judge_vote(JudgeVoteInput(
        lane_id="L1", judge_role="semantic", verdict="confirmed",
        score=0.9, confidence=0.8, reasoning="r", evidence_turns=[3]))
    assert isinstance(vid, str) and vid


def test_mock_mcp_telemetry_roundtrip():
    from infra.mock_mcp import MockMCP
    from interfaces.types import TelemetryEventInput
    m = MockMCP(verbose=False)
    eid = m.log_telemetry_event(TelemetryEventInput(
        session_id="S1", event_type="agent.session.started",
        actor="orchestrator", action_class="session"))
    assert isinstance(eid, str) and eid
    timeline = m.get_session_timeline("S1")
    assert len(timeline) == 1 and timeline[0].event_id == eid
