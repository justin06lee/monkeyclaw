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
