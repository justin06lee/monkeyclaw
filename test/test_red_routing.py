"""Routing dispatch tests — verifies the correct sequence of MCP calls per verdict."""

from __future__ import annotations

from infra.mock_mcp import MockMCP
from interfaces.types import CheckResult, IdeaObject, JudgmentResult
from red_team.routing import route_judgment


def _idea() -> IdeaObject:
    return IdeaObject(
        idea_id="IDEA-1", cycle_id=1, zone_id="PROMPT-INJ",
        source_mode="creative", title="t", approach="a",
        success_criteria="s", estimated_turns=1, novelty_notes="",
    )


def _judgment(verdict: str, severity: str = "high") -> JudgmentResult:
    return JudgmentResult(
        lane_id="LANE-1", idea_id="IDEA-1", zone_id="PROMPT-INJ",
        verdict=verdict, tier_that_caught="semantic",
        failure_class="prompt_injection", severity=severity,
        confidence=0.9,
        evidence=[CheckResult("c", True, severity, {})],
        reasoning="r", tokens_used_judgment=100, timestamp="t",
    )


class _SpyMCP(MockMCP):
    """Wraps MockMCP and records every method call."""

    def __init__(self):
        super().__init__(seed=0, verbose=False)
        self.calls: list[tuple[str, tuple, dict]] = []

    def _spy(self, name):
        original = getattr(MockMCP, name)
        def wrapped(self, *a, **kw):
            self.calls.append((name, a, kw))
            return original(self, *a, **kw)
        return wrapped


def _make_spy() -> _SpyMCP:
    mcp = _SpyMCP()
    for name in (
        "log_finding", "push_to_repro_queue", "update_zone_coverage",
        "send_alert",
    ):
        original = getattr(MockMCP, name)
        def make(name=name, original=original):
            def wrapped(self, *a, **kw):
                self.calls.append((name, a, kw))
                return original(self, *a, **kw)
            return wrapped
        setattr(_SpyMCP, name, make())
    return mcp


def test_confirmed_routes_finding_queue_coverage_alert():
    mcp = _make_spy()
    fid = route_judgment(_judgment("confirmed", "critical"), _idea(), mcp)
    names = [c[0] for c in mcp.calls]
    assert "log_finding" in names
    assert "push_to_repro_queue" in names
    assert "update_zone_coverage" in names
    assert "send_alert" in names
    # Repro queue should be high priority
    push = next(c for c in mcp.calls if c[0] == "push_to_repro_queue")
    assert push[2].get("priority") == "high" or "high" in push[1]
    assert fid.startswith("FND-")


def test_suspicious_routes_finding_queue_coverage_no_alert():
    mcp = _make_spy()
    route_judgment(_judgment("suspicious", "medium"), _idea(), mcp)
    names = [c[0] for c in mcp.calls]
    assert names.count("log_finding") == 1
    assert names.count("push_to_repro_queue") == 1
    assert names.count("update_zone_coverage") == 1
    assert "send_alert" not in names
    push = next(c for c in mcp.calls if c[0] == "push_to_repro_queue")
    assert push[2].get("priority") == "low" or "low" in push[1]


def test_clean_only_logs_and_updates_coverage():
    mcp = _make_spy()
    route_judgment(_judgment("clean", "low"), _idea(), mcp)
    names = [c[0] for c in mcp.calls]
    assert names.count("log_finding") == 1
    assert names.count("update_zone_coverage") == 1
    assert "push_to_repro_queue" not in names
    assert "send_alert" not in names


def test_alert_floor_suppresses_low_severity_confirms():
    mcp = _make_spy()
    route_judgment(_judgment("confirmed", "low"), _idea(), mcp,
                    alert_severity_floor="high")
    names = [c[0] for c in mcp.calls]
    # log_finding + push_to_repro_queue + update_zone_coverage, but NO send_alert
    assert "send_alert" not in names
