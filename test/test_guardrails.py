from infra.guardrails import PolicyEnforcer
from interfaces.config_schema import GuardrailsConfig


def _enforcer(**overrides):
    defaults = dict(
        artifact_dir="/tmp/mc_artifacts",
        denied_host_paths=["/Users", "~/.ssh", "/etc/shadow"],
        network_allowlist={"analysis": ["docs.anthropic.com"],
                           "default": ["localhost"]},
        model_route_allowlist=["nvidia", "openai"],
        mcp_tool_allowlist=["argyph", "github-readonly"],
        max_lanes_per_cycle=8,
        max_tokens_per_cycle=500_000,
    )
    defaults.update(overrides)
    return PolicyEnforcer(GuardrailsConfig(**defaults))


def test_denied_host_path_is_blocked():
    e = _enforcer()
    d = e.check_path_read("/Users/ezzy/.ssh/id_rsa")
    assert d.decision == "deny"
    assert d.reason_code == "denied_host_path"


def test_artifact_dir_path_allowed():
    e = _enforcer()
    assert e.check_path_read("/tmp/mc_artifacts/run1/out.txt").decision == "allow"


def test_network_egress_outside_phase_allowlist_blocked():
    e = _enforcer()
    assert e.check_network("evil.example.com", phase="analysis").decision == "deny"
    assert e.check_network("docs.anthropic.com", phase="analysis").decision == "allow"


def test_unknown_mcp_tool_blocked():
    e = _enforcer()
    assert e.check_mcp_tool("filesystem-write").decision == "deny"
    assert e.check_mcp_tool("argyph").decision == "allow"


def test_unknown_model_route_blocked():
    e = _enforcer()
    assert e.check_model_route("anthropic_or_openai").decision == "deny"
    assert e.check_model_route("nvidia").decision == "allow"


def test_lane_budget_exhaustion():
    e = _enforcer(max_lanes_per_cycle=2)
    assert e.check_lane_budget(lanes_used=1).decision == "allow"
    assert e.check_lane_budget(lanes_used=2).decision == "deny"


def test_token_budget_exhaustion():
    e = _enforcer(max_tokens_per_cycle=1000)
    assert e.check_token_budget(tokens_used=999).decision == "allow"
    assert e.check_token_budget(tokens_used=1000).decision == "deny"


def test_emergency_stop():
    e = _enforcer()
    assert e.emergency_stopped() is False
    e.trigger_emergency_stop("manual abort")
    assert e.emergency_stopped() is True
    assert e.check_lane_budget(lanes_used=0).decision == "deny"


def _make_harness_with_guardrails(emitter, enforcer):
    """Build a MonitoringHarness wired with telemetry + a PolicyEnforcer."""
    from infra.monitoring_harness import HarnessConfig, MonitoringHarness

    cfg = HarnessConfig(watched_paths=[], allowed_paths=[])
    return MonitoringHarness(
        cfg=cfg, lane_id="LANE1", idea_id="IDEA1", zone_id="ZONE1",
        telemetry=emitter, enforcer=enforcer)


def test_harness_denies_read_of_denied_host_path():
    """A planted lane reading a denied host path is denied + telemetry-logged."""
    from infra.mock_mcp import MockMCP
    from infra.monitoring_harness import MonitoringHarness
    from infra.telemetry import TelemetryEmitter

    mcp = MockMCP(verbose=False)
    enforcer = _enforcer()
    emitter = TelemetryEmitter(mcp, session_id="LANE1")
    harness = _make_harness_with_guardrails(emitter, enforcer)
    decision = harness.guard_path_read("/Users/ezzy/.ssh/id_rsa")
    assert decision.decision == "deny"
    tl = mcp.get_session_timeline("LANE1")
    assert any(e.event_type == "agent.tool.decision" and e.decision == "deny"
               for e in tl)
