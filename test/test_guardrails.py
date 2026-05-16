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
