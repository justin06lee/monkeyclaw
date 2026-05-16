"""Phase 5 — self_governance audits MonkeyClaw's own agents."""

from __future__ import annotations

from purple_team.self_governance import AgentProfile, SelfGovernance


def _ok_agent(name: str) -> AgentProfile:
    return AgentProfile(
        name=name, egress_bounded=True, sandboxed=True,
        reads_secret_paths=False, audit_trail_complete=True)


def _bad_agent(name: str) -> AgentProfile:
    # deliberately mis-sandboxed test agent.
    return AgentProfile(
        name=name, egress_bounded=True, sandboxed=False,
        reads_secret_paths=False, audit_trail_complete=True)


def test_all_compliant_agents_pass(server):
    report = SelfGovernance(server).audit_self(agents=[
        _ok_agent("attacker"), _ok_agent("cold-verifier"),
        _ok_agent("patch-generator")])
    assert report.passed is True
    assert report.violations == []


def test_mis_sandboxed_agent_is_flagged(server):
    report = SelfGovernance(server).audit_self(agents=[
        _ok_agent("attacker"), _bad_agent("patch-generator")])
    assert report.passed is False
    assert any("patch-generator" in v for v in report.violations)
    assert any("sandbox" in v.lower() for v in report.violations)


def test_secret_path_read_is_flagged(server):
    leaky = AgentProfile(
        name="attacker", egress_bounded=True, sandboxed=True,
        reads_secret_paths=True, audit_trail_complete=True)
    report = SelfGovernance(server).audit_self(agents=[leaky])
    assert report.passed is False
    assert any("secret" in v.lower() for v in report.violations)


def test_unbounded_egress_is_flagged(server):
    open_egress = AgentProfile(
        name="attacker", egress_bounded=False, sandboxed=True,
        reads_secret_paths=False, audit_trail_complete=True)
    report = SelfGovernance(server).audit_self(agents=[open_egress])
    assert report.passed is False
    assert any("egress" in v.lower() for v in report.violations)


def test_incomplete_audit_trail_is_flagged(server):
    no_audit = AgentProfile(
        name="cold-verifier", egress_bounded=True, sandboxed=True,
        reads_secret_paths=False, audit_trail_complete=False)
    report = SelfGovernance(server).audit_self(agents=[no_audit])
    assert report.passed is False
    assert any("audit" in v.lower() for v in report.violations)


def test_report_lists_one_check_per_control_per_agent(server):
    report = SelfGovernance(server).audit_self(agents=[_ok_agent("attacker")])
    # 4 controls x 1 agent.
    assert len(report.checks) == 4
