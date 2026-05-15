"""Regression runner tests."""

from __future__ import annotations

from pathlib import Path

from infra.mock_mcp import MockMCP
from infra.provisioning_nemoclaw import MockProvisioner
from interfaces.types import RegressionTestInput
from red_team import mock_victim

from blue_team._common import default_policy
from blue_team.regression_runner import RegressionRunner


def setup_function(_):
    mock_victim.reset_all()


def _planted_provisioner(allowed: Path, escape: Path) -> MockProvisioner:
    base = MockProvisioner()
    real = base.provision_victim

    def _patched(config):
        inst = real(config)
        mock_victim.build_and_register(
            endpoint=inst.chat_endpoint,
            allowed_root=str(allowed),
            escape_root=str(escape),
        )
        return inst

    base.provision_victim = _patched  # type: ignore[assignment]
    return base


# A minimal regression test script that decides pass/fail from a module-level
# constant — lets us steer pass/fail independent of the replay function.
def _always_passing_script() -> str:
    return (
        "RESULT = {'passed': True, 'expected': 'vulnerability_blocked', "
        "'actual': 'vulnerability_blocked'}\n"
    )


def _always_failing_script() -> str:
    return "RESULT = {'passed': False, 'expected': 'a', 'actual': 'b'}\n"


# ---------------------------------------------------------------------------
# Empty suite
# ---------------------------------------------------------------------------


def test_regression_runner_handles_empty_suite(tmp_path: Path):
    provisioner = _planted_provisioner(tmp_path / "a", tmp_path / "b")
    mcp = MockMCP(seed=0, verbose=False)
    runner = RegressionRunner(mcp, provisioner, policy=default_policy())
    result = runner.run()
    assert result.total_tests == 0
    assert result.tests_passing == 0
    assert result.tests_failing == 0
    assert result.newly_failing == []
    assert result.run_duration_seconds >= 0


# ---------------------------------------------------------------------------
# All passing
# ---------------------------------------------------------------------------


def test_regression_runner_reports_all_passing(tmp_path: Path):
    provisioner = _planted_provisioner(tmp_path / "a", tmp_path / "b")
    mcp = MockMCP(seed=0, verbose=False)
    for i in range(3):
        mcp.add_regression_test(RegressionTestInput(
            vuln_id=f"MC-V{i}", zone_id="SBX-FS",
            test_script=_always_passing_script(),
            expected_result="vulnerability_blocked",
            functionality_test_script=None,
        ))
    runner = RegressionRunner(mcp, provisioner, policy=default_policy())
    result = runner.run()
    assert result.total_tests == 3
    assert result.tests_passing == 3
    assert result.tests_failing == 0
    assert result.newly_failing == []
    # Coverage delta bumped positively
    assert result.coverage_delta.get("SBX-FS", 0) > 0


# ---------------------------------------------------------------------------
# Mixed pass / fail
# ---------------------------------------------------------------------------


def test_regression_runner_flags_newly_failing(tmp_path: Path):
    provisioner = _planted_provisioner(tmp_path / "a", tmp_path / "b")
    mcp = MockMCP(seed=0, verbose=False)
    test_ids = []
    for script in (_always_passing_script(), _always_passing_script()):
        tid = mcp.add_regression_test(RegressionTestInput(
            vuln_id=f"MC-V-{len(test_ids)}", zone_id="SBX-NET",
            test_script=script,
            expected_result="vulnerability_blocked",
            functionality_test_script=None,
        ))
        test_ids.append(tid)
    runner = RegressionRunner(mcp, provisioner, policy=default_policy())
    # First run: both pass.
    r1 = runner.run()
    assert r1.tests_passing == 2 and r1.tests_failing == 0
    # Flip one test to failing by mutating the in-memory MCP test.
    failing_id = test_ids[1]
    mcp._regression_tests[failing_id].test_script = _always_failing_script()
    # Second run: one newly failing.
    r2 = runner.run()
    assert r2.tests_passing == 1
    assert r2.tests_failing == 1
    assert failing_id in r2.newly_failing
    # Coverage delta now penalized
    assert r2.coverage_delta["SBX-NET"] < 0


def test_regression_runner_tracks_consecutive_passes(tmp_path: Path):
    provisioner = _planted_provisioner(tmp_path / "a", tmp_path / "b")
    mcp = MockMCP(seed=0, verbose=False)
    mcp.add_regression_test(RegressionTestInput(
        vuln_id="MC-V1", zone_id="SBX-FS",
        test_script=_always_passing_script(),
        expected_result="vulnerability_blocked",
        functionality_test_script=None,
    ))
    runner = RegressionRunner(mcp, provisioner, policy=default_policy())
    for _ in range(3):
        runner.run()
    # First (and only) test_id from the mock
    [tid] = list(mcp._regression_tests.keys())
    assert runner.record(tid).consecutive_passes == 3
    assert runner.record(tid).last_run_result == "pass"


def test_regression_runner_resets_consecutive_passes_on_fail(tmp_path: Path):
    provisioner = _planted_provisioner(tmp_path / "a", tmp_path / "b")
    mcp = MockMCP(seed=0, verbose=False)
    mcp.add_regression_test(RegressionTestInput(
        vuln_id="MC-V1", zone_id="SBX-FS",
        test_script=_always_passing_script(),
        expected_result="vulnerability_blocked",
        functionality_test_script=None,
    ))
    runner = RegressionRunner(mcp, provisioner, policy=default_policy())
    runner.run()
    runner.run()
    [tid] = list(mcp._regression_tests.keys())
    assert runner.record(tid).consecutive_passes == 2
    # Flip to failing.
    mcp._regression_tests[tid].test_script = _always_failing_script()
    runner.run()
    assert runner.record(tid).consecutive_passes == 0
    assert runner.record(tid).last_run_result == "fail"
