"""Phase 2 — control_validator runs the corpus against the victim build
and reports drift. A fixture corpus seeds one case to regress."""

from __future__ import annotations

from purple_team.control_validator import ControlValidator
from red_team.policy_corpus import PolicyCorpusCase


def _case(case_id: str, zone: str, expected: str) -> PolicyCorpusCase:
    return PolicyCorpusCase(
        case_id=case_id, title=case_id, description="d", zone=zone,
        expected_decision=expected, expected_evidence=["evt"],
        attacker_prompt="p", severity="high", tactic_tags=[])


CORPUS = [
    _case("T01", "SBX-FS", "deny"),
    _case("T02", "SBX-NET", "deny"),
    _case("T03", "PROMPT-INJ", "deny"),
]


def test_inline_validates_only_the_zone_cases(server):
    # runner: every case observes the expected decision -> all pass.
    runner = lambda c: c.expected_decision  # noqa: E731
    validator = ControlValidator(server, corpus=CORPUS, case_runner=runner)
    run = validator.validate_inline("SBX-FS")
    assert run.kind == "inline"
    assert run.cases_total == 1
    assert run.cases_passed == 1


def test_full_validates_the_entire_corpus(server):
    runner = lambda c: c.expected_decision  # noqa: E731
    validator = ControlValidator(server, corpus=CORPUS, case_runner=runner)
    run = validator.validate_full()
    assert run.kind == "full"
    assert run.cases_total == 3
    assert run.cases_passed == 3
    assert run.status == "ok"


def test_regression_from_prior_pass_is_detected_and_recorded(server):
    ok = lambda c: c.expected_decision  # noqa: E731
    # First full sweep: everything passes.
    validator = ControlValidator(server, corpus=CORPUS, case_runner=ok)
    validator.validate_full()

    # Second sweep: T02 now returns "allow" — a regression from PASS.
    def broken(c):
        return "allow" if c.case_id == "T02" else c.expected_decision

    validator.case_runner = broken
    run = validator.validate_full()
    assert run.cases_passed == 2
    regressed_ids = {r["case_id"] for r in run.regressions}
    assert "T02" in regressed_ids


def test_validator_errors_surface_as_errored_run(server):
    def explode(c):
        raise RuntimeError("victim unreachable")
    run = ControlValidator(
        server, corpus=CORPUS, case_runner=explode).validate_full()
    assert run.status == "errored"


def test_run_is_persisted_to_mcp(server):
    runner = lambda c: c.expected_decision  # noqa: E731
    ControlValidator(server, corpus=CORPUS, case_runner=runner).validate_full()
    runs = server.get_control_validation_runs(kind="full")
    assert len(runs) == 1
