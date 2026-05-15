"""Patch verifier — Deliverable 8.

Three-gate validation, per spec §9.5:

- **Gate 1 — Regression test**: run the new positive regression test
  against the patched victim. Expected: vuln no longer triggers.
- **Gate 2 — Functionality test**: run the new negative test against the
  patched victim. Expected: legitimate adjacent operation still works.
- **Gate 3 — Full regression suite**: pull every active test via
  `get_regression_suite()` and run them. Expected: no previously-fixed
  vuln regresses.

Per the user's choice ("Test-harness only"), this v1 does NOT shell into
NemoClaw to rebuild a real victim with the patch applied. Instead:

- Patches are stored via the mock_apply hook the pipeline sets up. The
  `provisioner` we pass through is the same MockProvisioner used by the
  rest of the system; for HTTP/IPC mode the production wiring upgrades
  to the real NemoClaw provisioner and the same code path executes.
- "Patched" semantics come from the provisioner's `patch_diff` field on
  `VictimConfig`. The MockProvisioner records but doesn't apply it; real
  builds honor it. Either way the verifier's job is to RUN the tests —
  whether the patch actually took effect is the provisioner's
  responsibility, not the verifier's.

Outputs:
- `VerifyOutcome.approved=True` → patch passes all gates.
- `approved=False` → which gate failed, with diagnostic detail.

The pipeline glue (`blue_team/pipeline.py`) is responsible for the
post-approval MCP side-effects: add_regression_test, mark finding patched,
reset coverage to 0.3, send_alert, etc.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.provisioning import VictimProvisioner
from interfaces.types import (
    CheckResult,
    PatchCandidate,
    PolicyConfig,
    RegressionTest,
    ReproPackage,
)

from blue_team._common import default_policy
from blue_team.replay_minimizer import (
    JudgeFn,
    ReplayFn,
    default_judge,
    make_mock_replay_fn,
)
from blue_team.test_generator import RegressionTestPair, execute_test_script

LOG = logging.getLogger("monkeyclaw.blue.patch_verify")


# ---------------------------------------------------------------------------
# Outcome types
# ---------------------------------------------------------------------------


@dataclass
class GateResult:
    name: str
    passed: bool
    detail: dict


@dataclass
class VerifyOutcome:
    approved: bool
    failed_gate: str | None
    gates: list[GateResult]
    patch_id: str
    notes: str = ""
    triggered_evidence: list[CheckResult] = field(default_factory=list)


@dataclass
class PatchVerifierConfig:
    max_attempts_per_patch: int = 3  # used by the pipeline glue, not here
    full_suite_concurrency: int = 1  # placeholder for future parallelism

    @classmethod
    def from_blue_team_cfg(cls, blue_cfg) -> "PatchVerifierConfig":
        return cls(
            max_attempts_per_patch=getattr(blue_cfg, "patch_verify_max_attempts", 3),
        )


# ---------------------------------------------------------------------------
# Patched-victim factory
# ---------------------------------------------------------------------------


PatchedReplayFactory = Callable[[PatchCandidate], ReplayFn]
"""Given a candidate patch, return the replay function the gates should use.

Production wiring: build a replay_fn that asks the provisioner for a
victim with `patch_diff` set. With MockProvisioner this is a no-op (the
patch is recorded, never applied), so the mock-replay defaults are used.
Tests inject a factory that returns a deterministic replay function.
"""


def default_patched_replay_factory(patch: PatchCandidate) -> ReplayFn:
    """Default factory — uses the in-process mock replay regardless of
    the patch. With the MockProvisioner this is what the rest of the
    pipeline already does, so the patch verifier's gates run on the same
    surface as the original replay-minimizer."""
    _ = patch
    return make_mock_replay_fn()


# ---------------------------------------------------------------------------
# Patch verifier
# ---------------------------------------------------------------------------


class PatchVerifier:
    """Runs the three gates against a candidate patch + test pair."""

    def __init__(
        self,
        mcp: MonkeyClawMCP,
        provisioner: VictimProvisioner,
        *,
        cfg: PatchVerifierConfig | None = None,
        policy: PolicyConfig | None = None,
        patched_replay_factory: PatchedReplayFactory | None = None,
        judge_fn: JudgeFn | None = None,
    ) -> None:
        self.mcp = mcp
        self.provisioner = provisioner
        self.cfg = cfg or PatchVerifierConfig()
        self.policy = policy or default_policy()
        self.patched_replay_factory = (
            patched_replay_factory or default_patched_replay_factory
        )
        self.judge_fn = judge_fn or default_judge

    # ------------------------------------------------------------------
    def verify(
        self,
        *,
        patch: PatchCandidate,
        package: ReproPackage,
        test_pair: RegressionTestPair,
    ) -> VerifyOutcome:
        gates: list[GateResult] = []
        replay_fn = self.patched_replay_factory(patch)

        # ---- Gate 1: positive regression ----
        g1 = self._run_script(
            "gate1_regression",
            test_pair.positive_test.test_script,
            replay_fn,
        )
        gates.append(g1)
        if not g1.passed:
            return self._reject("gate1_regression", patch, gates,
                                  "the patch did not block the original "
                                  "vulnerability")

        # ---- Gate 2: functionality ----
        if test_pair.negative_test_script:
            g2 = self._run_script(
                "gate2_functionality",
                test_pair.negative_test_script,
                replay_fn,
            )
            gates.append(g2)
            if not g2.passed:
                return self._reject("gate2_functionality", patch, gates,
                                      "the patch broke legitimate adjacent "
                                      "functionality")
        else:
            gates.append(GateResult(
                name="gate2_functionality",
                passed=True,
                detail={"skipped": True, "reason": "no negative test generated"},
            ))

        # ---- Gate 3: full regression suite ----
        suite_result = self._run_full_suite(replay_fn)
        gates.append(suite_result)
        if not suite_result.passed:
            return self._reject("gate3_full_suite", patch, gates,
                                  "patch caused at least one previously-"
                                  "fixed vulnerability to regress")

        return VerifyOutcome(
            approved=True,
            failed_gate=None,
            gates=gates,
            patch_id=patch.patch_id,
            notes="all three gates passed",
        )

    # ------------------------------------------------------------------
    # Gate runners
    # ------------------------------------------------------------------
    def _run_script(
        self, name: str, script: str, replay_fn: ReplayFn,
    ) -> GateResult:
        try:
            result = execute_test_script(
                script,
                replay_fn=replay_fn,
                judge_fn=self.judge_fn,
                policy=self.policy,
                provisioner=self.provisioner,
            )
        except Exception as e:  # noqa: BLE001
            LOG.exception("%s execution exploded: %s", name, e)
            return GateResult(
                name=name, passed=False,
                detail={"error": repr(e)},
            )
        return GateResult(
            name=name,
            passed=bool(result.get("passed")),
            detail=result,
        )

    def _run_full_suite(self, replay_fn: ReplayFn) -> GateResult:
        try:
            suite = self.mcp.get_regression_suite()
        except Exception as e:  # noqa: BLE001
            return GateResult(
                name="gate3_full_suite", passed=False,
                detail={"error": f"get_regression_suite failed: {e!r}"},
            )
        if not suite:
            return GateResult(
                name="gate3_full_suite",
                passed=True,
                detail={"total": 0, "note": "no existing regression tests"},
            )
        results: list[dict] = []
        failed: list[str] = []
        for t in suite:
            r = execute_test_script(
                t.test_script,
                replay_fn=replay_fn,
                judge_fn=self.judge_fn,
                policy=self.policy,
                provisioner=self.provisioner,
            )
            results.append({"test_id": t.test_id, "vuln_id": t.vuln_id, **r})
            if not r.get("passed"):
                failed.append(t.test_id)
        return GateResult(
            name="gate3_full_suite",
            passed=not failed,
            detail={
                "total": len(suite),
                "failed": failed,
                "results": results,
            },
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _reject(
        gate: str, patch: PatchCandidate, gates: list[GateResult],
        notes: str,
    ) -> VerifyOutcome:
        return VerifyOutcome(
            approved=False, failed_gate=gate, gates=gates,
            patch_id=patch.patch_id, notes=notes,
        )


__all__ = [
    "GateResult",
    "PatchVerifier",
    "PatchVerifierConfig",
    "PatchedReplayFactory",
    "VerifyOutcome",
    "default_patched_replay_factory",
]
