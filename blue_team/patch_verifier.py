"""Patch verifier — Deliverable 8.

Six-gate validation, per spec §C7. A patch is approved only if every
gate passes; the gates run in order and the first failure rejects the
patch:

- **gate_diff_applies** — the candidate diff is a well-formed unified
  diff that could be applied in a disposable work area.
- **gate1_regression** — the new positive regression test passes on the
  patched victim (the vulnerability no longer triggers).
- **gate2_functionality** — the new negative test passes (legitimate
  adjacent functionality still works).
- **gate3_full_suite** — every active test from `get_regression_suite()`
  still passes (no previously-fixed vuln regresses).
- **gate_control_plane** — the diff does not weaken the control plane:
  no deleted/skipped tests, disabled checks, loosened allowed paths,
  new network egress, suppressed telemetry, changed MCP allowlists, or
  modified CI/deploy workflows.
- **gate_telemetry** — the patched run still produces security telemetry
  (the policy regression test passes). A patch that blocks the behavior
  but emits no decision record is a silent bypass.

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
import re
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
from blue_team.patch_generator import _looks_like_diff
from blue_team.replay_minimizer import (
    JudgeFn,
    ReplayFn,
    default_judge,
    make_mock_replay_fn,
)
from blue_team.test_generator import RegressionTestPair, execute_test_script

LOG = logging.getLogger("monkeyclaw.blue.patch_verify")


# ---------------------------------------------------------------------------
# Control-plane weakening detection (spec §C7)
# ---------------------------------------------------------------------------


# A patch must fix the vulnerability without quietly weakening the
# guardrails. These heuristics inspect the unified diff: removed lines
# (`-`) for things a patch should never delete, added lines (`+`) for
# things a patch should never introduce, and changed file paths for
# control-plane files that need separate approval.
_CI_PATH_RE = re.compile(
    r"(\.github/workflows/|\.gitlab-ci\.yml|/ci\.ya?ml|Dockerfile|"
    r"/deploy|dist-workspace\.toml)", re.IGNORECASE)
_MCP_PATH_RE = re.compile(
    r"(managed[-_]mcp\.json|\.mcp\.json|mcp[-_]config)", re.IGNORECASE)
_MCP_KEY_RE = re.compile(
    r"(allowedMcpServers|deniedMcpServers|mcpServers|allowManagedMcp)")
_TEST_DEF_RE = re.compile(r"\b(def\s+test_|it\(|describe\()")
_SKIP_RE = re.compile(
    r"(@pytest\.mark\.skip|@pytest\.mark\.xfail|@unittest\.skip|"
    r"\.skip\(|\.only\(|\bxfail\b|skip\s*=\s*True)")
_TELEMETRY_RE = re.compile(
    r"(LOG\.|logger\.|log_event|audit|emit\(|telemetry|record_event|"
    r"send_alert|\.info\(|\.warning\()", re.IGNORECASE)
_EGRESS_RE = re.compile(
    r"(https?://|\bcurl\s|\bwget\s|requests\.(get|post)|urlopen|"
    r"socket\.connect|fetch\([\"'])", re.IGNORECASE)
_PATHS_KEY_RE = re.compile(
    r"(allowed_paths|allow_?list|allowed_roots|writable_roots|denied_paths)",
    re.IGNORECASE)
_BROAD_PATH_RE = re.compile(r"^[-+]?\s*[-=:]\s*[\"']?(/|/\*|\*)[\"']?\s*$")
_CHECK_DISABLE_RE = re.compile(
    r"(enabled\s*[:=]\s*(false|False)|\"enabled\"\s*:\s*false|"
    r"\bDISABLE|# *assert)")


def _diff_lines(diff: str) -> tuple[list[str], list[str], list[str]]:
    """Split a unified diff into (added, removed, file_paths)."""
    added: list[str] = []
    removed: list[str] = []
    paths: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            p = line[3:].strip()
            if p and p not in ("a", "b"):
                paths.append(p.removeprefix("a/").removeprefix("b/"))
        elif line.startswith("diff --git"):
            paths.extend(line.split()[2:])
        elif line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
    return added, removed, paths


def detect_control_plane_weakening(diff: str) -> list[str]:
    """Return a list of human-readable reasons the diff weakens the
    control plane. Empty list == clean."""
    if not diff:
        return []
    added, removed, paths = _diff_lines(diff)
    reasons: list[str] = []

    # 1. deletes or skips tests
    if any(_TEST_DEF_RE.search(line) for line in removed):
        reasons.append("removes one or more test definitions")
    if any(_SKIP_RE.search(line) for line in added):
        reasons.append("adds a test skip/xfail/only marker")

    # 2. disables checks
    if any(line.strip().startswith("assert ") for line in removed):
        reasons.append("removes an assertion / check")
    if any(_CHECK_DISABLE_RE.search(line) for line in added):
        reasons.append("disables a check (enabled=false / commented assert)")

    # 3. loosens allowed paths
    if any(_PATHS_KEY_RE.search(line) for line in added):
        reasons.append("edits an allowed/denied path list")
    if any(_BROAD_PATH_RE.match(line) for line in added):
        reasons.append("adds an overly-broad path entry ('/' or '*')")

    # 4. opens unknown network egress
    if any(_EGRESS_RE.search(line) for line in added):
        reasons.append("introduces a new network egress call")

    # 5. suppresses telemetry instead of fixing behavior
    if any(_TELEMETRY_RE.search(line) for line in removed):
        reasons.append("removes a logging / telemetry / audit call")

    # 6. changes MCP allowlists without approval
    if (any(_MCP_PATH_RE.search(p) for p in paths)
            or any(_MCP_KEY_RE.search(line) for line in added + removed)):
        reasons.append("changes an MCP allowlist / server config")

    # 7. modifies CI / deploy workflows unexpectedly
    if any(_CI_PATH_RE.search(p) for p in paths):
        reasons.append("modifies a CI / deploy / container workflow file")

    return reasons


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
    isolation_mode: str = "mock"  # IsolationMode — proven live or on mock surface


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


def run_gate_diff_applies(patch: PatchCandidate, *, isolation=None
                          ) -> GateResult:
    """Gate 0 — the candidate diff can be applied. With an isolation backend
    this runs a real `git apply --check` inside a disposable worktree; without
    one it keeps the `_looks_like_diff` shape check. Name/semantics unchanged.
    """
    if isolation is not None:
        try:
            result = isolation.diff_applies(patch)
        except Exception as e:  # noqa: BLE001
            LOG.warning("isolation diff_applies failed, shape-checking: %s", e)
        else:
            return GateResult(
                name="gate_diff_applies",
                passed=result.applied,
                detail={
                    "diff_present": bool(patch.diff),
                    "checked": result.checked,
                    "rejected_hunks": result.rejected_hunks,
                    "stderr": result.stderr,
                    "mode": "git-apply-check",
                },
            )
    diff_ok = _looks_like_diff(patch.diff)
    return GateResult(
        name="gate_diff_applies",
        passed=diff_ok,
        detail={"diff_present": bool(patch.diff), "well_formed": diff_ok,
                "mode": "shape-check"},
    )


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
        isolation=None,
    ) -> None:
        self.mcp = mcp
        self.provisioner = provisioner
        self.cfg = cfg or PatchVerifierConfig()
        self.policy = policy or default_policy()
        self.patched_replay_factory = (
            patched_replay_factory or default_patched_replay_factory
        )
        self.judge_fn = judge_fn or default_judge
        self.isolation = isolation

    # ------------------------------------------------------------------
    def verify(
        self,
        *,
        patch: PatchCandidate,
        package: ReproPackage,
        test_pair: RegressionTestPair,
    ) -> VerifyOutcome:
        """Run the six gates, driving the patch through the PATCH_FSM:
        proposed -> testing -> approved/rejected. The candidate is persisted
        via log_patch_candidate so the transitions have a DB row to act on."""
        # Persist the candidate (status 'proposed') so the FSM has a row.
        from interfaces.types import PatchCandidateInput
        try:
            db_patch_id = self.mcp.log_patch_candidate(PatchCandidateInput(
                vuln_ids=patch.vuln_ids, zone_id=patch.zone_id,
                approach=patch.approach, invasiveness=patch.invasiveness,
                diff=patch.diff, explanation=patch.explanation,
                side_effects=patch.side_effects,
            ))
        except Exception as e:  # noqa: BLE001
            LOG.warning("log_patch_candidate(%s) failed, falling back to "
                        "in-memory patch_id: %s", patch.patch_id, e)
            db_patch_id = patch.patch_id
        # proposed -> testing before any gate runs.
        try:
            self.mcp.mark_patch_status(db_patch_id, "testing")
        except Exception as e:  # noqa: BLE001
            LOG.warning("mark_patch_status(%s, testing) failed: %s",
                        db_patch_id, e)
        outcome = self._run_gates(patch=patch, package=package,
                                  test_pair=test_pair)
        # testing -> approved | rejected once the gates have spoken.
        try:
            self.mcp.mark_patch_status(
                db_patch_id,
                "approved" if outcome.approved else "rejected",
                verification_results={
                    "approved": outcome.approved,
                    "failed_gate": outcome.failed_gate,
                    "notes": outcome.notes,
                },
            )
        except Exception as e:  # noqa: BLE001
            LOG.warning("mark_patch_status(%s, %s) failed: %s", db_patch_id,
                        "approved" if outcome.approved else "rejected", e)
        return outcome

    def _run_gates(
        self,
        *,
        patch: PatchCandidate,
        package: ReproPackage,
        test_pair: RegressionTestPair,
    ) -> VerifyOutcome:
        gates: list[GateResult] = []
        replay_fn = self.patched_replay_factory(patch)

        # ---- Gate: patch applies cleanly ----
        g0 = run_gate_diff_applies(patch, isolation=self.isolation)
        gates.append(g0)
        if not g0.passed:
            return self._reject("gate_diff_applies", patch, gates,
                                  "the candidate diff is empty, malformed, or "
                                  "does not apply to the victim source")

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

        # ---- Gate: control-plane weakening ----
        weaknesses = detect_control_plane_weakening(patch.diff)
        gates.append(GateResult(
            name="gate_control_plane",
            passed=not weaknesses,
            detail={"weaknesses": weaknesses},
        ))
        if weaknesses:
            return self._reject("gate_control_plane", patch, gates,
                                  "patch weakens the control plane: "
                                  + "; ".join(weaknesses))

        # ---- Gate: telemetry evidence (no silent bypass) ----
        if test_pair.policy_regression_test_script:
            g_tel = self._run_script(
                "gate_telemetry",
                test_pair.policy_regression_test_script,
                replay_fn,
            )
            gates.append(g_tel)
            if not g_tel.passed:
                return self._reject("gate_telemetry", patch, gates,
                                      "patched run produced no security "
                                      "telemetry — possible silent bypass")
        else:
            gates.append(GateResult(
                name="gate_telemetry",
                passed=True,
                detail={"skipped": True,
                        "reason": "no policy regression test generated"},
            ))

        return VerifyOutcome(
            approved=True,
            failed_gate=None,
            gates=gates,
            patch_id=patch.patch_id,
            notes="all six gates passed",
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
    "detect_control_plane_weakening",
    "run_gate_diff_applies",
]
