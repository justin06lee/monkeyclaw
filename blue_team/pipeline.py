"""Blue-team pipeline — the orchestrator entrypoint.

Conforms to `infra.orchestrator.BluePipeline` Protocol:

    class Pipeline:
        def process_repro_queue(self) -> int
        def process_blue_queue(self) -> int
        def run_regression(self) -> None

Wires:

repro pipeline (`process_repro_queue`):
    get_repro_queue
    → ReplayMinimizer.replay_and_minimize
    → RootCauseLocator.locate (severity-gated)
    → ReproWriter.write
    → ColdVerifier.verify (with rewrite_fn that re-emits the markdown
       carrying the diagnostic into the Summary section)
    → push_repro_package + update_zone_coverage + send_alert

blue queue (`process_blue_queue`):
    get_blue_team_queue
    → TriageAgent.triage
    → for each FixTask: PatchGenerator.generate_for_task
       → for each candidate: TestGenerator.generate
          → PatchVerifier.verify
          → if approved: add_regression_test + update_zone_coverage(+0.3 reset)
                        + send_alert + update package status to "verified"

regression (`run_regression`):
    RegressionRunner.run

Usage:
    uv run python -m infra.orchestrator \\
        --red red_team.pipeline:Pipeline \\
        --blue blue_team.pipeline:Pipeline
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict

from infra.bootstrap import Runtime
from interfaces.config_schema import MonkeyClawConfig
from interfaces.llm import LLMClient, make_llm
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.provisioning import VictimProvisioner
from interfaces.types import (
    FindingRecord,
    PatchCandidate,
    PolicyConfig,
    RegressionRunResult,
    ReproPackage,
    ReproPackageInput,
)

from blue_team._common import (
    SEVERITY_ORDER,
    lane_result_from_finding,
    mint_vuln_id,
    policy_from_config,
    severity_at_least,
    to_jsonable,
)
from blue_team.cold_verifier import (
    ColdVerifier,
    ColdVerifierConfig,
    ColdVerifyResult,
    FailureDiagnostic,
)
from blue_team.patch_generator import PatchGenerator, PatchGeneratorConfig
from blue_team.patch_verifier import (
    PatchVerifier,
    PatchVerifierConfig,
    VerifyOutcome,
)
from blue_team.regression_runner import RegressionRunner
from blue_team.replay_minimizer import (
    MinimizeResult,
    ReplayMinimizer,
    ReplayMinimizerConfig,
)
from blue_team.repro_writer import ReproWriter, ReproWriterInput
from blue_team.root_cause import RootCauseConfig, RootCauseLocator, RootCauseResult
from blue_team.test_generator import RegressionTestPair, TestGenerator
from blue_team.triage import FixTask, TriageAgent, TriageConfig

LOG = logging.getLogger("monkeyclaw.blue.pipeline")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class Pipeline:
    """Person 3's pipeline. Bound via `--blue blue_team.pipeline:Pipeline`."""

    def __init__(
        self,
        runtime: Runtime | None = None,
        *,
        mcp: MonkeyClawMCP | None = None,
        provisioner: VictimProvisioner | None = None,
        llm: LLMClient | None = None,
        policy: PolicyConfig | None = None,
        # Test-time injection points so the suite can wire deterministic
        # replay/judge functions without touching globals.
        replay_minimizer: ReplayMinimizer | None = None,
        root_cause: RootCauseLocator | None = None,
        cold_verifier: ColdVerifier | None = None,
        patch_generator: PatchGenerator | None = None,
        patch_verifier: PatchVerifier | None = None,
        regression_runner: RegressionRunner | None = None,
        triage: TriageAgent | None = None,
        test_generator: TestGenerator | None = None,
        repro_writer: ReproWriter | None = None,
        alert_severity_floor: str = "high",
    ) -> None:
        # ---- Runtime resolution ----
        if runtime is not None:
            self.mcp = runtime.mcp
            self.provisioner = runtime.provisioner
            self.cfg = runtime.cfg
        else:
            if mcp is None or provisioner is None:
                raise ValueError(
                    "Pipeline needs either a Runtime or explicit `mcp=` + "
                    "`provisioner=`. The orchestrator passes a Runtime when "
                    "loading via --blue."
                )
            self.mcp = mcp
            self.provisioner = provisioner
            self.cfg = MonkeyClawConfig()

        self.llm = llm or make_llm()
        self.policy = policy or policy_from_config(self.cfg)
        self.alert_severity_floor = alert_severity_floor

        # ---- Component wiring (every component injectable for tests) ----
        self.repro_writer = repro_writer or ReproWriter()
        self.replay_minimizer = replay_minimizer or ReplayMinimizer(
            provisioner=self.provisioner,
            cfg=ReplayMinimizerConfig.from_runtime_cfg(
                self.cfg.repro, self.cfg.nemoclaw,
            ),
            policy=self.policy,
        )
        self.root_cause = root_cause or RootCauseLocator(
            llm=self.llm, mcp=self.mcp,
            cfg=RootCauseConfig(
                severity_threshold=self.cfg.repro.root_cause_severity_threshold,
            ),
        )
        self.cold_verifier = cold_verifier or ColdVerifier(
            llm=self.llm, provisioner=self.provisioner,
            cfg=ColdVerifierConfig.from_runtime_cfg(
                self.cfg.repro, self.cfg.nemoclaw,
            ),
            policy=self.policy,
        )
        self.triage = triage or TriageAgent(TriageConfig())
        self.patch_generator = patch_generator or PatchGenerator(
            llm=self.llm, mcp=self.mcp,
            cfg=PatchGeneratorConfig.from_blue_team_cfg(self.cfg.blue_team),
        )
        self.test_generator = test_generator or TestGenerator()
        self.patch_verifier = patch_verifier or PatchVerifier(
            mcp=self.mcp, provisioner=self.provisioner,
            cfg=PatchVerifierConfig.from_blue_team_cfg(self.cfg.blue_team),
            policy=self.policy,
        )
        self.regression_runner = regression_runner or RegressionRunner(
            mcp=self.mcp, provisioner=self.provisioner, policy=self.policy,
        )

        # Track patches per task so we don't retry the same patch_id
        # forever. Bounded by config.blue_team.patch_verify_max_attempts.
        self._task_attempt_count: dict[str, int] = {}

    # ==================================================================
    # process_repro_queue
    # ==================================================================
    def process_repro_queue(self) -> int:
        """Drain the repro queue until empty (one finding per iteration).

        Returns the number of findings processed in this batch.
        """
        processed = 0
        while True:
            batch = self.mcp.get_repro_queue()
            if not batch:
                break
            for finding in batch:
                try:
                    self._process_one_finding(finding)
                except Exception as e:  # noqa: BLE001
                    LOG.exception(
                        "repro pipeline crashed for finding %s: %s",
                        finding.finding_id, e,
                    )
                processed += 1
        return processed

    def _process_one_finding(self, finding: FindingRecord) -> None:
        LOG.info(
            "repro: pulling finding %s zone=%s severity=%s",
            finding.finding_id, finding.zone_id, finding.severity,
        )
        # 1. Replay + minimize
        minimize: MinimizeResult = self.replay_minimizer.replay_and_minimize(finding)
        if minimize.downgraded_to_suspicious:
            LOG.info("finding %s downgraded to suspicious — parked, no doc",
                      finding.finding_id)
            # No repro_package is pushed — the queue side simply drops it.
            return

        # 2. Root cause (severity-gated inside the locator)
        rc: RootCauseResult = self.root_cause.locate(
            zone_id=finding.zone_id,
            severity=finding.severity,
            minimal_transcript=minimize.minimal_transcript,
            evidence=minimize.evidence,
        )

        # 3. Write the markdown repro document
        vuln_id = mint_vuln_id()
        writer_input = ReproWriterInput(
            vuln_id=vuln_id,
            title=_title_from_finding(finding),
            severity=finding.severity,
            summary=_summary_from_finding(finding, minimize),
            zone_id=finding.zone_id,
            minimal_transcript=minimize.minimal_transcript,
            repro_rate=minimize.repro_rate,
            replays_total=minimize.attempts_total,
            replays_successful=minimize.successful_attempts,
            evidence=minimize.evidence,
            root_cause=rc if not rc.skipped else None,
            ideas_used=[(finding.idea_id, finding.source_mode, finding.zone_id)],
            suggested_mitigations=_mitigations_from_evidence(minimize, rc),
            nemoclaw_version=self.cfg.nemoclaw.version,
        )
        doc = self.repro_writer.write(writer_input)

        # 4. Cold-verify with a rewrite hook so diagnostics shape later attempts
        def _rewrite_fn(prev_md: str, diag: FailureDiagnostic) -> str:
            return _rewrite_with_diagnostic(prev_md, diag, writer_input,
                                              self.repro_writer)

        cold: ColdVerifyResult = self.cold_verifier.verify(
            zone_id=finding.zone_id,
            markdown=doc.markdown,
            rewrite_fn=_rewrite_fn,
        )

        # 5. Push the repro package to the MCP
        # A no-result root cause still returns a list containing one
        # "(unknown)" FixSite — filter those so affected_paths is None
        # rather than a list of placeholders.
        sites = [s for s in rc.candidate_fix_sites if s.file != "(unknown)"]
        affected_paths = sites or None
        package_input = ReproPackageInput(
            finding_id=finding.finding_id,
            vuln_id=vuln_id,
            title=writer_input.title,
            severity=finding.severity,
            repro_rate=minimize.repro_rate,
            minimal_steps=doc.minimal_steps,
            affected_zone=finding.zone_id,
            affected_paths=affected_paths,
            ideas_used=[finding.idea_id],
            transcripts={
                "original": minimize.original_transcript,
                "minimal": minimize.minimal_transcript,
            },
            suggested_mitigations=writer_input.suggested_mitigations,
            repro_document_md=doc.markdown,
            cold_verified=cold.cold_verified,
            ready_for_blue=cold.cold_verified,
        )
        package_id = self.mcp.push_repro_package(package_input)
        LOG.info(
            "repro: published package %s vuln_id=%s cold_verified=%s ready=%s",
            package_id, vuln_id, cold.cold_verified, package_input.ready_for_blue,
        )

        # 6. Side effects: coverage bump for the zone (we tested it),
        #    alert if cold-verified + high severity.
        try:
            self.mcp.update_zone_coverage(finding.zone_id, 0.05)
        except Exception as e:  # noqa: BLE001
            LOG.warning("update_zone_coverage failed: %s", e)
        if cold.cold_verified and severity_at_least(
            finding.severity, self.alert_severity_floor
        ):
            self.mcp.send_alert(
                f"[REPRO READY / {finding.severity}] {vuln_id} — "
                f"{writer_input.title} (zone {finding.zone_id})",
                severity=finding.severity,
            )

    # ==================================================================
    # process_blue_queue
    # ==================================================================
    def process_blue_queue(self) -> int:
        """Drain the blue team queue once.

        Returns the number of patches APPROVED (not generated) in this
        batch. Approved patches are committed via add_regression_test +
        coverage reset + alert.
        """
        packages = list(self.mcp.get_blue_team_queue())
        if not packages:
            return 0
        tasks = self.triage.triage(packages)
        approved = 0
        for task in tasks:
            outcome = self._patch_task(task)
            patched = outcome is not None and outcome.approved
            if patched:
                approved += 1
            # Transition each package out of "queued" so the next call to
            # get_blue_team_queue() (which only returns queued packages)
            # does not re-triage and re-patch the same work every cycle.
            # Statuses per schema.sql: queued|triaged|patching|verified.
            new_status = "verified" if patched else "triaged"
            for pkg in task.packages:
                try:
                    self.mcp.mark_repro_package_status(
                        pkg.package_id, new_status,
                    )
                except Exception as e:  # noqa: BLE001
                    LOG.warning(
                        "mark_repro_package_status(%s, %s) failed: %s",
                        pkg.package_id, new_status, e,
                    )
        return approved

    def _patch_task(self, task: FixTask) -> VerifyOutcome | None:
        max_attempts = self.cfg.blue_team.patch_verify_max_attempts
        attempts_used = self._task_attempt_count.get(task.task_id, 0)
        if attempts_used >= max_attempts:
            LOG.warning("task %s: already exhausted %d attempts — skipping",
                          task.task_id, attempts_used)
            return None

        candidates = self.patch_generator.generate_for_task(task)
        if not candidates:
            LOG.info("task %s: no patch candidates produced", task.task_id)
            return None

        for cand in candidates:
            attempts_used = self._task_attempt_count.get(task.task_id, 0)
            if attempts_used >= max_attempts:
                LOG.info("task %s: per-task attempt cap %d reached",
                          task.task_id, max_attempts)
                break
            pair = self.test_generator.generate(task.primary_package, cand)
            outcome = self.patch_verifier.verify(
                patch=cand, package=task.primary_package, test_pair=pair,
            )
            # The attempt cap counts genuine verification attempts. A
            # candidate rejected at the cheap structural `gate_diff_applies`
            # check never reached real verification — don't burn an attempt
            # on it.
            if outcome.failed_gate != "gate_diff_applies":
                self._task_attempt_count[task.task_id] = attempts_used + 1
            if outcome.approved:
                self._on_patch_approved(task, cand, pair, outcome)
                return outcome
            LOG.info(
                "task %s: patch %s rejected at %s — %s",
                task.task_id, cand.patch_id, outcome.failed_gate,
                outcome.notes,
            )
        # All candidates failed — escalate.
        self._on_task_exhausted(task)
        return None

    def _on_patch_approved(
        self,
        task: FixTask,
        patch: PatchCandidate,
        pair: RegressionTestPair,
        outcome: VerifyOutcome,
    ) -> None:
        # 1. Add the positive regression test to the permanent suite.
        try:
            test_id = self.mcp.add_regression_test(pair.positive_test)
        except Exception as e:  # noqa: BLE001
            LOG.warning("add_regression_test failed: %s", e)
            test_id = "(uncommitted)"

        # 2. Reset zone coverage to 0.3 per spec §4.4.
        try:
            self._reset_zone_coverage(patch.zone_id)
        except Exception as e:  # noqa: BLE001
            LOG.warning("coverage reset failed for %s: %s", patch.zone_id, e)

        # 3. Send alert.
        self.mcp.send_alert(
            f"[PATCH APPROVED / {task.severity}] task={task.task_id} "
            f"patch={patch.patch_id} approach={patch.approach!r} "
            f"vulns={','.join(task.vuln_ids)} (zone {patch.zone_id})",
            severity=task.severity,
        )

        LOG.info(
            "patch APPROVED: task=%s patch=%s test=%s vulns=%s notes=%s",
            task.task_id, patch.patch_id, test_id,
            task.vuln_ids, outcome.notes,
        )

    def _reset_zone_coverage(self, zone_id: str) -> None:
        """Snap the zone's coverage score to 0.3.

        `update_zone_coverage` takes a DELTA, not an absolute value — to
        snap we need to know the current score. We use get_coverage_gaps
        with a high top_n to find it; this is the spec-mandated behavior
        (§4.4: "on patch, reset to 0.3").
        """
        gaps = list(self.mcp.get_coverage_gaps(top_n=999))
        for g in gaps:
            if g.zone_id == zone_id:
                delta = 0.3 - g.coverage_score
                self.mcp.update_zone_coverage(zone_id, delta)
                return
        # Zone not in the gap list — just push +0.3 as a fallback.
        self.mcp.update_zone_coverage(zone_id, 0.3)

    def _on_task_exhausted(self, task: FixTask) -> None:
        msg = (
            f"[PATCH STUCK / {task.severity}] task={task.task_id} "
            f"vulns={','.join(task.vuln_ids)} — all candidate patches "
            f"failed verification. Manual review required."
        )
        LOG.warning(msg)
        try:
            self.mcp.send_alert(msg, severity=task.severity)
        except Exception as e:  # noqa: BLE001
            LOG.warning("send_alert(stuck) failed: %s", e)

    # ==================================================================
    # run_regression
    # ==================================================================
    def run_regression(self) -> None:
        result: RegressionRunResult = self.regression_runner.run()
        if result.newly_failing:
            self.mcp.send_alert(
                f"[REGRESSION / high] {len(result.newly_failing)} test(s) "
                f"newly failing: {','.join(result.newly_failing[:10])}",
                severity="high",
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _title_from_finding(finding: FindingRecord) -> str:
    """Short, human-readable title for the vuln document."""
    base = (finding.idea_summary or "").split(":", 1)[0].strip()
    return base[:80] or f"Vulnerability in {finding.zone_id}"


def _summary_from_finding(
    finding: FindingRecord, minimize: MinimizeResult,
) -> str:
    return (
        f"During cycle {finding.cycle_id} an attacker targeting "
        f"{finding.zone_id} produced a {finding.failure_class} via the "
        f"{finding.source_mode} ideation mode. The vulnerability "
        f"reproduces at a rate of "
        f"{minimize.successful_attempts}/{minimize.attempts_total} "
        f"({minimize.repro_rate * 100:.0f}%) across fresh victim "
        f"instances."
    )


def _mitigations_from_evidence(
    minimize: MinimizeResult, rc: RootCauseResult,
) -> list[str]:
    """Suggest mitigations from the triggered Tier 1 check name + zone."""
    mitigations: list[str] = []
    triggered_names = {c.check_name for c in minimize.evidence if c.triggered}
    table = {
        "filesystem_breach":
            "Pre-resolve symlinks and canonicalize paths before the policy "
            "boundary check.",
        "network_violation":
            "Tighten the domain allowlist; reject CNAME chains crossing "
            "policy boundaries.",
        "process_escape":
            "Add the offending syscall to the seccomp deny list and verify "
            "default_action=deny.",
        "permission_escalation":
            "Re-check capabilities at call time rather than caching grants "
            "across role transitions.",
        "pii_in_cloud_route":
            "Tighten the PII regex set and add a fallback NER pass before "
            "cloud routing.",
        "policy_modification":
            "Make the policy directory read-only at the OS level for the "
            "agent user.",
    }
    for name in triggered_names:
        if name in table:
            mitigations.append(table[name])
    if rc and rc.candidate_fix_sites and not rc.skipped:
        top = rc.candidate_fix_sites[0]
        if top.file != "(unknown)":
            mitigations.append(
                f"See candidate fix site `{top.file}` (confidence "
                f"{top.confidence:.2f})."
            )
    return mitigations or [
        "Manual review required — automated checks did not produce a "
        "concrete mitigation."
    ]


def _rewrite_with_diagnostic(
    prev_md: str,
    diag: FailureDiagnostic,
    writer_input: ReproWriterInput,
    writer: ReproWriter,
) -> str:
    """Re-emit the markdown with a 'Cold-Verifier Diagnostic' section
    inserted at the top of the Reproduction Steps section.

    The diagnostic includes which step failed and why, so the next cold
    agent has an explicit hint about the ambiguity. We do NOT regenerate
    the steps — those are pinned to the minimal transcript by design.
    """
    note = (
        f"\n> ⚠️  **Cold-verifier diagnostic (attempt {diag.attempt}):** "
        f"step {diag.failed_step or 'n/a'} — {diag.reason}. "
        f"_{diag.notes}_\n"
    )
    # Insert directly under the "## Reproduction Steps" heading.
    marker = "## Reproduction Steps"
    if marker in prev_md:
        before, _, after = prev_md.partition(marker)
        return f"{before}{marker}{note}{after}"
    # Fall back: append at the end.
    return prev_md + "\n\n" + note


__all__ = ["Pipeline"]
