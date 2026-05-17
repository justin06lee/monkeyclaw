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
from infra.patch_builds_store import PatchBuildsStore
from interfaces.config_schema import MonkeyClawConfig
from interfaces.llm import LLMClient
from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.model_router import ModelRouter
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
from blue_team.patch_isolation import (
    PatchIsolation,
    build_demo_patched_replay_factory,
    build_patched_replay_factory,
    make_demo_patched_regression_replay_fn,
    sweep_orphaned_worktrees,
)
from blue_team.patch_isolation import (
    PatchIsolationConfig as PatchIsolationRuntimeConfig,
)
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
from blue_team.code_graph_sqlite import PythonCodeGraph
from blue_team.path_tracer import PathTracer
from blue_team.repro_writer import ReproWriter, ReproWriterInput
from blue_team.root_cause import RootCauseConfig, RootCauseLocator, RootCauseResult
from blue_team.test_generator import RegressionTestPair, TestGenerator
from blue_team.triage import FixTask, TriageAgent, TriageConfig
from infra.approval_service import ApprovalService
from infra.notifications import AlertDispatcher
from infra.pr_generator import PRGenerator
from purple_team.generalization_loop import (
    GeneralizationConfig,
    GeneralizationLoop,
    load_generalization_config,
)

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
        cfg: MonkeyClawConfig | None = None,
        llm: LLMClient | None = None,
        router: ModelRouter | None = None,
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
        generalization_cfg: GeneralizationConfig | None = None,
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
            self.cfg = cfg or MonkeyClawConfig()

        if router is not None:
            self.router = router
        elif runtime is not None:
            self.router = runtime.router
        else:
            self.router = ModelRouter(self.cfg, mcp=self.mcp)

        def _client(role: str) -> LLMClient:
            return llm if llm is not None else self.router.client_for(role)

        # Default `self.llm` kept for any code path still reading it directly.
        self.llm = llm or self.router.client_for("patch_generation")
        self.policy = policy or policy_from_config(self.cfg)
        self.alert_severity_floor = alert_severity_floor

        # ---- Patch isolation (real disposable-worktree verification) ----
        pi_cfg = self.cfg.blue_team.patch_isolation
        self.patch_isolation: PatchIsolation | None = None
        if pi_cfg.enabled and pi_cfg.nemoclaw_repo_path:
            mcp_db = (getattr(self.mcp, "db", None)
                      or getattr(self.mcp, "_db", None))
            store = PatchBuildsStore(mcp_db) if mcp_db is not None else None
            self.patch_isolation = PatchIsolation(
                provisioner=self.provisioner, store=store,
                cfg=PatchIsolationRuntimeConfig(
                    nemoclaw_repo_path=pi_cfg.nemoclaw_repo_path,
                    base_ref=pi_cfg.base_ref,
                    build_timeout_s=pi_cfg.build_timeout_s,
                    worktree_root=pi_cfg.worktree_root))
            # Janitor sweep — reclaim worktrees leaked by a prior crash.
            sweep_orphaned_worktrees(pi_cfg.worktree_root, store)
        else:
            LOG.warning(
                "patch isolation disabled (enabled=%s, repo=%s) — patch "
                "verification runs on the mock surface (isolation_mode=mock)",
                pi_cfg.enabled, pi_cfg.nemoclaw_repo_path)

        # ---- Component wiring (every component injectable for tests) ----
        self.repro_writer = repro_writer or ReproWriter()
        self.replay_minimizer = replay_minimizer or ReplayMinimizer(
            provisioner=self.provisioner,
            cfg=ReplayMinimizerConfig.from_runtime_cfg(
                self.cfg.repro, self.cfg.nemoclaw,
            ),
            policy=self.policy,
        )
        if root_cause is not None:
            self.root_cause = root_cause
        else:
            # The tracer needs a Database handle — for code-graph reads
            # (PythonCodeGraph) and executed_paths persistence. The MCP server
            # exposes one as `.db`; mock MCPs do not, in which case the
            # locator falls back to its keyword (degraded) path.
            tracer = None
            cg = self.cfg.repro.code_graph
            mcp_db = getattr(self.mcp, "db", None)
            if cg.enabled and mcp_db is not None:
                tracer = PathTracer(
                    graph=PythonCodeGraph(mcp_db),
                    mcp=self.mcp,
                    max_hops=cg.max_hops,
                    db=mcp_db,
                )
            self.root_cause = RootCauseLocator(
                llm=_client("root_cause"), mcp=self.mcp,
                cfg=RootCauseConfig(
                    severity_threshold=self.cfg.repro.root_cause_severity_threshold,
                    path_rank_weight=cg.path_rank_weight,
                    llm_conf_weight=cg.llm_conf_weight,
                    max_hops=cg.max_hops,
                ),
                tracer=tracer,
            )
        self.cold_verifier = cold_verifier or ColdVerifier(
            llm=_client("cold_verification"), provisioner=self.provisioner,
            cfg=ColdVerifierConfig.from_runtime_cfg(
                self.cfg.repro, self.cfg.nemoclaw,
            ),
            policy=self.policy,
        )
        self.triage = triage or TriageAgent(TriageConfig())
        self.patch_generator = patch_generator or PatchGenerator(
            llm=_client("patch_generation"), mcp=self.mcp,
            cfg=PatchGeneratorConfig.from_blue_team_cfg(self.cfg.blue_team),
        )
        self.test_generator = test_generator or TestGenerator()
        # gate_detection consumes the purple-team detection oracle; inject it
        # only when the purple layer is enabled. Absent → gate auto-skips.
        detection_oracle = None
        purple_cfg = getattr(self.cfg, "purple", None)
        if purple_cfg is not None and getattr(purple_cfg, "enabled", False):
            try:
                from purple_team.detection_oracle import DetectionOracle
                detection_oracle = DetectionOracle()
            except Exception as e:  # noqa: BLE001
                LOG.warning("purple detection oracle unavailable: %s", e)
                detection_oracle = None
        # Patched-replay factory selection:
        #   1. Real disposable-worktree isolation when a NemoClaw checkout is
        #      wired (isolation_mode="live").
        #   2. Demo / zero-credential mode (`red.demo_playbooks`): no checkout,
        #      so verify against a PATCHED mock victim — the provisioner honors
        #      `patch_diff` by fixing the planted flaws, so a generated patch
        #      genuinely blocks the recorded attack (isolation_mode="mock").
        #   3. Otherwise None → the unpatched in-process mock replay default.
        if self.patch_isolation is not None:
            patched_replay_factory = build_patched_replay_factory(
                self.patch_isolation)
        elif getattr(self.cfg.red, "demo_playbooks", False):
            patched_replay_factory = build_demo_patched_replay_factory(
                self.provisioner)
        else:
            patched_replay_factory = None
        self.patch_verifier = patch_verifier or PatchVerifier(
            mcp=self.mcp, provisioner=self.provisioner,
            cfg=PatchVerifierConfig.from_blue_team_cfg(self.cfg.blue_team),
            policy=self.policy,
            detection_oracle=detection_oracle,
            isolation=self.patch_isolation,
            patched_replay_factory=patched_replay_factory,
        )
        # The permanent regression suite records FIXED vulnerabilities. In
        # demo / zero-credential mode there is no real patched build, so the
        # runner replays against a patched mock victim — otherwise every
        # fixed-vuln test would re-trigger on the unpatched mock surface.
        regression_replay_fn = None
        if (self.patch_isolation is None
                and getattr(self.cfg.red, "demo_playbooks", False)):
            regression_replay_fn = make_demo_patched_regression_replay_fn(
                self.provisioner)
        self.regression_runner = regression_runner or RegressionRunner(
            mcp=self.mcp, provisioner=self.provisioner, policy=self.policy,
            replay_fn=regression_replay_fn,
        )

        # Track patches per task so we don't retry the same patch_id
        # forever. Bounded by config.blue_team.patch_verify_max_attempts.
        self._task_attempt_count: dict[str, int] = {}

        # Patch generalization loop (patch-generalization-loop spec §10).
        self.generalization_cfg = (
            generalization_cfg or load_generalization_config())
        self.generalization_enabled = self.generalization_cfg.enabled

        # Severity-gated approval service — verified patches route through
        # this gate before being finalized (approval spec §11).
        self.approval_service = ApprovalService(
            mcp=self.mcp,
            dispatcher=AlertDispatcher(self.cfg.notifications),
            cfg=self.cfg.approvals,
        )
        # Patches held pending approval keep their PatchCandidate +
        # RegressionTestPair + FixTask here so the resolved-request poll can
        # finalize them later (the pipeline does not persist patch rows).
        self._pending_patches: dict[str, PatchCandidate] = {}
        self._pending_test_pairs: dict[str, RegressionTestPair] = {}
        self._pending_tasks: dict[str, FixTask] = {}
        self._pending_outcomes: dict[str, VerifyOutcome] = {}
        # patch_id -> committed regression test_id. A patch's positive
        # regression test is committed once, the moment verification proves
        # the patch blocks the finding — independent of the ship/approval
        # decision (the test guards "this finding is reproducibly blocked").
        # Tracked so finalize / unconverged paths don't double-insert it.
        self._committed_regression_tests: dict[str, str] = {}

        # Optional post-approval PR drafting (approval spec §6.3).
        self.pr_generator = PRGenerator(
            base_branch=self.cfg.approvals.pr_base_branch)

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
            # The queue row is in 'processing' (it was claimed) — explicitly
            # fail it so the stale-claim sweep does not later requeue it and
            # so the dashboard shows it needs review. Closes a real leak.
            try:
                self.mcp.mark_repro_queue_status(
                    finding.finding_id, "failed",
                    worker_id="repro_pipeline")
            except Exception as e:  # noqa: BLE001
                LOG.warning("failed to mark queue row failed: %s", e)
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
        # Lapse stale requests and finalize any newly-resolved approvals
        # before draining the queue (approval spec §11).
        finalized_resolved = self._finalize_resolved_approvals()

        packages = list(self.mcp.get_blue_team_queue())
        if not packages:
            return finalized_resolved
        tasks = self.triage.triage(packages)
        approved = finalized_resolved
        for task in tasks:
            outcome = self._patch_task(task)
            patched = outcome is not None and outcome.approved
            # Count only finalized patches — a verified-but-PENDING patch is
            # held by the approval gate, not finalized (approval spec §11).
            if patched and outcome is not None and outcome.finalized:
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

        # Advance the package lifecycle: queued -> triaged -> patching.
        pkg_id = task.primary_package.package_id
        try:
            self.mcp.mark_repro_package_status(pkg_id, "triaged")
            self.mcp.mark_repro_package_status(pkg_id, "patching")
        except Exception as e:  # noqa: BLE001
            LOG.warning("package %s lifecycle advance failed: %s", pkg_id, e)

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
                # The patch passed every gate — commit its positive
                # regression test now. The test asserts the finding stays
                # blocked; it is a permanent guard regardless of whether the
                # patch is auto-allowed or held pending human approval.
                self._commit_regression_test(cand.patch_id, pair.positive_test)
                gen = None
                try:
                    gen = self._run_generalization(
                        cand, task.primary_package, pair, task)
                except Exception as e:  # noqa: BLE001
                    LOG.warning("generalization loop crashed for task %s: "
                                "%s — finalizing the verified patch",
                                task.task_id, e)
                if gen is None or gen.status == "generalized":
                    finalized = self._on_patch_generalized(
                        task, cand, pair, outcome, gen)
                else:  # unconverged
                    finalized = self._on_patch_unconverged(
                        task, cand, pair, outcome, gen)
                # A PENDING patch passed verification but is not finalized;
                # signal that to process_blue_queue via `finalized`.
                outcome.finalized = finalized
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
    ) -> bool:
        """A patch passed the six gates — gate it through the approval
        service before finalizing (approval spec §11).

        Returns True only when the patch was finalized this call (an
        auto-allow); a PENDING patch is held and returns False.
        """
        generalization = getattr(outcome, "generalization_status", None)
        try:
            decision = self.approval_service.request(
                patch, severity=task.severity, generalization=generalization)
        except Exception as e:  # noqa: BLE001
            # A service crash leaves the patch in the safe state — unfinalized.
            LOG.exception("approval service failed for %s: %s",
                          patch.patch_id, e)
            self._safe_mark_patch(patch.patch_id, "pending_approval")
            return False

        if decision.decision == "ALLOW":
            self._finalize_patch(
                task.task_id, task.severity, list(task.vuln_ids),
                patch.zone_id, patch, pair.positive_test, outcome.notes,
                task.primary_package)
            return True
        if decision.decision == "PENDING":
            LOG.info("patch %s held pending approval (request %s)",
                     patch.patch_id, decision.request_id)
            self._safe_mark_patch(patch.patch_id, "pending_approval")
            self._pending_patches[patch.patch_id] = patch
            self._pending_test_pairs[patch.patch_id] = pair
            self._pending_tasks[patch.patch_id] = task
            self._pending_outcomes[patch.patch_id] = outcome
            return False
        # DENY (cannot occur from request(), kept for completeness).
        self._safe_mark_patch(patch.patch_id, "rejected")
        self._on_task_exhausted(task)
        return False

    def _commit_regression_test(self, patch_id: str, positive_test) -> str:  # noqa: ANN001
        """Persist a patch's positive regression test to the permanent suite,
        exactly once per patch. Returns the test_id (or a sentinel on failure).

        A verified patch commits its test the moment the gates pass; later
        finalize / unconverged paths call this again and get the same id back
        rather than inserting a duplicate row."""
        existing = self._committed_regression_tests.get(patch_id)
        if existing is not None:
            return existing
        try:
            test_id = self.mcp.add_regression_test(positive_test)
        except Exception as e:  # noqa: BLE001
            LOG.warning("add_regression_test failed: %s", e)
            return "(uncommitted)"
        self._committed_regression_tests[patch_id] = test_id
        return test_id

    def _safe_mark_patch(self, patch_id: str, status: str) -> None:
        """mark_patch_status, swallowing FSM/transition errors — used for the
        approval-gate statuses which the patch may not have an FSM edge for."""
        try:
            self.mcp.mark_patch_status(patch_id, status)
        except Exception as e:  # noqa: BLE001
            LOG.warning("mark_patch_status(%s, %s) failed: %s",
                        patch_id, status, e)

    def _finalize_patch(
        self,
        task_id: str,
        severity: str,
        vuln_ids: list[str],
        zone_id: str,
        patch: PatchCandidate,
        positive_test,  # noqa: ANN001 — RegressionTestInput
        notes: str,
        package,  # noqa: ANN001 — ReproPackage
    ) -> None:
        """Commit an approved patch: regression test, coverage reset, alert,
        lifecycle close. The original _on_patch_approved body."""
        # 1. Add the positive regression test to the permanent suite.
        #    Idempotent: a verified patch already committed its test at
        #    verification time, so this just reuses that test_id.
        test_id = self._commit_regression_test(patch.patch_id, positive_test)

        # 2. Reset zone coverage to 0.3 per spec §4.4.
        try:
            self._reset_zone_coverage(zone_id)
        except Exception as e:  # noqa: BLE001
            LOG.warning("coverage reset failed for %s: %s", zone_id, e)

        # 3. Send alert.
        self.mcp.send_alert(
            f"[PATCH APPROVED / {severity}] task={task_id} "
            f"patch={patch.patch_id} approach={patch.approach!r} "
            f"vulns={','.join(vuln_ids)} (zone {zone_id})",
            severity=severity,
        )

        LOG.info(
            "patch APPROVED: task=%s patch=%s test=%s vulns=%s notes=%s",
            task_id, patch.patch_id, test_id, vuln_ids, notes,
        )

        # 3b. Optional post-approval PR draft (approval spec §6.3).
        if self.cfg.approvals.auto_pr:
            self._maybe_open_pr(patch, package)

        # 4. Close the lifecycle loop: package patching->verified, and each
        #    linked finding in_progress->patched->verified.
        if package is not None:
            try:
                self.mcp.mark_repro_package_status(
                    package.package_id, "verified")
            except Exception as e:  # noqa: BLE001
                LOG.warning("mark package %s verified failed: %s",
                            package.package_id, e)
            try:
                self.mcp.mark_finding_patched(package.finding_id)
            except Exception as e:  # noqa: BLE001
                LOG.warning("finding %s verify transition failed: %s",
                            package.finding_id, e)

    def _maybe_open_pr(self, patch: PatchCandidate, package) -> None:  # noqa: ANN001
        """Draft a PR for an approved patch — non-fatal on any failure."""
        try:
            events = self.mcp.get_approval_events(patch.patch_id)
            allow = next((e for e in events if e.decision == "allow"), None)
            if allow is None:
                return
            draft = self.pr_generator.draft(patch, package, allow)
            if draft is None:
                self.mcp.send_alert(
                    f"[PR NOT OPENED] patch={patch.patch_id} — PR generation "
                    f"failed; open the PR by hand. Approval still stands.",
                    severity="medium")
                return
            LOG.info("PR drafted for %s: %s", patch.patch_id, draft.pr_url)
        except Exception as e:  # noqa: BLE001
            LOG.warning("auto-PR step failed for %s: %s", patch.patch_id, e)

    def _finalize_resolved_approvals(self) -> int:
        """Sweep expiry, then finalize patches whose approval is now `allow`.

        Patches held pending approval are tracked on this Pipeline instance
        (`_pending_patches`) — the pipeline does not persist patch rows, so
        the resolved poll walks the stash and consults the approval audit
        log for each. Returns the count finalized this pass.
        """
        try:
            self.approval_service.expire_stale()
        except Exception as e:  # noqa: BLE001
            LOG.warning("expire_stale failed: %s", e)

        finalized = 0
        for patch_id in list(self._pending_patches.keys()):
            patch = self._pending_patches[patch_id]
            try:
                events = self.mcp.get_approval_events(patch_id)
            except Exception as e:  # noqa: BLE001
                LOG.warning("get_approval_events failed for %s: %s",
                            patch_id, e)
                continue
            decisions = [e.decision for e in events]
            if "expired" in decisions:
                LOG.info("patch %s approval expired — abandoning", patch_id)
                self._safe_mark_patch(patch_id, "rejected")
                self._drop_pending(patch_id)
            elif "deny" in decisions:
                LOG.info("patch %s approval denied", patch_id)
                self._safe_mark_patch(patch_id, "rejected")
                self._drop_pending(patch_id)
            elif "allow" in decisions:
                self._safe_mark_patch(patch_id, "approved")
                self._finalize_patch_by_id(patch)
                finalized += 1
        return finalized

    def _drop_pending(self, patch_id: str) -> None:
        self._pending_patches.pop(patch_id, None)
        self._pending_test_pairs.pop(patch_id, None)
        self._pending_tasks.pop(patch_id, None)
        self._pending_outcomes.pop(patch_id, None)

    def _finalize_patch_by_id(self, patch: PatchCandidate) -> None:
        """Re-finalize a patch whose approval has resolved to `allow`, using
        the RegressionTestPair / FixTask stashed when it went PENDING."""
        pair = self._pending_test_pairs.get(patch.patch_id)
        task = self._pending_tasks.get(patch.patch_id)
        outcome = self._pending_outcomes.get(patch.patch_id)
        self._drop_pending(patch.patch_id)
        if pair is None or task is None:
            LOG.warning(
                "cannot finalize resolved patch %s: no stashed test pair/task",
                patch.patch_id)
            return
        notes = outcome.notes if outcome is not None else ""
        self._finalize_patch(
            task.task_id, task.severity, list(task.vuln_ids),
            patch.zone_id, patch, pair.positive_test, notes,
            task.primary_package)

    # ==================================================================
    # Patch generalization loop (patch-generalization-loop spec §10)
    # ==================================================================
    def _run_generalization(self, patch, package, test_pair, task):
        """Run the purple generalization loop on a verified patch. Returns a
        GeneralizationResult, or None if the loop is disabled.

        The verifier's replay function is `(transcript, victim) -> LaneResult`
        and its judge is `(lane, zone, policy) -> (checks, semantic)`; the
        loop's MutationReplayer/BypassDetector use the simpler `(transcript)`
        and `(lane) -> (verdict, checks)` contracts. We bridge them here with
        adapters so the loop replays against exactly the patched surface the
        verifier proved, with the same oracle gate1_regression uses."""
        if not self.generalization_enabled:
            return None

        verifier = self.patch_verifier
        zone = getattr(package, "affected_zone", "")
        base_replay = verifier.patched_replay_factory(patch)

        # Provision one victim for the whole loop's replays.
        from interfaces.provisioning import VictimConfig

        victim = self.provisioner.provision_victim(VictimConfig(
            nemoclaw_version="alpha",
            policy_path="configs/default_policy.yaml",
            agent_type="coding_assistant",
            agent_config_path="configs/default_agent.yaml",
            enable_monitoring=False,
        ))

        def _replay_fn(transcript):
            return base_replay(transcript, victim)

        def _judge_fn(lane):
            checks, semantic = verifier.judge_fn(lane, zone, self.policy)
            triggered = semantic or any(c.triggered for c in checks)
            return ("confirmed" if triggered else "clean", checks)

        try:
            loop = GeneralizationLoop(
                mcp=self.mcp,
                replay_fn=_replay_fn,
                judge_fn=_judge_fn,
                patch_generator=self.patch_generator,
                patch_verifier=verifier,
                cfg=self.generalization_cfg)
            return loop.run(patch, package, test_pair, task)
        finally:
            try:
                self.provisioner.teardown_victim(victim.instance_id)
            except Exception as e:  # noqa: BLE001
                LOG.warning("generalization victim teardown failed: %s", e)

    def _on_patch_generalized(self, task, patch, pair, outcome, gen) -> bool:
        """Finalize a GENERALIZED patch. If a re-patch round happened (the
        patch changed from round 0), additionally commit one regression test
        per bypassed-and-now-closed operator so the closed bypasses stay
        closed (spec §10)."""
        outcome.generalization_status = "generalized" if gen is not None else None
        finalized = self._on_patch_approved(task, patch, pair, outcome)
        if gen is None:
            return finalized
        bypassed_ops: set[str] = set()
        for rnd in gen.rounds:
            bypassed_ops.update(rnd.bypass_operators)
        for operator in sorted(bypassed_ops):
            bypass_test = self._make_bypass_regression_test(
                task, pair, operator)
            try:
                self.mcp.add_regression_test(bypass_test)
            except Exception as e:  # noqa: BLE001
                LOG.warning("closed-bypass test commit failed for %s: %s",
                            operator, e)
        return finalized

    def _make_bypass_regression_test(self, task, pair, operator):
        """A regression test asserting the `operator`-mutated variant of the
        finding stays blocked. Reuses the positive test's shape with an
        operator-tagged vuln id so the closed bypass is a permanent guard."""
        from dataclasses import replace

        _ = task
        base = pair.positive_test
        return replace(
            base,
            vuln_id=f"{base.vuln_id}-mut-{operator}",
        )

    def _on_patch_unconverged(self, task, patch, pair, outcome, gen) -> bool:
        """An UNCONVERGED generalization result: the last verified patch is
        retained (it still blocks the original finding) but the zone is NOT
        proven fixed. No coverage reset; route to the approval service for
        mandatory human review, per spec §10."""
        # The positive regression test for the literal finding is still
        # committed — the original transcript is blocked. Idempotent: the
        # verified patch already committed it at verification time.
        self._commit_regression_test(patch.patch_id, pair.positive_test)
        ops = sorted({r.operator for r in gen.open_bypasses})
        self.mcp.send_alert(
            f"[PATCH UNCONVERGED / {task.severity}] task={task.task_id} "
            f"patch={patch.patch_id} reason={gen.reason} "
            f"open-bypass-operators={','.join(ops) or 'none'} — "
            f"generalization=unconverged, human review required; "
            f"coverage NOT reset for zone {patch.zone_id}",
            severity=task.severity,
        )
        LOG.warning("patch UNCONVERGED: task=%s patch=%s reason=%s "
                    "open_bypasses=%d", task.task_id, patch.patch_id,
                    gen.reason, len(gen.open_bypasses))
        outcome.generalization_status = "unconverged"
        return self._on_patch_approved(task, patch, pair, outcome)

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
        pkg_id = task.primary_package.package_id
        msg = (
            f"[PATCH STUCK / {task.severity}] task={task.task_id} "
            f"vulns={','.join(task.vuln_ids)} — all candidate patches "
            f"failed verification. Manual review required."
        )
        LOG.warning(msg)
        try:
            self.mcp.mark_repro_package_status(pkg_id, "stuck")
        except Exception as e:  # noqa: BLE001
            LOG.warning("mark package %s stuck failed: %s", pkg_id, e)
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
