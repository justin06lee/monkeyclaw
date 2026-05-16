"""Application bootstrap — wire infra components into a runnable system.

Used by both the orchestrator (`infra.orchestrator`) and the smoke tests.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from infra.config import load_config, setup_logging
from infra.database import Database
from infra.guardrails import PolicyEnforcer
from infra.mcp_server import MCPServer
from infra.notifications import AlertDispatcher
from infra.provisioning_nemoclaw import MockProvisioner, NemoClawProvisioner
from infra.sandbox_capabilities import probe as probe_capabilities
from interfaces.config_schema import MonkeyClawConfig
from interfaces.model_router import ModelRouter
from interfaces.provisioning import VictimProvisioner, set_provisioner

LOG = logging.getLogger("monkeyclaw.bootstrap")


@dataclass
class Runtime:
    """Container of all bootstrapped components."""
    cfg: MonkeyClawConfig
    db: Database
    mcp: MCPServer
    provisioner: VictimProvisioner
    alert_dispatcher: AlertDispatcher
    enforcer: PolicyEnforcer
    router: ModelRouter

    def shutdown(self) -> None:
        self.alert_dispatcher.close()
        self.db.close()


def boot(config_path: str | Path | None = None,
         use_mock_provisioner: bool = False) -> Runtime:
    cfg = load_config(config_path)
    setup_logging(cfg)
    # Mock/demo runs (planted-victim) use a SEPARATE database so they never
    # write fabricated findings into the real knowledge base. A real run
    # against a live sandbox always uses the configured db_path.
    db_path = cfg.storage.db_path
    if use_mock_provisioner:
        p = Path(db_path)
        db_path = str(p.with_name(f"{p.stem}-mock{p.suffix}"))
    db = Database(db_path)
    # Persistent memory — surface what carried over from prior runs so the
    # continuity is visible (the SQLite knowledge base survives restarts).
    try:
        nf = db.fetchone("SELECT COUNT(*) AS n FROM findings")
        nt = db.fetchone(
            "SELECT COUNT(*) AS n FROM regression_tests WHERE deprecated = 0")
        nz = db.fetchone("SELECT COUNT(*) AS n FROM surface_zones")
        print(f"[memory] Loaded {nf['n'] if nf else 0} findings, "
              f"{nt['n'] if nt else 0} regression tests, "
              f"{nz['n'] if nz else 0} zones from persistent memory "
              f"({db_path})", flush=True)
    except Exception as e:  # noqa: BLE001
        LOG.warning("could not read persistent memory: %s", e)
    dispatcher = AlertDispatcher(cfg.notifications)
    mcp = MCPServer(db, alert_sink=dispatcher.send)
    mcp.set_code_context(
        backend=cfg.code_context.backend,
        argyph_binary=cfg.code_context.argyph_binary,
        repo_path=cfg.nemoclaw.repo_path,
    )
    if use_mock_provisioner:
        provisioner: VictimProvisioner = MockProvisioner()
    else:
        caps = probe_capabilities(cfg.nemoclaw.cli_binary,
                                  cfg.nemoclaw.sandbox_name)
        if not caps.cli_present:
            LOG.warning(
                "`%s` CLI not found — falling back to MockProvisioner. "
                "Install NemoClaw to run against a live victim.",
                cfg.nemoclaw.cli_binary)
            provisioner = MockProvisioner()
        else:
            provisioner = NemoClawProvisioner(
                cli_binary=cfg.nemoclaw.cli_binary,
                sandbox_name=cfg.nemoclaw.sandbox_name,
                sandbox_namespace=cfg.nemoclaw.sandbox_namespace,
                clean_snapshot=cfg.nemoclaw.clean_snapshot,
                baseline_snapshot=cfg.nemoclaw.baseline_snapshot,
                gateway_endpoint=cfg.nemoclaw.gateway_endpoint,
                gateway_container=cfg.nemoclaw.gateway_container,
                snapshot_restore_timeout_s=(
                    cfg.nemoclaw.snapshot_restore_timeout_s),
                recover_timeout_s=cfg.nemoclaw.recover_timeout_s,
                work_area_dir=cfg.nemoclaw.work_area_dir,
                nemoclaw_repo_path=cfg.nemoclaw.repo_path,
                patch_build_timeout_s=cfg.nemoclaw.patch_build_timeout_s,
            )
    set_provisioner(provisioner)
    # A8 — one PolicyEnforcer per run; the orchestrator/CLI threads it into
    # the lane scheduler and per-lane harnesses.
    enforcer = PolicyEnforcer(cfg.guardrails)
    # The single LLM construction point — every pipeline component routes
    # through this instead of bare make_llm(). Shares the mcp handle so each
    # complete() writes a model_runs row.
    router = ModelRouter(cfg, mcp=mcp)
    return Runtime(cfg=cfg, db=db, mcp=mcp, provisioner=provisioner,
                    alert_dispatcher=dispatcher, enforcer=enforcer, router=router)
