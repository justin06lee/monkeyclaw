"""Application bootstrap — wire infra components into a runnable system.

Used by both the orchestrator (`infra.orchestrator`) and the smoke tests.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from infra.config import load_config, setup_logging
from infra.database import Database
from infra.mcp_server import MCPServer
from infra.notifications import AlertDispatcher
from infra.provisioning_nemoclaw import MockProvisioner, NemoClawProvisioner
from interfaces.config_schema import MonkeyClawConfig
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

    def shutdown(self) -> None:
        self.alert_dispatcher.close()
        self.db.close()


def boot(config_path: str | Path | None = None,
         use_mock_provisioner: bool = False) -> Runtime:
    cfg = load_config(config_path)
    setup_logging(cfg)
    db = Database(cfg.storage.db_path)
    dispatcher = AlertDispatcher(cfg.notifications)
    mcp = MCPServer(db, alert_sink=dispatcher.send)
    if use_mock_provisioner:
        provisioner: VictimProvisioner = MockProvisioner()
    else:
        provisioner = NemoClawProvisioner(
            cli_binary=cfg.nemoclaw.cli_binary,
            repo_path=cfg.nemoclaw.repo_path,
            default_timeout_s=cfg.nemoclaw.sandbox_create_timeout_s,
        )
    set_provisioner(provisioner)
    return Runtime(cfg=cfg, db=db, mcp=mcp, provisioner=provisioner,
                    alert_dispatcher=dispatcher)
