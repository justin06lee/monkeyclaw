"""NemoClaw-backed victim provisioner.

Shells out to the `nemoclaw` CLI to spin up a fresh sandbox + OpenClaw agent
for each lane. The CLI must be on PATH (installed via the official installer).

For the dev path where NemoClaw isn't available locally, see `MockProvisioner`.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from interfaces.provisioning import (
    ProvisioningError,
    VictimConfig,
    VictimInstance,
    VictimProvisioner,
)

LOG = logging.getLogger("monkeyclaw.provisioning")


def _now() -> str:
    return datetime.now(UTC).isoformat()


class NemoClawProvisioner(VictimProvisioner):
    """Provision via the real `nemoclaw` CLI.

    NemoClaw v0.1 alpha is interactive by default; we set
    NEMOCLAW_NON_INTERACTIVE=1 to run inside our orchestrator.
    """

    def __init__(self, cli_binary: str = "nemoclaw",
                 repo_path: str | None = None,
                 default_timeout_s: int = 120) -> None:
        self.cli = cli_binary
        self.repo_path = Path(repo_path).expanduser() if repo_path else None
        self.default_timeout_s = default_timeout_s
        self._instances: dict[str, VictimInstance] = {}

    # ------------------------------------------------------------------
    def provision_victim(self, config: VictimConfig) -> VictimInstance:
        if not shutil.which(self.cli) and self.repo_path is None:
            raise ProvisioningError(
                f"nemoclaw CLI not found on PATH and no repo_path configured. "
                f"Install with `curl -fsSL https://www.nvidia.com/nemoclaw.sh | bash` "
                f"or set nemoclaw.repo_path in config."
            )
        instance_id = f"VICT-{uuid.uuid4().hex[:10]}"
        sandbox_name = f"mc-{instance_id.lower()}"

        env = {**os.environ,
               "NEMOCLAW_NON_INTERACTIVE": "1",
               "NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE": "1",
               **config.env}

        # Note: the real CLI surface depends on the alpha version. We invoke
        # `nemoclaw sandbox create --name ... --policy ... --agent-config ...`
        # which mirrors the documented `nemoclaw onboard` pipeline. If the
        # actual subcommand differs in a given NemoClaw build, this method
        # is the one place that needs updating.
        cmd = [
            self.cli, "sandbox", "create",
            "--name", sandbox_name,
            "--policy", config.policy_path,
            "--agent-config", config.agent_config_path,
            "--agent-type", config.agent_type,
        ]
        if config.patch_diff:
            patch_path = self._materialize_patch(config.patch_diff)
            cmd.extend(["--apply-patch", str(patch_path)])
        LOG.info("provisioning victim %s via %s", instance_id, " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd, env=env, capture_output=True, text=True,
                timeout=self.default_timeout_s, cwd=self.repo_path,
            )
        except subprocess.TimeoutExpired as e:
            raise ProvisioningError(f"timed out after {self.default_timeout_s}s") from e
        if proc.returncode != 0:
            raise ProvisioningError(
                f"nemoclaw exited {proc.returncode}:\nSTDERR: {proc.stderr}\nSTDOUT: {proc.stdout}"
            )
        # The CLI is expected to emit a JSON envelope on stdout in NON_INTERACTIVE
        # mode. Real alpha builds may print a banner instead — parse defensively.
        details = self._parse_create_output(proc.stdout)
        instance = VictimInstance(
            instance_id=instance_id,
            chat_endpoint=details.get("chat_endpoint", f"ipc:///tmp/openshell/{sandbox_name}.sock"),
            shell_endpoint=details.get("shell_endpoint"),
            status="running",
            sandbox_id=details.get("sandbox_id", sandbox_name),
            pid=details.get("pid"),
            started_at=_now(),
            metadata={"policy_path": config.policy_path,
                      "agent_config_path": config.agent_config_path,
                      "nemoclaw_version": config.nemoclaw_version},
        )
        self._instances[instance_id] = instance
        return instance

    def teardown_victim(self, instance_id: str) -> None:
        instance = self._instances.get(instance_id)
        if instance is None:
            return
        sandbox = instance.sandbox_id or instance_id
        try:
            subprocess.run(
                [self.cli, "sandbox", "destroy", "--name", sandbox, "--force"],
                check=False, capture_output=True, text=True, timeout=60,
            )
        except Exception as e:  # noqa: BLE001
            LOG.warning("teardown error for %s: %s", sandbox, e)
        instance.status = "stopped"

    def list_victims(self) -> list[VictimInstance]:
        return list(self._instances.values())

    # ------------------------------------------------------------------
    def _parse_create_output(self, stdout: str) -> dict:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {}

    def _materialize_patch(self, diff: str) -> Path:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False)
        f.write(diff)
        f.close()
        return Path(f.name)


class MockProvisioner(VictimProvisioner):
    """In-memory provisioner for tests and offline development."""

    def __init__(self) -> None:
        self._instances: dict[str, VictimInstance] = {}

    def provision_victim(self, config: VictimConfig) -> VictimInstance:
        iid = f"MOCK-{uuid.uuid4().hex[:10]}"
        instance = VictimInstance(
            instance_id=iid,
            chat_endpoint=f"mock://chat/{iid}",
            shell_endpoint=f"mock://shell/{iid}",
            status="running",
            sandbox_id=iid,
            started_at=_now(),
            metadata={"policy_path": config.policy_path,
                      "agent_type": config.agent_type},
        )
        self._instances[iid] = instance
        return instance

    def teardown_victim(self, instance_id: str) -> None:
        if instance_id in self._instances:
            self._instances[instance_id].status = "stopped"

    def list_victims(self) -> list[VictimInstance]:
        return list(self._instances.values())
