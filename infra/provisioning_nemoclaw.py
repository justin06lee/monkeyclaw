"""NemoClaw-backed victim provisioner.

Provisions against a single, persistent NemoClaw sandbox (`monkey-victim`)
using a snapshot-restore strategy rather than create/destroy:

- `provision_victim` restores the sandbox to a clean snapshot and restarts
  its gateway/agent (`recover`), giving each lane a genuinely fresh agent
  with no carried-over conversation or runtime state.
- `teardown_victim` is a no-op — the sandbox persists; state is reset on the
  next `provision_victim`.

Because there is exactly one sandbox, lanes must run serially (the lane
scheduler enforces this).

For the dev path where NemoClaw isn't available locally, see `MockProvisioner`.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infra.telemetry import TelemetryEmitter

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
    """Provision via the real `nemoclaw` CLI against one persistent sandbox.

    Per `provision_victim`:
      1. `nemoclaw <sandbox> snapshot restore <clean_snapshot>` — reset state
      2. `nemoclaw <sandbox> recover` — restart gateway + agent
      3. fetch the gateway auth token

    The resulting `VictimInstance.chat_endpoint` is the gateway WebSocket;
    `VictimClient` speaks the gateway protocol to it. The token is published
    in `metadata["gateway_token"]` and mirrored into `MC_GATEWAY_TOKEN` so
    `VictimClient(endpoint)` constructed without an explicit token still
    authenticates.
    """

    def __init__(
        self,
        cli_binary: str = "nemoclaw",
        *,
        sandbox_name: str = "monkey-victim",
        sandbox_namespace: str = "openshell",
        clean_snapshot: str = "clean-baseline",
        gateway_endpoint: str = "ws://localhost:18789/",
        gateway_container: str = "openshell-cluster-nemoclaw",
        snapshot_restore_timeout_s: int = 180,
        recover_timeout_s: int = 600,
        telemetry: TelemetryEmitter | None = None,
    ) -> None:
        self.cli = cli_binary
        # Optional TelemetryEmitter. When set, provisioning emits A5
        # policy events. Unset -> behavior is identical to before.
        self._telemetry = telemetry
        self.sandbox_name = sandbox_name
        self.sandbox_namespace = sandbox_namespace
        self.clean_snapshot = clean_snapshot
        self.gateway_endpoint = gateway_endpoint
        self.gateway_container = gateway_container
        self.snapshot_restore_timeout_s = snapshot_restore_timeout_s
        self.recover_timeout_s = recover_timeout_s
        self._instances: dict[str, VictimInstance] = {}

    # ------------------------------------------------------------------
    def provision_victim(self, config: VictimConfig) -> VictimInstance:
        if not shutil.which(self.cli):
            raise ProvisioningError(
                f"`{self.cli}` CLI not found on PATH. Install NemoClaw, or use "
                f"the MockProvisioner (orchestrator flag --use-mock-provisioner)."
            )
        if config.patch_diff:
            # The snapshot model resets to a fixed baseline; per-lane patch
            # application would need the patch baked into a snapshot. Not
            # supported on this path yet — surface it loudly rather than
            # silently running an unpatched victim.
            raise ProvisioningError(
                "VictimConfig.patch_diff is set, but the snapshot-based "
                "NemoClawProvisioner cannot apply per-lane patches. Build a "
                "patched snapshot and point `clean_snapshot` at it instead."
            )

        instance_id = f"VICT-{uuid.uuid4().hex[:10]}"
        if self._telemetry is not None:
            self._telemetry.policy_loaded(actor="provisioner",
                                          target=config.policy_path)
        LOG.info("provisioning victim %s: restoring %s -> %s, then recover",
                 instance_id, self.sandbox_name, self.clean_snapshot)

        # 1. Reset filesystem/state to the clean snapshot.
        self._run(
            [self.cli, self.sandbox_name, "snapshot", "restore", self.clean_snapshot],
            timeout=self.snapshot_restore_timeout_s,
            what="snapshot restore",
        )
        # 2. Restart the gateway + agent so no runtime/session state carries over.
        self._run(
            [self.cli, self.sandbox_name, "recover"],
            timeout=self.recover_timeout_s,
            what="recover",
        )
        # 3. Fetch the gateway auth token for VictimClient.
        token = self._run(
            [self.cli, self.sandbox_name, "gateway-token", "--quiet"],
            timeout=30,
            what="gateway-token",
        ).strip()
        if not token:
            raise ProvisioningError("gateway-token returned empty output")
        # Mirror into the environment so a bare VictimClient(endpoint) — as
        # constructed by the red/blue replay paths — picks it up.
        os.environ["MC_GATEWAY_TOKEN"] = token

        instance = VictimInstance(
            instance_id=instance_id,
            chat_endpoint=self.gateway_endpoint,
            shell_endpoint=None,
            status="running",
            sandbox_id=self.sandbox_name,
            started_at=_now(),
            metadata={
                "gateway_token": token,
                "sandbox_name": self.sandbox_name,
                "sandbox_namespace": self.sandbox_namespace,
                "sandbox_container": self.gateway_container,
                "nemoclaw_version": config.nemoclaw_version,
            },
        )
        self._instances[instance_id] = instance
        LOG.info("victim %s ready: endpoint=%s", instance_id, self.gateway_endpoint)
        return instance

    def connect_existing(self) -> VictimInstance:
        """Return a `VictimInstance` for the already-running sandbox WITHOUT
        restoring or restarting it.

        Used for ad-hoc, direct probing of the victim's live state — the
        operator (or MonkeyClaw itself) talks to the victim to try things
        out, rather than running a full reset-and-attack lane.
        """
        if not shutil.which(self.cli):
            raise ProvisioningError(f"`{self.cli}` CLI not found on PATH.")
        token = self._run(
            [self.cli, self.sandbox_name, "gateway-token", "--quiet"],
            timeout=30, what="gateway-token",
        ).strip()
        if not token:
            raise ProvisioningError("gateway-token returned empty output")
        os.environ["MC_GATEWAY_TOKEN"] = token
        instance_id = f"VICT-{uuid.uuid4().hex[:10]}"
        instance = VictimInstance(
            instance_id=instance_id,
            chat_endpoint=self.gateway_endpoint,
            shell_endpoint=None,
            status="running",
            sandbox_id=self.sandbox_name,
            started_at=_now(),
            metadata={
                "gateway_token": token,
                "sandbox_name": self.sandbox_name,
                "sandbox_namespace": self.sandbox_namespace,
                "sandbox_container": self.gateway_container,
            },
        )
        self._instances[instance_id] = instance
        return instance

    def teardown_victim(self, instance_id: str) -> None:
        # No-op: the sandbox is persistent and reset on the next
        # provision_victim. We only mark our local record stopped.
        instance = self._instances.get(instance_id)
        if instance is not None:
            instance.status = "stopped"
        LOG.debug("teardown_victim(%s): no-op (sandbox persists, reset on "
                  "next provision)", instance_id)

    def list_victims(self) -> list[VictimInstance]:
        return list(self._instances.values())

    # ------------------------------------------------------------------
    def _run(self, cmd: list[str], *, timeout: int, what: str) -> str:
        """Run a nemoclaw subcommand and return its stdout.

        Output is captured to temp files rather than pipes: `recover`
        daemonizes the dashboard port-forward (an ssh child) which inherits
        the parent's stdio. With `capture_output=True` (pipes), `subprocess`
        would block in `communicate()` waiting for that lingering child to
        close the pipe — long after `nemoclaw` itself exited. A file fd has
        no such EOF dependency.
        """
        try:
            with (tempfile.TemporaryFile(mode="w+") as out,
                  tempfile.TemporaryFile(mode="w+") as err):
                proc = subprocess.run(
                    cmd, stdout=out, stderr=err,
                    stdin=subprocess.DEVNULL, timeout=timeout,
                )
                out.seek(0)
                err.seek(0)
                stdout_text = out.read()
                stderr_text = err.read()
        except subprocess.TimeoutExpired as e:
            raise ProvisioningError(
                f"`{what}` timed out after {timeout}s ({' '.join(cmd)})"
            ) from e
        except OSError as e:
            raise ProvisioningError(f"`{what}` failed to start: {e}") from e
        if proc.returncode != 0:
            raise ProvisioningError(
                f"`{what}` exited {proc.returncode}: "
                f"{(stderr_text or stdout_text).strip()[:500]}"
            )
        return stdout_text


class MockProvisioner(VictimProvisioner):
    """In-memory provisioner for tests and offline development."""

    def __init__(self, telemetry: TelemetryEmitter | None = None) -> None:
        self._instances: dict[str, VictimInstance] = {}
        # Optional TelemetryEmitter. Unset -> behavior is identical to before.
        self._telemetry = telemetry

    def provision_victim(self, config: VictimConfig) -> VictimInstance:
        iid = f"MOCK-{uuid.uuid4().hex[:10]}"
        if self._telemetry is not None:
            self._telemetry.policy_loaded(actor="provisioner",
                                          target=config.policy_path)
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
