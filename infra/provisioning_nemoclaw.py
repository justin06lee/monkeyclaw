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

from demo.victims.registry import make_victim
from infra.sandbox_capabilities import probe as probe_capabilities
from interfaces.provisioning import (
    ProvisioningError,
    VictimConfig,
    VictimInstance,
    VictimProvisioner,
    VictimSnapshot,
)
from interfaces.victim_client import register, unregister

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
    in `metadata["gateway_token"]`; callers pass it to `VictimClient` from
    there rather than relying on a process-global env var.
    """

    def __init__(
        self,
        cli_binary: str = "nemoclaw",
        *,
        sandbox_name: str = "monkey-victim",
        sandbox_namespace: str = "openshell",
        clean_snapshot: str = "clean-baseline",
        baseline_snapshot: str = "clean-baseline",
        gateway_endpoint: str = "ws://localhost:18789/",
        gateway_container: str = "openshell-cluster-nemoclaw",
        snapshot_restore_timeout_s: int = 180,
        recover_timeout_s: int = 600,
        work_area_dir: str = "/tmp/monkeyclaw-work",
        nemoclaw_repo_path: str | None = None,
        patch_build_timeout_s: int = 900,
        telemetry: TelemetryEmitter | None = None,
    ) -> None:
        self.cli = cli_binary
        # Optional TelemetryEmitter. When set, provisioning emits A5
        # policy events. Unset -> behavior is identical to before.
        self._telemetry = telemetry
        self.sandbox_name = sandbox_name
        self.sandbox_namespace = sandbox_namespace
        self.clean_snapshot = clean_snapshot
        self.baseline_snapshot = baseline_snapshot
        self.gateway_endpoint = gateway_endpoint
        self.gateway_container = gateway_container
        self.snapshot_restore_timeout_s = snapshot_restore_timeout_s
        self.recover_timeout_s = recover_timeout_s
        self.work_area_dir = work_area_dir
        self.nemoclaw_repo_path = nemoclaw_repo_path
        self.patch_build_timeout_s = patch_build_timeout_s
        self._instances: dict[str, VictimInstance] = {}

        # Probe the local nemoclaw build once. Every lifecycle method
        # branches on this; an unsupported capability degrades gracefully.
        self.capabilities = probe_capabilities(self.cli, self.sandbox_name)

    # ------------------------------------------------------------------
    def provision_victim(self, config: VictimConfig) -> VictimInstance:
        if not shutil.which(self.cli):
            raise ProvisioningError(
                f"`{self.cli}` CLI not found on PATH. Install NemoClaw, or use "
                f"the MockProvisioner (orchestrator flag --use-mock-provisioner)."
            )
        instance_id = f"VICT-{uuid.uuid4().hex[:10]}"
        if self._telemetry is not None:
            self._telemetry.policy_loaded(actor="provisioner",
                                          target=config.policy_path)

        patched_snapshot = None
        if config.patch_diff:
            if not self.capabilities.snapshots:
                raise ProvisioningError(
                    "VictimConfig.patch_diff is set but this nemoclaw build "
                    "has no snapshot support — refusing to run an unpatched "
                    "victim (no silent unpatched victims, spec §4 c6)")
            repo = config.nemoclaw_repo_path or self.nemoclaw_repo_path
            if not repo:
                raise ProvisioningError(
                    "VictimConfig.patch_diff is set but no nemoclaw_repo_path "
                    "is configured to build the patched victim from")
            from infra.patch_builder import PatchBuilder  # noqa: PLC0415

            builder = PatchBuilder(
                repo_path=repo, work_area_dir=self.work_area_dir,
                capabilities=self.capabilities,
                build_timeout_s=self.patch_build_timeout_s)
            patched_snapshot = builder.build_patched_snapshot(
                config.patch_diff,
                baseline=self.clean_snapshot or self.baseline_snapshot)

        if self.capabilities.ephemeral:
            # Ephemeral: clone the baseline into a per-lane disposable work
            # area, restore the clean snapshot into it, then recover.
            mode = "ephemeral"
            deterministic = True
            work = os.path.join(self.work_area_dir, instance_id)
            os.makedirs(work, exist_ok=True)
            LOG.info("provisioning ephemeral victim %s in %s",
                     instance_id, work)
            restore_target = (
                patched_snapshot.name if patched_snapshot is not None
                else (self.clean_snapshot or self.baseline_snapshot))
            self._run(
                [self.cli, self.sandbox_name, "snapshot", "restore",
                 restore_target],
                timeout=self.snapshot_restore_timeout_s,
                what="snapshot restore")
            self._run([self.cli, self.sandbox_name, "recover"],
                      timeout=self.recover_timeout_s, what="recover")
        else:
            # Recover-only: snapshots unavailable — restart the agent but
            # the filesystem is NOT reset. Isolation is not guaranteed.
            mode = "recover_only"
            deterministic = False
            work = None
            LOG.warning("provisioning victim %s: recover-only mode "
                        "(snapshots unavailable) — isolation NOT guaranteed",
                        instance_id)
            if self.clean_snapshot:
                self._run(
                    [self.cli, self.sandbox_name, "snapshot", "restore",
                     self.clean_snapshot],
                    timeout=self.snapshot_restore_timeout_s,
                    what="snapshot restore")
            self._run([self.cli, self.sandbox_name, "recover"],
                      timeout=self.recover_timeout_s, what="recover")

        token = self._run(
            [self.cli, self.sandbox_name, "gateway-token", "--quiet"],
            timeout=30, what="gateway-token").strip()
        if not token:
            raise ProvisioningError("gateway-token returned empty output")
        # The token is published in `metadata["gateway_token"]` below. We do
        # NOT mirror it into os.environ: that would leak the secret into the
        # process environment and every later subprocess inherits it for the
        # lifetime of the process. Consumers should read it from the
        # VictimInstance metadata (or be passed it explicitly).

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
                "sandbox_mode": mode,
                "deterministic": "true" if deterministic else "false",
                "patch_applied": "true" if patched_snapshot else "false",
                **({"work_area": work} if work else {}),
            },
        )
        self._instances[instance_id] = instance
        LOG.info("victim %s ready: mode=%s deterministic=%s",
                 instance_id, mode, deterministic)
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
        # No os.environ mirror — the token is published in instance metadata.
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

    def recover_victim(self, instance_id: str) -> VictimInstance:
        """Restart the gateway + agent in place — clears in-memory session/
        conversation state without a full reprovision. Promoted from the
        internal `recover` call to a first-class contract method."""
        instance = self._instances.get(instance_id)
        if instance is None:
            raise ProvisioningError(f"unknown instance {instance_id}")
        self._run(
            [self.cli, self.sandbox_name, "recover"],
            timeout=self.recover_timeout_s, what="recover")
        token = self._run(
            [self.cli, self.sandbox_name, "gateway-token", "--quiet"],
            timeout=30, what="gateway-token").strip()
        if not token:
            raise ProvisioningError("gateway-token returned empty output")
        # Published via metadata only — not mirrored into os.environ, to avoid
        # leaking the secret into every later subprocess (see provision()).
        instance.metadata["gateway_token"] = token
        instance.status = "running"
        return instance

    def snapshot_victim(self, instance_id: str, name: str) -> VictimSnapshot:
        """Capture the current victim state as a named snapshot. Raises when
        the local build has no snapshot support — never returns a snapshot
        that is not really a snapshot."""
        instance = self._instances.get(instance_id)
        if instance is None:
            raise ProvisioningError(f"unknown instance {instance_id}")
        if not self.capabilities.snapshots:
            raise ProvisioningError(
                f"cannot snapshot `{name}`: this nemoclaw build reports no "
                f"snapshot support (capabilities.snapshots=False)")
        self._run(
            [self.cli, self.sandbox_name, "snapshot", "create", name],
            timeout=self.snapshot_restore_timeout_s, what="snapshot create")
        return VictimSnapshot(
            name=name, sandbox_id=self.sandbox_name, created_at=_now(),
            deterministic=True, patched=False,
            base_snapshot=self.clean_snapshot or None)

    def teardown_victim(self, instance_id: str) -> None:
        """Discard the per-lane disposable work area. For recover-only mode
        (no work area) this just marks the local record stopped."""
        instance = self._instances.get(instance_id)
        if instance is None:
            return
        work = instance.metadata.get("work_area")
        if work:
            shutil.rmtree(work, ignore_errors=True)
            LOG.debug("teardown_victim(%s): discarded work area %s",
                      instance_id, work)
        instance.status = "stopped"

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
    """In-memory provisioner for tests and offline development.

    Each `provision_victim` plants a fresh `red_team.mock_victim.MockVictim`
    — an OpenClaw-agent-shaped target with deliberately-introduced flaws
    (system-prompt leak, filesystem escape, PII cloud-routing) — and
    registers it at the returned `mock://` endpoint. That makes the whole
    red → judge → repro → blue pipeline runnable end-to-end without a live
    NemoClaw sandbox: the planted target gives the pipeline something real
    to find, reproduce, and patch.
    """

    def __init__(self, telemetry: TelemetryEmitter | None = None) -> None:
        self._instances: dict[str, VictimInstance] = {}
        # Optional TelemetryEmitter. Unset -> behavior is identical to before.
        self._telemetry = telemetry

    def provision_victim(self, config: VictimConfig) -> VictimInstance:
        # Lazy import: this dev/test provisioner is the one place infra is
        # intentionally coupled to the red-team planted-victim fixture.
        from red_team import mock_victim  # noqa: PLC0415

        iid = f"MOCK-{uuid.uuid4().hex[:10]}"
        if self._telemetry is not None:
            self._telemetry.policy_loaded(actor="provisioner",
                                          target=config.policy_path)
        chat_endpoint = f"mock://chat/{iid}"
        metadata = {"policy_path": config.policy_path,
                    "agent_type": config.agent_type}

        # Profile selector: a planted victim profile name carried in the
        # config's `env` dict (VictimConfig has no `metadata` field), or in
        # the process environment as `MC_PROFILE` (how the `demo --profile`
        # path routes it, since the lane scheduler builds VictimConfig with
        # an empty `env`). When set, bind that planted victim to the mock
        # transport for this instance. When unset, fall back to the
        # red_team multi-flaw MockVictim with tempdir sandbox roots.
        # A non-empty `patch_diff` means the caller (the patch verifier)
        # wants a victim built WITH a candidate patch applied. The mock
        # provisioner cannot apply a real source diff, but it models the
        # patched surface honestly: the planted flaws are fixed so the
        # recorded attack no longer reproduces. This is the spec'd
        # contract — "patched semantics come from the provisioner's
        # patch_diff field" (see blue_team/patch_verifier.py docstring).
        patched = bool(config.patch_diff and config.patch_diff.strip())

        profile = config.env.get("MC_PROFILE") or os.environ.get("MC_PROFILE")
        if profile:
            # Planted-profile mode (Person A demo profiles).
            # make_victim raises KeyError for an unknown profile.
            victim = make_victim(profile)
            # Honor the patched surface for profiles that model it.
            if patched and hasattr(victim, "patched"):
                victim.patched = True  # type: ignore[attr-defined]
            register(chat_endpoint, victim)
            metadata["profile"] = profile
            if patched:
                metadata["patched"] = "true"
        else:
            # Default: the red_team multi-flaw MockVictim with tempdir
            # sandbox roots.
            base = tempfile.mkdtemp(prefix=f"mc-mock-{iid}-")
            allowed = os.path.join(base, "allowed")
            escape = os.path.join(base, "escape")
            chat_endpoint, _ = mock_victim.build_and_register(
                endpoint=chat_endpoint,
                allowed_root=allowed, escape_root=escape,
                patched=patched,
            )
            metadata.update(allowed_root=allowed, escape_root=escape,
                            base_dir=base)
            if patched:
                metadata["patched"] = "true"

        instance = VictimInstance(
            instance_id=iid,
            chat_endpoint=chat_endpoint,
            shell_endpoint=f"mock://shell/{iid}",
            status="running",
            sandbox_id=iid,
            started_at=_now(),
            metadata=metadata,
        )
        self._instances[iid] = instance
        return instance

    def teardown_victim(self, instance_id: str) -> None:
        instance = self._instances.get(instance_id)
        if instance is None:
            return
        # Release whichever victim was bound to the mock transport.
        # `mock_victim.unregister` and `interfaces.victim_client.unregister`
        # are the same function over the same registry, so one call covers
        # both planted-profile and default MockVictim instances.
        unregister(instance.chat_endpoint)
        base = instance.metadata.get("base_dir")
        if base:
            shutil.rmtree(base, ignore_errors=True)
        instance.status = "stopped"

    def recover_victim(self, instance_id: str) -> VictimInstance:
        """The mock victim is replanted fresh per provision, so recover is a
        no-op that returns the existing instance."""
        instance = self._instances.get(instance_id)
        if instance is None:
            raise ProvisioningError(f"unknown instance {instance_id}")
        return instance

    def snapshot_victim(self, instance_id: str, name: str) -> VictimSnapshot:
        """The mock victim's state is deterministic by construction."""
        instance = self._instances.get(instance_id)
        if instance is None:
            raise ProvisioningError(f"unknown instance {instance_id}")
        return VictimSnapshot(
            name=name, sandbox_id=instance.sandbox_id or instance_id,
            created_at=_now(), deterministic=True, patched=False,
            base_snapshot=None)

    def list_victims(self) -> list[VictimInstance]:
        return list(self._instances.values())
