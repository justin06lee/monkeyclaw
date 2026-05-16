"""Capability prober — real-nemoclaw-provisioner spec §7.2.

Runs once at NemoClawProvisioner construction. Probes the local `nemoclaw`
build with throwaway commands and produces a frozen SandboxCapabilities.
A probe never raises: an unsupported capability simply becomes False.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile

from interfaces.provisioning import SandboxCapabilities

LOG = logging.getLogger("monkeyclaw.provisioning.caps")

_PROBE_TIMEOUT_S = 30


def _run_ok(cmd: list[str]) -> tuple[bool, str]:
    """Run a probe command; return (exit-zero?, stdout). Never raises."""
    try:
        with tempfile.TemporaryFile(mode="w+") as out:
            proc = subprocess.run(
                cmd, stdout=out, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, timeout=_PROBE_TIMEOUT_S,
            )
            out.seek(0)
            return proc.returncode == 0, out.read()
    except (subprocess.TimeoutExpired, OSError) as e:
        LOG.debug("probe %s failed: %s", " ".join(cmd), e)
        return False, ""


def probe(cli: str, sandbox_name: str) -> SandboxCapabilities:
    """Probe the local `nemoclaw` build for sandbox capabilities."""
    if not shutil.which(cli):
        LOG.warning("`%s` CLI not on PATH — sandbox capabilities all False", cli)
        return SandboxCapabilities(
            cli_present=False, snapshots=False, ephemeral=False,
            container_fsdiff=False, recover=False)

    snapshots, _ = _run_ok(
        [cli, sandbox_name, "snapshot", "create", "mc-probe-snapshot"])
    recover_ok, _ = _run_ok([cli, sandbox_name, "recover", "--dry-run"])
    container_ok, container = _run_ok(
        [cli, sandbox_name, "inspect", "--container"])
    # Ephemeral per-lane clones require working snapshots — without them the
    # provisioner can only recover-in-place a single persistent sandbox.
    caps = SandboxCapabilities(
        cli_present=True,
        snapshots=snapshots,
        ephemeral=snapshots,
        container_fsdiff=container_ok and bool(container.strip()),
        recover=recover_ok,
    )
    LOG.info("probed sandbox capabilities for %s: %s", sandbox_name, caps)
    return caps


__all__ = ["probe"]
