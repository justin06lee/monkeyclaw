"""Victim provisioning API — Contract 3.

Both Person 2 (execution lanes) and Person 3 (replay, cold verification, patch
verification) call into this module. The concrete implementation lives in
`infra.provisioning_nemoclaw` and shells out to the NemoClaw CLI.

We expose a thin Protocol so red/blue can mock provisioning when developing
against the mock MCP, and swap in the real backend on integration day.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class VictimConfig:
    """Inputs for spinning up a single fresh NemoClaw victim instance."""

    nemoclaw_version: str
    policy_path: str  # Path to NemoClaw policy YAML
    agent_type: str  # "coding_assistant" | "general_purpose" | custom string
    agent_config_path: str  # Path to victim agent config
    enable_monitoring: bool = True
    patch_diff: str | None = None  # Optional: apply this patch before starting
    nemoclaw_repo_path: str | None = None  # Override location of NemoClaw checkout
    env: dict[str, str] = field(default_factory=dict)
    # Routing preference — useful for INF-* zone tests
    inference_routing: str = "default"  # "default" | "force_local" | "force_cloud"


@dataclass
class VictimInstance:
    """Connection details for a running victim. teardown_victim(instance_id) cleans up."""

    instance_id: str
    chat_endpoint: str  # URL or socket path for chat-style attacks
    shell_endpoint: str | None  # For sandbox-level attacks
    status: str  # "running" | "stopped" | "error"
    sandbox_id: str | None = None  # NemoClaw sandbox identifier, if any
    pid: int | None = None
    started_at: str = ""  # ISO-8601
    metadata: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class VictimProvisioner(Protocol):
    """Abstract provisioning surface. Implemented by:

    - `infra.provisioning_nemoclaw.NemoClawProvisioner` — real (shells to `nemoclaw`)
    - `infra.provisioning_mock.MockProvisioner` — for tests
    """

    def provision_victim(self, config: VictimConfig) -> VictimInstance:
        """Spin up a fresh NemoClaw sandbox with a victim agent.

        Blocks until the agent is reachable on `chat_endpoint`. Raises
        `ProvisioningError` on failure.
        """
        ...

    def teardown_victim(self, instance_id: str) -> None:
        """Destroy a victim instance and clean up its sandbox/state. Idempotent."""
        ...

    def list_victims(self) -> list[VictimInstance]:
        """All currently-tracked victim instances (running or stopped-pending-cleanup)."""
        ...


class ProvisioningError(RuntimeError):
    """Raised when a victim cannot be provisioned."""


# Module-level singleton convenience: code that just calls
# `provision_victim(...)` gets the configured backend.
# `infra.bootstrap` sets `_PROVISIONER`.

_PROVISIONER: VictimProvisioner | None = None


def set_provisioner(p: VictimProvisioner) -> None:
    global _PROVISIONER
    _PROVISIONER = p


def get_provisioner() -> VictimProvisioner:
    if _PROVISIONER is None:
        raise RuntimeError(
            "No provisioner configured. Call interfaces.provisioning.set_provisioner(...) "
            "during application bootstrap (see infra/bootstrap.py)."
        )
    return _PROVISIONER


def provision_victim(config: VictimConfig) -> VictimInstance:
    """Module-level convenience wrapping the configured backend."""
    return get_provisioner().provision_victim(config)


def teardown_victim(instance_id: str) -> None:
    """Module-level convenience wrapping the configured backend."""
    get_provisioner().teardown_victim(instance_id)


__all__ = [
    "ProvisioningError",
    "VictimConfig",
    "VictimInstance",
    "VictimProvisioner",
    "get_provisioner",
    "provision_victim",
    "set_provisioner",
    "teardown_victim",
]
