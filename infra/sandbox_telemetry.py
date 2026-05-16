"""Real telemetry capturer — real-nemoclaw-provisioner spec §7.3.

Reads fs/network/process/inference/memory observables from a running (or
just-finished) victim sandbox and returns them in the EXISTING observable
dataclass shapes. A missing or unreadable stream degrades that field to
empty with a warning — telemetry capture never aborts a lane.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile

from interfaces.provisioning import VictimInstance
from interfaces.types import (
    InferenceEvent,
    NetworkEvent,
    ProcessEvent,
    VictimTelemetryBundle,
)

LOG = logging.getLogger("monkeyclaw.provisioning.telemetry")

_CAPTURE_TIMEOUT_S = 60


def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()


class SandboxTelemetryCapturer:
    """Captures real observables from a victim sandbox."""

    def __init__(self, cli_binary: str = "nemoclaw") -> None:
        self.cli = cli_binary

    def capture(self, instance: VictimInstance) -> VictimTelemetryBundle:
        sandbox = instance.metadata.get("sandbox_name", instance.sandbox_id)
        return VictimTelemetryBundle(
            fs_diff=None,  # filesystem diffing stays in MonitoringHarness
            network_events=self._network(sandbox),
            process_events=self._process(sandbox),
            inference_events=self._inference(sandbox),
            memory_diff=None,
        )

    # ------------------------------------------------------------------
    def _lines(self, sandbox: str, subcommand: str) -> list[dict]:
        """Run a nemoclaw log subcommand; return parsed JSON lines. A failed
        or unreadable stream returns [] with a warning — never raises."""
        try:
            with tempfile.TemporaryFile(mode="w+") as out:
                proc = subprocess.run(
                    [self.cli, sandbox, subcommand],
                    stdout=out, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, timeout=_CAPTURE_TIMEOUT_S)
                out.seek(0)
                text = out.read()
            if proc.returncode != 0:
                LOG.warning("telemetry stream `%s` unavailable (exit %s) — "
                            "degrading to empty", subcommand, proc.returncode)
                return []
        except (subprocess.TimeoutExpired, OSError) as e:
            LOG.warning("telemetry stream `%s` failed: %s — degrading to "
                        "empty", subcommand, e)
            return []
        rows: list[dict] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                LOG.debug("skipping non-JSON telemetry line: %s", line[:120])
        return rows

    def _network(self, sandbox: str) -> list[NetworkEvent]:
        return [
            NetworkEvent(
                timestamp=r.get("timestamp", _now()),
                destination_domain=r.get("destination_domain", ""),
                destination_port=int(r.get("destination_port", 0)),
                method=r.get("method", ""),
                payload_size_bytes=int(r.get("payload_size_bytes", 0)),
                response_code=r.get("response_code"),
                blocked=bool(r.get("blocked", False)),
            )
            for r in self._lines(sandbox, "net-log")
        ]

    def _process(self, sandbox: str) -> list[ProcessEvent]:
        return [
            ProcessEvent(
                timestamp=r.get("timestamp", _now()),
                process_name=r.get("process_name", ""),
                pid=int(r.get("pid", 0)),
                syscall=r.get("syscall"),
                syscall_args=r.get("syscall_args"),
                blocked=bool(r.get("blocked", False)),
                inside_sandbox=bool(r.get("inside_sandbox", True)),
            )
            for r in self._lines(sandbox, "proc-log")
        ]

    def _inference(self, sandbox: str) -> list[InferenceEvent]:
        return [
            InferenceEvent(
                timestamp=r.get("timestamp", _now()),
                routed_to=r.get("routed_to", "unknown"),
                content_preview=r.get("content_preview", ""),
                pii_detected=bool(r.get("pii_detected", False)),
                pii_types=r.get("pii_types"),
            )
            for r in self._lines(sandbox, "inference-log")
        ]


__all__ = ["SandboxTelemetryCapturer"]
