"""Phase 3 — real telemetry capture (real-nemoclaw-provisioner spec §7.3)."""

from __future__ import annotations

from pathlib import Path

from infra.sandbox_telemetry import SandboxTelemetryCapturer
from interfaces.provisioning import VictimInstance
from test._nemoclaw_stub import write_stub


def _instance() -> VictimInstance:
    return VictimInstance(
        instance_id="VICT-1", chat_endpoint="ws://x", shell_endpoint=None,
        status="running", sandbox_id="monkey-victim",
        metadata={"sandbox_name": "monkey-victim",
                  "sandbox_container": "openshell-cluster-nemoclaw"})


def test_capture_maps_all_streams_into_observable_shapes(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    cap = SandboxTelemetryCapturer(cli_binary="nemoclaw")
    bundle = cap.capture(_instance())
    assert len(bundle.network_events) == 1
    assert bundle.network_events[0].destination_domain == "evil.test"
    assert bundle.network_events[0].blocked is True
    assert len(bundle.process_events) == 1
    assert bundle.process_events[0].process_name == "curl"
    assert len(bundle.inference_events) == 1
    assert bundle.inference_events[0].routed_to == "cloud"


def test_capture_degrades_missing_stream_to_empty(tmp_path: Path, monkeypatch):
    # A stub whose net-log subcommand fails: the field degrades, not raises.
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    script = bindir / "nemoclaw"
    script.write_text(
        "#!/bin/sh\n"
        'case "$*" in *net-log*) exit 3 ;; *) exit 0 ;; esac\n')
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    cap = SandboxTelemetryCapturer(cli_binary="nemoclaw")
    bundle = cap.capture(_instance())
    assert bundle.network_events == []   # degraded, no exception
