"""Lifecycle tests for the real provisioner against a stubbed nemoclaw CLI."""

from __future__ import annotations

from pathlib import Path

from infra.provisioning_nemoclaw import NemoClawProvisioner
from test._nemoclaw_stub import write_stub


def test_provisioner_probes_capabilities_at_construction(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    assert p.capabilities.cli_present is True
    assert p.capabilities.snapshots is True
    assert p.capabilities.ephemeral is True


def test_snapshotless_provisioner_records_recover_only(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    assert p.capabilities.snapshots is False
    assert p.capabilities.ephemeral is False


def test_recover_victim_restarts_gateway_in_place(
    tmp_path: Path, monkeypatch):
    calls = write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    inst = p.connect_existing()
    calls.write_text("")  # clear connect_existing's gateway-token calls
    recovered = p.recover_victim(inst.instance_id)
    assert recovered.instance_id == inst.instance_id
    log = calls.read_text()
    assert "monkey-victim recover" in log
    assert "gateway-token" in log  # token re-fetched after restart


def test_recover_victim_unknown_instance_raises(
    tmp_path: Path, monkeypatch):
    from interfaces.provisioning import ProvisioningError
    import pytest

    write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    with pytest.raises(ProvisioningError):
        p.recover_victim("VICT-nope")
