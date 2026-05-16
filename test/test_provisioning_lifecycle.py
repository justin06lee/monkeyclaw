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
