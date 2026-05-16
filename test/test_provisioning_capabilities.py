"""Phase 0 — the capability prober (real-nemoclaw-provisioner spec §7.2)."""

from __future__ import annotations

from pathlib import Path

from infra.sandbox_capabilities import probe
from test._nemoclaw_stub import remove_stub, write_stub


def test_full_featured_stub_reports_all_capabilities(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    caps = probe("nemoclaw", "monkey-victim")
    assert caps.cli_present is True
    assert caps.snapshots is True
    assert caps.ephemeral is True
    assert caps.recover is True
    assert caps.container_fsdiff is True


def test_snapshotless_stub_disables_snapshots_and_ephemeral(
    tmp_path: Path, monkeypatch):
    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    caps = probe("nemoclaw", "monkey-victim")
    assert caps.cli_present is True
    assert caps.snapshots is False
    assert caps.ephemeral is False        # no clones without snapshots
    assert caps.recover is True           # recover-only mode still works


def test_cli_absent_reports_nothing_present(tmp_path: Path, monkeypatch):
    remove_stub(monkeypatch)
    caps = probe("nemoclaw", "monkey-victim")
    assert caps.cli_present is False
    assert caps.snapshots is False
    assert caps.ephemeral is False
    assert caps.recover is False
    assert caps.container_fsdiff is False
