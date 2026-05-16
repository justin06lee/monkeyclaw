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


def test_snapshot_victim_issues_create_call(tmp_path: Path, monkeypatch):
    calls = write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    inst = p.connect_existing()
    snap = p.snapshot_victim(inst.instance_id, "lane-snap")
    assert snap.name == "lane-snap"
    assert snap.deterministic is True
    assert "snapshot create lane-snap" in calls.read_text()


def test_snapshot_victim_without_support_raises(tmp_path: Path, monkeypatch):
    from interfaces.provisioning import ProvisioningError
    import pytest

    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim")
    inst = p.connect_existing()
    with pytest.raises(ProvisioningError, match="snapshot"):
        p.snapshot_victim(inst.instance_id, "lane-snap")


def test_sandbox_runs_store_writes_and_closes_a_run(db):
    from infra.sandbox_runs_store import SandboxRunsStore
    from interfaces.provisioning import SandboxCapabilities

    store = SandboxRunsStore(db)
    caps = SandboxCapabilities(
        cli_present=True, snapshots=True, ephemeral=True,
        container_fsdiff=True, recover=True)
    run_id = store.open_run(
        instance_id="VICT-1", lane_id="L1", mode="ephemeral",
        deterministic=True, patch_applied=False, capabilities=caps)
    rows = db.fetchall("SELECT * FROM sandbox_runs WHERE run_id = ?", (run_id,))
    assert len(rows) == 1
    assert rows[0]["mode"] == "ephemeral"
    assert rows[0]["torn_down_at"] is None
    store.close_run(run_id)
    row = db.fetchone("SELECT * FROM sandbox_runs WHERE run_id = ?", (run_id,))
    assert row["torn_down_at"] is not None


def test_sandbox_runs_store_records_a_snapshot(db):
    from infra.sandbox_runs_store import SandboxRunsStore
    from interfaces.provisioning import VictimSnapshot

    store = SandboxRunsStore(db)
    store.record_snapshot(VictimSnapshot(
        name="clean-baseline", sandbox_id="monkey-victim",
        created_at="2026-05-15T00:00:00Z", deterministic=True,
        patched=False, base_snapshot=None))
    rows = db.fetchall("SELECT * FROM victim_snapshots")
    assert len(rows) == 1
    assert rows[0]["name"] == "clean-baseline"
    assert rows[0]["deterministic"] == 1


def test_nemoclaw_config_has_work_area_fields():
    from interfaces.config_schema import NemoClawConfig

    c = NemoClawConfig()
    assert hasattr(c, "baseline_snapshot")
    assert hasattr(c, "work_area_dir")
    assert c.patch_build_timeout_s > 0


def test_ephemeral_provision_clones_baseline_and_stamps_deterministic(
    tmp_path: Path, monkeypatch):
    from interfaces.provisioning import VictimConfig

    calls = write_stub(tmp_path, monkeypatch, snapshots=True, recover=True)
    p = NemoClawProvisioner(
        sandbox_name="monkey-victim", clean_snapshot="clean-baseline",
        work_area_dir=str(tmp_path / "work"))
    inst = p.provision_victim(VictimConfig(
        nemoclaw_version="v0", policy_path="p", agent_type="coding_assistant",
        agent_config_path="c"))
    assert inst.metadata["deterministic"] == "true"
    assert inst.metadata["sandbox_mode"] == "ephemeral"
    log = calls.read_text()
    assert "snapshot restore clean-baseline" in log
    assert "recover" in log
    work = tmp_path / "work" / inst.instance_id
    assert work.exists()
    p.teardown_victim(inst.instance_id)
    assert not work.exists()   # real teardown discards the work area


def test_recover_only_provision_stamps_not_deterministic(
    tmp_path: Path, monkeypatch):
    from interfaces.provisioning import VictimConfig

    write_stub(tmp_path, monkeypatch, snapshots=False, recover=True)
    p = NemoClawProvisioner(sandbox_name="monkey-victim", clean_snapshot="")
    inst = p.provision_victim(VictimConfig(
        nemoclaw_version="v0", policy_path="p", agent_type="coding_assistant",
        agent_config_path="c"))
    assert inst.metadata["deterministic"] == "false"
    assert inst.metadata["sandbox_mode"] == "recover_only"


def test_lane_result_carries_deterministic_flag():
    from dataclasses import fields

    from interfaces.types import LaneResult

    fnames = {f.name for f in fields(LaneResult)}
    assert "deterministic" in fnames
