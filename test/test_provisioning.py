"""Tests for the victim provisioners (infra/provisioning_nemoclaw.py)."""

from __future__ import annotations

from infra.provisioning_nemoclaw import MockProvisioner
from interfaces.provisioning import VictimConfig
from interfaces.victim_client import lookup


def test_mock_provisioner_selects_planted_profile():
    """Provisioning with a profile selector binds that planted victim and
    records the profile on the returned instance."""
    p = MockProvisioner()
    cfg = VictimConfig(
        nemoclaw_version="alpha",
        policy_path="x",
        agent_type="mock",
        agent_config_path="y",
        env={"MC_PROFILE": "planted-filesystem"},
    )
    inst = p.provision_victim(cfg)
    try:
        assert inst.status in ("ready", "running")
        # The chosen profile is observable on the returned instance.
        assert inst.metadata.get("profile") == "planted-filesystem"
        # The planted victim is bound to the mock transport.
        victim = lookup(inst.chat_endpoint)
        assert victim is not None
        assert getattr(victim, "profile", None) == "planted-filesystem"
    finally:
        p.teardown_victim(inst.instance_id)


def test_mock_provisioner_no_profile_default():
    """Without a profile selector, provisioning keeps the existing default
    behavior (no profile recorded, no planted victim bound)."""
    p = MockProvisioner()
    cfg = VictimConfig(
        nemoclaw_version="alpha",
        policy_path="x",
        agent_type="mock",
        agent_config_path="y",
    )
    inst = p.provision_victim(cfg)
    try:
        assert inst.status in ("ready", "running")
        assert "profile" not in inst.metadata
    finally:
        p.teardown_victim(inst.instance_id)


def test_mock_provisioner_unknown_profile_rejected():
    """An unknown profile selector raises a clear error."""
    p = MockProvisioner()
    cfg = VictimConfig(
        nemoclaw_version="alpha",
        policy_path="x",
        agent_type="mock",
        agent_config_path="y",
        env={"MC_PROFILE": "planted-does-not-exist"},
    )
    try:
        try:
            p.provision_victim(cfg)
        except KeyError as e:
            assert "planted-does-not-exist" in str(e)
        else:
            raise AssertionError("expected KeyError for unknown profile")
    finally:
        for inst in p.list_victims():
            p.teardown_victim(inst.instance_id)


# ---------------------------------------------------------------------------
# Real NemoClawProvisioner — verified against a faked subprocess.
#
# The real provisioner runs three `nemoclaw` subcommands in order via its
# private `_run` helper:
#   1. `nemoclaw <sandbox> snapshot restore <clean_snapshot>`
#   2. `nemoclaw <sandbox> recover`
#   3. `nemoclaw <sandbox> gateway-token --quiet`  -> stdout is the raw token
# `_run` captures output to temp files (it passes `stdout=`/`stderr=` file
# objects to `subprocess.run`), so the fake must write to those fds and the
# faked proc only needs a `returncode`.
# ---------------------------------------------------------------------------


def _real_cfg():
    return VictimConfig(
        nemoclaw_version="alpha",
        policy_path="p",
        agent_type="real",
        agent_config_path="a",
    )


def test_real_provisioner_runs_snapshot_restore_and_recover(monkeypatch):
    """NemoClawProvisioner shells out in the right order and surfaces a
    VictimInstance — verified against a fake subprocess."""
    from infra import provisioning_nemoclaw as pn

    calls = []

    class FakeProc:
        def __init__(self, returncode=0):
            self.returncode = returncode

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        # `_run` hands real temp files in stdout=/stderr=; the gateway-token
        # subcommand's stdout is parsed via `.strip()`, so emit a token there.
        if "gateway-token" in cmd:
            kwargs["stdout"].write("TOKEN-abc123")
        return FakeProc(returncode=0)

    # `nemoclaw` is not installed; bypass the PATH guard.
    monkeypatch.setattr(pn.shutil, "which", lambda _: "/usr/bin/nemoclaw")
    monkeypatch.setattr(pn.subprocess, "run", fake_run)

    prov = pn.NemoClawProvisioner(cli_binary="nemoclaw")
    inst = prov.provision_victim(_real_cfg())

    assert inst.chat_endpoint.startswith("ws://")
    assert inst.status == "running"
    assert inst.metadata["gateway_token"] == "TOKEN-abc123"
    # Three subcommands, in order: restore -> recover -> gateway-token.
    joined = " ".join(" ".join(str(x) for x in c) for c in calls)
    assert "snapshot" in joined and "restore" in joined
    assert "recover" in joined
    assert "gateway-token" in joined
    assert len(calls) == 3
    assert "restore" in " ".join(calls[0])
    assert "recover" in " ".join(calls[1])
    assert "gateway-token" in " ".join(calls[2])


def test_real_provisioner_raises_on_restore_failure(monkeypatch):
    """A non-zero exit from the snapshot-restore subcommand surfaces a
    typed ProvisioningError carrying the failed command's stderr."""
    from infra import provisioning_nemoclaw as pn
    from interfaces.provisioning import ProvisioningError

    class FailProc:
        returncode = 1

    def fake_run(cmd, **kwargs):
        kwargs["stderr"].write("snapshot not found")
        return FailProc()

    monkeypatch.setattr(pn.shutil, "which", lambda _: "/usr/bin/nemoclaw")
    monkeypatch.setattr(pn.subprocess, "run", fake_run)

    prov = pn.NemoClawProvisioner(cli_binary="nemoclaw")
    import pytest
    with pytest.raises(ProvisioningError) as exc:
        prov.provision_victim(_real_cfg())
    assert "snapshot not found" in str(exc.value)


def test_real_provisioner_raises_on_subprocess_timeout(monkeypatch):
    """A subprocess.TimeoutExpired is re-raised as a typed ProvisioningError
    naming the command that timed out and its timeout."""
    from infra import provisioning_nemoclaw as pn
    from interfaces.provisioning import ProvisioningError

    def fake_run(cmd, **kwargs):
        raise pn.subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

    monkeypatch.setattr(pn.shutil, "which", lambda _: "/usr/bin/nemoclaw")
    monkeypatch.setattr(pn.subprocess, "run", fake_run)

    prov = pn.NemoClawProvisioner(cli_binary="nemoclaw")
    import pytest
    with pytest.raises(ProvisioningError) as exc:
        prov.provision_victim(_real_cfg())
    assert "timed out" in str(exc.value)


def test_victim_snapshot_records_determinism_and_patched():
    from interfaces.provisioning import VictimSnapshot

    s = VictimSnapshot(
        name="clean-baseline", sandbox_id="monkey-victim",
        created_at="2026-05-15T00:00:00Z", deterministic=True,
        patched=False, base_snapshot=None,
    )
    assert s.deterministic is True
    assert s.patched is False


def test_sandbox_capabilities_has_five_flags():
    from dataclasses import fields

    from interfaces.provisioning import SandboxCapabilities

    fnames = {f.name for f in fields(SandboxCapabilities)}
    assert fnames == {"cli_present", "snapshots", "ephemeral",
                      "container_fsdiff", "recover"}


def test_victim_provisioner_protocol_includes_recover_and_snapshot():
    from interfaces.provisioning import VictimProvisioner

    # Method names are part of the extended contract.
    assert hasattr(VictimProvisioner, "recover_victim")
    assert hasattr(VictimProvisioner, "snapshot_victim")


def test_victim_telemetry_bundle_carries_five_observable_lists():
    from dataclasses import fields

    from interfaces.types import VictimTelemetryBundle

    fnames = {f.name for f in fields(VictimTelemetryBundle)}
    assert {"fs_diff", "network_events", "process_events",
            "inference_events", "memory_diff"} <= fnames
