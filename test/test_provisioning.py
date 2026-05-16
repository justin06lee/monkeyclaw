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
