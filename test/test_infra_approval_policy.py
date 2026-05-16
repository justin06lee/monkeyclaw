"""Phase 1 — the pure severity -> posture policy."""

from __future__ import annotations

import pytest

from infra.approval_policy import gate_policy
from interfaces.config_schema import ApprovalsConfig


@pytest.fixture
def policy():
    return gate_policy(ApprovalsConfig())


@pytest.mark.parametrize("severity,expected", [
    ("critical", "require_approval"),
    ("high", "require_approval"),
    ("medium", "auto_allow"),
    ("low", "auto_allow"),
])
def test_posture_for_each_severity(policy, severity, expected):
    assert policy.posture_for(severity) == expected


def test_unknown_severity_defaults_to_require_approval(policy):
    assert policy.posture_for("bizarre") == "require_approval"


def test_missing_severity_defaults_to_require_approval(policy):
    assert policy.posture_for(None) == "require_approval"


def test_unconverged_generalization_forces_require_approval(policy):
    # Even a low-severity patch is held when the generalization loop is open.
    assert policy.posture_for("low", generalization="unconverged") \
        == "require_approval"


def test_generalized_generalization_keeps_severity_posture(policy):
    assert policy.posture_for("low", generalization="generalized") \
        == "auto_allow"


def test_expiry_accessors_read_config():
    p = gate_policy(ApprovalsConfig(ask_expiry_hours=24, grant_expiry_hours=8))
    assert p.ask_expiry_hours() == 24
    assert p.grant_expiry_hours() == 8
