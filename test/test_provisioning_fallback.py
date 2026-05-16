"""Phase 5 — bootstrap falls back to mock when nemoclaw is absent."""

from __future__ import annotations

import logging

from infra.bootstrap import boot
from infra.provisioning_nemoclaw import MockProvisioner
from test._nemoclaw_stub import remove_stub


def test_bootstrap_without_cli_falls_back_to_mock(monkeypatch):
    remove_stub(monkeypatch)
    # boot() calls setup_logging() which wipes root handlers — including the
    # caplog fixture's. Attach a capturing handler to the named bootstrap
    # logger directly so the fallback warning is observed regardless.
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture()
    boot_logger = logging.getLogger("monkeyclaw.bootstrap")
    boot_logger.addHandler(handler)
    try:
        rt = boot(use_mock_provisioner=False)
        try:
            assert isinstance(rt.provisioner, MockProvisioner)
            assert any("falling back to MockProvisioner" in r.getMessage()
                       for r in records)
        finally:
            rt.shutdown()
    finally:
        boot_logger.removeHandler(handler)


def test_bootstrap_with_explicit_mock_flag_uses_mock(monkeypatch):
    rt = boot(use_mock_provisioner=True)
    try:
        assert isinstance(rt.provisioner, MockProvisioner)
    finally:
        rt.shutdown()
