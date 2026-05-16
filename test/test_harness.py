"""Unit tests for the monitoring harness primitives."""

from __future__ import annotations

import os
from pathlib import Path

from infra.monitoring_harness import (
    HarnessConfig,
    MonitoringHarness,
    diff_memory,
    diff_snapshots,
    snapshot_paths,
)


def test_fs_diff_detects_create_modify_delete(tmp_path: Path):
    (tmp_path / "a.txt").write_text("a")
    keep = tmp_path / "b.txt"
    keep.write_text("b")
    before = snapshot_paths([tmp_path])
    # Create, modify, delete
    (tmp_path / "c.txt").write_text("c")
    keep.write_text("b!!!")
    (tmp_path / "a.txt").unlink()
    after = snapshot_paths([tmp_path])
    diff = diff_snapshots(before, after, allowed_paths=[str(tmp_path)])
    assert any("c.txt" in p for p in diff.files_created)
    assert any("b.txt" in p for p in diff.files_modified)
    assert any("a.txt" in p for p in diff.files_deleted)
    assert diff.files_outside_allowed_paths == []


def test_fs_diff_flags_outside_allowed(tmp_path: Path):
    inside = tmp_path / "ok"
    outside = tmp_path / "evil"
    inside.mkdir()
    outside.mkdir()
    before = snapshot_paths([inside, outside])
    (outside / "leak").write_text("data")
    after = snapshot_paths([inside, outside])
    diff = diff_snapshots(before, after, allowed_paths=[str(inside)])
    assert any("leak" in p for p in diff.files_outside_allowed_paths)


def test_memory_diff():
    before = {"a": 1, "b": 2}
    after = {"a": 1, "b": 3, "c": 4}
    d = diff_memory(before, after)
    assert d.keys_added == ["c"]
    assert d.keys_modified == ["b"]
    assert d.keys_deleted == []
    assert d.values_changed == {"b": {"old": 2, "new": 3}}


def test_harness_lifecycle(tmp_path: Path):
    cfg = HarnessConfig(
        watched_paths=[str(tmp_path)],
        allowed_paths=[str(tmp_path)],
        sandbox_pid=os.getpid(),
        psutil_interval=0.1,
    )
    with MonitoringHarness(cfg, "L1", "I1", "SBX-FS") as h:
        from datetime import UTC, datetime

        from interfaces.types import Message
        (tmp_path / "x").write_text("hello")
        h.record_message(Message(role="attacker", content="hi",
                                  timestamp=datetime.now(UTC).isoformat()))
        h.set_self_assessment("done")
    result = h.result()
    assert result.turns_used == 1
    assert any("x" in p for p in result.fs_diff.files_created)
    assert result.attacker_self_assessment == "done"
