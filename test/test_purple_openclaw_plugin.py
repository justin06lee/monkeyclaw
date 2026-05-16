"""OpenClaw purple-team-telemetry plugin — manifest + index.js consistency.

The plugin (purple_team/openclaw_plugin/) is the event source the
NativeEventAdapter ingests. These tests assert the manifest declares all
17 hooks, marks the 4 decision hooks, and that every hook the plugin emits
is one the adapter knows how to map (no silent drift between the two).
"""

from __future__ import annotations

import json
from pathlib import Path

from purple_team.native_event_adapter import _DECISION_HOOKS, _HOOK_MAP

_PLUGIN = Path(__file__).resolve().parents[1] / "purple_team" / "openclaw_plugin"


def _manifest() -> dict:
    return json.loads((_PLUGIN / "openclaw.json").read_text(encoding="utf-8"))


def test_manifest_declares_17_hooks():
    hooks = _manifest()["hooks"]
    assert len(hooks) == 17
    assert len(set(hooks)) == 17  # no duplicates


def test_manifest_marks_the_4_decision_hooks():
    decision_hooks = set(_manifest()["decisionHooks"])
    assert len(decision_hooks) == 4
    assert decision_hooks == set(_DECISION_HOOKS)


def test_manifest_entry_and_name():
    manifest = _manifest()
    assert manifest["entry"] == "index.js"
    assert manifest["name"] == "purple-team-telemetry"
    assert (_PLUGIN / "index.js").exists()
    assert (_PLUGIN / "README.md").exists()


def test_every_emitted_hook_is_adapter_mappable():
    # Each manifest hook must be mappable by the adapter — the network.request
    # hook fans out into network.request.{blocked,approved,denied} lines.
    known = set(_HOOK_MAP) | {"after_tool_call", "before_tool_call"}
    for hook in _manifest()["hooks"]:
        if hook == "network.request":
            assert "network.request.blocked" in _HOOK_MAP
            assert "network.request.approved" in _HOOK_MAP
            assert "network.request.denied" in _HOOK_MAP
        else:
            assert hook in known, hook


def test_index_js_is_observe_only():
    src = (_PLUGIN / "index.js").read_text(encoding="utf-8")
    assert "definePlugin" in src
    # Decision hooks always return an allow — observe-only, never enforce.
    assert "{ decision: 'allow' }" in src
    assert "module.exports" in src
