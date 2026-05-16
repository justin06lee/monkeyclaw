"""A fake `nemoclaw` CLI for stubbed-CLI provisioner tests.

write_stub() drops an executable shell script named `nemoclaw` into a temp
dir, prepends that dir to PATH, and records every invocation (one line per
call) into a calls log the tests assert against. Capability flags select
which subcommands succeed, so a single helper drives the full-featured,
snapshot-less, and CLI-absent scenarios.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def write_stub(
    tmp_path: Path,
    monkeypatch,
    *,
    snapshots: bool = True,
    recover: bool = True,
    container: str = "openshell-cluster-nemoclaw",
) -> Path:
    """Install a fake `nemoclaw` on PATH. Returns the calls-log file path."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    calls = tmp_path / "nemoclaw_calls.log"
    script = bindir / "nemoclaw"
    snap_rc = "0" if snapshots else "1"
    rec_rc = "0" if recover else "1"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{calls}"\n'
        'case "$*" in\n'
        f'  *"snapshot create"*|*"snapshot restore"*) exit {snap_rc} ;;\n'
        f'  *"snapshot diff"*) echo "M /work/leak.txt"; exit {snap_rc} ;;\n'
        f'  *recover*) exit {rec_rc} ;;\n'
        '  *gateway-token*) echo "tok-stub"; exit 0 ;;\n'
        f'  *"inspect --container"*) echo "{container}"; exit 0 ;;\n'
        '  *"net-log"*) echo \'{"host":"evil.test","decision":"deny"}\'; exit 0 ;;\n'
        '  *"proc-log"*) echo \'{"comm":"curl","pid":42}\'; exit 0 ;;\n'
        '  *"inference-log"*) echo \'{"route":"cloud","pii_class":"email"}\'; exit 0 ;;\n'
        '  *) exit 0 ;;\n'
        'esac\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return calls


def remove_stub(monkeypatch) -> None:
    """Simulate a CLI-absent environment by emptying PATH of any nemoclaw."""
    monkeypatch.setenv("PATH", "/nonexistent")
