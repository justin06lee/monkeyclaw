"""Offline, human-run training for the learned ranker (spec §6.5, §8, §9).

NEVER invoked by the loop. It reads attempt_traces + pairwise_labels, checks
the §8 dataset-readiness gate, and — only if the gate passes — builds
train/val/test splits, trains the learned ranker, runs the §9 offline
evaluation against HeuristicRanker, and writes a versioned artifact + report.

It refuses to emit a servable artifact if the gate fails or the candidate
loses the offline evaluation (spec §9 promotion rule).

Usage:
    python scripts/train_ranker.py [--dry-run] [--db PATH]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow `python scripts/train_ranker.py` from the repo root to import the
# package modules — the script's own directory, not the repo root, is what
# Python puts on sys.path by default.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from infra.database import Database  # noqa: E402
from infra.mcp_server import MCPServer  # noqa: E402
from red_team.dataset_readiness import evaluate_readiness  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the learned ranker.")
    parser.add_argument("--dry-run", action="store_true",
                        help="check the readiness gate only; never train.")
    parser.add_argument("--db", default="data/monkeyclaw.db",
                        help="path to the MonkeyClaw SQLite database.")
    args = parser.parse_args(argv)

    db = Database(args.db)
    try:
        mcp = MCPServer(db)
        traces = mcp.get_attempt_traces()
        pairs = mcp.get_pairwise_labels()
    finally:
        db.close()

    gate = evaluate_readiness(traces, pairs)
    print(f"dataset-readiness gate: {'READY' if gate.ready else 'NOT READY'}")
    for key, value in sorted(gate.metrics.items()):
        print(f"  {key}: {value}")
    if not gate.ready:
        print("training aborted — the dataset is not ready:")
        for failure in gate.failures:
            print(f"  - {failure}")
        return 1

    if args.dry_run:
        print("dry run: gate passed; training skipped.")
        return 0

    # --- Phase 3 training proper -------------------------------------------
    # The gate passed. Building train/val/test splits, training the learned
    # ranking head, running the §9 offline evaluation against HeuristicRanker,
    # and — only if the candidate strictly beats the heuristic — writing the
    # versioned artifact, is implemented in the gated Phase 3 follow-up
    # (learned_ranker.py lands the load side). This script's committed Phase 3
    # surface is the readiness gate and the dry-run path; it never emits an
    # artifact while the gate or the eval has not been met.
    print("gate passed — full training is the gated Phase 3 follow-up.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
