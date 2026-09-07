#!/usr/bin/env python3
"""
E2 diff runner — compute what's NEW (and removed) between two run directories and
write the current run's diff.json. Offline, zero traffic. Imports the shared
compute from stages/diff_runs.py (never reimplements).

Usage:
    python3 run_diff.py --baseline /path/to/previous_run --current /path/to/current_run
"""
import argparse
import logging
from pathlib import Path
import sys

_R = Path(__file__).resolve().parent
for _p in (_R, *_R.parents):
    if (_p / "state.py").exists():
        _R = _p; break
sys.path.insert(0, str(_R))
sys.path.insert(0, str(_R / "stages"))
from state import RunState
from diff_runs import compute_run_diff, write_diff_artifact

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("recon_agent")


def main():
    ap = argparse.ArgumentParser(description="Diff two recon run directories (E2)")
    ap.add_argument("--baseline", required=True, help="Previous run directory (the baseline)")
    ap.add_argument("--current", required=True, help="Current run directory (diff.json is written here)")
    args = ap.parse_args()

    baseline = RunState(Path(args.baseline))
    current = RunState(Path(args.current))
    diff = compute_run_diff(baseline, current)
    path = write_diff_artifact(current, diff)
    t = diff["totals"]
    logger.info("Diff written to %s — %d new, %d removed", path, t["new"], t["removed"])
    for layer, s in diff["summary"].items():
        if s["new"] or s["removed"]:
            logger.info("  %-15s +%d / -%d", layer, s["new"], s["removed"])


if __name__ == "__main__":
    main()
