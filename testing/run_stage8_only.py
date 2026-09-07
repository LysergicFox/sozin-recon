#!/usr/bin/env python3
"""
Standalone stage 8 runner - re-runs ONLY stage 8 (nuclei takeover
detection) against an existing run directory's assets.db, without
repeating stages 1-7. Mirrors run_stage5_only.py / run_stage7_only.py's
existing pattern for this exact use case.

Usage:
    python3 run_stage8_only.py --run-dir /path/to/existing_run_directory

Expects the run directory to already have a populated assets.db from a
prior stages 1-7 run (or at minimum, some in-scope subdomain assets) -
this script does NOT run stages 1-7, it only seeds stage 8 from whatever
is already on disk.
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
from state import RunState

from main import run_stage8_and_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("recon_agent")


def main():
    parser = argparse.ArgumentParser(description="Re-run stage 8 (takeover detection) only")
    parser.add_argument("--run-dir", required=True, help="Path to an existing run directory with a populated assets.db")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    state = RunState(run_dir)

    # load_scope() also enforces verified_by_human, same guard every other
    # entrypoint (main.py, run_stage5_only.py, run_stage7_only.py) applies
    # before touching a run directory
    state.load_scope()

    existing_hosts = [
        a for a in state.load_assets()
        if a.type == "subdomain" and a.scope_status == "in_scope"
    ]
    if not existing_hosts:
        logger.error(
            "No in_scope subdomain assets found in %s - run stages 1-7 "
            "first, or check --run-dir points at the right directory",
            state.assets_db_path,
        )
        return

    logger.info("Found %d existing in_scope host(s) in assets.db - proceeding with stage 8 only",
                len(existing_hosts))

    run_stage8_and_report(state)

    findings = state.load_takeover_findings()
    logger.info("Stage 8 complete. %d total takeover finding(s) now in %s",
                len(findings), state.assets_db_path)


if __name__ == "__main__":
    main()
