#!/usr/bin/env python3
"""
Standalone stage 9 runner - re-runs ONLY stage 9 (whatweb deep tech
fingerprinting) against an existing run directory's assets.db, without
repeating stages 1-8. Mirrors run_stage5_only.py / run_stage7_only.py /
run_stage8_only.py's existing pattern for this exact use case.

Usage:
    python3 run_stage9_only.py --run-dir /path/to/existing_run_directory

Expects the run directory to already have a populated assets.db with at
least one confirmed-live host (carrying httpx_status_code in its
metadata, i.e. stage 4 has already run against it) - this script does
NOT run stages 1-8, it only seeds stage 9 from whatever is already on
disk.
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
from main import run_stage9_and_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("recon_agent")


def main():
    parser = argparse.ArgumentParser(description="Re-run stage 9 (whatweb deep tech fingerprinting) only")
    parser.add_argument("--run-dir", required=True, help="Path to an existing run directory with a populated assets.db")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    state = RunState(run_dir)

    # load_scope() also enforces verified_by_human, same guard every other
    # entrypoint (main.py, run_stage5_only.py, run_stage7_only.py,
    # run_stage8_only.py) applies before touching a run directory
    scope = state.load_scope()

    live_hosts = [
        a for a in state.load_assets()
        if a.type == "subdomain" and a.scope_status == "in_scope"
        and "httpx_status_code" in a.metadata
    ]
    if not live_hosts:
        logger.error(
            "No confirmed-live in_scope subdomain assets found in %s "
            "(need httpx_status_code in metadata, i.e. stage 4 must have "
            "already run) - run stages 1-4 first, or check --run-dir "
            "points at the right directory",
            state.assets_db_path,
        )
        return

    logger.info("Found %d confirmed-live in_scope host(s) in assets.db - proceeding with stage 9 only",
                len(live_hosts))

    run_stage9_and_report(state, scope)

    # quick summary: how many hosts now carry whatweb_tech
    updated = [
        a for a in state.load_assets()
        if a.type == "subdomain" and "whatweb_tech" in a.metadata
    ]
    logger.info("Stage 9 complete. %d host(s) now carry whatweb_tech metadata in %s",
                len(updated), state.assets_db_path)


if __name__ == "__main__":
    main()
