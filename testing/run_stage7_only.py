#!/usr/bin/env python3
"""
Standalone stage 7 re-run.

Runs ONLY stage 7 (jsluice JS discovery + extraction) against an existing
run directory's assets.db, without repeating stages 1/3/4/5/6. Useful when
iterating on stage 7 itself (e.g. testing the bundler-probe false-positive
fix) against a target where earlier stages have already been run - no need
to burn time re-discovering hosts/urls that are already there.

Reuses the EXACT same seeding (in run_stage7_and_report) and apply/report
logic main.py's full pipeline uses - imported directly from main.py, not
reimplemented here, so there is exactly one place that logic lives and
this script can never drift out of sync with what the full pipeline does
for stage 7. Same pattern as run_stage5_only.py.

Requires assets.db to already have in-scope subdomain assets (for the
bundler-path probe) - ideally also some in-scope url-type assets ending in
.js from stage 6's crawl, though stage 7 works fine without any (the
bundler probe runs regardless).

Usage:
    python3 run_stage7_only.py --run-dir /path/to/run_directory
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
from scope_gate import ScopePatterns

from main import run_stage7_and_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("recon_agent.stage7_only")


def main():
    parser = argparse.ArgumentParser(description="Re-run stage 7 (jsluice JS discovery + extraction) only")
    parser.add_argument("--run-dir", required=True, help="Path to an existing run directory with assets.db already populated")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    state = RunState(run_dir)

    logger.info("Loading scope from %s", state.scope_path)
    scope = state.load_scope()
    patterns = ScopePatterns.from_scope_dict(scope)

    run_stage7_and_report(patterns, state)

    logger.info("Stage 7 re-run complete. See %s and %s", state.assets_db_path, state.review_path)


if __name__ == "__main__":
    main()
