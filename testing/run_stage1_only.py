#!/usr/bin/env python3
"""
Standalone re-run of stage 1 (passive discovery) only, against an existing
run directory. Follows the same pattern as run_stage5_only.py and
run_stage7_only.py (see CONTRIBUTING.md, "Standalone re-run scripts import,
never duplicate"): imports run_stage_and_report() and extract_root_domains()
directly from main.py rather than reimplementing the scope-gate -> de-dupe/
merge -> log breakdown -> run_state update tail, so this script and the
full pipeline can never drift apart on what "run stage 1" actually means.

Useful for the exact kind of isolated real-run verification stage1_passive.py
changes need (per the locked staged-verification workflow: built -> mocked
tests -> real run -> fix bugs -> second real run to confirm) without paying
for stages 3/4/5/6/7/8/9 on every iteration.

Usage:
    python3 run_stage1_only.py --run-dir /path/to/run_directory

Expects run_directory/scope.json to already exist and have
verified_by_human: true (same precondition as main.py - see state.py).
Does NOT touch current_stage/current_pass in run_state.json beyond what
run_stage_and_report() itself updates, so re-running this against a run
directory that's already progressed past stage 1 in a real pipeline run
won't reset its overall progress - it just re-does stage 1's discovery
and merges any newly-found assets in via the normal add_assets() dedupe.
"""

import argparse
import sys
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
from rate_limit_gate import check_run_not_blocked
from stages.stage1_passive import run_stage1

from main import run_stage_and_report, extract_root_domains  # also triggers main.py's
                                                                # module-level logging setup -
                                                                # don't call setup_logging_with_banner()
                                                                # again here, it would just
                                                                # double-print the banner
                                                                # (setup itself is idempotent
                                                                # via force=True, so no harm,
                                                                # just noise)

logger = logging.getLogger("recon_agent.stage1_only")


def main():
    parser = argparse.ArgumentParser(description="Re-run stage 1 (passive discovery) only")
    parser.add_argument("--run-dir", required=True, help="Path to the run directory containing scope.json")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    state = RunState(run_dir)

    logger.info("Loading scope from %s", state.scope_path)
    scope = state.load_scope()
    patterns = ScopePatterns.from_scope_dict(scope)

    logger.info("Checking rate_limit gate")
    check_run_not_blocked(scope)

    root_domains = extract_root_domains(scope)
    if not root_domains:
        logger.error("No in_scope domains found in scope.json - nothing to do")
        sys.exit(1)
    logger.info("Root domains for this run: %s", root_domains)

    logger.info("--- Stage 1 only: passive discovery ---")
    stage1_found = run_stage1(root_domains, state, current_pass=1)
    run_stage_and_report(1, "passive discovery", stage1_found, patterns, state)

    logger.info("Stage 1 standalone re-run complete.")


if __name__ == "__main__":
    main()
