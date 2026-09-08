#!/usr/bin/env python3
"""
Standalone stage 5 (hidden parameter discovery: paramspider + x8) runner -
re-runs ONLY stage 5 against an existing run directory's assets.db, without
repeating stages 1-4. Mirrors run_content_discovery_only.py's pattern and
IMPORTS the shared run_stage5_and_report from main (never reimplements it -
two implementations drift; see CONTRIBUTING).

Usage:
    python3 run_stage5_only.py --run-dir /path/to/existing_run_directory

Expects a populated assets.db (stages 1-4 already run). paramspider seeds from
the scope's root domains; x8 seeds from the in-scope live URLs already in the
DB. Requires x8 + paramspider on PATH and the SecLists param-name wordlist.
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
from main import run_stage5_and_report, extract_root_domains

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("recon_agent")


def main():
    parser = argparse.ArgumentParser(description="Re-run stage 5 (paramspider + x8 hidden params) only")
    parser.add_argument("--run-dir", required=True, help="Path to an existing run directory with a populated assets.db")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    state = RunState(run_dir)

    # load_scope() also enforces verified_by_human, same guard every other
    # entrypoint applies before touching a run directory.
    scope = state.load_scope()
    patterns = ScopePatterns.from_scope_dict(scope)
    root_domains = extract_root_domains(scope)

    if not state.load_assets():
        logger.error(
            "No assets found in %s (stages 1-4 must have already run) - run "
            "stages 1-4 first, or check --run-dir", state.assets_db_path,
        )
        return

    logger.info("Proceeding with stage 5 only (%d root domain(s) for paramspider)", len(root_domains))

    run_stage5_and_report(root_domains, patterns, state, scope)

    logger.info("Stage 5 complete. See %s", state.assets_db_path)


if __name__ == "__main__":
    main()
