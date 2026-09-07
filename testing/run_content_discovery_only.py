#!/usr/bin/env python3
"""
Standalone stage 6.5 (B1 content discovery / ffuf) runner - re-runs ONLY the
content-discovery stage against an existing run directory's assets.db, without
repeating stages 1-6. Mirrors run_stage7_only.py / run_stage9_only.py's pattern
and IMPORTS the shared run_content_discovery_and_report from main (never
reimplements it - two implementations drift; see CONTRIBUTING).

Usage:
    python3 run_content_discovery_only.py --run-dir /path/to/existing_run_directory

Expects a populated assets.db with at least one confirmed-live in_scope host
(carrying httpx_status_code, i.e. stage 4 has already run). Requires ffuf on PATH
and the SecLists wordlist at stage_content_discovery.WORDLIST_PATH.
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
from main import run_content_discovery_and_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("recon_agent")


def main():
    parser = argparse.ArgumentParser(description="Re-run stage 6.5 (ffuf content discovery) only")
    parser.add_argument("--run-dir", required=True, help="Path to an existing run directory with a populated assets.db")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    state = RunState(run_dir)

    # load_scope() also enforces verified_by_human, same guard every other
    # entrypoint applies before touching a run directory.
    scope = state.load_scope()
    patterns = ScopePatterns.from_scope_dict(scope)

    live_hosts = [
        a for a in state.load_assets()
        if a.type == "subdomain" and a.scope_status == "in_scope"
        and "httpx_status_code" in a.metadata
    ]
    if not live_hosts:
        logger.error(
            "No confirmed-live in_scope subdomain assets found in %s (need "
            "httpx_status_code in metadata, i.e. stage 4 must have already run) "
            "- run stages 1-4 first, or check --run-dir", state.assets_db_path,
        )
        return

    logger.info("Found %d confirmed-live in_scope host(s) - proceeding with stage 6.5 only",
                len(live_hosts))

    run_content_discovery_and_report(patterns, state, scope)

    logger.info("Stage 6.5 complete. See %s", state.assets_db_path)


if __name__ == "__main__":
    main()
