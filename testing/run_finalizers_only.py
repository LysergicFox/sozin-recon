#!/usr/bin/env python3
"""
Standalone finalizers/enrichment runner - runs the DETERMINISTIC, no-traffic
tail passes against an existing run directory's assets.db, in the same order
run_pipeline does, WITHOUT repeating any active stage:

    E4  secret classification   (run_secret_classification)
    C5  tech→CVE candidates      (run_cve_candidates)
    C4  auth-surface classification (run_auth_classification)
    F1  URL clustering           (run_url_clustering)
    A2  interest scoring         (run_interest_scoring)
    F6  target-profile digest    (run_target_profile → target_profile.{json,md})

These are exactly the passes that produce target_profile.json + the interest/
cluster/auth/cve enrichment the dashboard consumes. They only run at the END of
a full pipeline, so a stitched or interrupted run (e.g. one assembled from the
run_stageN_only scripts, or one that errored mid-pipeline) won't have them until
this is run. IMPORTS the canonical stage functions main/run_pipeline calls (never
reimplements them; see CONTRIBUTING).

NOT included: C2 screenshots — it makes ACTIVE headless-Chrome requests to the
target, so it is not a no-traffic finalizer; run the full pipeline (or a future
screenshots-only runner) for that.

Usage:
    python3 run_finalizers_only.py --run-dir /path/to/existing_run_directory
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
from stages.secret_classification import run_secret_classification
from stages.cve_candidates import run_cve_candidates
from stages.auth_classification import run_auth_classification
from stages.url_clustering import run_url_clustering
from stages.interest_scoring import run_interest_scoring
from stages.target_profile import run_target_profile

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("recon_agent")


def main():
    parser = argparse.ArgumentParser(
        description="Run the deterministic finalizer/enrichment passes (E4/C5/C4/F1/A2/F6) only")
    parser.add_argument("--run-dir", required=True, help="Path to an existing run directory with a populated assets.db")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    state = RunState(run_dir)

    # load_scope() also enforces verified_by_human, same guard every other
    # entrypoint applies before touching a run directory.
    state.load_scope()

    if not state.load_assets():
        logger.error(
            "No assets found in %s - nothing to finalize (run the pipeline "
            "stages first, or check --run-dir)", state.assets_db_path,
        )
        return

    # Same order as run_pipeline's tail. All deterministic, no target traffic.
    logger.info("--- E4: offline secret classification ---")
    run_secret_classification(state)
    logger.info("--- C5: tech→CVE candidate flagging ---")
    run_cve_candidates(state)
    logger.info("--- C4: auth-surface classification ---")
    run_auth_classification(state)
    logger.info("--- F1: URL clustering ---")
    run_url_clustering(state)
    logger.info("--- A2: interest scoring ---")
    run_interest_scoring(state)
    logger.info("--- F6: target-profile digest ---")
    run_target_profile(state)

    logger.info("Finalizers complete. See %s and target_profile.{json,md} in %s",
                state.assets_db_path, run_dir)


if __name__ == "__main__":
    main()
