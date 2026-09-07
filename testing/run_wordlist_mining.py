#!/usr/bin/env python3
"""
E3 wordlist miner — extract target-derived path + parameter wordlists from a run
directory's assets.db and write them into the run dir. Offline. Imports the shared
mining logic (never reimplements).

Usage:
    python3 run_wordlist_mining.py --run-dir /path/to/existing_run_directory
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
from wordlist_mining import run_wordlist_mining

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("recon_agent")


def main():
    ap = argparse.ArgumentParser(description="Mine target-derived wordlists from a run (E3)")
    ap.add_argument("--run-dir", required=True, help="Run directory with a populated assets.db")
    args = ap.parse_args()
    state = RunState(Path(args.run_dir))
    result = run_wordlist_mining(state)
    logger.info("Wrote %d path tokens and %d param names to %s",
                result["paths"], result["params"], args.run_dir)


if __name__ == "__main__":
    main()
