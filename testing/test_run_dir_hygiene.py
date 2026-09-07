"""
Mocked-tier tests for RunState run-dir hygiene (R8).

Tier 2 (no real tools, no network) - exercises RunState.__init__'s
filesystem behavior. R8 brings the primitive design's run-dir posture
forward to recon: the run dir already holds sensitive-at-rest data (stage
7's jsluice `secrets` mode writes real secrets into assets.db metadata), so
the dir must be owner-only (chmod 700) at init. At-rest encryption stays
deferred (it would break the sqlite3/cat inspectability that is a core
design value).

Location-independent: resolves the repo root by walking up to the dir that
contains state.py, so it runs from the repo root or under testing/.
"""
import os
import stat
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _p in (_HERE, *_HERE.parents):
    if (_p / "state.py").exists():
        _REPO_ROOT = _p
        break
sys.path.insert(0, str(_REPO_ROOT))

from state import RunState


def test_run_dir_created_mode_0700():
    run_dir = Path(tempfile.mkdtemp()) / "run_under_test"
    assert not run_dir.exists()
    RunState(run_dir)
    mode = stat.S_IMODE(os.stat(run_dir).st_mode)
    assert mode == 0o700, oct(mode)
    print("PASS: RunState creates the run dir with mode 0700")


def test_existing_run_dir_tightened_to_0700():
    # a run dir that already exists with looser perms (a human with a
    # 0755 umask, or a pre-R8 run) must be tightened on the next
    # RunState() open, not left world-readable.
    run_dir = Path(tempfile.mkdtemp()) / "preexisting_run"
    run_dir.mkdir(parents=True)
    run_dir.chmod(0o755)
    RunState(run_dir)
    mode = stat.S_IMODE(os.stat(run_dir).st_mode)
    assert mode == 0o700, oct(mode)
    print("PASS: pre-existing looser-mode run dir is tightened to 0700")


if __name__ == "__main__":
    test_run_dir_created_mode_0700()
    test_existing_run_dir_tightened_to_0700()
    print("\nAll checks passed.")
