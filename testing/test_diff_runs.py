"""
Mocked-tier tests for E2 — incremental / diff runs. Pure offline set-difference
over two synthetic run dirs. Location-independent.
"""
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
sys.path.insert(0, str(_REPO_ROOT / "stages"))

import diff_runs as e2
from state import RunState, Asset, Endpoint, Secret, secret_fingerprint


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def _asset(value, type_="subdomain"):
    return Asset(value=value, type=type_, discovered_by="t", discovered_at_stage=1,
                discovered_in_pass=1, scope_status="in_scope")


def test_compute_run_diff_new_and_removed():
    base = fresh_state()
    cur = fresh_state()
    # shared + baseline-only (removed) + current-only (new)
    base.add_assets([_asset("shared.example.com"), _asset("gone.example.com")])
    cur.add_assets([_asset("shared.example.com"), _asset("new.example.com")])
    base.add_endpoints([Endpoint(url="https://h/old", host="h", path="/old", method="GET")])
    cur.add_endpoints([Endpoint(url="https://h/new", host="h", path="/new", method="GET")])
    # a rotated secret: baseline has one fingerprint, current a different one
    base.add_secrets([Secret(kind="x", fingerprint=secret_fingerprint("OLDSECRET"), raw_log_ref="r")])
    cur.add_secrets([Secret(kind="x", fingerprint=secret_fingerprint("NEWSECRET"), raw_log_ref="r")])

    diff = e2.compute_run_diff(base, cur)
    new_subs = {a["value"] for a in diff["new"]["assets"]}
    removed_subs = {a["value"] for a in diff["removed"]["assets"]}
    assert new_subs == {"new.example.com"} and removed_subs == {"gone.example.com"}
    assert {e["url"] for e in diff["new"]["endpoints"]} == {"https://h/new"}
    assert {e["url"] for e in diff["removed"]["endpoints"]} == {"https://h/old"}
    # secrets diffed by fingerprint (never raw value); raw text absent from artifact
    assert diff["summary"]["secrets"] == {"new": 1, "removed": 1}
    import json
    assert "OLDSECRET" not in json.dumps(diff) and "NEWSECRET" not in json.dumps(diff)
    print("PASS: compute_run_diff finds new/removed per layer; secrets by fingerprint, no raw value")


def test_identical_runs_empty_diff():
    base = fresh_state()
    cur = fresh_state()
    for st in (base, cur):
        st.add_assets([_asset("same.example.com")])
    diff = e2.compute_run_diff(base, cur)
    assert diff["totals"] == {"new": 0, "removed": 0}
    print("PASS: identical runs → empty diff")


def test_write_diff_artifact():
    base = fresh_state()
    cur = fresh_state()
    cur.add_assets([_asset("brand-new.example.com")])
    diff = e2.compute_run_diff(base, cur)
    path = e2.write_diff_artifact(cur, diff)
    assert path.exists() and path.name == "diff.json"
    import json
    loaded = json.loads(path.read_text())
    assert loaded["totals"]["new"] == 1
    print("PASS: write_diff_artifact writes diff.json into the current run dir")


if __name__ == "__main__":
    test_compute_run_diff_new_and_removed()
    test_identical_runs_empty_diff()
    test_write_diff_artifact()
    print("\nAll checks passed.")
