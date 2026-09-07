"""
Mocked-tier tests for E3 — target-derived wordlist mining. Offline. Location-independent.
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

import wordlist_mining as e3
from state import RunState, Asset, Endpoint, Parameter


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def test_mine_path_tokens_cleaning():
    assets = [
        Asset(value="https://h.example.com/api/v3/product/42", type="url", discovered_by="t",
              discovered_at_stage=1, discovered_in_pass=1),
        Asset(value="https://h.example.com/admin/config.json", type="url", discovered_by="t",
              discovered_at_stage=1, discovered_in_pass=1),
    ]
    endpoints = [Endpoint(url="https://h/backup", host="h", path="/backup/db", method="GET")]
    tokens = e3.mine_path_tokens(assets, endpoints)
    assert "product" in tokens and "42" not in tokens, "pure-numeric id dropped"
    assert "config.json" in tokens and "config" in tokens, "dotted file → whole + stem"
    assert "admin" in tokens and "backup" in tokens and "db" in tokens
    assert "v3" in tokens  # short-but-≥2 token kept
    print("PASS: mine_path_tokens — segments cleaned (no numeric ids), dotted file → whole+stem")


def test_mine_param_names():
    params = [Parameter(name="user_id", host="h", endpoint="https://h/a", method="GET",
                        location="query", discovered_by="t")]
    assets = [Asset(value="https://h/search?q=x&debug=1", type="url", discovered_by="t",
                    discovered_at_stage=1, discovered_in_pass=1)]
    names = e3.mine_param_names(params, assets)
    assert names == {"user_id", "q", "debug"}
    print("PASS: mine_param_names — from parameters table + url query strings")


def test_run_wordlist_mining_writes_artifacts():
    st = fresh_state()
    st.add_assets([Asset(value="https://h.example.com/admin/login", type="url", discovered_by="t",
                         discovered_at_stage=1, discovered_in_pass=1, scope_status="in_scope")])
    st.add_parameters([Parameter(name="token", host="h.example.com",
                                 endpoint="https://h.example.com/admin/login", method="POST",
                                 location="body", discovered_by="t")])
    result = e3.run_wordlist_mining(st)
    paths = (st.run_dir / "target_derived_paths.txt").read_text().split()
    params = (st.run_dir / "target_derived_params.txt").read_text().split()
    assert "admin" in paths and "login" in paths
    assert "token" in params
    assert result["paths"] == len(paths) and result["params"] == len(params)
    print("PASS: run_wordlist_mining writes target_derived_paths.txt + target_derived_params.txt")


def test_empty_db():
    st = fresh_state()
    result = e3.run_wordlist_mining(st)
    assert result["paths"] == 0 and result["params"] == 0
    assert (st.run_dir / "target_derived_paths.txt").read_text() == ""
    print("PASS: empty db → empty wordlist files, no crash")


if __name__ == "__main__":
    test_mine_path_tokens_cleaning()
    test_mine_param_names()
    test_run_wordlist_mining_writes_artifacts()
    test_empty_db()
    print("\nAll checks passed.")
