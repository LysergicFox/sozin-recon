"""
Mocked-tier tests for A2 — deterministic interest scoring. No tools, no traffic.
Location-independent.
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

import interest_scoring as a2
from state import RunState, Asset, Endpoint, Parameter, Secret, Service, ReconFinding, secret_fingerprint


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def test_score_url_rules():
    # /admin (kw 5) + gated (3) + params (1) = 9
    score, sig = a2.score_url("/admin", "gated", True)
    assert score == 9 and sig["keywords"] == {"admin": 5} and sig["auth"] == {"gated": 3}
    # segment boundary: /gitlab must NOT score the "git" keyword
    score2, sig2 = a2.score_url("/gitlab/repo", None, False)
    assert score2 == 0 and sig2 == {}
    # a bare product path scores 0
    assert a2.score_url("/products", None, False) == (0, {})
    print("PASS: score_url — keywords+auth+params add up; /gitlab≠git (segment boundary)")


def test_run_interest_scoring_url_and_host():
    st = fresh_state()
    st.add_assets([
        Asset(value="https://h.example.com/admin", type="url", discovered_by="ffuf",
              discovered_at_stage=6.5, discovered_in_pass=1, scope_status="in_scope"),
        Asset(value="https://h.example.com/products", type="url", discovered_by="ffuf",
              discovered_at_stage=6.5, discovered_in_pass=1, scope_status="in_scope"),
        Asset(value="h.example.com", type="subdomain", discovered_by="t",
              discovered_at_stage=4, discovered_in_pass=1, scope_status="in_scope",
              metadata={"waf_suspected": True}),
    ])
    st.add_endpoints([Endpoint(url="https://h.example.com/admin", host="h.example.com",
                               path="/admin", method="GET", auth_status="gated")])
    st.add_parameters([Parameter(name="id", host="h.example.com",
                                 endpoint="https://h.example.com/admin", method="GET",
                                 location="query", discovered_by="ffuf")])
    # host-level signals
    st.add_recon_findings([ReconFinding(host="h.example.com", template_id="git-exposure",
                                        severity="high", matched_at="https://h.example.com/.git/config")])
    st.add_services([Service(target="h.example.com", host="h.example.com", port=4000,
                             proto="tcp", discovered_by="naabu")])

    summary = a2.run_interest_scoring(st)
    by_val = {a.value: a for a in st.load_assets()}
    admin = by_val["https://h.example.com/admin"].metadata
    products = by_val["https://h.example.com/products"].metadata
    host = by_val["h.example.com"].metadata
    assert admin["interest_score"] == 9, admin           # admin5 + gated3 + params1
    assert products["interest_score"] == 0
    # host: high finding (7) + non-std service 4000 (2) + waf (1) = 10
    assert host["interest_score"] == 10, host["interest_signals"]
    assert host["interest_signals"]["findings"]["points"] == 7
    assert host["interest_signals"]["nonstd_services"]["count"] == 1
    # top list is ranked
    assert summary["top"][0][1] >= summary["top"][-1][1]
    print("PASS: run_interest_scoring scores url + host assets from findings/services/waf/auth/keywords")


def test_run_interest_scoring_idempotent_and_empty():
    st = fresh_state()
    assert a2.run_interest_scoring(st) == {"scored": 0, "top": []}  # empty graph, no crash
    st.add_assets([Asset(value="https://h/api", type="url", discovered_by="t",
                         discovered_at_stage=1, discovered_in_pass=1, scope_status="in_scope")])
    a = a2.run_interest_scoring(st)
    b = a2.run_interest_scoring(st)
    assert a == b
    print("PASS: A2 handles empty graph and is idempotent")


if __name__ == "__main__":
    test_score_url_rules()
    test_run_interest_scoring_url_and_host()
    test_run_interest_scoring_idempotent_and_empty()
    print("\nAll checks passed.")
