"""
Mocked-tier tests for C4 — deterministic auth-surface classification. No tools,
no traffic (C4 is pure post-processing over the on-disk endpoints table + host
metadata). Location-independent.
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

import auth_classification as c4
from state import RunState, Asset, Endpoint


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# --- classify_endpoint unit -------------------------------------------------

def test_classify_endpoint_rules():
    # gated is response-confirmed → never downgraded
    assert c4.classify_endpoint("/api/pet", "gated", None) is None
    # login/oauth/sso paths → auth_surface
    assert c4.classify_endpoint("/login", None, None) == "auth_surface"
    assert c4.classify_endpoint("/oauth/token", None, None) == "auth_surface"
    assert c4.classify_endpoint("/.well-known/openid-configuration", None, 200) == "auth_surface"
    # THE trap: /authors must NOT match /auth (segment-boundary), falls to public on 2xx
    assert c4.classify_endpoint("/authors", None, 200) == "public"
    # 2xx, no auth keyword → public; unknown status → leave NULL
    assert c4.classify_endpoint("/products", None, 200) == "public"
    assert c4.classify_endpoint("/products", None, None) is None
    # already auth_surface / public → no redundant relabel
    assert c4.classify_endpoint("/login", "auth_surface", None) is None
    assert c4.classify_endpoint("/products", "public", 200) is None
    print("PASS: classify_endpoint — gated kept, auth keywords→auth_surface, /authors≠/auth, 2xx→public")


# --- run over a synthetic assets.db -----------------------------------------

def _seed(st):
    st.add_assets([Asset(value="h.example.com", type="subdomain", discovered_by="t",
                         discovered_at_stage=4, discovered_in_pass=1, scope_status="in_scope")])
    st.add_endpoints([
        Endpoint(url="https://h.example.com/login", host="h.example.com", path="/login", method="GET"),
        Endpoint(url="https://h.example.com/secure", host="h.example.com", path="/secure",
                 method="GET", auth_status="gated"),                       # B1-set, must survive
        Endpoint(url="https://h.example.com/pub", host="h.example.com", path="/pub", method="GET",
                 metadata={"ffuf_status": 200}),
        Endpoint(url="https://h.example.com/api", host="h.example.com", path="/api", method="GET"),  # NULL
    ])


def test_run_auth_classification_labels_and_model():
    st = fresh_state()
    _seed(st)
    summary = c4.run_auth_classification(st)
    eps = {e.path: e for e in st.load_endpoints()}
    assert eps["/login"].auth_status == "auth_surface"
    assert eps["/secure"].auth_status == "gated", "response-confirmed gated must not be downgraded"
    assert eps["/pub"].auth_status == "public"
    assert eps["/api"].auth_status is None, "no signal → left NULL"
    # C4-set labels are marked; the gated one is NOT (C4 didn't touch it)
    assert eps["/login"].metadata.get("auth_classified_by") == "c4"
    assert "auth_classified_by" not in eps["/secure"].metadata
    # per-host auth_model written to the host asset
    host = next(a for a in st.load_assets() if a.type == "subdomain")
    model = host.metadata["auth_model"]
    assert model["gated"] == 1 and model["auth_surface"] == 1 and model["public"] == 1
    assert model["auth_surface_paths"] == ["/login"]
    assert summary["hosts_labeled"] == 1
    print("PASS: run_auth_classification labels endpoints (gated kept) + writes per-host auth_model")


def test_run_auth_classification_idempotent():
    st = fresh_state()
    _seed(st)
    first = c4.run_auth_classification(st)
    second = c4.run_auth_classification(st)
    assert first == second, "a second pass must produce the identical summary (idempotent)"
    # labels unchanged on re-run
    eps = {e.path: e.auth_status for e in st.load_endpoints()}
    assert eps == {"/login": "auth_surface", "/secure": "gated", "/pub": "public", "/api": None}
    print("PASS: C4 is idempotent (re-run changes nothing)")


if __name__ == "__main__":
    test_classify_endpoint_rules()
    test_run_auth_classification_labels_and_model()
    test_run_auth_classification_idempotent()
    print("\nAll checks passed.")
