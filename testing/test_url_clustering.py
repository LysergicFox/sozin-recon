"""Mocked-tier tests for F1 — URL clustering. Offline. Location-independent."""
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

import url_clustering as f1
from state import RunState, Asset


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def _url(v):
    return Asset(value=v, type="url", discovered_by="t", discovered_at_stage=6,
                discovered_in_pass=1, scope_status="in_scope")


def test_url_template():
    assert f1.url_template("https://h/product/42") == "/product/{id}"
    assert f1.url_template("https://h/product/99?ref=x&sort=y") == "/product/{id}?ref,sort"
    # uuid + hex collapse; /api/v3 does NOT (v3 is not id-like)
    assert f1.url_template("https://h/u/550e8400-e29b-41d4-a716-446655440000") == "/u/{id}"
    assert f1.url_template("https://h/api/v3/pet") == "/api/v3/pet"
    print("PASS: url_template collapses numeric/uuid/hex ids; keeps /api/v3; sorts query names")


def test_run_url_clustering_marks_representatives():
    st = fresh_state()
    st.add_assets([_url(f"https://h.example.com/product/{i}") for i in range(1, 6)]  # 5 → cluster
                  + [_url("https://h.example.com/about")])                            # 1 → not a cluster
    result = f1.run_url_clustering(st)
    assert result["clusters"] == 1
    by = {a.value: a for a in st.load_assets() if a.type == "url"}
    prods = [by[f"https://h.example.com/product/{i}"] for i in range(1, 6)]
    assert all(a.metadata["url_cluster"] == "/product/{id}" and a.metadata["cluster_size"] == 5 for a in prods)
    reps = [a for a in prods if a.metadata.get("cluster_representative")]
    assert len(reps) == 2, "exactly REPRESENTATIVES_PER_CLUSTER marked representative"
    assert "url_cluster" not in by["https://h.example.com/about"].metadata, "size-1 not clustered"
    print("PASS: run_url_clustering marks a template cluster + 2 representatives; leaves singletons alone")


def test_idempotent_and_empty():
    st = fresh_state()
    assert f1.run_url_clustering(st) == {"clusters": 0, "clustered_assets": 0}
    st.add_assets([_url(f"https://h/x/{i}") for i in range(1, 4)])
    a = f1.run_url_clustering(st)
    b = f1.run_url_clustering(st)
    assert a == b
    print("PASS: F1 empty graph + idempotent")


if __name__ == "__main__":
    test_url_template()
    test_run_url_clustering_marks_representatives()
    test_idempotent_and_empty()
    print("\nAll checks passed.")
