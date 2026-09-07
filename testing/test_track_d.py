"""
Mocked-tier tests for Track D (first-class source records: parameter /
endpoint / secret / service). Tier 2 (no real tools, no network). Covers the
RunState add/load/dedup methods, the secret fingerprint (capped + never
leaks the raw value), the stage 5 (x8) / stage 7 (jsluice) producer
rewiring, and main.persist_records (asset_id linkage + out-of-scope drop).

Location-independent: resolves the repo root by walking up to the dir that
contains state.py, so it runs from the repo root or under testing/.
"""
import json
import sys
import tempfile
import unittest.mock as mock
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _p in (_HERE, *_HERE.parents):
    if (_p / "state.py").exists():
        _REPO_ROOT = _p
        break
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "stages"))

import main
from state import (
    RunState, Asset, Parameter, Endpoint, Secret, Service, secret_fingerprint,
)
import stage5_hidden_params as s5
import stage7_js_extraction as s7


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def _asset(value, type_="url", scope_status="in_scope"):
    return Asset(value=value, type=type_, discovered_by="t",
                 discovered_at_stage=1, discovered_in_pass=1,
                 scope_status=scope_status)


# ---------------------------------------------------------------------------
# RunState add/load/dedup for each table
# ---------------------------------------------------------------------------

def test_parameters_add_load_dedup():
    st = fresh_state()
    p = Parameter(name="id", host="h.example.com", endpoint="https://h.example.com/a",
                  method="GET", location="query", reflected=True, discovered_by="x8",
                  target_derived=False, discovered_at_stage=5, discovered_in_pass=1)
    new = st.add_parameters([p])
    assert len(new) == 1
    again = st.add_parameters([Parameter(name="id", host="h.example.com",
                                         endpoint="https://h.example.com/a", method="GET",
                                         location="query", discovered_by="x8")])
    assert again == [], "same (host,endpoint,name,method,location) must dedup"
    loaded = st.load_parameters()
    assert len(loaded) == 1
    assert loaded[0].reflected is True and loaded[0].target_derived is False
    print("PASS: parameters add/load/dedup + bool round-trip")


def test_endpoints_add_load_dedup():
    st = fresh_state()
    e = Endpoint(url="https://h.example.com/api", host="h.example.com", path="/api",
                 method="POST", discovered_by="jsluice", target_derived=True)
    assert len(st.add_endpoints([e])) == 1
    assert st.add_endpoints([Endpoint(url="https://h.example.com/api", host="h.example.com",
                                      path="/api", method="POST")]) == []
    loaded = st.load_endpoints()
    assert loaded[0].method == "POST" and loaded[0].target_derived is True
    print("PASS: endpoints add/load/dedup")


def test_services_add_load_dedup():
    st = fresh_state()
    sv = Service(target="1.2.3.4", ip="1.2.3.4", port=8080, proto="tcp", discovered_by="naabu")
    assert len(st.add_services([sv])) == 1
    assert st.add_services([Service(target="1.2.3.4", port=8080, proto="tcp")]) == []
    loaded = st.load_services()
    assert loaded[0].port == 8080 and loaded[0].proto == "tcp"
    print("PASS: services add/load/dedup")


def test_secrets_add_load_dedup_and_no_raw_value():
    st = fresh_state()
    raw_value = "AKIAIOSFODNN7EXAMPLEKEY"  # the kind of thing we must never store
    fp = secret_fingerprint(raw_value)
    s = Secret(kind="aws_key", fingerprint=fp, raw_log_ref="raw/stage7_jsluice_secrets_x.json",
               severity="high", discovered_by="jsluice", asset_id="a1",
               metadata={"source_url": "https://h.example.com/app.js"})
    assert len(st.add_secrets([s])) == 1
    # same (asset_id, fingerprint) dedups
    assert st.add_secrets([Secret(kind="aws_key", fingerprint=fp, raw_log_ref="x",
                                  asset_id="a1")]) == []
    loaded = st.load_secrets()
    assert loaded[0].validated is None and loaded[0].target_derived is True

    # the raw secret value must NOT appear anywhere in the stored row
    with st._connect() as conn:
        rows = conn.execute("SELECT * FROM secrets").fetchall()
    blob = json.dumps(rows)
    assert raw_value not in blob, "raw secret value leaked into assets.db!"
    print("PASS: secrets add/load/dedup; raw value never stored")


def test_secret_fingerprint_caps_and_hides():
    v = "AKIAIOSFODNN7EXAMPLEKEY"
    fp = secret_fingerprint(v)
    assert fp.startswith("AKIA")  # head preserved
    assert v[4:-4] not in fp, "middle of secret must not appear"
    assert f"len={len(v)}" in fp and "sha256=" in fp
    # short secret shows only a single leading char
    short = secret_fingerprint("abcd")
    assert short.startswith("a…") and "abcd" not in short
    # deterministic (doubles as dedup key)
    assert secret_fingerprint(v) == fp
    print("PASS: secret_fingerprint caps head, hides the middle, is deterministic")


# ---------------------------------------------------------------------------
# stage 5 - x8 -> parameter records
# ---------------------------------------------------------------------------

def test_stage5_x8_emits_parameter_records():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    with mock.patch.object(s5, "run_x8", return_value=["id", "debug"]):
        new_assets, meta, records = s5.run_stage5(
            [], ["https://api.example.com/v1?x=1"], st, current_pass=1, scope=scope
        )
    assert meta == {}, "x8 no longer emits metadata"
    params = records["parameters"]
    assert len(params) == 2
    for p in params:
        assert p.endpoint == "https://api.example.com/v1?x=1"
        assert p.host == "api.example.com"
        assert p.method == "GET" and p.location == "query"
        assert p.reflected is True
        assert p.target_derived is False  # names come from our wordlist
    print("PASS: stage 5 x8 findings become parameter records (target_derived=False, reflected)")


# ---------------------------------------------------------------------------
# stage 7 - jsluice -> endpoint / parameter / secret records
# ---------------------------------------------------------------------------

def test_stage7_jsluice_urls_returns_rich_dicts():
    st = fresh_state()
    jsonl = json.dumps({"url": "/api/x", "method": "post",
                        "queryParams": ["q"], "bodyParams": ["b"]})
    with mock.patch.object(s7, "_run_tool", return_value=(jsonl, "", 0)):
        findings = s7.run_jsluice_urls("https://h.example.com/app.js", st)
    assert findings == [{
        "url": "https://h.example.com/api/x",  # resolved against source js
        "method": "POST",
        "queryParams": ["q"],
        "bodyParams": ["b"],
    }], findings
    # R5-style per-source raw filename
    assert (st.raw_dir / "stage7_jsluice_urls_https___h.example.com_app.js.json").exists()
    print("PASS: stage 7 run_jsluice_urls returns url+method+params, per-source raw file")


def test_stage7_builds_endpoint_param_secret_records():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    url_finding = {"url": "https://h.example.com/api", "method": "POST",
                   "queryParams": ["q"], "bodyParams": ["b"]}
    secret_finding = {"kind": "aws", "data": "AKIAsecretvalueZZZZ", "severity": "high"}
    with mock.patch.object(s7, "probe_bundler_paths", return_value=[]), \
         mock.patch.object(s7, "run_jsluice_urls", return_value=[url_finding]), \
         mock.patch.object(s7, "run_jsluice_secrets", return_value=[secret_finding]):
        new_assets, meta, records = s7.run_stage7(
            [], ["https://h.example.com/app.js"], st, current_pass=1, scope=scope
        )
    assert meta == {}, "jsluice secrets no longer emit metadata"
    # endpoint
    eps = records["endpoints"]
    assert len(eps) == 1 and eps[0].method == "POST" and eps[0].target_derived is True
    # params: one query + one body, both target_derived, reflected None
    ps = records["parameters"]
    assert {(p.name, p.location) for p in ps} == {("q", "query"), ("b", "body")}
    assert all(p.target_derived and p.reflected is None for p in ps)
    # secret: fingerprint set, raw value absent from the record
    secs = records["secrets"]
    assert len(secs) == 1
    sec = secs[0]
    assert sec.kind == "aws" and sec.validated is None and sec.target_derived is True
    assert "AKIAsecretvalueZZZZ" not in sec.fingerprint
    assert "AKIAsecretvalueZZZZ" not in json.dumps(sec.metadata)
    assert sec.metadata.get("source_url") == "https://h.example.com/app.js"
    # the resolved endpoint url also became a url asset
    assert any(a.type == "url" and a.value == "https://h.example.com/api" for a in new_assets)
    print("PASS: stage 7 jsluice builds endpoint + query/body params + fingerprinted secret")


# ---------------------------------------------------------------------------
# main.persist_records - asset_id linkage + out-of-scope drop
# ---------------------------------------------------------------------------

def test_persist_records_links_and_drops_out_of_scope():
    st = fresh_state()
    # in-scope url asset (parent for an endpoint/param) + out-of-scope one
    st.add_assets([
        _asset("https://h.example.com/api", "url", "in_scope"),
        _asset("https://tracker.evil.com/x", "url", "out_of_scope"),
        _asset("h.example.com", "subdomain", "in_scope"),
    ])
    in_asset_id = {a.value: a.asset_id for a in st.load_assets()}["https://h.example.com/api"]

    records = {
        "endpoints": [
            Endpoint(url="https://h.example.com/api", host="h.example.com", path="/api",
                     method="GET", discovered_by="jsluice"),
            Endpoint(url="https://tracker.evil.com/x", host="tracker.evil.com", path="/x",
                     method="GET", discovered_by="jsluice"),  # out_of_scope -> dropped
        ],
        "parameters": [
            Parameter(name="q", host="h.example.com", endpoint="https://h.example.com/api",
                      method="GET", location="query", discovered_by="jsluice"),
        ],
        "services": [
            Service(target="h.example.com", host="h.example.com", port=8080, proto="tcp",
                    discovered_by="naabu"),
        ],
    }
    main.persist_records(st, records)

    eps = st.load_endpoints()
    assert len(eps) == 1, "the out_of_scope endpoint must be dropped"
    assert eps[0].url == "https://h.example.com/api"
    assert eps[0].asset_id == in_asset_id, "endpoint linked to its in-scope url asset"

    params = st.load_parameters()
    assert len(params) == 1 and params[0].asset_id == in_asset_id

    svcs = st.load_services()
    assert len(svcs) == 1 and svcs[0].port == 8080
    print("PASS: persist_records links asset_id and drops out-of-scope records")


if __name__ == "__main__":
    test_parameters_add_load_dedup()
    test_endpoints_add_load_dedup()
    test_services_add_load_dedup()
    test_secrets_add_load_dedup_and_no_raw_value()
    test_secret_fingerprint_caps_and_hides()
    test_stage5_x8_emits_parameter_records()
    test_stage7_jsluice_urls_returns_rich_dicts()
    test_stage7_builds_endpoint_param_secret_records()
    test_persist_records_links_and_drops_out_of_scope()
    print("\nAll checks passed.")
