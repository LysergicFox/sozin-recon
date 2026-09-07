"""
Mocked-tier tests for stage 10 / B2a API-schema discovery (OpenAPI/Swagger).
Tier 2 (no network). Covers the OpenAPI 2.0 + 3.0 parsers (path×method, params
incl. body-$ref, per-op security → auth_status, same-origin base path), the
content-based spec check that rejects an SPA catch-all, per-host discovery +
R5 raw archive + R7 isolation, and persist_records linkage. All records
target_derived=True (schema is target-authored).

Location-independent: walks up to the dir containing state.py.
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
import stage_api_discovery as scd
from state import RunState, Asset


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# --- real-shaped fixtures (compact) -----------------------------------------
SPEC_V2 = {
    "swagger": "2.0",
    "basePath": "/api",
    "host": "OTHER.example.com",  # must be IGNORED (same-origin, R1)
    "paths": {
        "/pet/{petId}": {
            "parameters": [{"name": "trace", "in": "header"}],  # path-level shared param
            "get": {"parameters": [{"name": "petId", "in": "path", "type": "integer"}],
                    "security": [{"api_key": []}]},              # → gated
            "delete": {"security": []},                          # [] → explicitly public
        },
        "/pet": {
            "post": {"parameters": [{"name": "body", "in": "body",
                                     "schema": {"$ref": "#/definitions/Pet"}}]},
        },
    },
    "definitions": {"Pet": {"properties": {"id": {}, "name": {}, "status": {}}}},
}

SPEC_V3 = {
    "openapi": "3.0.4",
    "servers": [{"url": "/v3"}],                                 # relative base path
    "paths": {
        "/user": {
            "post": {
                "requestBody": {"content": {"application/json":
                                {"schema": {"$ref": "#/components/schemas/User"}}}},
                "security": [{"oauth": ["w"]}],                  # → gated
            },
        },
    },
    "components": {"schemas": {"User": {"properties": {"username": {}, "email": {}}}}},
}


# --- _looks_like_spec: the central SPA-catch-all trap ------------------------

def test_looks_like_spec_rejects_spa_and_accepts_real():
    assert scd._looks_like_spec("<html><body>app</body></html>", "text/html") is None
    assert scd._looks_like_spec('{"foo": 1}', "application/json") is None, "JSON without markers rejected"
    assert scd._looks_like_spec('{"swagger":"2.0"}', "application/json") is None, "marker but no paths rejected"
    ok = scd._looks_like_spec(json.dumps(SPEC_V2), "application/json")
    assert isinstance(ok, dict) and "paths" in ok
    print("PASS: _looks_like_spec rejects SPA/HTML + markerless JSON, accepts a real spec")


# --- OpenAPI 2.0 parser -----------------------------------------------------

def test_parse_openapi_v2():
    eps = scd.parse_openapi(SPEC_V2, "http://h.example.com:3000")
    by = {(e["method"], e["path"]): e for e in eps}
    # base path applied; spec host IGNORED (same-origin)
    g = by[("GET", "/api/pet/{petId}")]
    assert g["url"] == "http://h.example.com:3000/api/pet/{petId}"
    assert g["auth_status"] == "gated"
    assert {(p["name"], p["location"]) for p in g["params"]} == {("petId", "path"), ("trace", "header")}
    d = by[("DELETE", "/api/pet/{petId}")]
    assert d["auth_status"] is None, "security:[] means explicitly public"
    assert {(p["name"], p["location"]) for p in d["params"]} == {("trace", "header")}
    post = by[("POST", "/api/pet")]
    assert {(p["name"], p["location"]) for p in post["params"]} == {
        ("id", "body"), ("name", "body"), ("status", "body")}, "body $ref → property names"
    print("PASS: OpenAPI 2.0 → endpoints (base path, auth from security) + params (path/header/body-$ref)")


# --- OpenAPI 3.0 parser -----------------------------------------------------

def test_parse_openapi_v3():
    eps = scd.parse_openapi(SPEC_V3, "https://h.example.com")
    assert len(eps) == 1
    e = eps[0]
    assert e["url"] == "https://h.example.com/v3/user" and e["method"] == "POST"
    assert e["auth_status"] == "gated" and e["content_type"] == "application/json"
    assert {(p["name"], p["location"]) for p in e["params"]} == {("username", "body"), ("email", "body")}
    print("PASS: OpenAPI 3.0 → requestBody $ref body params + relative servers base path")


def test_parse_openapi_v3_ignores_absolute_server_origin():
    spec = dict(SPEC_V3, servers=[{"url": "https://api.OTHER.com/v9"}])
    e = scd.parse_openapi(spec, "https://h.example.com")[0]
    assert e["url"] == "https://h.example.com/user", "absolute server origin ignored (R1 same-origin)"
    print("PASS: absolute servers[].url not followed off-origin (R1)")


# --- per-host discovery: SPA first, then a real spec ------------------------

def test_discover_openapi_for_host_skips_spa_then_finds_spec():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    # first candidate = SPA catch-all (200 html); second = the real spec
    fetches = iter([
        (200, "text/html", "<html>spa</html>"),
        (200, "application/json", json.dumps(SPEC_V2)),
    ])
    with mock.patch.object(scd, "_fetch", side_effect=lambda u, timeout=15: next(fetches)), \
         mock.patch.object(scd.time, "sleep"):
        assets, eps, params = scd.discover_openapi_for_host(
            "h.example.com", "http://h.example.com:3000", st, scope)
    # spec URL asset + 3 endpoint assets; endpoints target_derived
    assert any(a.metadata.get("openapi_spec") for a in assets)
    assert len(eps) == 3 and all(e.target_derived for e in eps)
    assert all(p.target_derived for p in params)
    # R5 raw archive written for this host
    assert (st.raw_dir / "stage10_openapi_h.example.com.json").exists()
    print("PASS: discover skips SPA, finds real spec on 2nd candidate, archives raw (R5), builds records")


def test_discover_openapi_none_when_no_spec():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    with mock.patch.object(scd, "_fetch", return_value=(200, "text/html", "<html>spa</html>")), \
         mock.patch.object(scd.time, "sleep"):
        assets, eps, params = scd.discover_openapi_for_host("h", "http://h", st, scope)
    assert (assets, eps, params) == ([], [], [])
    print("PASS: a host serving only an SPA catch-all yields no records")


# --- B2b: GraphQL introspection ---------------------------------------------

INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "user", "args": [{"name": "id"}, {"name": "active"}]},
            {"name": "products", "args": [{"name": "limit"}]}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "deleteUser", "args": [{"name": "id"}]},
            {"name": "login", "args": [{"name": "username"}, {"name": "password"}]}]},
        {"name": "User", "kind": "OBJECT", "fields": [{"name": "id", "args": []}]},
    ]}}}


def test_looks_like_introspection():
    assert scd._looks_like_introspection("<html>graphiql</html>") is None
    assert scd._looks_like_introspection('{"errors":[{"message":"introspection disabled"}]}') is None
    assert scd._looks_like_introspection('{"data":{"__schema":{"types":[]}}}') is None, "empty types rejected"
    sch = scd._looks_like_introspection(json.dumps(INTROSPECTION))
    assert isinstance(sch, dict) and sch["queryType"]["name"] == "Query"
    print("PASS: _looks_like_introspection rejects HTML/errors/empty, accepts a real __schema")


def test_parse_graphql():
    entry, args = scd.parse_graphql(INTROSPECTION["data"]["__schema"], "http://h.example.com/graphql")
    assert entry["method"] == "POST" and entry["path"] == "/graphql"
    md = entry["metadata"]
    assert md["graphql_queries"] == {"user": ["id", "active"], "products": ["limit"]}
    assert md["graphql_mutations"] == {"deleteUser": ["id"], "login": ["username", "password"]}
    assert md["graphql_operation_count"] == 4
    assert args == ["active", "id", "limit", "password", "username"], "distinct arg names, sorted"
    print("PASS: parse_graphql → one endpoint + query/mutation→args catalog + distinct arg params")


def test_discover_graphql_skips_nonql_then_finds():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    resp = iter([(404, "", ""),                                   # /graphql not here
                 (200, "application/json", json.dumps(INTROSPECTION))])  # /api/graphql real
    with mock.patch.object(scd, "_post_json", side_effect=lambda u, o, timeout=15: next(resp)), \
         mock.patch.object(scd.time, "sleep"):
        assets, eps, params = scd.discover_graphql_for_host("h.example.com", "http://h.example.com", st, scope)
    assert len(assets) == 1 and assets[0].metadata.get("graphql") is True
    assert len(eps) == 1 and eps[0].method == "POST" and eps[0].target_derived
    assert eps[0].metadata["graphql_operation_count"] == 4
    assert {p.name for p in params} == {"id", "active", "limit", "username", "password"}
    assert all(p.target_derived and p.location == "body" for p in params)
    assert (st.raw_dir / "stage10_graphql_h.example.com.json").exists()
    print("PASS: discover_graphql skips non-GraphQL path, finds introspection, archives raw, builds records")


def test_discover_graphql_none_when_introspection_disabled():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    with mock.patch.object(scd, "_post_json",
                           return_value=(200, "application/json", '{"errors":[{"message":"disabled"}]}')), \
         mock.patch.object(scd.time, "sleep"):
        out = scd.discover_graphql_for_host("h", "http://h", st, scope)
    assert out == ([], [], [])
    print("PASS: introspection-disabled endpoint yields no records")


# --- run_api_discovery: R7 isolation (OpenAPI + GraphQL), empty -------------

def test_run_api_discovery_fault_isolation_R7():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    good = ([Asset(value="http://good/x", type="url", discovered_by="openapi",
                   discovered_at_stage=10, discovered_in_pass=1)], [], [])

    def _side(host, base, state, scope):
        if host == "bad":
            raise RuntimeError("boom")
        return good

    with mock.patch.object(scd, "discover_openapi_for_host", side_effect=_side), \
         mock.patch.object(scd, "discover_graphql_for_host", return_value=([], [], [])):
        new_assets, records = scd.run_api_discovery(["bad", "good"], st, 1, scope,
                                                    host_base={"bad": "http://bad", "good": "http://good"})
    assert [a.value for a in new_assets] == ["http://good/x"], "bad host isolated (R7)"
    print("PASS: one host raising doesn't kill stage 10; OpenAPI/GraphQL isolated per-capability (R7)")


def test_run_api_discovery_empty_hosts():
    st = fresh_state()
    assert scd.run_api_discovery([], st, 1, {"rate_limit": {"resolution": "not_applicable"}}) == \
        ([], {"endpoints": [], "parameters": []})
    print("PASS: empty hosts → no work")


# --- integration: endpoint/param link to the minted url asset ---------------

def test_persist_links_openapi_records():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    fetches = iter([(200, "application/json", json.dumps(SPEC_V3))])
    with mock.patch.object(scd, "_fetch", side_effect=lambda u, timeout=15: next(fetches)), \
         mock.patch.object(scd.time, "sleep"):
        new_assets, eps, params = scd.discover_openapi_for_host(
            "h.example.com", "https://h.example.com", st, scope)
    for a in new_assets:
        a.scope_status = "in_scope"
    st.add_assets(new_assets)
    main.persist_records(st, {"endpoints": eps, "parameters": params})
    saved_eps = st.load_endpoints()
    assert len(saved_eps) == 1
    url_id = {a.value: a.asset_id for a in st.load_assets()}["https://h.example.com/v3/user"]
    assert saved_eps[0].asset_id == url_id
    saved_params = st.load_parameters()
    assert {p.name for p in saved_params} == {"username", "email"}
    assert all(p.asset_id == url_id for p in saved_params)
    print("PASS: openapi endpoint + params link to the minted url asset via persist_records")


if __name__ == "__main__":
    test_looks_like_spec_rejects_spa_and_accepts_real()
    test_parse_openapi_v2()
    test_parse_openapi_v3()
    test_parse_openapi_v3_ignores_absolute_server_origin()
    test_discover_openapi_for_host_skips_spa_then_finds_spec()
    test_discover_openapi_none_when_no_spec()
    test_looks_like_introspection()
    test_parse_graphql()
    test_discover_graphql_skips_nonql_then_finds()
    test_discover_graphql_none_when_introspection_disabled()
    test_run_api_discovery_fault_isolation_R7()
    test_run_api_discovery_empty_hosts()
    test_persist_links_openapi_records()
    print("\nAll checks passed.")
