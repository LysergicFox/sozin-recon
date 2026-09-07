"""
Mocked-tier tests for stage 11 / B4 archived-JS mining. Tier 2 (no network).
Covers the CDX parser (header-row skip, client-side statuscode + digest dedup,
degrade-on-failure), the id_ raw-snapshot fetch + R5 raw archiving, record
construction (endpoint/parameter/secret, target_derived + source=wayback
provenance), the base_url resolution trap (relative endpoints resolve onto the
ORIGINAL target host, never the local temp path), the D3 secret rule (fingerprint
+ raw_log_ref, no raw value), two-level R7 fault isolation, INSERT OR IGNORE dedup
against a live stage-7 endpoint, persist_records linkage, and the not-live-gated
seed (the deliberate divergence from B1/B2).

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
import stage_archived_js as asj
from stages import stage7_js_extraction as s7   # SAME module object asj imports the runners from
from state import RunState, Asset


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# --- real-shaped CDX fixture: header row + rows to filter/dedup -------------
# fl=original,timestamp,mimetype,statuscode,digest (the order query_cdx_js requests)
CDX_ROWS = [
    ["original", "timestamp", "mimetype", "statuscode", "digest"],   # header (skipped)
    ["https://h.example.com/app.js", "20200101000000", "application/javascript", "200", "AAA"],
    ["https://h.example.com/app.js", "20210601000000", "application/javascript", "200", "AAA"],  # dup digest (non-adjacent) -> dropped client-side
    ["https://h.example.com/vendor.js", "20200101000000", "text/javascript", "200", "BBB"],
    ["https://h.example.com/err.js", "20200101000000", "application/javascript", "404", "CCC"],  # non-200 -> dropped
]
CDX_JSON = json.dumps(CDX_ROWS).encode()


# --- phase 1: CDX parse (header skip, statuscode + digest dedup, R5 raw) ----

def test_query_cdx_js_filters_and_dedups():
    st = fresh_state()
    with mock.patch.object(asj, "_http_get", return_value=(CDX_JSON, 200)):
        snaps = asj.query_cdx_js("h.example.com", st)
    keys = {(s["original"], s["timestamp"]) for s in snaps}
    assert keys == {
        ("https://h.example.com/app.js", "20200101000000"),   # first AAA kept
        ("https://h.example.com/vendor.js", "20200101000000"),  # BBB
    }, keys  # header skipped, 404 dropped, second AAA (dup digest) dropped
    assert (st.raw_dir / "stage11_cdx_h.example.com.json").exists()   # R5 per-host raw
    print("PASS: CDX parse skips header, drops non-200 + duplicate-digest, archives raw (R5)")


def test_query_cdx_degrades_on_non_json_and_on_error():
    st = fresh_state()
    with mock.patch.object(asj, "_http_get", return_value=(b"<html>rate limited</html>", 200)):
        assert asj.query_cdx_js("h", st) == []          # non-JSON -> [] (logged, not raised)
    with mock.patch.object(asj, "_http_get", side_effect=TimeoutError("slow")):
        assert asj.query_cdx_js("h", st) == []          # network error -> [] (degrade, certspotter-style)
    print("PASS: CDX degrades to zero snapshots on non-JSON body and on network error (no raise)")


# --- phase 2: id_ raw fetch + R5 body archive ------------------------------

def test_fetch_snapshot_uses_id_form_and_r5_body_file():
    st = fresh_state()
    snap = {"original": "https://h.example.com/app.js", "timestamp": "20200101000000",
            "digest": "AAA", "mimetype": "application/javascript"}
    seen = {}

    def _capture(url, timeout):
        seen["url"] = url
        return (b"var real=1;", 200)

    with mock.patch.object(asj, "_http_get", side_effect=_capture):
        path = asj.fetch_snapshot(snap, st)
    assert "20200101000000id_/https://h.example.com/app.js" in seen["url"], seen["url"]  # id_ raw form
    assert path.exists() and path.read_bytes() == b"var real=1;"
    assert path.name == "stage11_wayback_body_https___h.example.com_app.js_20200101000000.js"  # R5
    print("PASS: fetch_snapshot builds the id_ raw URL and writes the body to an R5-suffixed .js file")


def test_fetch_snapshot_rejects_empty_or_non_200():
    st = fresh_state()
    snap = {"original": "https://h/a.js", "timestamp": "20200101000000", "digest": "D"}
    with mock.patch.object(asj, "_http_get", return_value=(b"", 200)):
        try:
            asj.fetch_snapshot(snap, st); assert False, "empty body should raise"
        except ValueError:
            pass
    print("PASS: fetch_snapshot raises on an empty/non-200 snapshot (caller R7-skips it)")


# --- record construction: endpoints/params/secrets + provenance ------------

def _mine_one_snapshot(st, url_findings, raw_secrets):
    """Drive run_archived_js_mining over exactly one host/one snapshot with the
    CDX + fetch + jsluice runners mocked; return (new_assets, records)."""
    snap = {"original": "https://h.example.com/app.js", "timestamp": "20200101000000",
            "digest": "AAA", "mimetype": "application/javascript"}
    with mock.patch.object(asj, "query_cdx_js", return_value=[snap]), \
         mock.patch.object(asj, "fetch_snapshot", return_value=Path("/tmp/body.js")), \
         mock.patch.object(asj, "run_jsluice_urls", return_value=url_findings), \
         mock.patch.object(asj, "run_jsluice_secrets", return_value=raw_secrets):
        return asj.run_archived_js_mining(["h.example.com"], st, current_pass=1, scope={})


def test_records_carry_wayback_provenance_and_target_derived():
    st = fresh_state()
    findings = [{"url": "https://h.example.com/api/users", "method": "GET",
                 "queryParams": ["id"], "bodyParams": ["role"]}]   # run_jsluice_urls already upcased
    new_assets, records = _mine_one_snapshot(st, findings, [])

    vals = {a.value for a in new_assets}
    assert "https://h.example.com/app.js" in vals, "archived .js URL minted as a url asset (parents its secrets)"
    assert "https://h.example.com/api/users" in vals, "resolved endpoint minted as a url asset"

    ep = records["endpoints"][0]
    assert ep.url == "https://h.example.com/api/users" and ep.host == "h.example.com"
    assert ep.path == "/api/users" and ep.method == "GET" and ep.target_derived is True
    assert ep.discovered_by == "wayback_jsluice" and ep.discovered_at_stage == 11
    assert ep.metadata["source"] == "wayback"
    assert ep.metadata["snapshot_timestamp"] == "20200101000000"
    assert ep.metadata["archived_url"] == "https://h.example.com/app.js"

    params = {(p.name, p.location) for p in records["parameters"]}
    assert params == {("id", "query"), ("role", "body")}
    assert all(p.target_derived and p.discovered_by == "wayback_jsluice" for p in records["parameters"])
    print("PASS: endpoint/param records carry target_derived + source=wayback/snapshot/archived_url provenance")


def test_secret_record_fingerprint_only_no_raw_value():
    st = fresh_state()
    RAW = "AKIAREALSECRETVALUE0000"
    new_assets, records = _mine_one_snapshot(st, [], [{"kind": "aws_key", "value": RAW}])
    sec = records["secrets"][0]
    assert sec.kind == "aws_key" and sec.fingerprint and sec.target_derived is True
    assert sec.raw_log_ref == "raw/stage11_jsluice_secrets_https___h.example.com_app.js.json"
    assert sec.metadata["source_url"] == "https://h.example.com/app.js"  # links to the minted .js asset
    assert RAW not in json.dumps({"fp": sec.fingerprint, "ref": sec.raw_log_ref, "md": sec.metadata}), \
        "the raw secret value must NEVER appear in the record (D3)"
    print("PASS: secret record is fingerprint + raw_log_ref only, never the raw value (D3)")


# --- the central B4 correctness trap: base_url resolution -------------------

def test_base_url_resolves_relative_onto_original_host_not_temp_path():
    """A relative endpoint in an archived body must resolve against the ORIGINAL
    archived URL, not the local temp file path jsluice actually read."""
    st = fresh_state()
    jsluice_out = json.dumps({"url": "/api/internal/debug", "method": "GET"}) + "\n"
    with mock.patch.object(s7, "_run_tool", return_value=(jsluice_out, "", 0)):
        findings = asj.run_jsluice_urls("/tmp/local_body.js", st,
                                        base_url="https://h.example.com/static/app.js", stage=11)
    assert findings[0]["url"] == "https://h.example.com/api/internal/debug", findings[0]["url"]
    print("PASS: relative endpoint resolves onto the original target host, not the local temp path")


# --- R7 two-level fault isolation ------------------------------------------

def test_r7_host_cdx_failure_isolated():
    st = fresh_state()
    good = {"original": "https://ok.example.com/a.js", "timestamp": "20200101000000",
            "digest": "D", "mimetype": "application/javascript"}

    def _cdx(host, state):
        if host == "bad.example.com":
            raise RuntimeError("cdx boom")
        return [good]

    with mock.patch.object(asj, "query_cdx_js", side_effect=_cdx), \
         mock.patch.object(asj, "fetch_snapshot", return_value=Path("/tmp/b.js")), \
         mock.patch.object(asj, "run_jsluice_urls",
                           return_value=[{"url": "https://ok.example.com/x", "method": "GET",
                                          "queryParams": [], "bodyParams": []}]), \
         mock.patch.object(asj, "run_jsluice_secrets", return_value=[]):
        new_assets, records = asj.run_archived_js_mining(
            ["bad.example.com", "ok.example.com"], st, 1, {})
    assert any(a.value == "https://ok.example.com/x" for a in new_assets), "good host survived bad host's CDX failure"
    print("PASS: one host's CDX failure is isolated; the stage continues (R7)")


def test_r7_snapshot_fetch_failure_isolated():
    st = fresh_state()
    snaps = [
        {"original": "https://h/bad.js", "timestamp": "20200101000000", "digest": "1"},
        {"original": "https://h/ok.js", "timestamp": "20200101000000", "digest": "2"},
    ]

    def _fetch(snap, state):
        if snap["original"].endswith("bad.js"):
            raise ValueError("fetch boom")
        return Path("/tmp/ok.js")

    with mock.patch.object(asj, "query_cdx_js", return_value=snaps), \
         mock.patch.object(asj, "fetch_snapshot", side_effect=_fetch), \
         mock.patch.object(asj, "run_jsluice_urls",
                           return_value=[{"url": "https://h/api", "method": "GET",
                                          "queryParams": [], "bodyParams": []}]), \
         mock.patch.object(asj, "run_jsluice_secrets", return_value=[]):
        new_assets, records = asj.run_archived_js_mining(["h"], st, 1, {})
    vals = {a.value for a in new_assets}
    assert "https://h/ok.js" in vals and "https://h/bad.js" not in vals, "only the good snapshot's records survive"
    print("PASS: one snapshot's fetch failure is isolated; sibling snapshots still mined (R7)")


# --- empty seed -------------------------------------------------------------

def test_empty_hosts_no_work():
    st = fresh_state()
    assert asj.run_archived_js_mining([], st, 1, {}) == \
        ([], {"endpoints": [], "parameters": [], "secrets": []})
    print("PASS: empty in-scope host list -> no work, empty records")


# --- persist_records linkage + out-of-scope drop ----------------------------

def test_persist_links_records_and_drops_out_of_scope():
    st = fresh_state()
    findings = [{"url": "https://h.example.com/api/users", "method": "GET",
                 "queryParams": ["id"], "bodyParams": []}]
    new_assets, records = _mine_one_snapshot(st, findings, [{"kind": "k", "value": "V"}])
    for a in new_assets:
        a.scope_status = "in_scope"
    st.add_assets(new_assets)
    main.persist_records(st, records)

    by_val = {a.value: a.asset_id for a in st.load_assets()}
    saved_eps = st.load_endpoints()
    assert len(saved_eps) == 1
    assert saved_eps[0].asset_id == by_val["https://h.example.com/api/users"], "endpoint links to its url asset"
    saved_secs = st.load_secrets()
    assert len(saved_secs) == 1
    assert saved_secs[0].asset_id == by_val["https://h.example.com/app.js"], "secret links via metadata[source_url]"

    # now an out-of-scope parent -> record dropped
    st2 = fresh_state()
    na2, rec2 = _mine_one_snapshot(st2, findings, [])
    for a in na2:
        a.scope_status = "out_of_scope"
    st2.add_assets(na2)
    main.persist_records(st2, rec2)
    assert st2.load_endpoints() == [], "endpoint whose parent url is out_of_scope is dropped"
    print("PASS: persist links endpoint/secret to parent assets; out-of-scope parent drops the record")


# --- dedup: live stage-7 endpoint wins the keep-first race ------------------

def test_archived_endpoint_dedups_against_live_stage7_row():
    st = fresh_state()
    findings = [{"url": "https://h.example.com/api/users", "method": "GET",
                 "queryParams": [], "bodyParams": []}]
    new_assets, records = _mine_one_snapshot(st, findings, [])
    for a in new_assets:
        a.scope_status = "in_scope"
    st.add_assets(new_assets)
    # a live stage-7 row already exists for the same (url, method)
    live = records["endpoints"][0].__class__(
        url="https://h.example.com/api/users", host="h.example.com", path="/api/users",
        method="GET", discovered_by="jsluice", target_derived=True,
        discovered_at_stage=7, discovered_in_pass=1)
    live.asset_id = {a.value: a.asset_id for a in st.load_assets()}["https://h.example.com/api/users"]
    st.add_endpoints([live])                       # stage 7 inserts first (keep-first)
    main.persist_records(st, records)              # stage 11 duplicate INSERT OR IGNORE'd
    saved = st.load_endpoints()
    assert len(saved) == 1 and saved[0].discovered_by == "jsluice", "live row wins UNIQUE(url,method)"
    print("PASS: an endpoint present in both live + archived JS keeps the stage-7 row (INSERT OR IGNORE)")


# --- not-live-gated seed (the deliberate divergence from B1/B2) -------------

def test_seed_includes_dead_in_scope_hosts():
    st = fresh_state()
    live = Asset(value="live.example.com", type="subdomain", discovered_by="x",
                 discovered_at_stage=1, discovered_in_pass=1)
    live.scope_status = "in_scope"
    live.metadata = {"httpx_status_code": 200}
    dead = Asset(value="dead.example.com", type="subdomain", discovered_by="x",
                 discovered_at_stage=1, discovered_in_pass=1)
    dead.scope_status = "in_scope"          # no httpx_status_code -> dead today
    st.add_assets([live, dead])

    seen = {}

    def _capture(hosts, state, current_pass, scope):
        seen["hosts"] = list(hosts)
        return ([], {"endpoints": [], "parameters": [], "secrets": []})

    with mock.patch.object(main, "run_archived_js_mining", side_effect=_capture), \
         mock.patch.object(main, "run_stage_and_report"):
        main.run_archived_js_and_report(None, st, {})
    assert set(seen["hosts"]) == {"live.example.com", "dead.example.com"}, \
        "B4 seeds ALL in-scope subdomains, live or not (divergence from B1/B2)"
    print("PASS: stage 11 seeds dead-but-in-scope hosts too (not gated on httpx_status_code)")


if __name__ == "__main__":
    test_query_cdx_js_filters_and_dedups()
    test_query_cdx_degrades_on_non_json_and_on_error()
    test_fetch_snapshot_uses_id_form_and_r5_body_file()
    test_fetch_snapshot_rejects_empty_or_non_200()
    test_records_carry_wayback_provenance_and_target_derived()
    test_secret_record_fingerprint_only_no_raw_value()
    test_base_url_resolves_relative_onto_original_host_not_temp_path()
    test_r7_host_cdx_failure_isolated()
    test_r7_snapshot_fetch_failure_isolated()
    test_empty_hosts_no_work()
    test_persist_links_records_and_drops_out_of_scope()
    test_archived_endpoint_dedups_against_live_stage7_row()
    test_seed_includes_dead_in_scope_hosts()
    print("\nAll checks passed.")
