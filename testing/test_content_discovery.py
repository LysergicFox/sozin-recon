"""
Mocked-tier tests for stage 6.5 / B1 content discovery (ffuf). Tier 2 (no real
ffuf, no network). Covers the verified-ffuf-shape parser, the WAF/early-stop
detector (stderr-string + 403-ratio, NEVER exit code), ffuf_rate_args (per-host,
unscaled), the per-host record-building loop (assets + endpoint records,
auth_status, R7 fault isolation, R5 raw filename), and persist_records linkage.

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
import rate_limits
from rate_limit_gate import CONSERVATIVE_DEFAULT_RPS
from state import RunState, Asset
import stage_content_discovery as scd


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def _hit(url, status, length=100, ctype="text/html", redirect=""):
    """A ffuf result dict in the VERIFIED shape (content-type hyphenated)."""
    return {"input": {"FUZZ": url.rsplit("/", 1)[-1], "FFUFHASH": "abc"},
            "position": 1, "status": status, "length": length, "words": 1,
            "lines": 1, "content-type": ctype, "redirectlocation": redirect,
            "url": url, "host": "h.example.com"}


# ---------------------------------------------------------------------------
# _parse_ffuf_json — verified shape, missing file, malformed
# ---------------------------------------------------------------------------

def test_parse_ffuf_json_verified_shape():
    st = fresh_state()
    p = st.raw_path(6.5, "ffuf_h.example.com")
    p.write_text(json.dumps({"commandline": "ffuf ...", "config": {},
                             "results": [_hit("https://h.example.com/admin", 200)],
                             "time": "..."}))
    hits = scd._parse_ffuf_json(p)
    assert len(hits) == 1 and hits[0]["url"] == "https://h.example.com/admin"
    assert hits[0]["content-type"] == "text/html"
    print("PASS: _parse_ffuf_json reads the verified results[] shape")


def test_parse_ffuf_json_missing_and_empty_and_malformed():
    st = fresh_state()
    missing = st.raw_path(6.5, "ffuf_nope")
    assert scd._parse_ffuf_json(missing) == [], "missing file (hard kill) → []"
    empty = st.raw_path(6.5, "ffuf_empty")
    empty.write_text(json.dumps({"results": []}))
    assert scd._parse_ffuf_json(empty) == [], "empty results → []"
    bad = st.raw_path(6.5, "ffuf_bad")
    bad.write_text("{not json")
    assert scd._parse_ffuf_json(bad) == [], "malformed → [] (never raises)"
    print("PASS: _parse_ffuf_json tolerates missing / empty / malformed")


# ---------------------------------------------------------------------------
# _detect_waf — stderr signals + 403-ratio, exit code irrelevant
# ---------------------------------------------------------------------------

def test_detect_waf_403_flood_signal():
    results = [_hit("u", 403) for _ in range(9)] + [_hit("u", 200)]
    waf = scd._detect_waf("... Getting an unusual amount of 403 responses, exiting.\n", results)
    assert waf["waf_suspected"] is True and waf["waf_signal"] == "403_flood"
    assert abs(waf["waf_block_ratio"] - 0.9) < 1e-9
    print("PASS: _detect_waf flags 403 flood from stderr + computes block ratio")


def test_detect_waf_maxtime_signal():
    waf = scd._detect_waf("Maximum running time for this job reached, continuing...\n", [])
    assert waf["waf_suspected"] is True and waf["waf_signal"] == "maxtime"
    assert waf["waf_block_ratio"] is None  # no results
    print("PASS: _detect_waf flags maxtime early-stop from stderr")


def test_detect_waf_clean_run():
    waf = scd._detect_waf("normal ffuf stderr banner\n", [_hit("u", 200), _hit("u", 403)])
    assert waf["waf_suspected"] is False and waf["waf_signal"] is None
    assert abs(waf["waf_block_ratio"] - 0.5) < 1e-9  # ratio reported even when not suspected
    print("PASS: _detect_waf: clean run not flagged; ratio still reported as intel")


# ---------------------------------------------------------------------------
# ffuf_rate_args — per-host, unscaled, global-safe
# ---------------------------------------------------------------------------

def test_ffuf_rate_args_default_and_confirmed_and_global():
    default = rate_limits.ffuf_rate_args({"rate_limit": {"resolution": "not_applicable"}})
    assert default.extra_args == ["-rate", str(CONSERVATIVE_DEFAULT_RPS)]
    confirmed = rate_limits.ffuf_rate_args(
        {"rate_limit": {"resolution": "confirmed", "requests_per_second": 5, "scope": "per_host"}})
    assert confirmed.extra_args == ["-rate", "5"]
    glob = rate_limits.ffuf_rate_args(
        {"rate_limit": {"resolution": "confirmed", "requests_per_second": 10, "scope": "global"}})
    assert glob.extra_args == ["-rate", "10"], "global cap passed through unscaled, same as per-host"
    print("PASS: ffuf_rate_args = -rate <effective_rps>, never scaled by host count")


# ---------------------------------------------------------------------------
# run_ffuf — per-host raw filename (R5), reads its -o file
# ---------------------------------------------------------------------------

def test_run_ffuf_seed_scheme_from_base():
    """Real-run fix: ffuf seed uses the confirmed-live origin (http OR https),
    defaulting to https only when no base is given."""
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    captured = {}

    def _capture(cmd, timeout=1800):
        captured["cmd"] = cmd
        return ("", "", 0)

    with mock.patch.object(scd, "_run_tool", side_effect=_capture):
        scd.run_ffuf("127.0.0.1", st, scope, base="http://127.0.0.1:3000")
    assert "http://127.0.0.1:3000/FUZZ" in captured["cmd"], captured["cmd"]

    with mock.patch.object(scd, "_run_tool", side_effect=_capture):
        scd.run_ffuf("h.example.com", st, scope)  # no base → default https
    assert "https://h.example.com/FUZZ" in captured["cmd"], captured["cmd"]
    print("PASS: run_ffuf seeds from base origin (http/https); defaults https when unknown")


def test_run_ffuf_uses_per_host_raw_file():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    # pre-write the file ffuf WOULD write, at the R5 per-host path, then mock the
    # subprocess so no real ffuf runs — confirms run_ffuf reads stage6.5_ffuf_<host>.json
    out = st.raw_path(6.5, "ffuf_h.example.com")
    out.write_text(json.dumps({"results": [_hit("https://h.example.com/admin", 200)]}))
    assert out.name == "stage6.5_ffuf_h.example.com.json"
    with mock.patch.object(scd, "_run_tool", return_value=("", "", 0)):
        hits, waf = scd.run_ffuf("h.example.com", st, scope)
    assert len(hits) == 1 and hits[0]["url"] == "https://h.example.com/admin"
    assert waf["waf_suspected"] is False
    print("PASS: run_ffuf writes/reads the R5 per-host raw file stage6.5_ffuf_<host>.json")


# ---------------------------------------------------------------------------
# run_content_discovery — the per-host loop (records, auth_status, R7, waf)
# ---------------------------------------------------------------------------

def _patched_wordlist():
    """Context: point WORDLIST_PATH at a real temp file so the existence guard passes."""
    wl = Path(tempfile.mkdtemp()) / "words.txt"
    wl.write_text("admin\napi\n")
    return mock.patch.object(scd, "WORDLIST_PATH", str(wl))


def test_run_content_discovery_builds_assets_and_endpoints():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    hits = [_hit("https://h.example.com/admin", 200, length=67, ctype="text/html"),
            _hit("https://h.example.com/api", 200, length=45, ctype="application/json")]
    with _patched_wordlist(), mock.patch.object(scd, "run_ffuf", return_value=(hits, scd._detect_waf("", hits))):
        new_assets, records, waf_flags = scd.run_content_discovery(
            ["h.example.com"], st, current_pass=1, scope=scope)
    # url assets with curated ffuf_* metadata, NO body
    assert {a.value for a in new_assets} == {"https://h.example.com/admin", "https://h.example.com/api"}
    for a in new_assets:
        assert a.type == "url" and a.discovered_by == ["ffuf"]
        assert set(a.metadata) == {"ffuf_status", "ffuf_length", "ffuf_content_type"}
    # endpoint records: target_derived False (path from OUR wordlist), method GET
    eps = records["endpoints"]
    assert len(eps) == 2
    for e in eps:
        assert e.method == "GET" and e.target_derived is False and e.discovered_by == "ffuf"
        assert e.host == "h.example.com" and e.path.startswith("/")
        assert e.discovered_at_stage == 6.5
    api = next(e for e in eps if e.path == "/api")
    assert api.content_type == "application/json"
    print("PASS: run_content_discovery emits url assets + target_derived=False endpoint records")


def test_run_content_discovery_flags_5xx():
    """Real-run finding (Juice Shop): 5xx hits are kept but FLAGGED server_error so
    downstream can skip error responses; 2xx/3xx are not flagged."""
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    hits = [_hit("https://h.example.com/ok", 200),
            _hit("https://h.example.com/api.bak", 500),
            _hit("https://h.example.com/boom", 503)]
    with _patched_wordlist(), mock.patch.object(scd, "run_ffuf", return_value=(hits, scd._detect_waf("", hits))):
        new_assets, records, _waf = scd.run_content_discovery(["h.example.com"], st, 1, scope)
    flagged = {e.path: e.metadata.get("server_error") for e in records["endpoints"]}
    assert flagged["/ok"] is None, "2xx must not be flagged"
    assert flagged["/api.bak"] is True and flagged["/boom"] is True, "5xx must be flagged"
    # same flag mirrored on the url asset
    boom = next(a for a in new_assets if a.value.endswith("/boom"))
    assert boom.metadata.get("server_error") is True
    print("PASS: 5xx hits kept but flagged server_error (2xx/3xx unflagged)")


def test_run_content_discovery_auth_status():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    hits = [_hit("https://h.example.com/pub", 200),
            _hit("https://h.example.com/login", 401),
            _hit("https://h.example.com/secure", 403),
            _hit("https://h.example.com/old", 301, redirect="http://x/new")]
    with _patched_wordlist(), mock.patch.object(scd, "run_ffuf", return_value=(hits, scd._detect_waf("", hits))):
        _new, records, _waf = scd.run_content_discovery(["h.example.com"], st, current_pass=1, scope=scope)
    by_path = {e.path: e.auth_status for e in records["endpoints"]}
    assert by_path["/pub"] is None
    assert by_path["/login"] == "gated" and by_path["/secure"] == "gated"
    assert by_path["/old"] is None, "a 30x is a recorded finding, not 'gated'"
    print("PASS: auth_status='gated' only on 401/403; None otherwise (incl. 30x)")


def test_run_content_discovery_fault_isolation_R7():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    good = [_hit("https://good.example.com/admin", 200)]

    def _side_effect(host, state, scope, base=None):
        if host == "bad.example.com":
            raise RuntimeError("ffuf blew up on this host")
        return good, scd._detect_waf("", good)

    with _patched_wordlist(), mock.patch.object(scd, "run_ffuf", side_effect=_side_effect):
        new_assets, records, waf_flags = scd.run_content_discovery(
            ["bad.example.com", "good.example.com"], st, current_pass=1, scope=scope)
    # bad host raised → skipped; good host's hit still present (R7)
    assert [a.value for a in new_assets] == ["https://good.example.com/admin"]
    assert "bad.example.com" not in waf_flags and "good.example.com" in waf_flags
    print("PASS: one host raising doesn't kill the stage (R7 per-host isolation)")


def test_run_content_discovery_waf_flag_propagates():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    flooded = [_hit("u", 403) for _ in range(10)]
    waf = scd._detect_waf("Getting an unusual amount of 403 responses, exiting.", flooded)
    with _patched_wordlist(), mock.patch.object(scd, "run_ffuf", return_value=(flooded, waf)):
        _new, _records, waf_flags = scd.run_content_discovery(["h.example.com"], st, current_pass=1, scope=scope)
    assert waf_flags["h.example.com"]["waf_suspected"] is True
    assert waf_flags["h.example.com"]["waf_signal"] == "403_flood"
    print("PASS: per-host waf flag propagates out of run_content_discovery")


def test_run_content_discovery_empty_and_missing_wordlist():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    # empty hosts short-circuits before any wordlist check
    assert scd.run_content_discovery([], st, 1, scope) == ([], {"endpoints": []}, {})
    # missing wordlist → fail-safe empty, run_ffuf never called
    with mock.patch.object(scd, "WORDLIST_PATH", "/nonexistent/seclists/raft.txt"), \
         mock.patch.object(scd, "run_ffuf") as m:
        out = scd.run_content_discovery(["h.example.com"], st, 1, scope)
    assert out == ([], {"endpoints": []}, {}) and m.call_count == 0
    print("PASS: empty hosts and missing wordlist both fail safe (no crash, no traffic)")


# ---------------------------------------------------------------------------
# integration with main: WAF flags → host metadata; endpoint → url asset link
# ---------------------------------------------------------------------------

def test_endpoint_links_to_ffuf_url_asset_via_persist_records():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    hits = [_hit("https://h.example.com/admin", 200)]
    with _patched_wordlist(), mock.patch.object(scd, "run_ffuf", return_value=(hits, scd._detect_waf("", hits))):
        new_assets, records, _waf = scd.run_content_discovery(["h.example.com"], st, 1, scope)
    # simulate the orchestrator: assets added in-scope, THEN persist_records
    for a in new_assets:
        a.scope_status = "in_scope"
    st.add_assets(new_assets)
    main.persist_records(st, records)
    eps = st.load_endpoints()
    url_asset_id = {a.value: a.asset_id for a in st.load_assets()}["https://h.example.com/admin"]
    assert len(eps) == 1 and eps[0].asset_id == url_asset_id, \
        "endpoint.url (canonical) must resolve to the just-added url asset"
    print("PASS: ffuf endpoint links to its url asset (canonical-value match) via persist_records")


def test_apply_waf_flags_writes_host_metadata():
    st = fresh_state()
    st.add_assets([Asset(value="h.example.com", type="subdomain", discovered_by="t",
                         discovered_at_stage=1, discovered_in_pass=1, scope_status="in_scope")])
    main._apply_waf_flags(st, {"h.example.com": {"waf_suspected": True, "waf_signal": "403_flood",
                                                 "waf_block_ratio": 1.0}})
    host = next(a for a in st.load_assets() if a.type == "subdomain")
    assert host.metadata.get("waf_suspected") is True
    assert host.metadata.get("waf_signal") == "403_flood"
    print("PASS: _apply_waf_flags writes waf_suspected/signal/ratio to host metadata")


if __name__ == "__main__":
    test_parse_ffuf_json_verified_shape()
    test_parse_ffuf_json_missing_and_empty_and_malformed()
    test_detect_waf_403_flood_signal()
    test_detect_waf_maxtime_signal()
    test_detect_waf_clean_run()
    test_ffuf_rate_args_default_and_confirmed_and_global()
    test_run_ffuf_seed_scheme_from_base()
    test_run_ffuf_uses_per_host_raw_file()
    test_run_content_discovery_builds_assets_and_endpoints()
    test_run_content_discovery_flags_5xx()
    test_run_content_discovery_auth_status()
    test_run_content_discovery_fault_isolation_R7()
    test_run_content_discovery_waf_flag_propagates()
    test_run_content_discovery_empty_and_missing_wordlist()
    test_endpoint_links_to_ffuf_url_asset_via_persist_records()
    test_apply_waf_flags_writes_host_metadata()
    print("\nAll checks passed.")
