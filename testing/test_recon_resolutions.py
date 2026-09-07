"""
Mocked-tier tests for the R1-R13 recon-review resolutions pass (Batches
1-3). Per CONTRIBUTING.md's staged verification discipline this is tier 2
(no real tools, no network) - it exercises the logic each fix changed
without hitting real CLIs or targets. Tier 3 (real runs) still has to
happen against zonetransfer.me + the synthetic multi-root / global scopes;
this file is the mocked-subprocess suite the plan calls for, one section
per resolution.

Location-independent: resolves the repo root by walking up to the directory
that contains state.py, so it runs whether it sits at the repo root or under
testing/ (or anywhere else). Adds the repo root and stages/ to sys.path so
`import main` (which uses the stages.* package) and bare `import
stage4_live_probing` etc. (for mocking) both resolve.
"""
import json
import sys
import tempfile
import unittest.mock as mock
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# find the repo root = the dir containing state.py (this file may live at the
# repo root or under testing/)
_REPO_ROOT = _HERE
for _p in (_HERE, *_HERE.parents):
    if (_p / "state.py").exists():
        _REPO_ROOT = _p
        break
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "stages"))

import main
from state import Asset, RunState, canonicalize, TARGET_DERIVED_METADATA_KEYS
from scope_gate import ScopePatterns
from rate_limit_gate import check_run_not_blocked
from rate_limits import httpx_rate_args, resolve_rate_scope, resolve_effective_rps

import stage1_passive
import stage4_live_probing
import stage6_crawling
import stage9_whatweb


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def _patterns(in_scope_domains):
    return ScopePatterns.from_scope_dict({"in_scope": {"domains": in_scope_domains}})


def _sub(value):
    return Asset(value=value, type="subdomain", discovered_by="t",
                 discovered_at_stage=1, discovered_in_pass=1)


# ---------------------------------------------------------------------------
# R6 - conservative canonicalization
# ---------------------------------------------------------------------------

def test_r6_canonicalize_url_rules():
    assert canonicalize("url", "https://X.com:443/a#f") == "https://x.com/a"
    assert canonicalize("url", "http://X.com:80/a") == "http://x.com/a"
    # non-default port preserved
    assert canonicalize("url", "https://x.com:8443/a") == "https://x.com:8443/a"
    # PATH and QUERY are never merged (the conservative guarantee)
    assert canonicalize("url", "https://x.com/a") != canonicalize("url", "https://x.com/a/")
    assert canonicalize("url", "https://x.com/p?id=1") != canonicalize("url", "https://x.com/p?id=2")
    # idempotent
    once = canonicalize("url", "HTTPS://X.com:443/a#f")
    assert canonicalize("url", once) == once
    print("PASS: R6 url canonicalization (host-case/default-port/fragment, path+query untouched)")


def test_r6_canonicalize_subdomain():
    assert canonicalize("subdomain", "WWW.X.COM.") == "www.x.com"
    # ip left alone
    assert canonicalize("ip", "5.6.7.8") == "5.6.7.8"
    print("PASS: R6 subdomain lowercased + trailing dot stripped; ip untouched")


def test_r6_asset_canonicalizes_on_construction():
    a = Asset(value="HTTPS://X.com:443/a#f", type="url", discovered_by="t",
              discovered_at_stage=1, discovered_in_pass=1)
    assert a.value == "https://x.com/a", a.value
    print("PASS: R6 Asset.__post_init__ canonicalizes value at construction")


def test_r6_add_assets_dedupes_variants():
    state = fresh_state()
    a1 = Asset(value="https://x.com/", type="url", discovered_by="t1",
               discovered_at_stage=1, discovered_in_pass=1)
    a2 = Asset(value="https://X.com:443/", type="url", discovered_by="t2",
               discovered_at_stage=1, discovered_in_pass=1)
    new = state.add_assets([a1, a2])
    assert len(new) == 1, new
    assert len(state.load_assets()) == 1
    print("PASS: R6 host-case/default-port URL variants dedupe to one asset")


def test_r6_lazy_renormalize_on_load():
    state = fresh_state()
    # simulate a pre-R6 raw (non-canonical) row written directly to the db
    with state._connect() as conn:
        conn.execute(
            "INSERT INTO assets (asset_id,value,type,discovered_by,"
            "discovered_at_stage,discovered_in_pass,scope_status,"
            "scope_decision_by,parent_asset_id,metadata) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("id1", "HTTPS://RAW.example.com:443/x#frag", "url",
             json.dumps(["t"]), 1, 1, "in_scope", None, None, "{}"),
        )
    loaded = state.load_assets()
    assert loaded[0].value == "https://raw.example.com/x", loaded[0].value
    print("PASS: R6 pre-existing raw row lazily re-normalizes on load")


# ---------------------------------------------------------------------------
# R9 - target-derived metadata registry
# ---------------------------------------------------------------------------

def test_r9_registry_covers_target_authored_keys():
    for k in ("whatweb_tech", "whatweb_redirect_chain", "katana_headers",
              "katana_error", "jsluice_secrets", "httpx_title", "httpx_tls_san"):
        assert k in TARGET_DERIVED_METADATA_KEYS, k
    # tool-derived facts are deliberately NOT in the registry
    for k in ("httpx_status_code", "naabu_open_ports", "httpx_body_hash",
              "httpx_tech", "katana_status_code", "x8_reflected_params"):
        assert k not in TARGET_DERIVED_METADATA_KEYS, k
    print("PASS: R9 registry names the target-authored keys, excludes tool-derived facts")


# ---------------------------------------------------------------------------
# R13 - js_file routes through classify_url
# ---------------------------------------------------------------------------

def test_r13_js_file_uses_classify_url():
    state = fresh_state()
    patterns = _patterns(["*.example.com"])
    a = Asset(value="https://cdn.example.com/app.js", type="js_file",
              discovered_by="t", discovered_at_stage=7, discovered_in_pass=1)
    main.apply_scope_gate([a], patterns, state)
    # in_scope proves the URL host was extracted (classify_url); classify_domain
    # on the whole URL string would have fallen through to ambiguous
    assert a.scope_status == "in_scope", a.scope_status
    assert a.scope_decision_by == "deterministic"
    print("PASS: R13 js_file asset classifies via classify_url, not classify_domain")


# ---------------------------------------------------------------------------
# R10 - review-queue dedup
# ---------------------------------------------------------------------------

def test_r10_dedup_across_calls():
    state = fresh_state()
    patterns = _patterns(["*.example.com"])
    main.apply_scope_gate([_sub("mystery.other.com")], patterns, state)
    main.apply_scope_gate([_sub("mystery.other.com")], patterns, state)
    q = state.load_review_queue()
    assert len([i for i in q if i.value == "mystery.other.com"]) == 1, q
    print("PASS: R10 ambiguous asset rediscovered across calls -> one review entry")


def test_r10_dedup_within_batch_and_via_canonical_value():
    state = fresh_state()
    patterns = _patterns(["*.example.com"])
    # different casing -> same canonical value (R6), so R10 collapses them
    main.apply_scope_gate([_sub("mystery.other.com"), _sub("Mystery.Other.com")], patterns, state)
    q = state.load_review_queue()
    assert len(q) == 1, q
    print("PASS: R10 within-batch dedup by canonical value (leans on R6)")


# ---------------------------------------------------------------------------
# R5 - per-target raw filenames
# ---------------------------------------------------------------------------

def test_r5_per_target_raw_filenames_no_overwrite():
    state = fresh_state()
    with mock.patch.object(stage1_passive, "_run_tool", return_value=("", "", 0)):
        stage1_passive.run_subfinder("example.com", state)
        stage1_passive.run_subfinder("other.org", state)
    assert (state.raw_dir / "stage1_subfinder_example.com.json").exists()
    assert (state.raw_dir / "stage1_subfinder_other.org.json").exists()
    print("PASS: R5 two roots produce two distinct subfinder raw archives, neither overwritten")


# ---------------------------------------------------------------------------
# R7 - fault isolation
# ---------------------------------------------------------------------------

def test_r7_stage4_isolates_httpx_failure():
    state = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    host = _sub("h1.example.com")
    with mock.patch.object(stage4_live_probing, "run_httpx", side_effect=RuntimeError("boom")), \
         mock.patch.object(stage4_live_probing, "run_naabu", return_value={"h1.example.com": [80, 443]}):
        new_assets, meta = stage4_live_probing.run_stage4([host], state, 1, scope)
    # httpx raising did not abort - naabu's result still made it through
    assert meta.get("h1.example.com", {}).get("naabu_open_ports") == [80, 443], meta
    print("PASS: R7 stage 4 httpx failure isolated - naabu results still returned")


def test_r7_stage6_isolates_katana_failure():
    state = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    with mock.patch.object(stage6_crawling, "run_katana", side_effect=RuntimeError("boom")):
        out = stage6_crawling.run_stage6(["h1.example.com"], state, 1, scope)
    assert out == [], out
    print("PASS: R7 stage 6 katana failure isolated - returns [] instead of aborting")


def test_r7_main_marks_error_status_on_crash():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "scope.json").write_text(json.dumps({
        "verified_by_human": True,
        "in_scope": {"domains": ["example.com"]},
        "rate_limit": {"resolution": "not_applicable"},
    }))
    argv = ["main.py", "--run-dir", str(tmp)]
    with mock.patch.object(main, "run_pipeline", side_effect=RuntimeError("boom")), \
         mock.patch.object(sys, "argv", argv):
        try:
            main.main()
            assert False, "expected the RuntimeError to propagate"
        except RuntimeError:
            pass
    rs = RunState(tmp).load_run_state()
    assert rs["status"] == "error", rs
    assert "failed_at_stage" in rs, rs
    print("PASS: R7 an unhandled pipeline crash leaves run_state status='error'")


# ---------------------------------------------------------------------------
# R2 - rate_limit block required-affirmative
# ---------------------------------------------------------------------------

def test_r2_absent_block_blocks_run():
    try:
        check_run_not_blocked({})
        assert False, "expected ValueError for an absent rate_limit block"
    except ValueError:
        pass
    print("PASS: R2 absent rate_limit block blocks the run")


def test_r2_not_applicable_and_confirmed_pass_pending_blocks():
    check_run_not_blocked({"rate_limit": {"resolution": "not_applicable"}})  # no raise
    check_run_not_blocked({"rate_limit": {"resolution": "confirmed",
                                          "requests_per_second": 5, "scope": "per_host"}})
    try:
        check_run_not_blocked({"rate_limit": {"resolution": "pending"}})
        assert False, "expected ValueError for pending"
    except ValueError:
        pass
    print("PASS: R2 not_applicable/confirmed pass, pending blocks")


# ---------------------------------------------------------------------------
# R4 - rate_limit.scope (per_host vs global)
# ---------------------------------------------------------------------------

def test_r4_global_cap_not_scaled():
    scope = {"rate_limit": {"resolution": "confirmed", "requests_per_second": 10, "scope": "global"}}
    assert resolve_rate_scope(scope) == "global"
    assert httpx_rate_args(scope, host_count=5).extra_args == ["-rl", "10"]
    print("PASS: R4 global cap passes through unscaled regardless of host count")


def test_r4_per_host_cap_scaled():
    scope = {"rate_limit": {"resolution": "confirmed", "requests_per_second": 10, "scope": "per_host"}}
    assert httpx_rate_args(scope, host_count=5).extra_args == ["-rl", "50"]
    print("PASS: R4 per_host cap scaled by host count (existing behavior)")


def test_r4_default_is_per_host():
    scope = {"rate_limit": {"resolution": "not_applicable"}}  # -> conservative default 5, per_host
    assert resolve_rate_scope(scope) == "per_host"
    assert httpx_rate_args(scope, host_count=3).extra_args == ["-rl", "15"]
    print("PASS: R4 missing/non-confirmed scope defaults to per_host (back-compat)")


# ---------------------------------------------------------------------------
# naabu packet-rate anchor (real-run fix 2026-08-24): -rate is packets/sec,
# decoupled from the HTTP courtesy rate, its own NAABU_PACKET_RATE anchor,
# clamped only by a program-stated GLOBAL cap.
# ---------------------------------------------------------------------------

def test_naabu_uses_dedicated_packet_anchor_not_http_rate():
    from rate_limits import naabu_rate_args, NAABU_PACKET_RATE
    # conservative-default run: naabu must NOT inherit the 5-req/s HTTP courtesy
    # rate; it uses NAABU_PACKET_RATE per host, scaled by host count.
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    assert naabu_rate_args(scope, host_count=1).extra_args == ["-rate", str(NAABU_PACKET_RATE)]
    assert naabu_rate_args(scope, host_count=4).extra_args == ["-rate", str(NAABU_PACKET_RATE * 4)]
    # a confirmed per_host HTTP limit still does NOT govern the packet rate
    per_host = {"rate_limit": {"resolution": "confirmed", "requests_per_second": 5, "scope": "per_host"}}
    assert naabu_rate_args(per_host, host_count=1).extra_args == ["-rate", str(NAABU_PACKET_RATE)]
    print("PASS: naabu uses its dedicated packet anchor, not the HTTP courtesy rate")


def test_naabu_clamps_down_to_global_cap():
    from rate_limits import naabu_rate_args, NAABU_PACKET_RATE
    # a stated GLOBAL cap below the anchor is a hard ceiling over all target traffic
    scope = {"rate_limit": {"resolution": "confirmed", "requests_per_second": 20, "scope": "global"}}
    assert naabu_rate_args(scope, host_count=10).extra_args == ["-rate", "20"]
    # a global cap ABOVE the per-host-scaled anchor doesn't inflate the scan
    high = {"rate_limit": {"resolution": "confirmed", "requests_per_second": 100000, "scope": "global"}}
    assert naabu_rate_args(high, host_count=1).extra_args == ["-rate", str(NAABU_PACKET_RATE)]
    print("PASS: naabu clamps DOWN to a program global cap, never up (R4)")


# ---------------------------------------------------------------------------
# R1 - off-scope traffic flags (mocked command inspection; the real flag
# verification against whatweb/katana --help was done separately - both
# confirmed 2026-08-23)
# ---------------------------------------------------------------------------

def test_r1_katana_has_fs_rdn():
    state = fresh_state()
    captured = {}

    def fake(cmd, *a, **k):
        captured["cmd"] = cmd
        return ("", "", 0)

    with mock.patch.object(stage6_crawling, "_run_tool", side_effect=fake):
        stage6_crawling.run_katana(["h1.example.com"], state, {"rate_limit": {"resolution": "not_applicable"}})
    cmd = captured["cmd"]
    assert "-fs" in cmd and cmd[cmd.index("-fs") + 1] == "rdn", cmd
    print("PASS: R1 katana invocation includes -fs rdn (flag verified vs real katana -h)")


def test_r1_whatweb_follow_redirect_same_site():
    state = fresh_state()
    captured = {}

    def fake(cmd, *a, **k):
        captured["cmd"] = cmd
        return ("", "", 0)

    with mock.patch.object(stage9_whatweb, "_run_tool", side_effect=fake):
        stage9_whatweb._scan_one_host("h1.example.com", state, {"rate_limit": {"resolution": "not_applicable"}})
    assert "--follow-redirect=same-site" in captured["cmd"], captured["cmd"]
    print("PASS: R1 whatweb invocation includes --follow-redirect=same-site (flag verified vs real whatweb --help)")


def test_r1_redirect_origin_scope_guard():
    """Real-run fix (2026-08-24): _live_hosts_with_origins must NOT hand the active
    per-host stages (ffuf/wafw00f/screenshots/API) an origin that redirected
    OFF-host - the zonetransfer.me -> digi.ninja leak. A same-host http->https
    redirect origin is kept (that's why the map exists); an off-host redirect target
    is dropped so the consumer falls back to its own https://{in-scope-host}."""
    state = fresh_state()
    same_host = Asset(value="a.example.com", type="subdomain", discovered_by="t",
                      discovered_at_stage=4, discovered_in_pass=1,
                      scope_status="in_scope",
                      metadata={"httpx_status_code": 200,
                                "httpx_final_url": "https://a.example.com/"})
    off_host = Asset(value="b.example.com", type="subdomain", discovered_by="t",
                     discovered_at_stage=4, discovered_in_pass=1,
                     scope_status="in_scope",
                     metadata={"httpx_status_code": 200,
                               "httpx_final_url": "https://evil.attacker.tld/"})
    state.add_assets([same_host, off_host])

    hosts, host_base = main._live_hosts_with_origins(state)
    assert set(hosts) == {"a.example.com", "b.example.com"}, hosts
    # same-host redirect: origin kept (confirms http vs https for the fuzzers)
    assert host_base.get("a.example.com") == "https://a.example.com", host_base
    # off-host redirect: target NOT adopted; consumer defaults to https://b.example.com
    assert "b.example.com" not in host_base, host_base
    print("PASS: R1 redirect-origin scope guard drops off-host redirect targets (digi.ninja leak)")


# ---------------------------------------------------------------------------
# R11 - certspotter pagination
# ---------------------------------------------------------------------------

def test_r11_pagination_walks_all_pages():
    state = fresh_state()

    def page(ids):
        return json.dumps([{"id": i, "dns_names": [f"h{i}.example.com"]} for i in ids])

    pages = [(page(["1", "2"]), "", 0), (page(["3", "4"]), "", 0), (page(["5"]), "", 0)]
    m = mock.Mock(side_effect=pages)
    with mock.patch.object(stage1_passive, "CERTSPOTTER_PAGE_LIMIT", 2), \
         mock.patch.object(stage1_passive, "_run_tool", m):
        assets = stage1_passive.run_certspotter("example.com", state)
    vals = sorted(a.value for a in assets)
    assert vals == ["h1.example.com", "h2.example.com", "h3.example.com",
                    "h4.example.com", "h5.example.com"], vals
    assert m.call_count == 3, m.call_count  # 2 full pages + 1 short page
    for p in range(3):
        assert (state.raw_dir / f"stage1_certspotter_example.com_p{p}.json").exists()
    print("PASS: R11 pagination walks all pages until a short page, archives each page")


def test_r11_stops_when_after_ignored():
    state = fresh_state()
    same = json.dumps([{"id": "1", "dns_names": ["h1.example.com"]},
                       {"id": "2", "dns_names": ["h2.example.com"]}])
    m = mock.Mock(return_value=(same, "", 0))
    with mock.patch.object(stage1_passive, "CERTSPOTTER_PAGE_LIMIT", 2), \
         mock.patch.object(stage1_passive, "_run_tool", m):
        assets = stage1_passive.run_certspotter("example.com", state)
    # page 0 has new ids; page 1 repeats them -> no-new-ids guard stops
    assert m.call_count == 2, m.call_count
    assert sorted(a.value for a in assets) == ["h1.example.com", "h2.example.com"]
    print("PASS: R11 no-new-ids guard stops pagination if after= is ignored")


if __name__ == "__main__":
    # R6
    test_r6_canonicalize_url_rules()
    test_r6_canonicalize_subdomain()
    test_r6_asset_canonicalizes_on_construction()
    test_r6_add_assets_dedupes_variants()
    test_r6_lazy_renormalize_on_load()
    # R9
    test_r9_registry_covers_target_authored_keys()
    # R13
    test_r13_js_file_uses_classify_url()
    # R10
    test_r10_dedup_across_calls()
    test_r10_dedup_within_batch_and_via_canonical_value()
    # R5
    test_r5_per_target_raw_filenames_no_overwrite()
    # R7
    test_r7_stage4_isolates_httpx_failure()
    test_r7_stage6_isolates_katana_failure()
    test_r7_main_marks_error_status_on_crash()
    # R2
    test_r2_absent_block_blocks_run()
    test_r2_not_applicable_and_confirmed_pass_pending_blocks()
    # R4
    test_r4_global_cap_not_scaled()
    test_r4_per_host_cap_scaled()
    test_r4_default_is_per_host()
    # naabu packet-rate anchor
    test_naabu_uses_dedicated_packet_anchor_not_http_rate()
    test_naabu_clamps_down_to_global_cap()
    # R1
    test_r1_katana_has_fs_rdn()
    test_r1_whatweb_follow_redirect_same_site()
    test_r1_redirect_origin_scope_guard()
    # R11
    test_r11_pagination_walks_all_pages()
    test_r11_stops_when_after_ignored()
    print("\nAll checks passed.")
