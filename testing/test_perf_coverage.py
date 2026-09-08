"""
Tests for the 2026-09-07 performance & coverage changes
(RECON_PERF_COVERAGE_FINDINGS): the max_workers config knob, per-host-stage
parallelization (content discovery, whatweb, stage 1 roots, stage 5 host-grouped
x8), and the ffuf wordlist/extension right-size. Tier 2: no real tools/network.
"""
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

from state import RunState, Asset


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# ------------------------------------------------------- max_workers knob
def test_resolve_max_workers():
    from stages.parallelism import resolve_max_workers, DEFAULT_MAX_WORKERS
    assert resolve_max_workers({}) == DEFAULT_MAX_WORKERS
    assert resolve_max_workers({"performance": {"max_workers": 3}}) == 3
    assert resolve_max_workers({"performance": {"max_workers": 12}}) == 12
    # invalid → default
    assert resolve_max_workers({"performance": {"max_workers": 0}}) == DEFAULT_MAX_WORKERS
    assert resolve_max_workers({"performance": {"max_workers": -1}}) == DEFAULT_MAX_WORKERS
    assert resolve_max_workers({"performance": {"max_workers": "x"}}) == DEFAULT_MAX_WORKERS
    assert resolve_max_workers({"performance": None}) == DEFAULT_MAX_WORKERS
    print("PASS: resolve_max_workers honors the knob, defaults on absent/invalid")


# ------------------------------------------------------- ffuf wordlist/extensions
def test_ffuf_wordlist_and_no_extensions():
    import stage_content_discovery as m
    # quickhits is the right-sized default; extensions off (quickhits = complete paths)
    assert m.WORDLIST_PATH.endswith("quickhits.txt"), m.WORDLIST_PATH
    assert m.EXTENSIONS == [], m.EXTENSIONS
    captured = {}
    def cap(cmd, *a, **k):
        captured["cmd"] = list(cmd)
        return ("", "", 0)
    with mock.patch.object(m, "_run_tool", side_effect=cap):
        m.run_ffuf("a.example.com", fresh_state(), {}, base="https://a.example.com")
    cmd = captured["cmd"]
    assert "-e" not in cmd, f"-e should be absent when EXTENSIONS is empty: {cmd}"
    assert any(c.endswith("quickhits.txt") for c in cmd), cmd
    print("PASS: ffuf uses quickhits.txt with NO -e when EXTENSIONS is empty")


def test_ffuf_extensions_return_if_set():
    import stage_content_discovery as m
    captured = {}
    def cap(cmd, *a, **k):
        captured["cmd"] = list(cmd)
        return ("", "", 0)
    with mock.patch.object(m, "EXTENSIONS", [".bak", ".env"]), \
         mock.patch.object(m, "_run_tool", side_effect=cap):
        m.run_ffuf("a.example.com", fresh_state(), {}, base="https://a.example.com")
    cmd = captured["cmd"]
    assert "-e" in cmd and ".bak,.env" in cmd, cmd
    print("PASS: -e returns automatically when EXTENSIONS is set (dir-name list case)")


# ------------------------------------------------------- parallel aggregation
def test_content_discovery_parallel_aggregates_all_hosts():
    import stage_content_discovery as m
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    # bypass the wordlist-exists guard with a real temp file
    wl = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False); wl.write("admin\n"); wl.close()
    def fake_ffuf(host, state, scope, base=None):
        return ([{"url": f"https://{host}/admin", "status": 200, "length": 1, "content-type": "text/html"}],
                {"waf_suspected": False, "waf_signal": None, "waf_block_ratio": 0})
    with mock.patch.object(m, "WORDLIST_PATH", wl.name), \
         mock.patch.object(m, "run_ffuf", side_effect=fake_ffuf):
        assets, records, waf = m.run_content_discovery(hosts, fresh_state(), 1, {"performance": {"max_workers": 3}})
    got_hosts = {a.value.split("/")[2] for a in assets}
    assert got_hosts == set(hosts), got_hosts
    assert len(records["endpoints"]) == 3 and len(waf) == 3
    print("PASS: content discovery parallel run aggregates every host's hits (workers=3)")


def test_stage5_x8_host_grouping():
    import stage5_hidden_params as m
    live_urls = ["https://a.example.com/1", "https://a.example.com/2", "https://b.example.com/1"]
    calls = []
    def fake_x8(url, state, scope):
        calls.append(url)
        return ["q"]
    with mock.patch.object(m, "run_paramspider", return_value=[]), \
         mock.patch.object(m, "run_x8", side_effect=fake_x8):
        _assets, _meta, records = m.run_stage5(["example.com"], live_urls, fresh_state(), 1,
                                               {"performance": {"max_workers": 5}})
    params = records["parameters"]
    assert len(params) == 3, len(params)                 # one per URL
    assert sorted(calls) == sorted(live_urls)            # every URL probed exactly once
    by_host = {p.host for p in params}
    assert by_host == {"a.example.com", "b.example.com"}, by_host
    # host attribution correct: the two a.example.com URLs both map to that host
    a_eps = sorted(p.endpoint for p in params if p.host == "a.example.com")
    assert a_eps == ["https://a.example.com/1", "https://a.example.com/2"], a_eps
    print("PASS: stage 5 x8 host-grouping probes each URL once, correct host attribution")


def test_stage1_parallel_roots_aggregate_stable_order():
    import stage1_passive as m
    def fake_runner(domain, state):
        return [Asset(value=f"sub.{domain}", type="subdomain", discovered_by="fake",
                      discovered_at_stage=1, discovered_in_pass=1)]
    with mock.patch.object(m, "TOOL_RUNNERS", [fake_runner]):
        assets = m.run_stage1(["a.com", "b.com", "c.com"], fresh_state(), 1,
                              scope={"performance": {"max_workers": 3}})
    vals = [a.value for a in assets]
    assert vals == ["sub.a.com", "sub.b.com", "sub.c.com"], vals   # stable order despite parallelism
    print("PASS: stage 1 parallel roots aggregate all roots in stable order")


def test_x8_candidate_urls_filtering():
    import stage5_hidden_params as m
    urls = [
        "https://a.example.com/search?q=1",     # keep (first search)
        "https://a.example.com/search?q=2",      # drop (dup path)
        "https://a.example.com/search?foo=bar",  # drop (dup path)
        "https://a.example.com/app.js",          # drop (static .js)
        "https://a.example.com/logo.png",        # drop (static)
        "https://a.example.com/%3C/a%3E",        # drop (crawl noise)
        "https://a.example.com/api/users",       # keep (distinct path)
        "https://b.example.com/search?q=1",      # keep (diff host, same path)
    ]
    got = m.x8_candidate_urls(urls)
    assert got == [
        "https://a.example.com/search?q=1",
        "https://a.example.com/api/users",
        "https://b.example.com/search?q=1",
    ], got
    print("PASS: x8_candidate_urls drops static/noise, dedupes by (host,path), keeps first-seen")


def test_x8_candidate_urls_per_host_cap():
    import stage5_hidden_params as m
    orig = m.MAX_X8_URLS_PER_HOST
    try:
        m.MAX_X8_URLS_PER_HOST = 2
        urls = [f"https://h.example.com/p{i}" for i in range(5)]   # 5 distinct paths
        got = m.x8_candidate_urls(urls)
        assert len(got) == 2, got                                   # clamped to the cap
    finally:
        m.MAX_X8_URLS_PER_HOST = orig
    print("PASS: x8_candidate_urls respects MAX_X8_URLS_PER_HOST backstop")


def test_x8_wordlist_is_repo_curated_and_covers_common_params():
    import stage5_hidden_params as m
    wl = Path(m.DEFAULT_X8_WORDLIST)
    assert wl.name == "params_common.txt", wl
    assert wl.exists(), f"shipped x8 wordlist missing: {wl}"
    names = set(wl.read_text().split())
    # must cover the common web params the SecLists 211-list missed, incl. the
    # camelCase postId ginandjuice actually uses (params are case-sensitive).
    for p in ("search", "category", "postId", "id", "q", "page", "sort", "filter",
              "redirect", "url", "token", "callback"):
        assert p in names, f"curated x8 wordlist missing common param: {p}"
    assert 200 <= len(names) <= 600, f"unexpected wordlist size: {len(names)}"
    print(f"PASS: shipped x8 wordlist params_common.txt ({len(names)} params) covers the common set")


def test_run_x8_parses_dict_found_params():
    """x8's real found_params entries are dicts {name, reason_kind, ...}, not bare
    strings — run_x8 must extract .name (the bug that crashed add_parameters)."""
    import stage5_hidden_params as m
    # realistic x8 -O json stdout: human preamble, then a JSON array of results,
    # each with found_params as a list of DICTS.
    x8_stdout = (
        "x8 vX.Y\nchecking https://a.example.com ...\n"
        '[{"found_params": ['
        '{"name": "category", "value": null, "reason_kind": "Reflected", "status": 200},'
        '{"name": "q", "value": null, "reason_kind": "Code", "status": 200}'
        ']}]'
    )
    with mock.patch.object(m, "_run_tool", return_value=(x8_stdout, "", 0)):
        names = m.run_x8("https://a.example.com/search", fresh_state(), {})
    assert names == ["category", "q"], names   # names extracted, no dicts leak through
    print("PASS: run_x8 extracts names from dict found_params (no more add_parameters crash)")


def test_x8_candidate_urls_skips_destructive():
    import stage5_hidden_params as m
    urls = [
        "https://a.example.com/search?q=1",            # keep
        "https://a.example.com/users/delete/carlos",    # DROP (delete segment)
        "https://a.example.com/account/deactivate",      # DROP
        "https://a.example.com/auth/reset-password",     # DROP (compound word)
        "https://a.example.com/posts/deleted_at",        # keep ('deleted' != 'delete')
        "https://a.example.com/undeletable-widget",      # keep (not the token)
    ]
    got = m.x8_candidate_urls(urls)
    assert got == [
        "https://a.example.com/search?q=1",
        "https://a.example.com/posts/deleted_at",
        "https://a.example.com/undeletable-widget",
    ], got
    print("PASS: x8_candidate_urls skips destructive paths (delete/deactivate/reset-password), "
          "keeps deleted_at / undeletable")


if __name__ == "__main__":
    test_resolve_max_workers()
    test_ffuf_wordlist_and_no_extensions()
    test_ffuf_extensions_return_if_set()
    test_content_discovery_parallel_aggregates_all_hosts()
    test_stage5_x8_host_grouping()
    test_stage1_parallel_roots_aggregate_stable_order()
    test_x8_candidate_urls_filtering()
    test_x8_candidate_urls_per_host_cap()
    test_x8_wordlist_is_repo_curated_and_covers_common_params()
    test_run_x8_parses_dict_found_params()
    test_x8_candidate_urls_skips_destructive()
    print("\nALL perf/coverage TESTS PASSED")
