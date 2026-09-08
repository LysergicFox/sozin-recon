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


if __name__ == "__main__":
    test_resolve_max_workers()
    test_ffuf_wordlist_and_no_extensions()
    test_ffuf_extensions_return_if_set()
    test_content_discovery_parallel_aggregates_all_hosts()
    test_stage5_x8_host_grouping()
    test_stage1_parallel_roots_aggregate_stable_order()
    print("\nALL perf/coverage TESTS PASSED")
