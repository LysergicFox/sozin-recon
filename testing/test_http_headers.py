"""
Tests for required request-header injection (http_headers.py) and its wiring
into every target-facing stage. Tier 2: no real tools, no network — each
stage's `_run_tool` is mocked to capture the argv it would have run.

Confirms:
  - the helper normalizes/formats headers and no-ops cleanly when unconfigured;
  - every target-facing tool (httpx x2, katana, ffuf, nuclei x2, x8, whatweb,
    wafw00f) actually receives the header when scope declares required_headers;
  - nothing is appended when scope declares none (default behavior preserved).
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

import http_headers as hh
from state import RunState

HDRS = {"X-HackerOne": "me", "X-Extra": "v"}
SCOPE = {
    "in_scope": {"domains": ["*.example.com"], "ip_ranges": []},
    "rate_limit": {"stated_by_program": False, "requests_per_second": 5,
                   "scope": "per_host", "resolution": "confirmed"},
    "required_headers": HDRS,
}


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# ---------------------------------------------------------------- unit tests
def test_required_headers_normalizes():
    assert hh.required_headers({"required_headers": {" A ": " b ", "": "x", "y": ""}}) == {"A": "b"}
    assert hh.required_headers({}) == {}
    assert hh.required_headers({"required_headers": None}) == {}
    assert hh.required_headers({"required_headers": ["not", "a", "dict"]}) == {}
    print("PASS: required_headers normalizes, drops empties, tolerates junk")


def test_header_args_and_x8():
    assert hh.header_args({}) == []
    assert hh.header_args({"required_headers": {"X-HackerOne": "me"}}) == ["-H", "X-HackerOne:me"]
    # x8: single -H then space-separated tokens
    assert hh.x8_header_args({}) == []
    assert hh.x8_header_args({"required_headers": {"X-HackerOne": "me"}}) == ["-H", "X-HackerOne:me"]
    print("PASS: header_args / x8_header_args format name:value and no-op when empty")


def test_wafw00f_header_file():
    assert hh.wafw00f_header_file({}) is None
    path = hh.wafw00f_header_file({"required_headers": {"X-HackerOne": "me"}})
    try:
        assert path is not None
        content = Path(path).read_text()
        assert "X-HackerOne: me" in content
    finally:
        if path:
            Path(path).unlink(missing_ok=True)
    print("PASS: wafw00f_header_file writes a 'Name: Value' file, None when empty")


# --------------------------------------------------- per-stage wiring (mocked)
def _capture(module):
    """Patch module._run_tool to record every argv and return an empty result."""
    calls = []
    def cap(cmd, *a, **k):
        calls.append(list(cmd))
        return ("", "", 0)
    return calls, mock.patch.object(module, "_run_tool", side_effect=cap)


def _assert_header_in(calls, label):
    flat = [tok for cmd in calls for tok in cmd]
    assert "-H" in flat, f"{label}: no -H flag in {calls}"
    assert "X-HackerOne:me" in flat, f"{label}: header token missing in {calls}"


def test_stage4_httpx_gets_header():
    import stage4_live_probing as m
    calls, p = _capture(m)
    with p:
        m.run_httpx(["a.example.com"], fresh_state(), SCOPE)
    _assert_header_in(calls, "httpx")
    print("PASS: stage4 httpx receives -H X-HackerOne:me")


def test_screenshots_httpx_gets_header():
    import stage_screenshots as m
    calls, p = _capture(m)
    with p:
        m.run_screenshots(["a.example.com"], fresh_state(), SCOPE)
    _assert_header_in(calls, "screenshots httpx")
    print("PASS: C2 screenshots httpx receives the header")


def test_stage6_katana_gets_header():
    import stage6_crawling as m
    calls, p = _capture(m)
    with p:
        m.run_katana(["a.example.com"], fresh_state(), SCOPE)
    _assert_header_in(calls, "katana")
    print("PASS: stage6 katana receives the header")


def test_content_discovery_ffuf_gets_header():
    import stage_content_discovery as m
    calls, p = _capture(m)
    with p:
        m.run_ffuf("a.example.com", fresh_state(), SCOPE, base="https://a.example.com")
    _assert_header_in(calls, "ffuf")
    print("PASS: stage6.5 ffuf receives the header")


def test_stage8_nuclei_gets_header():
    import stage8_takeover as m
    calls, p = _capture(m)
    with p:
        m.run_nuclei_takeover(["a.example.com"], fresh_state(), SCOPE)
        m.run_nuclei_detection(["a.example.com"], fresh_state(), SCOPE)
    _assert_header_in(calls, "nuclei")
    print("PASS: stage8 nuclei (takeover + detection) receive the header")


def test_stage5_x8_gets_header():
    import stage5_hidden_params as m
    calls, p = _capture(m)
    with p:
        m.run_x8("https://a.example.com/?q=1", fresh_state(), SCOPE)
    _assert_header_in(calls, "x8")
    print("PASS: stage5 x8 receives -H X-HackerOne:me")


def test_stage9_whatweb_gets_header():
    import stage9_whatweb as m
    calls, p = _capture(m)
    with p:
        m.run_whatweb(["a.example.com"], fresh_state(), SCOPE)
    _assert_header_in(calls, "whatweb")
    print("PASS: stage9 whatweb receives the header")


def test_wafw00f_gets_header_file():
    import stage_waf_cdn as m
    calls, p = _capture(m)
    with p:
        m.run_wafw00f("a.example.com", "https://a.example.com", fresh_state(), SCOPE)
    # wafw00f is the file-based exception: assert -H <file> and the file's content
    flat_pairs = [(cmd[i], cmd[i + 1]) for cmd in calls for i in range(len(cmd) - 1)]
    hfiles = [v for (f, v) in flat_pairs if f == "-H"]
    assert hfiles, f"wafw00f: no -H <file> in {calls}"
    # file is unlinked by run_wafw00f in its finally; we can't re-read it, so just
    # assert the flag/path shape is present (content is covered by the unit test).
    print("PASS: wafw00f receives -H <headers-file>")


def test_no_headers_appends_nothing():
    import stage4_live_probing as m
    calls, p = _capture(m)
    scope_no_hdr = {k: v for k, v in SCOPE.items() if k != "required_headers"}
    with p:
        m.run_httpx(["a.example.com"], fresh_state(), scope_no_hdr)
    flat = [tok for cmd in calls for tok in cmd]
    assert "-H" not in flat, f"expected no -H when unconfigured, got {calls}"
    print("PASS: no required_headers → no -H appended (default behavior preserved)")


if __name__ == "__main__":
    test_required_headers_normalizes()
    test_header_args_and_x8()
    test_wafw00f_header_file()
    test_stage4_httpx_gets_header()
    test_screenshots_httpx_gets_header()
    test_stage6_katana_gets_header()
    test_content_discovery_ffuf_gets_header()
    test_stage8_nuclei_gets_header()
    test_stage5_x8_gets_header()
    test_stage9_whatweb_gets_header()
    test_wafw00f_gets_header_file()
    test_no_headers_appends_nothing()
    print("\nALL http_headers TESTS PASSED")
