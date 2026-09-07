"""
Mocked-tier tests for C3 — WAF/CDN detection (stage 4.5). Real cdncheck/wafw00f
output shapes verified 2026-08-23 (example.com → Cloudflare). Location-independent.
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

import stage_waf_cdn as c3
from state import RunState


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# real-shaped cdncheck -jsonl -resp lines
CDNCHECK_OUT = "\n".join([
    json.dumps({"input": "wafhost", "ip": "104.20.23.154", "waf": True, "waf_name": "cloudflare"}),
    json.dumps({"input": "cdnhost", "ip": "8.8.8.8", "cdn": True, "cdn_name": "google"}),
    json.dumps({"input": "cloudhost", "ip": "1.2.3.4", "cloud": True, "cloud_name": "aws"}),
])


def test_run_cdncheck_parses_classes():
    st = fresh_state()
    with mock.patch.object(c3, "_run_tool", return_value=(CDNCHECK_OUT, "", 0)):
        out = c3.run_cdncheck(["wafhost", "cdnhost", "cloudhost", "barehost"], st)
    assert out["wafhost"] == {"is_behind_waf": True, "waf_name": "cloudflare"}
    assert out["cdnhost"] == {"is_cdn": True, "cdn_name": "google"}
    assert out["cloudhost"] == {"cloud_name": "aws"}
    assert "barehost" not in out, "a host with no CDN/WAF/cloud match yields no entry"
    print("PASS: run_cdncheck parses cdn/waf/cloud classes; bare host absent (offline batch)")


def test_run_wafw00f_reads_output_file():
    st = fresh_state()

    def _mock(cmd, timeout=120):
        out = cmd[cmd.index("-o") + 1]
        Path(out).write_text(json.dumps([
            {"detected": True, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]))
        return ("", "", 0)

    with mock.patch.object(c3, "_run_tool", side_effect=_mock):
        res = c3.run_wafw00f("h.example.com", "https://h.example.com", st)
    assert res == {"is_behind_waf": True, "waf_vendor": "Cloudflare"}
    print("PASS: run_wafw00f parses its JSON output file → is_behind_waf + waf_vendor")


def test_run_wafw00f_no_waf():
    st = fresh_state()

    def _mock(cmd, timeout=120):
        out = cmd[cmd.index("-o") + 1]
        Path(out).write_text(json.dumps([{"detected": False, "firewall": "None", "manufacturer": "None"}]))
        return ("", "", 0)

    with mock.patch.object(c3, "_run_tool", side_effect=_mock):
        assert c3.run_wafw00f("h", "https://h", st) == {}
    print("PASS: run_wafw00f returns {} when no WAF detected")


def test_run_waf_cdn_merges_and_isolates():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    cdn = {"wafhost": {"is_behind_waf": True, "waf_name": "cloudflare"},
           "cdnhost": {"is_cdn": True, "cdn_name": "google"}}

    def _waf(host, base, state):
        if host == "badhost":
            raise RuntimeError("boom")
        if host == "wafhost":
            return {"is_behind_waf": True, "waf_vendor": "Cloudflare"}
        return {}

    with mock.patch.object(c3, "run_cdncheck", return_value=cdn), \
         mock.patch.object(c3, "run_wafw00f", side_effect=_waf):
        updates = c3.run_waf_cdn(["wafhost", "cdnhost", "badhost"], st, 1, scope)
    # wafw00f's active vendor label merged over cdncheck's range data
    assert updates["wafhost"]["waf_vendor"] == "Cloudflare" and updates["wafhost"]["is_behind_waf"]
    assert updates["cdnhost"] == {"is_cdn": True, "cdn_name": "google"}
    assert "badhost" not in updates, "wafw00f failure on one host is isolated (R7)"
    print("PASS: run_waf_cdn merges cdncheck+wafw00f, wafw00f vendor wins, R7 isolates a failure")


if __name__ == "__main__":
    test_run_cdncheck_parses_classes()
    test_run_wafw00f_reads_output_file()
    test_run_wafw00f_no_waf()
    test_run_waf_cdn_merges_and_isolates()
    print("\nAll checks passed.")
