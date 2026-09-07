"""
Mocked-tier tests for C1 — broadened detection-only nuclei + the general
recon_findings (POI) table. Tier 2 (no real nuclei). The nuclei JSONL field
names used here were VERIFIED against real nuclei v3.11.1 positive output
(2026-08-23): top-level template-id/matched-at/type, info.{name,severity,
tags(list)}, plus request/response/curl-command (which must be trimmed).

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

import stage8_takeover as s8
from state import RunState, Asset, ReconFinding


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# real-shaped nuclei positive (mirrors the verified v3.11.1 schema)
NUCLEI_LINE = {
    "template-id": "git-config-nginxoff",
    "info": {"name": "Git Config Exposure", "severity": "medium",
             "tags": ["exposures", "config"]},
    "type": "http", "host": "h.example.com",
    "matched-at": "http://h.example.com/.git/config", "matcher-status": True,
    "request": "GET /.git/config HTTP/1.1\r\nHost: h.example.com\r\n\r\n",  # TRIM
    "response": "HTTP/1.1 200 OK\r\n\r\n[core]\n  repositoryformatversion = 0",  # TRIM
    "curl-command": "curl -X GET http://h.example.com/.git/config",  # TRIM
}


# --- recon_findings table add/load/dedup ------------------------------------

def test_recon_findings_add_load_dedup():
    st = fresh_state()
    f = ReconFinding(host="h.example.com", template_id="git-config",
                     template_name="Git Config", category="exposures,config",
                     severity="medium", matched_at="http://h.example.com/.git/config",
                     asset_id="a1", raw_finding={"template-id": "git-config"})
    assert len(st.add_recon_findings([f])) == 1
    # same (host, template_id, matched_at) dedups
    dup = ReconFinding(host="h.example.com", template_id="git-config",
                       matched_at="http://h.example.com/.git/config", raw_finding={})
    st.add_recon_findings([dup])
    loaded = st.load_recon_findings()
    assert len(loaded) == 1
    assert loaded[0].status == "new" and loaded[0].target_derived is True
    assert loaded[0].source == "nuclei" and loaded[0].category == "exposures,config"
    print("PASS: recon_findings add/load; dedup on (host, template_id, matched_at); status=new, td=1")


# --- parser: real field names, tags->category, raw trim ---------------------

def test_parse_nuclei_detection_real_shape():
    parsed = s8.parse_nuclei_detection_jsonl(json.dumps(NUCLEI_LINE))
    assert len(parsed) == 1
    p = parsed[0]
    assert p["template_id"] == "git-config-nginxoff"
    assert p["template_name"] == "Git Config Exposure" and p["severity"] == "medium"
    assert p["category"] == "exposures,config", "info.tags (list) joined into category"
    assert p["matched_at"] == "http://h.example.com/.git/config"
    # request/response/curl-command TRIMMED from the retained raw finding
    assert set(p["raw_finding"]) & {"request", "response", "curl-command"} == set()
    assert p["raw_finding"]["template-id"] == "git-config-nginxoff"  # metadata kept
    print("PASS: detection parser reads real nuclei fields, tags->category, trims request/response/curl")


def test_parse_nuclei_detection_skips_bad_lines():
    out = s8.parse_nuclei_detection_jsonl(json.dumps(NUCLEI_LINE) + "\n{not json\n" + json.dumps(NUCLEI_LINE))
    assert len(out) == 2, "one bad line skipped, valid ones kept"
    print("PASS: detection parser skips a malformed line, keeps the rest")


# --- stage function: builds ReconFinding, asset linkage, R7 -----------------

def test_run_stage8_detection_builds_findings():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    with mock.patch.object(s8, "run_nuclei_detection", return_value=json.dumps(NUCLEI_LINE)):
        findings = s8.run_stage8_detection(["h.example.com"], st, 1, scope,
                                           asset_lookup={"h.example.com": "asset-123"})
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, ReconFinding) and f.status == "new" and f.target_derived is True
    assert f.asset_id == "asset-123" and f.category == "exposures,config"
    assert f.discovered_at_stage == 8
    print("PASS: run_stage8_detection builds ReconFinding (status=new, td=1, asset_id linked)")


def test_run_stage8_detection_R7_isolation():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    with mock.patch.object(s8, "run_nuclei_detection", side_effect=RuntimeError("boom")):
        findings = s8.run_stage8_detection(["h"], st, 1, scope)
    assert findings == [], "a detection-run failure yields no findings, not a crash (R7)"
    print("PASS: run_stage8_detection isolates a nuclei failure (R7)")


# --- detection is DETECTION-ONLY (argv boundary) ----------------------------

def test_detection_argv_is_detection_only():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    captured = {}

    def _cap(cmd, timeout=600):
        captured["cmd"] = cmd
        return ("", "", 0)

    with mock.patch.object(s8, "_run_tool", side_effect=_cap):
        s8.run_nuclei_detection(["h.example.com"], st, scope)
    cmd = captured["cmd"]
    assert "exposures,misconfiguration,exposed-panels" in cmd, cmd
    assert "default-logins,intrusive,fuzzing,dos" in cmd, "must EXCLUDE default-logins/intrusive"
    # the include set must not contain default-logins/exploit tags
    inc = cmd[cmd.index("-tags") + 1]
    assert "default-login" not in inc and "intrusive" not in inc
    assert "takeover" not in inc, "detection run is separate from takeover"
    print("PASS: detection nuclei argv is detection-only (excludes default-logins/intrusive; not takeover)")


if __name__ == "__main__":
    test_recon_findings_add_load_dedup()
    test_parse_nuclei_detection_real_shape()
    test_parse_nuclei_detection_skips_bad_lines()
    test_run_stage8_detection_builds_findings()
    test_run_stage8_detection_R7_isolation()
    test_detection_argv_is_detection_only()
    print("\nAll checks passed.")
