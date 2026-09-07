"""
Mocked-tier tests for C5 — tech→CVE candidate flagging. The index parsing is
verified against the REAL on-box nuclei-templates in test_real_index (skipped if
absent). Matching logic uses a mock index. Location-independent.
"""
import os
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _p in (_HERE, *_HERE.parents):
    if (_p / "state.py").exists():
        _REPO_ROOT = _p
        break
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "stages"))

import cve_candidates as c5
from state import RunState, Asset


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def _host(value, **md):
    return Asset(value=value, type="subdomain", discovered_by="whatweb",
                discovered_at_stage=9, discovered_in_pass=1, scope_status="in_scope", metadata=md)


MOCK_INDEX = {
    ("apache", "2.4.49"): [{"cve": "CVE-2021-41773", "cvss": "7.5", "severity": "high",
                            "vendor": "apache", "product": "http_server", "version": "2.4.49"}],
    ("http_server", "2.4.49"): [{"cve": "CVE-2021-41773", "cvss": "7.5", "severity": "high",
                                 "vendor": "apache", "product": "http_server", "version": "2.4.49"}],
    ("nginx", "1.20.0"): [{"cve": "CVE-2021-23017", "cvss": "8.1", "severity": "high",
                           "vendor": "nginx", "product": "nginx", "version": "1.20.0"}],
}


def test_extract_tech_versions():
    h = _host("h", whatweb_tech={"nginx": {"version": ["1.20.0"]},
                                 "HTTPServer": {"string": ["Apache/2.4.49"]}},
              httpx_tech=["OpenSSL:1.1.1"])
    got = {(t, v) for t, v, _e in c5.extract_tech_versions(h)}
    assert ("nginx", "1.20.0") in got
    assert ("apache", "2.4.49") in got, "parsed from the HTTPServer string 'Apache/2.4.49'"
    assert ("openssl", "1.1.1") in got, "parsed from httpx_tech 'OpenSSL:1.1.1'"
    print("PASS: extract_tech_versions from whatweb version+string and httpx_tech")


def test_run_cve_candidates_exact_match():
    st = fresh_state()
    st.add_assets([_host("apachehost.example.com",
                         whatweb_tech={"HTTPServer": {"string": ["Apache/2.4.49"]}}),
                   _host("nginxhost.example.com",
                         whatweb_tech={"nginx": {"version": ["1.99.0"]}})])  # no matching CVE
    findings = c5.run_cve_candidates(st, index=MOCK_INDEX)
    # apache 2.4.49 → CVE-2021-41773 candidate; nginx 1.99.0 → nothing (exact-match gate)
    assert len(findings) == 1
    f = findings[0]
    assert f.template_id == "CVE-2021-41773" and f.source == "cve-candidate"
    assert f.category == "cve" and f.severity == "high" and f.status == "new"
    assert f.target_derived is True and f.host == "apachehost.example.com"
    assert "not a confirmed vuln" in f.raw_finding["note"]
    # persisted into recon_findings
    assert any(rf.source == "cve-candidate" for rf in st.load_recon_findings())
    print("PASS: run_cve_candidates emits exact-version CVE candidate; no version match → nothing")


def test_no_double_flag():
    st = fresh_state()
    # same CVE reachable via both vendor+product keys must dedup per (host, cve)
    st.add_assets([_host("h", whatweb_tech={"Apache": {"version": ["2.4.49"]},
                                            "HTTPServer": {"string": ["Apache/2.4.49"]}})])
    findings = c5.run_cve_candidates(st, index=MOCK_INDEX)
    assert len({f.template_id for f in findings}) == len(findings), "(host, cve) deduped"
    print("PASS: a CVE reachable via multiple tokens is flagged once per host")


def test_real_index_parses():
    if not os.path.isdir(os.path.join(c5.TEMPLATES_DIR, "http", "cves")):
        print("SKIP: nuclei-templates not present — real index parse not checked")
        return
    idx = c5.build_cve_index()
    assert idx, "real index should be non-empty"
    # the canonical apache http_server 2.4.49 → CVE-2021-41773 must be present
    cves = {e["cve"] for e in idx.get(("apache", "2.4.49"), [])}
    assert "CVE-2021-41773" in cves, cves
    # no malformed keys (version must start alnum, contain a digit)
    bad = [(n, v) for (n, v) in idx if not c5._VERSION_OK.match(v)]
    assert not bad, f"malformed version keys leaked: {bad[:5]}"
    print(f"PASS: real nuclei-templates index built ({len(idx)} keys); apache 2.4.49→CVE-2021-41773; no malformed keys")


if __name__ == "__main__":
    test_extract_tech_versions()
    test_run_cve_candidates_exact_match()
    test_no_double_flag()
    test_real_index_parses()
    print("\nAll checks passed.")
