"""Mocked-tier tests for F6 — target profile digest. Offline. Location-independent."""
import json
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

import target_profile as f6
from state import RunState, Asset, Endpoint, Service, ReconFinding


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def test_build_profile_aggregates():
    st = fresh_state()
    st.add_assets([
        Asset(value="h.example.com", type="subdomain", discovered_by="t", discovered_at_stage=4,
              discovered_in_pass=1, scope_status="in_scope",
              metadata={"httpx_status_code": 200, "whatweb_tech": {"nginx": {}, "WordPress": {}},
                        "is_behind_waf": True, "waf_vendor": "Cloudflare", "interest_score": 12}),
        Asset(value="https://h.example.com/admin", type="url", discovered_by="ffuf",
              discovered_at_stage=6.5, discovered_in_pass=1, scope_status="in_scope",
              metadata={"interest_score": 9}),
    ])
    st.add_endpoints([Endpoint(url="https://h.example.com/login", host="h.example.com",
                               path="/login", method="GET", auth_status="auth_surface")])
    st.add_services([Service(target="h.example.com", host="h.example.com", port=8081,
                             proto="tcp", discovered_by="naabu")])
    st.add_recon_findings([ReconFinding(host="h.example.com", template_id="CVE-2021-41773",
                                        source="cve-candidate", category="cve", severity="high",
                                        matched_at="apache/2.4.49")])
    p = f6.build_profile(st)
    assert p["scope_size"]["live_hosts"] == 1 and p["scope_size"]["endpoints"] == 1
    assert "nginx" in p["tech_stack"] and "WordPress" in p["tech_stack"]
    assert p["waf_cdn_posture"]["behind_waf"] == {"h.example.com": "Cloudflare"}
    assert p["auth_model"]["auth_surfaces"] == ["/login"]
    assert p["notable_exposures"]["cve_candidates"] == ["CVE-2021-41773"]
    assert p["notable_exposures"]["findings_by_severity"] == {"high": 1}
    assert p["top_interest"][0] == ("h.example.com", 12)  # ranked
    assert "h.example.com:8081" in p["non_standard_ports"]
    print("PASS: build_profile aggregates size/tech/waf/auth/exposures/interest/ports")


def test_run_target_profile_writes_artifacts():
    st = fresh_state()
    st.add_assets([Asset(value="h", type="subdomain", discovered_by="t", discovered_at_stage=4,
                         discovered_in_pass=1, scope_status="in_scope")])
    f6.run_target_profile(st)
    j = json.loads((st.run_dir / "target_profile.json").read_text())
    md = (st.run_dir / "target_profile.md").read_text()
    assert j["scope_size"]["subdomains"] == 1
    assert md.startswith("# Target profile") and "## Tech stack" in md
    print("PASS: run_target_profile writes target_profile.json + target_profile.md")


def test_empty_run_no_crash():
    st = fresh_state()
    p = f6.run_target_profile(st)
    assert p["scope_size"]["subdomains"] == 0 and p["tech_stack"] == []
    print("PASS: empty run → profile with zeros, no crash")


if __name__ == "__main__":
    test_build_profile_aggregates()
    test_run_target_profile_writes_artifacts()
    test_empty_run_no_crash()
    print("\nAll checks passed.")
