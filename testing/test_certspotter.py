"""
Mocked-subprocess tests for run_certspotter() (stage1_passive.py).

Tier 2 (mocked-subprocess) per CONTRIBUTING.md's staged discipline, using
_run_tool's REAL captured output from a live zonetransfer.me query
(2026-08-22) as the primary fixture. Tier 3 (real run) still needs a live
target/network.

Updated for R5 + R11: raw archives are now per-target (+ per-page) -
stage1_certspotter_{sanitized_domain}_p{page}.json; run_certspotter()
paginates (the 2-cert real fixture is a single short page under the default
100-item limit, so these single-response mocks issue exactly one request).

Location-independent: resolves the repo root by walking up to the dir that
contains state.py, so it runs from the repo root or under testing/.
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

from state import RunState
import stage1_passive


# The certspotter raw archive filename token for zonetransfer.me under R5
# (_sanitize keeps dots/hyphens, so the token is the domain verbatim), page 0.
_ZT_RAW = "stage1_certspotter_zonetransfer.me_p0.json"


# Real curl response captured 2026-08-22 against zonetransfer.me (see
# CHANGELOG.md's "crt.sh -> Cert Spotter" entry). Confirms: dns_names is
# a real JSON array, and a single cert bundles in totally unrelated
# domains (digi.ninja, vuln-demo.com, iot-cert.space, digininja.org)
# alongside the actual target - the off-target noise _is_subdomain_of_root()
# has to filter out.
REAL_ZONETRANSFER_ME_RESPONSE = json.dumps([
    {
        "id": "16006818930",
        "tbs_sha256": "10c31e9dc11bc24fcf2b120d9a080cd491e9fb320bc5f247641e8d1bd614d5a3",
        "cert_sha256": "78f15bec0e107edc3a4c907176466fa07372fbf9cd6344048ff03125717f763e",
        "dns_names": [
            "alertlab.digi.ninja", "authlab.digi.ninja", "cors-client.digi.ninja",
            "cors-server.digi.ninja", "crackedflask.digi.ninja", "digi.ninja",
            "digininja.org", "frontme.vuln-demo.com", "frontmecf.vuln-demo.com",
            "graphqlab.digi.ninja", "html5.digi.ninja", "html5server.digi.ninja",
            "iot-cert.space", "ip.digi.ninja", "secret.digi.ninja",
            "splitxsslab.digi.ninja", "svg.digi.ninja", "vuln-demo.com",
            "vulndap.digi.ninja", "ws.digi.ninja", "www.digi.ninja",
            "www.digininja.org", "www.iot-cert.space", "www.vuln-demo.com",
            "www.zonetransfer.me", "zonetransfer.me",
        ],
        "pubkey_sha256": "ff5273825c611268a3dff075d90d22f19476622c6ea014aad9651f673dd4a212",
        "not_before": "2026-07-21T21:50:10Z",
        "not_after": "2026-10-19T21:50:09Z",
        "revoked": False,
    },
    {
        "id": "16307834670",
        "tbs_sha256": "70b34ae4c2ce9a0394b89d6ff23aac7b467335c54aa9ad8b83847b39c7c9cc3d",
        "cert_sha256": "6858be5e691003111eb6634820ff3e26e7b6e5a4cbce2073e15a27dc29a37dad",
        "dns_names": [
            "alertlab.digi.ninja", "authlab.digi.ninja", "cors-client.digi.ninja",
            "cors-server.digi.ninja", "crackedflask.digi.ninja", "csrf.digi.ninja",
            "digi.ninja", "digininja.org", "frontme.vuln-demo.com",
            "frontmecf.vuln-demo.com", "graphqlab.digi.ninja", "html5.digi.ninja",
            "html5server.digi.ninja", "iot-cert.space", "ip.digi.ninja",
            "secret.digi.ninja", "splitxsslab.digi.ninja", "svg.digi.ninja",
            "vuln-demo.com", "vulndap.digi.ninja", "ws.digi.ninja",
            "www.digi.ninja", "www.digininja.org", "www.iot-cert.space",
            "www.vuln-demo.com", "www.zonetransfer.me", "zonetransfer.me",
        ],
        "pubkey_sha256": "7a2fd9c1b7dcaf8656af40122a809075d76e1e737ad71d0e9b65073619e03969",
        "not_before": "2026-08-05T13:54:52Z",
        "not_after": "2026-11-03T13:54:51Z",
        "revoked": False,
    },
])


def fresh_state():
    return RunState(Path(tempfile.mkdtemp()))


def run_with_mocked_curl(domain, stdout_text):
    state = fresh_state()
    with mock.patch.object(stage1_passive, "_run_tool", return_value=(stdout_text, "", 0)):
        return stage1_passive.run_certspotter(domain, state), state


def test_real_response_filters_off_target_and_dedupes():
    assets, state = run_with_mocked_curl("zonetransfer.me", REAL_ZONETRANSFER_ME_RESPONSE)
    values = sorted(a.value for a in assets)
    assert values == ["www.zonetransfer.me", "zonetransfer.me"], values
    for a in assets:
        assert a.type == "subdomain"
        assert a.discovered_by == ["certspotter"]
        assert a.metadata == {}, "neither real entry is a wildcard SAN"
    assert len(assets) == 2
    raw_path = state.raw_dir / _ZT_RAW
    assert raw_path.exists(), f"expected {_ZT_RAW} to exist"
    assert json.loads(raw_path.read_text()) == json.loads(REAL_ZONETRANSFER_ME_RESPONSE)
    print("PASS: real captured response filters off-target SANs and dedupes correctly")


def test_wildcard_san_kept_and_flagged():
    synthetic = json.dumps([{
        "id": "1", "dns_names": ["*.example.com", "example.com"],
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
        "revoked": False,
    }])
    assets, _ = run_with_mocked_curl("example.com", synthetic)
    by_value = {a.value: a for a in assets}
    assert set(by_value) == {"example.com"}, by_value
    assert by_value["example.com"].metadata.get("from_wildcard_san") is True
    print("PASS: wildcard SAN stripped, kept, and flagged in metadata")


def test_off_target_wildcard_excluded():
    synthetic = json.dumps([{
        "id": "1", "dns_names": ["*.totallydifferent.com"],
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
        "revoked": False,
    }])
    assets, _ = run_with_mocked_curl("example.com", synthetic)
    assert assets == [], assets
    print("PASS: wildcard SAN for an unrelated domain is correctly excluded")


def test_non_json_response_treated_as_zero_results():
    html_502 = "<html>\n<head><title>502 Bad Gateway</title></head>\n<body>...</body>\n</html>"
    assets, state = run_with_mocked_curl("zonetransfer.me", html_502)
    assert assets == []
    raw_path = state.raw_dir / _ZT_RAW
    assert raw_path.read_text() == html_502
    print("PASS: non-JSON (e.g. HTML error page) response treated as zero results, still archived")


def test_rate_limit_error_object_treated_as_zero_results():
    error_response = json.dumps({"code": "too-many-requests", "message": "rate limit exceeded"})
    assets, _ = run_with_mocked_curl("zonetransfer.me", error_response)
    assert assets == []
    print("PASS: Cert Spotter's rate-limit JSON-object error shape treated as zero results")


def test_empty_list_response():
    assets, _ = run_with_mocked_curl("nosuch-domain-with-no-certs.example", "[]")
    assert assets == []
    print("PASS: empty issuance list handled cleanly")


def test_single_short_page_is_one_request():
    # (R11) a page shorter than the requested limit is the last page - a
    # 2-cert response under the default 100-item limit must NOT trigger a
    # second request.
    state = fresh_state()
    m = mock.Mock(return_value=(REAL_ZONETRANSFER_ME_RESPONSE, "", 0))
    with mock.patch.object(stage1_passive, "_run_tool", m):
        stage1_passive.run_certspotter("zonetransfer.me", state)
    assert m.call_count == 1, f"expected 1 request for a short page, got {m.call_count}"
    print("PASS: a single short page issues exactly one request (R11)")


def test_amass_still_uses_shared_helper_correctly():
    amass_output = (
        "zonetransfer.me (FQDN) --> a_record --> 5.196.105.14 (IPAddress)\n"
        "unrelated-external.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)\n"
    )
    assets = stage1_passive._parse_amass_relationships(amass_output, "zonetransfer.me")
    values = {a.value for a in assets}
    assert "zonetransfer.me" in values
    assert "5.196.105.14" in values
    assert "unrelated-external.com" not in values, "off-root FQDN source should not become an asset"
    print("PASS: amass parser's behavior unchanged after refactor to shared _is_subdomain_of_root()")


if __name__ == "__main__":
    test_real_response_filters_off_target_and_dedupes()
    test_wildcard_san_kept_and_flagged()
    test_off_target_wildcard_excluded()
    test_non_json_response_treated_as_zero_results()
    test_rate_limit_error_object_treated_as_zero_results()
    test_empty_list_response()
    test_single_short_page_is_one_request()
    test_amass_still_uses_shared_helper_correctly()
    print("\nAll checks passed.")
