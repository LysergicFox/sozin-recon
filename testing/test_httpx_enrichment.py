"""
Mocked-tier tests for E1 — richer httpx enrichment on the stage-4 invocation.
The httpx JSON keys used here were VERIFIED against a real httpx probe 2026-08-23
(example.com → cdn/cdn_name/cdn_type, jarm_hash, body_preview; favicon & asn are
present only when available). Location-independent.
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

import stage4_live_probing as s4
from state import RunState, TARGET_DERIVED_METADATA_KEYS


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


# real-shaped httpx lines: one CDN-fronted with favicon, one bare
LINE_CDN = {
    "input": "example.com", "status_code": 200, "title": "Example",
    "hash": {"body_sha256": "abc", "header_sha256": "def"},
    "final_url": "https://example.com", "chain_status_codes": [200],
    "body_preview": "Example Domain ...", "cdn": True, "cdn_name": "cloudflare",
    "cdn_type": "waf", "jarm_hash": "27d40d40d00040d1", "favicon": "-12345",
    "favicon_url": "https://example.com/favicon.ico",
}
LINE_BARE = {
    "input": "zonetransfer.me", "status_code": 301,
    "hash": {}, "final_url": "https://zonetransfer.me",
    "body_preview": "Moved Permanently", "jarm_hash": "28d28d28",
    # NO cdn / favicon / asn keys (host doesn't serve/qualify)
}


def test_e1_keys_parsed_when_present():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    raw = json.dumps(LINE_CDN) + "\n" + json.dumps(LINE_BARE)
    with mock.patch.object(s4, "_run_tool", return_value=(raw, "", 0)):
        md, _redirects = s4.run_httpx(["example.com", "zonetransfer.me"], st, scope)
    ex = md["example.com"]
    assert ex["httpx_cdn"] is True and ex["httpx_cdn_name"] == "cloudflare" and ex["httpx_cdn_type"] == "waf"
    assert ex["httpx_jarm"] == "27d40d40d00040d1"
    assert ex["httpx_favicon_hash"] == "-12345" and ex["httpx_favicon_url"].endswith("/favicon.ico")
    assert ex["httpx_body_preview"] == "Example Domain ..."
    print("PASS: E1 enrichment keys (cdn/jarm/favicon/body_preview) parsed when present")


def test_e1_absent_keys_not_set():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    with mock.patch.object(s4, "_run_tool", return_value=(json.dumps(LINE_BARE), "", 0)):
        md, _ = s4.run_httpx(["zonetransfer.me"], st, scope)
    zt = md["zonetransfer.me"]
    # host served no favicon/cdn/asn → those keys must be ABSENT (not None-valued noise)
    for absent in ("httpx_cdn", "httpx_cdn_name", "httpx_favicon_hash", "httpx_asn"):
        assert absent not in zt, f"{absent} should not be set when httpx didn't return it"
    assert zt["httpx_jarm"] == "28d28d28" and zt["httpx_body_preview"] == "Moved Permanently"
    print("PASS: E1 absent httpx keys are not stored (no None-noise); present ones are")


def test_body_preview_is_target_derived():
    assert "httpx_body_preview" in TARGET_DERIVED_METADATA_KEYS, \
        "body_preview is target-authored → must be untrusted provenance"
    # favicon_hash / cdn / jarm are computed/observed → trusted (NOT in the set)
    for trusted in ("httpx_favicon_hash", "httpx_cdn", "httpx_jarm", "httpx_asn"):
        assert trusted not in TARGET_DERIVED_METADATA_KEYS
    print("PASS: body_preview marked target_derived; favicon/cdn/jarm/asn are trusted")


if __name__ == "__main__":
    test_e1_keys_parsed_when_present()
    test_e1_absent_keys_not_set()
    test_body_preview_is_target_derived()
    print("\nAll checks passed.")
