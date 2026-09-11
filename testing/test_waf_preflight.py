"""
Tests for the stage 6.5 (B1) pre-flight WAF-challenge retreat — the close-out of
the "`-sf` only catches 403 floods, a 200-JS-challenge won't trip it" blind spot.

A host whose stage-4 httpx fingerprint (title / body preview) looks like a
JS-challenge / interstitial wall is retreated-from BEFORE fuzzing (no ffuf, no
extra traffic), recorded as a WAF flag. is_behind_waf alone must NOT trip it, and
a reCAPTCHA widget on a real page must NOT be mistaken for a challenge wall.

Tier 2: mocked, no real tools / no network.
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


def test_challenge_signal():
    import stage_content_discovery as m
    # interstitial walls trip (title or body preview)
    assert m._challenge_signal({"httpx_title": "Just a moment..."}) == "just a moment"
    assert m._challenge_signal(
        {"httpx_body_preview": "Checking your browser before accessing example.com"})
    assert m._challenge_signal({"httpx_title": "Attention Required! | Cloudflare"})
    # is_behind_waf ALONE does not trip (most real targets sit behind a WAF)
    assert m._challenge_signal({"httpx_title": "Login", "is_behind_waf": True}) is None
    # a reCAPTCHA widget on a legit page is not a challenge wall
    assert m._challenge_signal(
        {"httpx_title": "Sign in", "httpx_body_preview": "<div class='g-recaptcha'></div>"}) is None
    assert m._challenge_signal({}) is None
    assert m._challenge_signal({"httpx_title": None, "httpx_body_preview": None}) is None
    print("PASS: _challenge_signal trips only on interstitial markers (not is_behind_waf / recaptcha)")


def test_content_discovery_retreats_from_challenged_host():
    import stage_content_discovery as m
    st = fresh_state()
    st.add_assets([
        Asset(value="a.example.com", type="subdomain", discovered_by="t",
              discovered_at_stage=4, discovered_in_pass=1,
              metadata={"httpx_title": "Just a moment...", "httpx_status_code": 403,
                        "is_behind_waf": True}),
        Asset(value="b.example.com", type="subdomain", discovered_by="t",
              discovered_at_stage=4, discovered_in_pass=1,
              metadata={"httpx_title": "Welcome", "httpx_status_code": 200}),
    ])
    wl = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    wl.write("admin\n"); wl.close()

    fuzzed = []
    def fake_ffuf(host, state, scope, base=None):
        fuzzed.append(host)
        return ([{"url": f"https://{host}/admin", "status": 200, "length": 1,
                  "content-type": "text/html"}],
                {"waf_suspected": False, "waf_signal": None, "waf_block_ratio": 0})

    with mock.patch.object(m, "WORDLIST_PATH", wl.name), \
         mock.patch.object(m, "run_ffuf", side_effect=fake_ffuf):
        assets, records, waf = m.run_content_discovery(
            ["a.example.com", "b.example.com"], st, 1, {})

    assert fuzzed == ["b.example.com"], f"challenged host must not be fuzzed; fuzzed={fuzzed}"
    assert waf["a.example.com"]["waf_suspected"] is True
    assert waf["a.example.com"]["waf_signal"] == "js_challenge"
    assert waf["b.example.com"]["waf_suspected"] is False
    # only the clean host produced discovery output
    assert {a.value for a in assets} == {"https://b.example.com/admin"}, {a.value for a in assets}
    assert len(records["endpoints"]) == 1
    print("PASS: stage 6.5 retreats from a JS-challenge host (no ffuf), fuzzes only the clean host")


if __name__ == "__main__":
    test_challenge_signal()
    test_content_discovery_retreats_from_challenged_host()
    print("\nALL WAF-preflight TESTS PASSED")
