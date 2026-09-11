"""
Tests for URL-hygiene ingestion filtering:
  - url_hygiene.is_malformed_url_asset (path-scoped noise detection)
  - main.drop_malformed_url_assets (the single ingestion choke point)

The malformed samples are the real crawl/history noise gau/katana produced on
the consented ginandjuice run (`</a>` fragments, trailing backslashes, HTML
entities in the path). The kept samples include the reflected-search endpoint
whose XSS payload lives in the QUERY, not the path — it must survive.
"""
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "stages"))

from url_hygiene import is_malformed_url_asset
from state import Asset
import main


_MALFORMED = [
    "https://ginandjuice.shop/%3C/a%3E",                       # </a>
    "https://ginandjuice.shop/%3C/a%3E%3C/span%3E%3C/div%3E",  # nested markup
    "https://ginandjuice.shop/%5C",                            # trailing backslash
    "https://ginandjuice.shop/)%3C/a%3E",
    "https://ginandjuice.shop/about%3C/a%3E",
    "https://ginandjuice.shop/users/delete/carlos%3C/a%3E&quot;",
    "https://ginandjuice.shop/users/delete/carlos%5C",
    "https://ginandjuice.shop/vulnerabilities%3C/a%3E",
]

_CLEAN = [
    "https://ginandjuice.shop/",
    "https://ginandjuice.shop/catalog?id=1",
    "https://ginandjuice.shop/catalog/product?productId=2",
    # payload is in the QUERY, path is clean "/" — a real reflected-search endpoint
    "https://ginandjuice.shop/?search=%3Cscript%3Eprompt(%27test%27);%3C/script%3E",
    # a legit space in a filename (%20) must NOT be treated as noise
    "https://ginandjuice.shop/files/my%20report.pdf",
    "https://sub.ginandjuice.shop/a/b/c",
]


def test_is_malformed_url_asset():
    for v in _MALFORMED:
        assert is_malformed_url_asset(v), f"should be malformed: {v}"
    for v in _CLEAN:
        assert not is_malformed_url_asset(v), f"should be clean: {v}"
    # non-string / unparseable -> malformed (never raises)
    assert is_malformed_url_asset(None)   # type: ignore[arg-type]
    assert is_malformed_url_asset(12345)  # type: ignore[arg-type]
    print("PASS: is_malformed_url_asset drops path-markup noise, keeps query payloads + %20")


def _url(v):
    return Asset(value=v, type="url", discovered_by="test",
                 discovered_at_stage=6, discovered_in_pass=1)


def test_drop_malformed_url_assets_ingestion():
    found = [
        _url(_MALFORMED[0]),
        _url(_CLEAN[1]),
        _url(_MALFORMED[2]),
        _url(_CLEAN[3]),   # the /?search= endpoint — must survive
        Asset(value=_MALFORMED[4], type="js_file", discovered_by="test",
              discovered_at_stage=7, discovered_in_pass=1),
        # non-url asset types pass through untouched
        Asset(value="example.com", type="subdomain", discovered_by="test",
              discovered_at_stage=1, discovered_in_pass=1),
        Asset(value="1.2.3.4", type="ip", discovered_by="test",
              discovered_at_stage=1, discovered_in_pass=1),
    ]
    kept = main.drop_malformed_url_assets(found, stage_num=6)
    kept_values = [a.value for a in kept]

    # 2 malformed url + 1 malformed js_file dropped -> 4 remain
    assert len(kept) == 4, kept_values
    assert _MALFORMED[0] not in kept_values
    assert _MALFORMED[2] not in kept_values
    assert _MALFORMED[4] not in kept_values
    assert _CLEAN[1] in kept_values
    assert _CLEAN[3] in kept_values           # query-payload endpoint survived
    assert "example.com" in kept_values       # subdomain untouched
    assert "1.2.3.4" in kept_values           # ip untouched
    # order preserved among survivors
    assert kept_values == [_CLEAN[1], _CLEAN[3], "example.com", "1.2.3.4"]
    print("PASS: drop_malformed_url_assets filters url/js_file noise, keeps real assets + non-url types")


if __name__ == "__main__":
    test_is_malformed_url_asset()
    test_drop_malformed_url_assets_ingestion()
    print("\nALL url-hygiene TESTS PASSED")
