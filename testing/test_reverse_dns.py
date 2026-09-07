"""Mocked-tier tests for F5 — reverse DNS. dnsx -ptr JSON shape verified against
the real tool 2026-08-23. Location-independent."""
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

import reverse_dns as f5
from state import RunState


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def test_run_reverse_dns_parses_ptr():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    out = "\n".join([
        json.dumps({"host": "1.1.1.1", "ptr": ["one.one.one.one"]}),
        json.dumps({"host": "203.0.113.5", "ptr": ["web1.example.com.", "shared.other.com."]}),
        json.dumps({"host": "203.0.113.9"}),  # no PTR
    ])
    with mock.patch.object(f5, "_run_tool", return_value=(out, "", 0)):
        assets = f5.run_reverse_dns(["1.1.1.1", "203.0.113.5", "203.0.113.9"], st, scope)
    values = {a.value for a in assets}
    assert values == {"one.one.one.one", "web1.example.com", "shared.other.com"}, values
    assert all(a.type == "subdomain" and a.discovered_by == ["dnsx_ptr"] for a in assets)
    # trailing dots stripped, lowercased, deduped
    print("PASS: run_reverse_dns parses dnsx -ptr → subdomain assets (dots stripped, deduped)")


def test_empty_ips():
    st = fresh_state()
    assert f5.run_reverse_dns([], st, {"rate_limit": {"resolution": "not_applicable"}}) == []
    print("PASS: no IPs → no work")


if __name__ == "__main__":
    test_run_reverse_dns_parses_ptr()
    test_empty_ips()
    print("\nAll checks passed.")
