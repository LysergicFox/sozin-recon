"""
Mocked-tier tests for C2 — screenshots (httpx headless Chrome). No real browser.
httpx screenshot JSON keys verified against a real run 2026-08-23. Location-independent.
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

import stage_screenshots as c2
from state import RunState


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


def test_run_screenshots_builds_metadata():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    line = json.dumps({"input": "https://h.example.com", "host": "h.example.com",
                       "screenshot_path_rel": "h.example.com/abc.png"})
    # the stage now verifies the PNG is non-empty before recording it (guard against
    # httpx reporting a path for a 0-byte render), so put a real non-zero file there.
    rel = "screenshots/screenshot/h.example.com/abc.png"
    png = st.run_dir / rel
    png.parent.mkdir(parents=True, exist_ok=True)
    png.write_bytes(b"\x89PNG\r\n\x1a\n fake but non-empty")
    with mock.patch.object(c2, "_run_tool", return_value=(line, "", 0)):
        updates = c2.run_screenshots(["h.example.com"], st, scope,
                                     host_base={"h.example.com": "https://h.example.com"})
    # host key normalized from the seeded URL back to the bare host
    assert "h.example.com" in updates
    assert updates["h.example.com"]["screenshot_path"].endswith("h.example.com/abc.png")
    print("PASS: run_screenshots maps httpx screenshot output → host screenshot_path metadata")


def test_run_screenshots_skips_zero_byte():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    line = json.dumps({"input": "https://h.example.com", "host": "h.example.com",
                       "screenshot_path_rel": "h.example.com/abc.png"})
    # a 0-byte PNG (httpx reported a path but the render failed) must NOT be recorded
    png = st.run_dir / "screenshots/screenshot/h.example.com/abc.png"
    png.parent.mkdir(parents=True, exist_ok=True)
    png.write_bytes(b"")   # empty
    with mock.patch.object(c2, "_run_tool", return_value=(line, "", 0)):
        updates = c2.run_screenshots(["h.example.com"], st, scope,
                                     host_base={"h.example.com": "https://h.example.com"})
    assert updates == {}, updates
    print("PASS: run_screenshots skips a 0-byte screenshot (no phantom record)")


def test_run_screenshots_empty_and_isolation():
    st = fresh_state()
    scope = {"rate_limit": {"resolution": "not_applicable"}}
    assert c2.run_screenshots([], st, scope) == {}
    # a subprocess blow-up yields no shots, not a crash (R7)
    with mock.patch.object(c2, "_run_tool", side_effect=RuntimeError("boom")):
        assert c2.run_screenshots(["h"], st, scope) == {}
    print("PASS: empty hosts → {}; a screenshot failure is isolated (R7)")


if __name__ == "__main__":
    test_run_screenshots_builds_metadata()
    test_run_screenshots_skips_zero_byte()
    test_run_screenshots_empty_and_isolation()
    print("\nAll checks passed.")
