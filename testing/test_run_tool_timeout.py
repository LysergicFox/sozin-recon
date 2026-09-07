"""
Mocked-subprocess test for _run_tool()'s partial-output salvage fix
(stage1_passive.py), added 2026-08-22 while investigating an amass hang
that recurred despite a confirmed-fresh config (see CHANGELOG).

Uses a real subprocess (a tiny throwaway Python script that prints then
hangs) rather than mocking subprocess.run itself, since the whole point
is verifying real Python subprocess.TimeoutExpired behavior - mocking it
away would test nothing. No network, no real target, no amass needed.
"""
import subprocess
import sys
import tempfile
from pathlib import Path
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _p in (_HERE, *_HERE.parents):
    if (_p / "state.py").exists():
        _REPO_ROOT = _p; break
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "stages"))
import stage1_passive


def _write_slow_script(tmpdir: Path, stdout_lines, sleep_seconds=5) -> Path:
    script = tmpdir / "slow.py"
    lines_code = "\n".join(f'print({line!r}, flush=True)' for line in stdout_lines)
    script.write_text(
        f"import time, sys\n{lines_code}\ntime.sleep({sleep_seconds})\n"
        f"print('should never be reached')\n"
    )
    return script


def test_timeout_salvages_partial_stdout():
    tmpdir = Path(tempfile.mkdtemp())
    script = _write_slow_script(tmpdir, ["line one", "line two"], sleep_seconds=5)

    stdout, stderr, code = stage1_passive._run_tool(
        [sys.executable, str(script)], timeout=1,
    )

    assert code == -1, f"expected -1 return code on timeout, got {code}"
    assert isinstance(stdout, str), f"stdout must be decoded str, got {type(stdout)}"
    assert "line one" in stdout and "line two" in stdout, stdout
    assert "should never be reached" not in stdout
    print("PASS: partial stdout salvaged and correctly decoded to str on timeout")


def test_timeout_with_zero_partial_output():
    tmpdir = Path(tempfile.mkdtemp())
    script = _write_slow_script(tmpdir, [], sleep_seconds=5)  # no output before hang

    stdout, stderr, code = stage1_passive._run_tool(
        [sys.executable, str(script)], timeout=1,
    )

    assert code == -1
    assert stdout == ""
    assert "timed out after 1s" in stderr
    print("PASS: a timeout with genuinely nothing produced still returns cleanly (no crash)")


def test_normal_completion_unaffected():
    tmpdir = Path(tempfile.mkdtemp())
    script = tmpdir / "fast.py"
    script.write_text("print('done')\n")

    stdout, stderr, code = stage1_passive._run_tool([sys.executable, str(script)], timeout=10)

    assert code == 0
    assert stdout.strip() == "done"
    assert isinstance(stdout, str)
    print("PASS: normal (non-timeout) completion still returns a plain decoded str, unaffected by the fix")


def test_amass_invocation_includes_internal_timeout_flag():
    # regression/contract check: run_amass() must pass its own -timeout
    # flag, and it must be safely under the external subprocess timeout
    # (otherwise the "give amass a head start to shut down cleanly"
    # reasoning doesn't hold)
    import unittest.mock as mock

    captured = {}

    def fake_run_tool(cmd, timeout=None):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return "", "", 0

    with mock.patch.object(stage1_passive, "_run_tool", side_effect=fake_run_tool):
        with mock.patch.object(stage1_passive, "_clear_stale_amass_config"):
            stage1_passive.run_amass("example.com", mock.MagicMock())

    assert "-timeout" in captured["cmd"], captured["cmd"]
    idx = captured["cmd"].index("-timeout")
    internal_minutes = int(captured["cmd"][idx + 1])
    external_seconds = captured["timeout"]
    assert internal_minutes * 60 < external_seconds, (
        f"amass's own -timeout ({internal_minutes}min) must be under the "
        f"external kill ({external_seconds}s) or it can never get a head start"
    )
    print(f"PASS: amass invoked with -timeout {internal_minutes} (min), "
          f"safely under the {external_seconds}s external kill")


if __name__ == "__main__":
    test_timeout_salvages_partial_stdout()
    test_timeout_with_zero_partial_output()
    test_normal_completion_unaffected()
    test_amass_invocation_includes_internal_timeout_flag()
    print("\nAll checks passed.")