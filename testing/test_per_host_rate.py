"""
Tests for the per-host rate-limiting hardening (R3 close-out):

  - resolve_host_workers(): global rate scope -> sequential (workers=1); per_host
    scope -> resolve_max_workers(). This is what keeps W concurrent hosts x the
    per-host rate from exceeding a stated GLOBAL ceiling.
  - katana (stage 6) and nuclei (stage 8) now run ONE HOST PER INVOCATION, so
    `-rl` is a true per-host cap (not a whole-invocation ceiling scaled by host
    count that one busy host could absorb).

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

from state import RunState


def fresh_state() -> RunState:
    return RunState(Path(tempfile.mkdtemp()))


_GLOBAL_SCOPE = {"rate_limit": {"stated_by_program": True, "requests_per_second": 5,
                                "scope": "global", "resolution": "confirmed"}}


def test_resolve_host_workers():
    from stages.parallelism import resolve_host_workers, DEFAULT_MAX_WORKERS
    # per_host (default when no rate_limit / no scope): full parallelism
    assert resolve_host_workers({}) == DEFAULT_MAX_WORKERS
    assert resolve_host_workers({"performance": {"max_workers": 3}}) == 3
    # global scope: forced sequential regardless of the max_workers knob
    assert resolve_host_workers(_GLOBAL_SCOPE) == 1
    g = dict(_GLOBAL_SCOPE, performance={"max_workers": 8})
    assert resolve_host_workers(g) == 1
    print("PASS: resolve_host_workers -> max_workers per_host, forced 1 under global scope")


def _rl_value(cmd):
    return cmd[cmd.index("-rl") + 1]


def test_katana_runs_one_host_per_invocation_true_cap():
    import stage6_crawling as m
    from rate_limits import katana_rate_args
    expected_rl = katana_rate_args({}).extra_args[1]   # base per-host rps, unscaled

    calls = []  # (cmd, seed-file-contents)

    def cap(cmd, *a, **k):
        cmd = list(cmd)
        seed_path = cmd[cmd.index("-list") + 1]
        calls.append((cmd, Path(seed_path).read_text()))
        return ("", "", 0)

    with mock.patch.object(m, "_run_tool", side_effect=cap):
        m.run_katana(["a.example.com", "b.example.com"], fresh_state(), {})

    assert len(calls) == 2, f"expected one katana invocation per host, got {len(calls)}"
    seeds = sorted(seed for _, seed in calls)
    assert seeds == ["https://a.example.com", "https://b.example.com"], seeds
    for cmd, _ in calls:
        # true per-host cap: -rl is the base rps, NOT base x host_count
        assert _rl_value(cmd) == expected_rl, (_rl_value(cmd), expected_rl)
    print("PASS: katana runs one host per invocation with a true per-host -rl (R3 closed)")


def test_nuclei_runs_one_host_per_invocation_true_cap():
    import stage8_takeover as m
    from rate_limits import nuclei_rate_args
    expected_rl = nuclei_rate_args({}).extra_args[1]

    calls = []

    def cap(cmd, *a, **k):
        cmd = list(cmd)
        tgt_path = cmd[cmd.index("-l") + 1]
        calls.append((cmd, Path(tgt_path).read_text()))
        return ("", "", 0)

    with mock.patch.object(m, "_run_tool", side_effect=cap):
        out = m.run_nuclei_takeover(["a.example.com", "b.example.com"], fresh_state(), {})

    assert out == "", "zero findings across hosts should concatenate to empty string"
    assert len(calls) == 2, f"expected one nuclei invocation per host, got {len(calls)}"
    targets = sorted(t for _, t in calls)
    assert targets == ["a.example.com", "b.example.com"], targets
    for cmd, _ in calls:
        assert _rl_value(cmd) == expected_rl, (_rl_value(cmd), expected_rl)
        assert "takeover" in cmd, cmd
    print("PASS: nuclei takeover runs one host per invocation with a true per-host -rl (R3 closed)")


def test_nuclei_per_host_failure_isolated_and_findings_concatenated():
    """A nonzero exit for one host drops only that host; other hosts' JSONL still
    returns, concatenated in stable order."""
    import stage8_takeover as m

    def cap(cmd, *a, **k):
        tgt = Path(cmd[cmd.index("-l") + 1]).read_text()
        if tgt == "bad.example.com":
            return ("", "boom", 1)            # host-level failure
        return ('{"host":"%s","template-id":"x"}' % tgt, "", 0)

    with mock.patch.object(m, "_run_tool", side_effect=cap):
        out = m.run_nuclei_takeover(["good1.example.com", "bad.example.com", "good2.example.com"],
                                    fresh_state(), {})
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) == 2, lines          # bad host dropped, two good hosts kept
    assert '"host":"good1.example.com"' in out and '"host":"good2.example.com"' in out
    assert "bad.example.com" not in out
    print("PASS: nuclei per-host failure is isolated (R7); surviving hosts concatenate in order")


if __name__ == "__main__":
    test_resolve_host_workers()
    test_katana_runs_one_host_per_invocation_true_cap()
    test_nuclei_runs_one_host_per_invocation_true_cap()
    test_nuclei_per_host_failure_isolated_and_findings_concatenated()
    print("\nALL per-host-rate TESTS PASSED")
