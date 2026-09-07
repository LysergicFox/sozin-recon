"""Mocked-tier tests for E5 — bounded parallelism helper. Location-independent."""
import sys
import threading
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _p in (_HERE, *_HERE.parents):
    if (_p / "state.py").exists():
        _REPO_ROOT = _p
        break
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "stages"))

from stages.parallelism import bounded_parallel_map


def test_results_correct_and_order_independent():
    out = bounded_parallel_map(lambda x: x * x, [1, 2, 3, 4, 5], workers=3)
    assert out == {1: 1, 2: 4, 3: 9, 4: 16, 5: 25}
    print("PASS: bounded_parallel_map returns {item: result} for all items")


def test_per_item_exception_isolated_R7():
    def fn(x):
        if x == "bad":
            raise RuntimeError("boom")
        return x.upper()
    out = bounded_parallel_map(fn, ["a", "bad", "c"], workers=2, label="probe")
    assert out == {"a": "A", "c": "C"}, "the failing item is skipped, the rest succeed (R7)"
    print("PASS: a per-item failure is isolated, others still complete")


def test_empty_and_worker_clamp():
    assert bounded_parallel_map(lambda x: x, [], workers=5) == {}
    # workers clamped to item count; still correct with more workers than items
    assert bounded_parallel_map(lambda x: x + 1, [10], workers=99) == {10: 11}
    print("PASS: empty items → {}; workers clamped to item count")


def test_actually_concurrent():
    # 5 items each blocking on a barrier of 5 only completes if they run concurrently
    barrier = threading.Barrier(5, timeout=5)
    out = bounded_parallel_map(lambda x: barrier.wait() is not None or x, [1, 2, 3, 4, 5], workers=5)
    assert set(out) == {1, 2, 3, 4, 5}
    print("PASS: work runs concurrently (5-way barrier releases)")


if __name__ == "__main__":
    test_results_correct_and_order_independent()
    test_per_item_exception_isolated_R7()
    test_empty_and_worker_clamp()
    test_actually_concurrent()
    print("\nAll checks passed.")
