"""
E5: bounded parallelism — run an independent per-host function across hosts with a
bounded thread pool, cutting wall-clock without violating the per-host courtesy rate.

The rate model is R3-correct BY CONSTRUCTION: each item is a DISTINCT host, and each
host keeps its own per-host rate (the tool's own -rl / delay); running W hosts
concurrently makes the aggregate W * per_host, which is exactly the intended "each
host gets its own budget" model — NOT one shared budget split across hosts. Only use
this for genuinely independent per-host work (whatweb, wafw00f, ffuf-per-host); never
to fan out many requests at ONE host (that would break the per-host cap).

R7 preserved: a per-item exception is logged and skipped, not fatal.
"""

import concurrent.futures
import logging

logger = logging.getLogger(__name__)

DEFAULT_MAX_WORKERS = 5


def resolve_max_workers(scope: dict) -> int:
    """Per-run parallelism dial from scope.json's optional `performance` block:

        "performance": { "max_workers": 5 }

    Controls how many DISTINCT hosts run concurrently across the per-host stages.
    Per-host rate is unchanged; the aggregate to the org's shared infra is
    workers x per_host_rate, spread across that many distinct hostnames — an
    explicit, per-engagement RoE dial (see RECON_PERF_COVERAGE_FINDINGS). Absent/
    invalid -> DEFAULT_MAX_WORKERS. Clamped to >=1 (0/negative would stall)."""
    perf = (scope or {}).get("performance") or {}
    n = perf.get("max_workers", DEFAULT_MAX_WORKERS)
    if not isinstance(n, int) or n < 1:
        logger.warning("performance.max_workers=%r invalid - using default %d",
                       n, DEFAULT_MAX_WORKERS)
        return DEFAULT_MAX_WORKERS
    return n


def resolve_host_workers(scope: dict) -> int:
    """Worker count for parallelizing a per-host-rate TARGET-FACING tool across
    distinct hosts, made safe for a GLOBAL rate scope.

    - per_host scope (default): distinct hosts run concurrently, each keeping its
      own per-host budget — the intended "each host gets its own rate" model.
      Returns resolve_max_workers(scope).
    - global scope: a single ceiling governs ALL hosts combined. Running W hosts
      concurrently, each at the per-host rate, would reach W x the ceiling — a
      violation (the per-host tools' own rate args assume only one host is in
      flight at a time). Force workers=1 so at most one host is hit at any instant
      and the instantaneous aggregate stays at or below the stated global rate.

    Use this (not resolve_max_workers) for every target-facing per-host stage
    (x8, ffuf, whatweb, katana, nuclei). Third-party/passive fan-out (stage 1's
    archive/cert APIs) has no target rate to protect and keeps resolve_max_workers."""
    # Imported here (not at module top) purely for tidiness; rate_limits does not
    # import parallelism, so a top-level import would also be cycle-free.
    from rate_limits import resolve_rate_scope
    if resolve_rate_scope(scope) == "global":
        return 1
    return resolve_max_workers(scope)


def bounded_parallel_map(fn, items, workers: int = DEFAULT_MAX_WORKERS, label: str = "task") -> dict:
    """Run fn(item) across items with a bounded thread pool. Returns {item: result}
    for successes; a per-item failure is logged and skipped (R7). Order-independent."""
    results: dict = {}
    if not items:
        return results
    workers = max(1, min(workers, len(items)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(fn, item): item for item in items}
        for fut in concurrent.futures.as_completed(futures):
            item = futures[fut]
            try:
                results[item] = fut.result()
            except Exception:
                logger.exception("%s failed for %r - skipping (R7)", label, item)
    return results
