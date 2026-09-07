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
