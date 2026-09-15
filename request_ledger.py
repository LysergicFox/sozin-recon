"""
G1: runtime request-count ledger + ratio rate-guard.

The layer that makes an UNATTENDED run safe. `rate_limits.py` computes each tool's
rate flag at config time and trusts the tool to honor it; this module OBSERVES how
fast target-facing tools actually send requests and gracefully halts the run if a
tool grossly exceeds the rate it was authorized for. See
design_docs/RECON_G1_REQUEST_LEDGER_DESIGN.md for the full rationale.

Organizing principle (locked): fail closed on RATE, never fabricate a VOLUME cap.
  - The ratio tripwire is ALWAYS on. It compares each target-facing invocation's
    observed rps to the rate that invocation was AUTHORIZED for (allowed_rps = the
    number the caller fed the tool's own rate flag). A well-behaved tool runs at
    ~allowed_rps (ratio ~1.0); the tripwire fires only on gross overshoot.
  - Volume caps (max_requests_per_host/_total, max_runtime_seconds) are OPT-IN and
    default absent/uncapped — a run staying at a polite rate for hours is a slow
    scan, not abuse. Only populate them when a program actually states such a limit.

What this does NOT catch (by construction): operator mis-transcription of the rate
itself (e.g. a global cap written as per_host). This enforces tool obedience to the
configured rate; the rate's correctness stays a config-time concern (rate_limit_gate
+ human + scope-tos-parser). See the design doc §1.

Thread-safety: record()/guard_allows() are called from bounded_parallel_map worker
threads. All mutable state is guarded by a single lock.

Fail-open-until-armed seam: a RunState always owns a DISARMED ledger (guard allows
all, telemetry accumulates, never trips). main.py arms it via configure() after the
pre-run gates, before any stage. The only unarmed callers are the standalone stage
re-runners and mocked tests — the real run path always arms. See design doc §8.
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# --- Tunable safety constants (one block). See RECON_G1_REQUEST_LEDGER_DESIGN.md §6.
HARD_FACTOR = 3.0            # single-invocation immediate trip multiple (x allowed_rps)
SOFT_FACTOR = 1.5            # per-tool CUMULATIVE-overshoot trip multiple (x allowed_rps)
MIN_REQUESTS_FOR_TRIP = 10   # signal floor: fewer requests -> telemetry only, no trip
MIN_ELAPSED_FOR_TRIP = 2.0   # signal floor (seconds): shorter -> telemetry only, no trip

# Trip reasons double as the run_state.status the orchestrator sets on a controlled halt.
RATE_EXCEEDED = "rate_exceeded"
BUDGET_EXHAUSTED = "budget_exhausted"
RUNTIME_EXCEEDED = "runtime_exceeded"


@dataclass
class Trip:
    """A recorded controlled-halt. reason is one of the *_EXCEEDED/EXHAUSTED constants."""
    reason: str
    host: Optional[str]
    tool: Optional[str]
    observed_rps: Optional[float]
    allowed_rps: Optional[float]
    at_stage: Optional[float]
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "reason": self.reason,
            "host": self.host,
            "tool": self.tool,
            "observed_rps": round(self.observed_rps, 2) if self.observed_rps is not None else None,
            "allowed_rps": self.allowed_rps,
            "at_stage": self.at_stage,
            "detail": self.detail,
        }


class Measurement:
    """Context manager from RequestLedger.measure(). Time the tool call inside the
    `with`, set `.requests` to the tool's REAL reported count (preferred) or an
    input-size estimate before the block exits; on exit the invocation is recorded
    (which may trip the guard). Never suppresses an exception from the block - the
    invocation is still recorded in that case (with whatever `.requests` was set)."""

    def __init__(self, ledger: "RequestLedger", host: Optional[str], tool: str,
                 allowed_rps: Optional[float], at_stage: Optional[float],
                 evaluate_rate: bool = True):
        self._ledger = ledger
        self._host = host
        self._tool = tool
        self._allowed_rps = allowed_rps
        self._at_stage = at_stage
        self._evaluate_rate = evaluate_rate
        self.requests = 0
        self._start = None

    def __enter__(self) -> "Measurement":
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        elapsed = time.monotonic() - (self._start or time.monotonic())
        self._ledger.record(self._host, self._tool, self.requests, elapsed,
                            self._allowed_rps, at_stage=self._at_stage,
                            evaluate_rate=self._evaluate_rate)
        return False  # never suppress


class RequestLedger:
    """Per-run request accounting + ratio rate-guard. One instance per RunState."""

    def __init__(self):
        self._lock = threading.RLock()
        self._armed = False
        self._configured_rps: Optional[float] = None
        self._budget: dict = {}
        self._arm_monotonic: Optional[float] = None
        self.total_requests = 0
        self.per_host: dict[str, int] = {}
        # per-tool cumulative (requests, sending-seconds, allowed_rps) for the soft tier
        self._cum: dict[str, dict] = {}
        self._tripped: Optional[Trip] = None

    # -- lifecycle ------------------------------------------------------------
    def configure(self, configured_rps, budget: Optional[dict] = None) -> None:
        """Arm the guard. configured_rps is the per-host courtesy rate
        (resolve_effective_rps); budget is scope.json's optional request_budget block
        (None/absent = uncapped). Mandatory on the real run path, before any stage."""
        with self._lock:
            self._configured_rps = (
                float(configured_rps)
                if isinstance(configured_rps, (int, float)) and configured_rps > 0
                else None
            )
            self._budget = dict(budget) if isinstance(budget, dict) else {}
            self._arm_monotonic = time.monotonic()
            self._armed = True
        logger.info(
            "request_ledger armed: configured_rps=%s, caps=%s",
            self._configured_rps,
            {k: self._budget.get(k) for k in
             ("max_requests_per_host", "max_requests_total", "max_runtime_seconds")
             if self._budget.get(k) is not None} or "none (rate-guard only)",
        )

    # -- guard / status -------------------------------------------------------
    def guard_allows(self) -> bool:
        """False once tripped. Check at the top of each target-facing per-host worker
        / per-URL loop iteration and skip the unit (send no traffic) when False."""
        with self._lock:
            return self._tripped is None

    def is_tripped(self) -> bool:
        with self._lock:
            return self._tripped is not None

    def is_armed(self) -> bool:
        """True once configure() has run. The real run path MUST arm before any stage
        (main.py); run_pipeline asserts this so a programmatic caller can never run a
        live target with the guard silently disarmed (fail-closed, mirrors the scope +
        rate gates). Only the standalone stage re-runners / mocked tests stay disarmed."""
        with self._lock:
            return self._armed

    @property
    def trip(self) -> Optional[Trip]:
        with self._lock:
            return self._tripped

    def measure(self, host: Optional[str], tool: str, allowed_rps: Optional[float],
                at_stage: Optional[float] = None, evaluate_rate: bool = True) -> Measurement:
        """Time a target-facing tool call. Set the returned object's `.requests` to the
        tool's real reported count (preferred) or an input-derived LOWER-bound estimate
        before the `with` exits. evaluate_rate=False for tools that expose no trustworthy
        count and cannot storm (x8 is serial; nuclei reliably honors -rl): they still
        accumulate telemetry, obey volume caps, and stop after any trip, but do not drive
        the rate tripwire (a bad count estimate must never false-trip a legit run)."""
        return Measurement(self, host, tool, allowed_rps, at_stage, evaluate_rate)

    # -- recording / tripwire -------------------------------------------------
    def record(self, host: Optional[str], tool: str, requests, elapsed,
               allowed_rps, at_stage: Optional[float] = None,
               evaluate_rate: bool = True) -> None:
        """Record one target-facing invocation. Accumulates telemetry always; runs the
        volume caps whenever armed; runs the rate tripwire only when armed AND
        evaluate_rate (a trustworthy count was supplied)."""
        with self._lock:
            try:
                req = int(requests)
            except (TypeError, ValueError):
                req = 0
            if req > 0:
                self.total_requests += req
                if host:
                    self.per_host[host] = self.per_host.get(host, 0) + req

            if not self._armed or self._tripped is not None:
                return

            self._check_caps(host, tool, at_stage)
            if self._tripped is not None:
                return
            if evaluate_rate:
                self._check_rate(host, tool, req, elapsed, allowed_rps, at_stage)

    def _check_caps(self, host, tool, at_stage) -> None:
        b = self._budget
        total_cap = b.get("max_requests_total")
        if isinstance(total_cap, int) and total_cap > 0 and self.total_requests >= total_cap:
            self._set_trip(BUDGET_EXHAUSTED, host, tool, None, None, at_stage,
                           f"total_requests={self.total_requests} >= max_requests_total={total_cap}")
            return
        per_host_cap = b.get("max_requests_per_host")
        if (isinstance(per_host_cap, int) and per_host_cap > 0 and host
                and self.per_host.get(host, 0) >= per_host_cap):
            self._set_trip(BUDGET_EXHAUSTED, host, tool, None, None, at_stage,
                           f"per_host[{host}]={self.per_host.get(host, 0)} >= "
                           f"max_requests_per_host={per_host_cap}")
            return
        rt_cap = b.get("max_runtime_seconds")
        if (isinstance(rt_cap, (int, float)) and rt_cap > 0 and self._arm_monotonic is not None
                and (time.monotonic() - self._arm_monotonic) >= rt_cap):
            self._set_trip(RUNTIME_EXCEEDED, host, tool, None, None, at_stage,
                           f"elapsed >= max_runtime_seconds={rt_cap}")

    def _check_rate(self, host, tool, req, elapsed, allowed_rps, at_stage) -> None:
        # No authorized baseline -> can't judge obedience. (Disarmed runs never reach here.)
        if not (isinstance(allowed_rps, (int, float)) and allowed_rps > 0):
            return
        try:
            elapsed = float(elapsed)
        except (TypeError, ValueError):
            return
        if elapsed <= 0:
            return

        # HARD tier - one egregious invocation halts immediately (below the signal floor
        # it's noise, e.g. "2 requests in 0.1s"; the volume tools are always well above).
        if req >= MIN_REQUESTS_FOR_TRIP and elapsed >= MIN_ELAPSED_FOR_TRIP:
            observed = req / elapsed
            if observed >= allowed_rps * HARD_FACTOR:
                self._set_trip(RATE_EXCEEDED, host, tool, observed, allowed_rps, at_stage,
                               f"observed {observed:.1f} rps >= {HARD_FACTOR:g}x authorized "
                               f"{allowed_rps:g} rps (single {tool} invocation)")
                return

        # SOFT tier - per-tool CUMULATIVE ratio. Sum this tool's requests and sending-time
        # across the whole run; sum(req)/sum(elapsed) approximates the tool's average
        # per-host rate (parallelism cancels: numerator and denominator both scale with
        # host count). This is order-independent (deterministic) and, unlike a per-host
        # consecutive streak, it FIRES for a tool that visits each host once (the loop's
        # L3 frontier) yet over-rates every one of them. Requires cumulative signal past
        # the floor so a single tiny invocation can't trip it.
        c = self._cum.setdefault(tool, {"req": 0, "sec": 0.0, "allowed": allowed_rps})
        c["req"] += req
        c["sec"] += elapsed
        c["allowed"] = allowed_rps
        if c["req"] >= MIN_REQUESTS_FOR_TRIP and c["sec"] >= MIN_ELAPSED_FOR_TRIP:
            observed_cum = c["req"] / c["sec"]
            if observed_cum >= allowed_rps * SOFT_FACTOR:
                self._set_trip(RATE_EXCEEDED, host, tool, observed_cum, allowed_rps, at_stage,
                               f"cumulative {observed_cum:.1f} rps >= {SOFT_FACTOR:g}x authorized "
                               f"{allowed_rps:g} rps across {tool}'s run "
                               f"({c['req']} req / {c['sec']:.0f}s)")

    def _set_trip(self, reason, host, tool, observed, allowed, at_stage, detail) -> None:
        self._tripped = Trip(reason=reason, host=host, tool=tool, observed_rps=observed,
                             allowed_rps=allowed, at_stage=at_stage, detail=detail)
        logger.warning(
            "request_ledger TRIP (%s): host=%s tool=%s %s - halting all further "
            "target-facing traffic; offline finalizers still run.",
            reason, host, tool, detail,
        )

    # -- serialization --------------------------------------------------------
    def snapshot(self) -> dict:
        """The run_state.json `request_ledger` block. elapsed_seconds is run wall-clock
        (from arm time), not a sum of invocation times (concurrency-safe telemetry)."""
        with self._lock:
            elapsed = (time.monotonic() - self._arm_monotonic) if self._arm_monotonic else 0.0
            return {
                "configured_rps": self._configured_rps,
                "total_requests": self.total_requests,
                "elapsed_seconds": round(elapsed, 1),
                "per_host": dict(self.per_host),
                "tripped": self._tripped.to_dict() if self._tripped else None,
            }
