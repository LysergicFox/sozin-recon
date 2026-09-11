"""
Per-tool rate-limit translation layer.

Resolves ONE effective requests-per-second ceiling (program-stated via
rate_limit_gate.py, or CONSERVATIVE_DEFAULT_RPS if none was confirmed) and
translates it into each tool's own REAL, verified CLI flags. "Verified" is
not a formality here - every flag name/semantics below was confirmed
against real `--help` output during the rate-limiting design pass (Aug
2026), same discipline as every other stage's tool-interface facts. Two
tools (paramspider, jsluice) have NO invocation changes because their real
`--help` output showed no target-facing rate lever is needed/applicable -
see their sections below for why, not just an oversight.

The ceiling is PER HOST by default, not global-across-the-pipeline. This
matches how real program rate-limit language is usually phrased (e.g. "5
requests per second per host" - see rate_limit_gate.py's
CONSERVATIVE_DEFAULT_RPS docstring for the research behind the default). A
flat global cap would either be needlessly slow once many in-scope hosts
are being worked in the same pass (dividing one shared budget across N
hosts), or silently violate the per-host intent if applied as a flat
pipeline-wide number. This has a real consequence for tools that take a
MULTI-HOST target list in a single invocation (httpx, naabu, dnsx, katana,
nuclei) - see _multi_host_rate() below for how the per-host ceiling is
scaled up for those invocations specifically, so a 20-host httpx run
doesn't accidentally throttle down to 5/20 = 0.25 req/s per individual
host.

(R4) A program can state a GLOBAL limit instead ("no more than 10 req/s
total against our infrastructure"). scope.json's rate_limit.scope
("per_host" default | "global") records which; resolve_rate_scope() reads
it and _effective_total() applies _multi_host_rate() ONLY for per_host. A
global cap is passed through UNSCALED, so a stated global limit is never
multiplied by host count. Given R3 (below), passing a global cap unscaled
is also the *safe* reading whenever a tool can burst many requests on one
host.

(R3) IMPORTANT, whole-invocation `-rl` is NOT a per-host guarantee for any
tool that issues MULTIPLE requests per target. The native -rl/-rate flag
caps the WHOLE invocation. For httpx liveness (stage 4, ~1 GET/host) and
dnsx/naabu's ~1-request-per-target scans, the per_host x host_count scaling
below distributes correctly. But for **nuclei** (stage 8, 60+ templates/host,
so one host can absorb the entire aggregate budget) and the **stage-7 bundler
probe** (15 paths/host in one httpx invocation), the same wrong-shape gap
that was originally flagged only for katana applies too - the whole-invocation
ceiling is not a real per-host cap. This is flagged as an accepted limitation
across all multi-request -rl tools, not re-fixed here; the candidate fix
(per-host invocations, mirroring whatweb's fix) rides with the future
request-count-instrumentation / ratio-safety-net work. The code comments' old
"~1 request per target" exemption is corrected in each affected function's
docstring below.

Tool shape 1 - native rate flag (-rl/-rate/-l style): the ceiling is passed
straight through (scaled for per_host multi-host invocations where
applicable; passed unscaled for a global cap).
Tool shape 2 - no native rate flag, only concurrency/delay knobs (x8,
whatweb): the ceiling is converted into a delay/wait value, accounting for
the tool's own concurrency default so the derived delay actually produces
the intended req/s rather than silently over- or under-shooting it. These
run one host at a time in a Python loop, so the per-host number is applied
directly (see x8/whatweb sections for why a global cap needs no special
handling there).
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Re-exported here so callers only need to import rate_limits, not both
# modules, for the common case of "give me the default".
from rate_limit_gate import CONSERVATIVE_DEFAULT_RPS, RateLimitInfo  # noqa: F401

# DNS query-rate cap for puredns's public-resolver leg (1.1.1.1/8.8.8.8/
# 9.9.9.9) - deliberately SEPARATE from CONSERVATIVE_DEFAULT_RPS. The two
# constants protect different things: CONSERVATIVE_DEFAULT_RPS is a
# courtesy rate toward the bug bounty TARGET's own infrastructure (derived
# from real program HTTP rate-limit policies - see rate_limit_gate.py).
# DNS_RESOLVER_RATE_LIMIT protects nothing in particular - it's just a
# sane query rate against public DNS infrastructure (Cloudflare/Google/
# Quad9) that has no relationship to the target's tolerance at all. Reusing
# CONSERVATIVE_DEFAULT_RPS here was a real bug caught on a real run against
# zonetransfer.me (Aug 20): it produced a ~32-minute wait for a single
# stage 3 sub-step (9640 candidates / 5 qps) with no actual protective
# benefit to anyone. See puredns_rate_args()'s docstring for the full
# reasoning behind 200 specifically (anchored below puredns's own
# --rate-limit-trusted default of 500 qps, confirmed via real --help).
DNS_RESOLVER_RATE_LIMIT = 200

# naabu's -rate is PACKETS per second (its own --help default is 1000), a
# fundamentally different quantity from CONSERVATIVE_DEFAULT_RPS's HTTP
# request-courtesy rate. A SYN/CONNECT port scan is target-facing, but program
# rate-limit language ("5 requests per second") governs HTTP request rate, not
# packet rate - pinning naabu's packet rate to the 5-req/s HTTP courtesy number
# is the SAME wrong-anchor bug class as reusing it for puredns/dnsx (see
# DNS_RESOLVER_RATE_LIMIT above). Confirmed on a real run against zonetransfer.me
# (2026-08-24): -rate 5 made a single-host top-1000 scan take ~600s (1000 ports x
# 3 default retries / 5 pps), hitting the stage timeout; the same scan at 150 pps
# is ~6s, finding identical ports. NAABU_PACKET_RATE is naabu's own per-host
# packet-scan anchor - well under naabu's native 1000 default (respectful), an
# order of magnitude faster than the HTTP courtesy rate. A program-stated CONFIRMED
# GLOBAL cap still clamps it down (R4, see naabu_rate_args); a per_host HTTP req/s
# limit does not, because packets/sec != requests/sec.
NAABU_PACKET_RATE = 150


def resolve_effective_rps(scope: dict) -> int:
    """
    Pull the effective per-host requests/second ceiling out of a loaded
    scope dict: the confirmed program-stated value if
    rate_limit.resolution == "confirmed", else CONSERVATIVE_DEFAULT_RPS.

    Does NOT itself check for a "pending" (blocking) resolution - that's
    rate_limit_gate.check_run_not_blocked()'s job, called separately before
    a run starts (see that function's docstring). By the time any stage
    module calls resolve_effective_rps(), the run is assumed to have
    already passed that gate - this function's only concern is picking the
    right number, not re-deriving the block/allow decision.
    """
    rate_limit = scope.get("rate_limit")
    if rate_limit and rate_limit.get("resolution") == "confirmed":
        rps = rate_limit.get("requests_per_second")
        if isinstance(rps, int) and rps > 0:
            return rps
        logger.warning(
            "rate_limits: scope.json rate_limit.resolution is 'confirmed' "
            "but requests_per_second is missing/invalid (%r) - falling back "
            "to conservative default. This shouldn't happen if "
            "rate_limit_gate.py wrote this block; check for a hand-edited "
            "scope.json.",
            rps,
        )
    return CONSERVATIVE_DEFAULT_RPS


def resolve_rate_scope(scope: dict) -> str:
    """
    (R4) Return the rate_limit.scope for a loaded scope dict: "per_host"
    (default) or "global". Only a CONFIRMED program-stated block can carry
    a meaningful global scope - when the run is on the conservative default
    (resolution="not_applicable" or absent-then-gated), the default is a
    per-host courtesy number by construction, so this returns "per_host"
    regardless of any stray scope field on a non-confirmed block.

    An unrecognized scope value falls back to "per_host" (the safe,
    pre-R4 behavior) with a warning rather than raising - a hand-edited
    scope.json shouldn't crash a run mid-flight, and per_host is the
    more-conservative reading for the native-rl tools this feeds.
    """
    rate_limit = scope.get("rate_limit")
    if rate_limit and rate_limit.get("resolution") == "confirmed":
        s = rate_limit.get("scope", "per_host")
        if s in ("per_host", "global"):
            return s
        logger.warning(
            "rate_limits: unrecognized rate_limit.scope %r - defaulting to "
            "per_host (the conservative reading).", s,
        )
    return "per_host"


def _multi_host_rate(per_host_rps: int, host_count: int) -> int:
    """
    Scale a per-host ceiling up for tools that take a combined multi-host
    target list in ONE invocation (httpx -l, naabu -list, dnsx -l, katana
    -list, nuclei -l) - their own -rl/-rate flag applies to the WHOLE
    invocation, not per individual host, so a bare per_host_rps would
    silently divide the intended per-host budget across every host in the
    list instead of giving each host its own share.

    host_count is clamped to at least 1 (an empty target list has no rate
    to compute, callers should skip invocation entirely in that case, same
    as every stage already does for empty inputs).

    Applied ONLY for a per_host rate scope (R4) - see _effective_total().
    """
    return per_host_rps * max(host_count, 1)


def _effective_total(scope: dict, host_count: int) -> tuple[int, int, str]:
    """
    (R4) Resolve the effective whole-invocation ceiling for a native-rl
    multi-host tool. Returns (base_rps, total_rps, rate_scope):
      - per_host: total = base_rps x host_count (existing scaling)
      - global:  total = base_rps  (passed through UNSCALED - a stated
                 global cap must never be multiplied by host count)
    base_rps is resolve_effective_rps()'s number (program-confirmed or the
    conservative default); rate_scope is resolve_rate_scope()'s reading.
    """
    base_rps = resolve_effective_rps(scope)
    rate_scope = resolve_rate_scope(scope)
    if rate_scope == "global":
        return base_rps, base_rps, rate_scope
    return base_rps, _multi_host_rate(base_rps, host_count), rate_scope


def _native_rl_note(tool: str, total: int, base_rps: int, host_count: int, rate_scope: str,
                    extra: str = "") -> str:
    """Shared log note for the native -rl multi-host tools (R4-aware)."""
    if rate_scope == "global":
        note = f"{tool} -rl {total} (GLOBAL cap, not scaled by host count - R4)"
    else:
        note = f"{tool} -rl {total} ({base_rps}/s/host x {host_count} host(s))"
    return f"{note}{extra}"


@dataclass
class ToolInvocationExtras:
    """
    Extra CLI args + any computed values a stage module needs to fold into
    its existing subprocess command list. Deliberately just the pieces
    (not a full command list) since every stage module already owns its
    own full invocation construction - this only adds the rate-relevant
    slice, stage modules splice it in alongside their existing flags.
    """
    extra_args: list[str]
    note: str  # short human-readable explanation of what was computed and why, for logging


# ---------------------------------------------------------------------------
# Shape 1: native rate-flag tools
# ---------------------------------------------------------------------------

def httpx_rate_args(scope: dict, host_count: int) -> ToolInvocationExtras:
    """httpx: confirmed real flag `-rl <n>` (requests/sec, whole invocation)."""
    base_rps, total, rate_scope = _effective_total(scope, host_count)
    return ToolInvocationExtras(
        extra_args=["-rl", str(total)],
        note=_native_rl_note("httpx", total, base_rps, host_count, rate_scope),
    )


def naabu_rate_args(scope: dict, host_count: int) -> ToolInvocationExtras:
    """
    naabu: confirmed real flag `-rate <n>` (PACKETS/sec; naabu --help default
    1000). Unlike the native-`-rl` HTTP tools, naabu is NOT anchored to
    CONSERVATIVE_DEFAULT_RPS (the HTTP request-courtesy rate) - it uses its own
    NAABU_PACKET_RATE packet-scan anchor, per-host, scaled by host count for the
    combined target list (each host gets its own packet-rate share, same
    _multi_host_rate() reasoning as the -rl tools). See NAABU_PACKET_RATE's
    comment for why packets/sec != requests/sec and the real-run (2026-08-24)
    600s-scan bug that forced the decoupling.

    (R4) A program-stated CONFIRMED GLOBAL cap is an explicit human ceiling over
    ALL traffic to the target, so naabu's total is clamped DOWN to it (never up).
    A per_host HTTP req/s limit does NOT clamp the packet rate - that's the whole
    point of the dedicated anchor.
    """
    hc = max(host_count, 1)
    total = _multi_host_rate(NAABU_PACKET_RATE, hc)
    note = (f"naabu -rate {total} ({NAABU_PACKET_RATE} pkt/s/host x {hc} host(s), "
            f"dedicated packet-scan anchor - NOT the HTTP courtesy rate)")

    # resolve_rate_scope() returns "global" only for a CONFIRMED global block.
    if resolve_rate_scope(scope) == "global":
        global_cap = resolve_effective_rps(scope)  # the confirmed global number
        if global_cap < total:
            total = global_cap
            note = (f"naabu -rate {total} (clamped DOWN to program-stated GLOBAL "
                    f"cap {global_cap} - R4; below the {NAABU_PACKET_RATE} "
                    f"pkt/s/host scan anchor)")

    return ToolInvocationExtras(extra_args=["-rate", str(total)], note=note)


def dnsx_rate_args(scope: dict) -> ToolInvocationExtras:
    """
    dnsx: confirmed real flag `-rl <n>` (requests/sec, whole invocation).

    SAME BUG CLASS AS puredns_rate_args() - caught by re-auditing every
    tool against "does this rate actually protect the bounty target?"
    after the real puredns incident (Aug 20, see that function's
    docstring for the full story). Stage 3's run_dnsx_validate() invokes
    dnsx with NO -r/--resolvers flag, meaning it uses dnsx's own built-in
    default resolvers - public DNS infrastructure, not anything belonging
    to the bounty target. dnsx here is a DNS-resolver-facing tool exactly
    like puredns, not an HTTP-target-facing one, so it should NOT be
    throttled to CONSERVATIVE_DEFAULT_RPS (the HTTP target-courtesy rate)
    any more than puredns should. It is likewise UNAFFECTED by R4's
    per-host/global scope, since it isn't hitting the target at all.

    Uses DNS_RESOLVER_RATE_LIMIT directly, same as puredns - NOT scaled
    by host_count and NOT read from rate_limit.scope. dnsx's -rl is
    described as a whole-invocation requests/sec cap same as httpx's, but
    unlike httpx (which sends N distinct HTTP requests to N distinct target
    hosts that each individually deserve their own rate budget), dnsx here
    is N DNS queries against the SAME small set of public resolvers - the
    resolvers, not the target hosts, are what could be overwhelmed by an
    unbounded rate, and querying public DNS infrastructure isn't
    meaningfully different in kind whether it's for 5 hostnames or 500.
    """
    return ToolInvocationExtras(
        extra_args=["-rl", str(DNS_RESOLVER_RATE_LIMIT)],
        note=(
            f"dnsx -rl {DNS_RESOLVER_RATE_LIMIT} (DNS query-stream cap against "
            f"default public resolvers, NOT the HTTP target-courtesy rate - "
            f"see dnsx_rate_args() docstring)"
        ),
    )


def katana_rate_args(scope: dict) -> ToolInvocationExtras:
    """
    katana: confirmed real flag `-rl <n>` (requests/sec, whole invocation).
    Stage 6's module docstring notes -d/-mdp (depth/page caps) are
    deliberately left at katana's own defaults, trusting loop-until-stable
    for completeness - -rl is a different, complementary concern (how FAST
    it crawls, not how FAR) and is set here regardless of that separate
    depth decision.

    (R3 CLOSED) Stage 6 now runs katana ONE HOST PER INVOCATION, parallelized
    across distinct hosts by resolve_host_workers() (which forces sequential
    execution under a global rate scope). Because only one host is crawled per
    process, `-rl <per_host>` is a TRUE per-host cap - the old whole-invocation
    ceiling (where a single link-heavy host could absorb the entire multi-host
    budget) is gone. This mirrors ffuf's per-host model; like ffuf, it takes
    only `scope` and uses resolve_effective_rps() directly (no host_count
    scaling, no _effective_total). A global scope needs no special handling
    here for the same reason ffuf/whatweb don't: cross-host concurrency is what
    resolve_host_workers() collapses to 1 for global.
    """
    per_host = resolve_effective_rps(scope)
    return ToolInvocationExtras(
        extra_args=["-rl", str(per_host)],
        note=(f"katana -rl {per_host} (per-host cap; one host per invocation, so a "
              f"TRUE per-host guarantee - closes the R3 whole-invocation gap for katana)"),
    )


def nuclei_rate_args(scope: dict) -> ToolInvocationExtras:
    """
    nuclei: confirmed real flag `-rl <n>` (requests/sec, whole invocation) -
    same flag family as httpx/naabu (see stage8_takeover.py).

    (R3 CLOSED) Stage 8 now runs nuclei ONE HOST PER INVOCATION, parallelized
    across distinct hosts by resolve_host_workers() (sequential under a global
    rate scope). The full `-tags takeover` set (60+ templates) all fires at a
    single host per process, so `-rl <per_host>` is a TRUE per-host cap - the
    old whole-invocation ceiling (one host could absorb the entire aggregate)
    is gone. Mirrors ffuf/katana: takes only `scope`, uses resolve_effective_rps()
    directly. Global scope handled by resolve_host_workers() collapsing cross-host
    concurrency to 1, so no scaling is needed here.
    """
    per_host = resolve_effective_rps(scope)
    return ToolInvocationExtras(
        extra_args=["-rl", str(per_host)],
        note=(f"nuclei -rl {per_host} (per-host cap; one host per invocation, so a "
              f"TRUE per-host guarantee - closes the R3 whole-invocation gap for nuclei)"),
    )


def puredns_rate_args(scope: dict) -> ToolInvocationExtras:
    """
    puredns: confirmed real flag `-l/--rate-limit <n>` for the PUBLIC
    resolver leg (0 = unlimited, which is the tool's own current default -
    today's stage 3 invocations pass neither -l nor --rate-limit-trusted,
    leaving the public leg fully unthrottled against the 3 hardcoded
    resolvers). --rate-limit-trusted already defaults to 500 (a puredns
    tool default, not something this project set) and is left alone here -
    not part of this pass's scope, and 500/s trusted-resolver validation
    traffic isn't the target-facing concern this pass is about.

    DELIBERATELY DOES NOT use resolve_effective_rps() / the program-stated
    or CONSERVATIVE_DEFAULT_RPS ceiling, and is UNAFFECTED by R4's
    per-host/global scope - caught during a real run against zonetransfer.me
    (Aug 20): the first version of this function reused the HTTP-target rate
    (5 req/s default) as puredns's DNS query-rate cap, which produced a real
    ~32-minute wait for a single stage 3 sub-step (9640 alterx-generated
    candidates / 5 qps). That number is the wrong anchor entirely -
    CONSERVATIVE_DEFAULT_RPS exists to be respectful of the bug bounty
    TARGET's own infrastructure (see rate_limit_gate.py's docstring, derived
    from real program HTTP rate-limit policies), but puredns's public-
    resolver leg queries 1.1.1.1/8.8.8.8/9.9.9.9 - public DNS infrastructure
    built to absorb enormous query volume, not the target at all.
    Throttling DNS resolution to a target-courtesy HTTP rate provides no
    real protective benefit to anyone and just makes the pipeline slow for
    no reason.

    DNS_RESOLVER_RATE_LIMIT below is a separate, deliberately more
    permissive constant for exactly this reason - anchored off puredns's
    OWN --rate-limit-trusted default of 500 qps (confirmed via real
    --help: the tool's own authors consider 500 qps a sane default rate
    for DNS validation traffic against trusted resolvers). The public leg
    here is kept somewhat below that trusted-leg default rather than
    matching it exactly, since the public resolvers are a much smaller
    fixed set (3 resolvers vs. whatever a "trusted" set might contain)
    and this project has no real signal on what those 3 specific public
    resolvers individually tolerate before throttling US - 200 qps is a
    reasonable middle ground: nowhere near the HTTP target-courtesy
    number that caused the bug, but a bit under puredns's own
    higher-volume trusted-leg default out of basic caution toward
    Cloudflare/Google/Quad9 rather than assuming they're infinitely
    tolerant just because they're well-resourced.

    NOT scaled by a host/candidate count the way the multi-host HTTP tools
    are - puredns's own --rate-limit is described in its --help as "limit
    total queries per second for public resolvers", i.e. it already
    naturally applies to the whole candidate list as one query stream
    against a small fixed resolver set, not "per target host" the way an
    HTTP tool's -rl is.
    """
    return ToolInvocationExtras(
        extra_args=["-l", str(DNS_RESOLVER_RATE_LIMIT)],
        note=(
            f"puredns -l {DNS_RESOLVER_RATE_LIMIT} (DNS query-stream cap against "
            f"public resolvers, NOT the HTTP target-courtesy rate - see "
            f"puredns_rate_args() docstring for why these are different concerns)"
        ),
    )




# ---------------------------------------------------------------------------
# Shape 2: no native rate flag - concurrency/delay tools
#
# Both run ONE host (whatweb) / ONE url (x8) per invocation in a Python
# loop, sequentially. So the per-host number applies directly, and a GLOBAL
# rate scope (R4) needs no special handling here: since only one host is
# being scanned at any instant, throttling that single host to the stated
# number already keeps the whole-pipeline instantaneous rate at or below it
# (there is no cross-host concurrency to divide a global budget across).
# ---------------------------------------------------------------------------

def x8_rate_args(scope: dict) -> ToolInvocationExtras:
    """
    x8: confirmed via real --help - NO native requests/sec flag exists at
    all. Real levers: `-c <concurrency>` (concurrent requests PER URL,
    default 1 already - stage 5 calls run_x8() once per URL in a Python
    loop, never passing x8 multiple URLs itself, so `-W`/workers is not
    applicable here) and `-d <delay-ms>` (delay between requests,
    default 0).

    Since -c already defaults to 1 (effectively serial per-URL requests
    already), the real lever for hitting a target rate is -d: with
    concurrency=1, one request completes roughly every (request time +
    delay), so delay_ms = 1000 / per_host_rps gives approximately the
    target rate for the dominant case where request latency is small
    relative to the delay itself. This is an approximation (real request
    latency adds on top, so actual achieved rate is always <= the target,
    never over it) - fine here since erring slower than the target ceiling
    is the safe direction, never the unsafe one.

    -c is left at 1 explicit (not omitted) so the computed delay's
    assumption (one in-flight request at a time) actually holds - if a
    future change raises -c, this function's delay math would need
    revisiting too, so pinning -c here makes that dependency visible
    rather than letting a caller silently bump concurrency elsewhere and
    invalidate the delay calculation.
    """
    per_host = resolve_effective_rps(scope)
    delay_ms = max(1, round(1000 / per_host))
    return ToolInvocationExtras(
        extra_args=["-c", "1", "-d", str(delay_ms)],
        note=f"x8 -c 1 -d {delay_ms}ms (derived from {per_host}/s target, no native rate flag exists)",
    )


def ffuf_rate_args(scope: dict) -> ToolInvocationExtras:
    """
    ffuf (B1 / stage 6.5 content discovery): confirmed real flag `-rate <n>`
    (requests/sec for the WHOLE ffuf process - verified 2026-08-23 on ffuf
    2.1.0-dev: 100 words at `-rate 20` took 5.0s, exactly 100/20).

    Unlike the native-rl MULTI-host tools above (httpx/naabu/katana/nuclei),
    stage 6.5 runs ffuf ONE HOST PER INVOCATION in a Python loop, so this
    belongs with the Shape-2 (x8/whatweb) sequential-per-host reasoning even
    though ffuf HAS a native rate flag: because only one host is fuzzed at any
    instant, `-rate` is a TRUE per-host cap, and this deliberately CLOSES the
    R3 whole-invocation-ceiling gap for the single most traffic-heavy tool in
    the pipeline (thousands of requests/host) - exactly where a real per-host
    guarantee matters most, at the cost of ffuf's cross-host parallelism.

    Uses resolve_effective_rps() directly (program-confirmed or the
    conservative default), NOT scaled by host_count and NOT via _effective_total:
    only one host is fuzzed at a time, so the per-host number applies as-is, and
    a GLOBAL rate scope (R4) needs no special handling here for the same reason
    x8/whatweb don't - sequential single-host invocations keep the instantaneous
    pipeline rate at or below the stated number.
    """
    per_host = resolve_effective_rps(scope)
    return ToolInvocationExtras(
        extra_args=["-rate", str(per_host)],
        note=(
            f"ffuf -rate {per_host} (per-host cap; one host per invocation, so a "
            f"TRUE per-host guarantee - closes the R3 whole-invocation gap for ffuf)"
        ),
    )


def whatweb_rate_args(scope: dict) -> ToolInvocationExtras:
    """
    whatweb: confirmed via real --help - NO native requests/sec flag.
    Real levers: `-t/--max-threads` (default 25) and `--wait=SECONDS`
    (delay, --help explicitly notes it's "useful when using a single
    thread"). Stage 9 already runs whatweb ONCE PER HOST (see
    stage9_whatweb.py's "REAL BUG FOUND AND FIXED" section - per-host
    invocation was a correctness fix for attribution, done before this
    rate-limiting pass existed), so -t here governs concurrency WITHIN one
    host's own plugin-driven requests (relevant given -a 3's "if a level 1
    plugin is matched, additional requests will be made" behavior, i.e. a
    single host scan can itself fire a real burst of requests, not just
    one).

    Pin -t to 1 (single-threaded within a host) and derive --wait the same
    way as x8's delay: 1000ms / per_host_rps, converted to whole seconds
    (whatweb's --wait takes SECONDS, not ms, per --help) with a minimum of
    1 second - a sub-1-second --wait would round to 0 and silently defeat
    the throttle entirely, so this floors at 1s even if that's more
    conservative than the raw per_host_rps math would imply. At the
    locked default (5 req/s -> 0.2s raw), this floor means whatweb runs
    slower than the raw target rate for hosts with many level-3-triggered
    plugin requests - an intentional, disclosed trade-off given --wait's
    whole-second granularity, not a silent surprise.
    """
    per_host = resolve_effective_rps(scope)
    raw_wait = 1000 / per_host / 1000  # ms -> s
    wait_seconds = max(1, round(raw_wait))
    return ToolInvocationExtras(
        extra_args=["-t", "1", "--wait", str(wait_seconds)],
        note=(
            f"whatweb -t 1 --wait {wait_seconds}s (derived from {per_host}/s target, "
            f"no native rate flag exists, --wait has whole-second granularity so this "
            f"floors at 1s minimum)"
        ),
    )


# ---------------------------------------------------------------------------
# Tools confirmed to need NO change this pass
# ---------------------------------------------------------------------------
#
# paramspider: confirmed via real --help - no rate/throttle/delay flag of
# any kind. Its own --help frames it as "Mining URLs from dark corners of
# Web Archives" (wayback/otx/commoncrawl) - it queries ARCHIVE APIs, not
# the target directly, so a target-facing rate limit doesn't apply to this
# tool at all. (If paramspider's own archive-API request volume ever
# becomes a problem - e.g. getting throttled BY wayback/otx/commoncrawl -
# that's a different concern from this pass's target-protection goal and
# would need its own investigation, not a rate_limits.py entry.)
#
# jsluice: confirmed via real --help - only `-c/--concurrency` (FILES
# processed concurrently, default 1, not a request-rate concept) exists.
# Only relevant to request volume at all when jsluice is given remote
# URLs directly (per stage7_js_extraction.py, jsluice can fetch a URL
# itself rather than only reading local files) - even then, stage 7's
# real per-file invocation pattern and -c's default of 1 means this isn't
# the acute case the way x8/whatweb were. The stage-7 BUNDLER PROBE,
# however, is httpx hitting ~15 paths/host in one invocation and shares
# the R3 whole-invocation-not-per-host gap - flagged there, not fixed.
# Left alone this pass; revisit if stage 7 usage patterns change to pass
# jsluice many remote URLs in one invocation.
