"""
Rate-limit extraction gate.

Single-shot, scope-setup-time LLM extraction of a program-stated rate limit
from raw program rules/ToS text (the same free text Jared pastes in during
scope setup, alongside domains/IP ranges). This is a DIFFERENT judgment
point from scope_gate.py's ambiguous-asset tier:

  - scope_gate.py runs deterministic-first, LLM-fallback, and does this
    PER ASSET across potentially thousands of discovered assets during a
    run - cheap deterministic pass matters at that volume.
  - This module runs LLM-FIRST (no deterministic pre-pass), ONCE, at scope
    setup time, against a single short block of program-rules text. There's
    no meaningful volume concern, and program rules are written in enough
    varied natural-language phrasing ("max 10 req/s", "please throttle your
    scanners", "no more than a handful of requests per second per host")
    that a regex/keyword pass would just be a worse, less honest version of
    what the LLM call already does directly - not a real cost saving, just
    a fragile extra layer. Locked design decision (see rate-limiting design
    pass conversation) - LLM-first is intentional here, not a shortcut.

Fail-closed philosophy, consistent with scope_gate.py and the recon agent's
architecture generally, adapted for this being a BLOCKING gate rather than a
per-asset queue:

  - Program states nothing about rate limits -> extracted_by=None,
    resolution="not_applicable". The conservative default in rate_limits.py
    applies. Does NOT block the run - "no policy stated" is a normal,
    common case (see rate-limiting research: quite a few programs simply
    don't mention it), not an error condition. NOTE (R2): this is the state
    that must be WRITTEN affirmatively into scope.json; a scope.json with
    NO rate_limit block at all now blocks the run (see
    check_run_not_blocked()), precisely so "human forgot to transcribe a
    stated limit" can't silently masquerade as "program stated nothing."
  - Program states a rate limit AND the LLM is confident about the number
    and units -> extracted_by="llm_flag", resolution="confirmed". Does NOT
    block the run - this is the clean, unambiguous case. Human can still
    override in scope.json directly if the extraction is wrong, same as any
    other scope.json field.
  - Program states SOMETHING about rate limits but the LLM can't confidently
    pin down a number/unit, OR can't tell whether a stated number is
    per-host or global (R4) -> extracted_by="llm_flag",
    resolution="pending". BLOCKS the run, same fail-closed spirit as
    verified_by_human gating run start in RunState.load_scope() - a human
    must resolve this (confirm the LLM's best-guess number + scope, override
    it, or explicitly mark not_applicable) before the pipeline is allowed to
    start hitting the target. This is the one meaningfully different design
    choice from scope_gate.py's ambiguous tier: scope_gate's LLM tier ALWAYS
    produces needs_review, by design, since it never has to be a blocking
    gate (individual assets can sit in the review queue while the rest of
    the run proceeds). A rate limit is different - it governs how hard EVERY
    tool invocation in the run hits the target, so an unresolved ambiguity
    here can't be quietly deferred the same way; the whole run needs to wait
    on it.

This module does NOT talk to assets.db, needs_review.json, or run_state.json
at all - it operates purely on the rate_limit block within scope.json, which
is loaded/saved through the same scope.json file RunState already owns (see
state.py's load_scope()). Kept as its own module rather than folded into
scope_gate.py because the two operate at genuinely different granularity
(once per run vs. once per discovered asset) and have a different blocking
contract (this one gates run start, scope_gate's never does) - conflating
them would blur two distinct concerns scope_gate.py's own docstring is
careful to keep separate.
"""

import json
import logging
from dataclasses import dataclass, asdict
from typing import Literal, Optional

logger = logging.getLogger(__name__)

ExtractedBy = Literal["llm_flag", "human", None]
RateLimitResolution = Literal["confirmed", "pending", "not_applicable"]
# (R4) whether a stated/confirmed rate limit is per-host or a single global
# ceiling across the whole invocation. Default per_host preserves the
# pre-R4 assumption, so existing scopes are unchanged.
RateLimitScope = Literal["per_host", "global"]

# Conservative fallback when no program-stated rate limit is found or
# confirmed. Locked value: 5 requests/second, PER HOST (not global across
# the whole pipeline - see rate_limits.py for why per-host matters once
# multiple in-scope hosts are being worked in the same pass).
#
# Chosen from real bug bounty program rate-limit conventions (see
# rate-limiting design pass conversation, Aug 2026): a real program's
# published policy caps automated tooling at 5 req/s/host; a survey of
# public program requirements found permitted automated-tool rates
# generally fall in the 2-10 req/s range depending on the program;
# Intigriti's own rate-limiting guidance uses 1 req/s as an illustrative
# safe-baseline example when demonstrating tool flags. 5 sits centered in
# the observed 2-10 range, matches a real program's actual stated number,
# and stays clearly on the "respectful" side rather than testing the
# tolerance ceiling - not derived from a specific program's rules text,
# just the sane baseline absent one.
CONSERVATIVE_DEFAULT_RPS = 5


@dataclass
class RateLimitInfo:
    stated_by_program: bool
    requests_per_second: Optional[int]
    source_text: Optional[str]
    extracted_by: ExtractedBy
    resolution: RateLimitResolution
    scope: RateLimitScope = "per_host"  # (R4) per_host (default) | global
    resolved_by: Optional[str] = None  # human identifier/note once a "pending" entry is confirmed, else None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "RateLimitInfo":
        return cls(
            stated_by_program=d.get("stated_by_program", False),
            requests_per_second=d.get("requests_per_second"),
            source_text=d.get("source_text"),
            extracted_by=d.get("extracted_by"),
            resolution=d.get("resolution", "not_applicable"),
            # (R4) default per_host for back-compat with any pre-R4
            # scope.json that omits the field entirely.
            scope=d.get("scope", "per_host"),
            resolved_by=d.get("resolved_by"),
        )

    @classmethod
    def not_applicable(cls) -> "RateLimitInfo":
        """No program rate-limit language found at all - conservative default applies, run not blocked."""
        return cls(
            stated_by_program=False,
            requests_per_second=None,
            source_text=None,
            extracted_by=None,
            resolution="not_applicable",
            scope="per_host",
        )


# ---------------------------------------------------------------------------
# LLM extraction call
#
# The actual LLM call is intentionally left as a thin seam
# (call_llm_extractor) rather than hardcoding a specific SDK/API call here -
# mirrors how scope_gate.py's own LLM tier is described as "not yet built"
# (llm_review.py) in its module docstring, i.e. this module defines the
# CONTRACT the extraction call must honor, wiring in the actual API client
# is a separate concern. Jared: plug in the real call in
# call_llm_extractor() when wiring this in for real - the prompt below is a
# starting point, not necessarily final wording.
# ---------------------------------------------------------------------------

EXTRACTION_PROMPT_TEMPLATE = """\
You are reviewing the rules-of-engagement / policy text for a bug bounty \
program, looking specifically for any stated limit on the rate of \
automated requests/scanning traffic testers are allowed to send.

Program rules text:
---
{program_rules_text}
---

Respond with ONLY a JSON object, no other text, in this exact shape:
{{
  "found": true or false,
  "requests_per_second": <integer, or null if not confidently determinable>,
  "scope": "per_host" or "global" or "unclear",
  "unit_confidence": "certain" or "ambiguous",
  "quoted_text": "<short exact quote from the program rules text that states the limit, or null>"
}}

Rules:
- "found": false if the text says nothing at all about rate limits,
  request throttling, or scanning speed/aggressiveness. In this case
  requests_per_second, quoted_text should be null, scope "per_host", and
  unit_confidence "certain" (nothing to be uncertain about).
- "found": true and "unit_confidence": "certain" ONLY if a specific numeric
  rate is stated unambiguously (e.g. "5 requests per second", "no more than
  10 req/s per host", "rate limit your scans to 2/sec"). Convert to a
  per-second integer regardless of the unit given (e.g. "600 requests per
  minute" -> 10).
- "scope": whether the stated number applies PER HOST/target ("per_host",
  e.g. "10 req/s per host") or as a single GLOBAL ceiling across the whole
  test ("global", e.g. "no more than 10 req/s total against our
  infrastructure"). Use "unclear" when a number is stated but the text does
  NOT make the per-host-vs-global distinction explicit - do NOT guess; an
  unclear scope is treated as an ambiguity requiring human resolution, the
  same as an unclear number.
- "found": true and "unit_confidence": "ambiguous" if the text mentions
  rate limiting / throttling / scanning aggressiveness but does NOT give a
  clear actionable number (e.g. "please be reasonable", "avoid aggressive
  scanning", "moderate automated tooling only", a number without clear
  units, or conflicting numbers in different places). In this case, still
  provide your best-guess requests_per_second if you can reasonably infer
  one, but it will be treated as a suggestion requiring human confirmation,
  not an authoritative extraction - never guess an unreasonably high number
  just to provide *some* value; when genuinely unclear, null is fine here
  too.
- Do not include any text outside the JSON object.
"""


def call_llm_extractor(program_rules_text: str) -> dict:
    """
    Seam for the actual LLM call - NOT YET WIRED to a real API client.
    Should return the parsed JSON dict described in
    EXTRACTION_PROMPT_TEMPLATE's response contract.

    Raises NotImplementedError until wired to a real client (e.g. the
    Anthropic API, same as any other LLM judgment point this pipeline
    uses). Deliberately raises rather than silently returning a fake
    "not found" result - a stubbed-out extractor silently reporting
    "no rate limit stated" would be actively dangerous (fail-open on a
    safety-relevant gate), the opposite of this module's whole purpose.
    """
    raise NotImplementedError(
        "call_llm_extractor() is a contract stub - wire in the real LLM "
        "API call before using extract_rate_limit() for a real run. See "
        "module docstring."
    )


def extract_rate_limit(program_rules_text: str) -> RateLimitInfo:
    """
    Run the LLM extraction against program_rules_text and translate its
    response into a RateLimitInfo per the fail-closed rules in the module
    docstring. Never raises on a malformed/unparseable LLM response - falls
    back to a "pending" (blocking) result instead, since a broken
    extraction is exactly the kind of ambiguity this gate exists to catch,
    not something to paper over with a silent default.
    """
    if not program_rules_text or not program_rules_text.strip():
        logger.info("rate_limit_gate: no program rules text provided, nothing to extract")
        return RateLimitInfo.not_applicable()

    try:
        response = call_llm_extractor(program_rules_text)
    except NotImplementedError:
        raise
    except Exception:
        logger.exception(
            "rate_limit_gate: LLM extraction call failed - failing closed "
            "to a blocking 'pending' result rather than guessing"
        )
        return RateLimitInfo(
            stated_by_program=False,
            requests_per_second=None,
            source_text=None,
            extracted_by="llm_flag",
            resolution="pending",
        )

    found = response.get("found", False)
    if not found:
        logger.info("rate_limit_gate: no rate-limit language found in program rules text")
        return RateLimitInfo.not_applicable()

    rps = response.get("requests_per_second")
    unit_confidence = response.get("unit_confidence", "ambiguous")
    quoted_text = response.get("quoted_text")
    rl_scope = response.get("scope", "unclear")

    # (R4) a stated number whose per-host-vs-global scope is unclear is an
    # ambiguity in its own right - the whole point is that a global cap
    # multiplied by host count (or a per-host cap left unscaled) is a real
    # misconfiguration. Treat an unclear/unknown scope exactly like an
    # unclear number: fail closed to pending. Only a certain number AND a
    # definite per_host/global scope is a clean confirmed extraction.
    scope_is_definite = rl_scope in ("per_host", "global")

    if unit_confidence == "certain" and isinstance(rps, int) and rps > 0 and scope_is_definite:
        logger.info("rate_limit_gate: confidently extracted %d req/s (%s) from program rules", rps, rl_scope)
        return RateLimitInfo(
            stated_by_program=True,
            requests_per_second=rps,
            source_text=quoted_text,
            extracted_by="llm_flag",
            resolution="confirmed",
            scope=rl_scope,
        )

    # Anything else - found=true but not a clean certain+positive-int+
    # definite-scope extraction - is ambiguous. Fails closed to "pending",
    # blocking the run until a human resolves it. This includes
    # unit_confidence "ambiguous", an unclear per-host-vs-global scope (R4),
    # and any malformed/missing rps value even when the LLM claimed
    # certainty, since a malformed response is itself a form of ambiguity
    # this gate should not paper over.
    logger.warning(
        "rate_limit_gate: program rules mention rate limiting but extraction "
        "is ambiguous (unit_confidence=%r, requests_per_second=%r, scope=%r) - "
        "flagging as pending, run will be blocked until a human resolves "
        "this in scope.json",
        unit_confidence, rps, rl_scope,
    )
    return RateLimitInfo(
        stated_by_program=True,
        requests_per_second=rps if isinstance(rps, int) and rps > 0 else None,
        source_text=quoted_text,
        extracted_by="llm_flag",
        resolution="pending",
        # keep a definite scope if the LLM gave one even though the number
        # was ambiguous; otherwise leave the default per_host - the human
        # resolving the pending entry sets the authoritative value anyway.
        scope=rl_scope if scope_is_definite else "per_host",
    )


def resolve_pending(scope: dict, requests_per_second: int, resolved_by: str,
                    rate_scope: RateLimitScope = "per_host") -> dict:
    """
    Human-resolution helper: given a scope dict with a "pending"
    rate_limit block, confirm it with a specific requests_per_second value,
    a rate_scope (per_host | global, R4), and a resolved_by note (e.g.
    "jared, confirmed via program dashboard chat"). Returns the updated
    scope dict for the caller to write back to scope.json - this module
    doesn't own file I/O for scope.json itself, same separation state.py
    already draws (RunState owns load/save, gate modules operate on the
    in-memory dict).

    Validates requests_per_second is a positive int and rate_scope is one
    of the two legal values before writing resolution="confirmed" - without
    the rps check, a caller typo (e.g. 0, a negative number, or a non-int)
    would leave scope.json in a self-contradictory state:
    resolution="confirmed" claiming a specific rate that
    rate_limits.resolve_effective_rps() would then silently reject and fall
    back from anyway (it independently checks rps > 0). That silent
    downstream rejection two files away is exactly the kind of surprise
    this gate exists to prevent - better to raise here, at the point of
    entry, than let a bad value sit in scope.json looking confirmed while
    actually being ignored.

    Does NOT accept resolution values other than "confirmed" - marking
    something not_applicable after the fact should be done by directly
    editing scope.json's rate_limit block by hand (an explicit, visible
    edit), not through a helper function that could make "quietly discard
    the ambiguity" too easy to call by accident.
    """
    if not isinstance(requests_per_second, int) or requests_per_second <= 0:
        raise ValueError(
            f"requests_per_second must be a positive int, got "
            f"{requests_per_second!r} - refusing to write a scope.json "
            f"rate_limit block that resolve_effective_rps() would silently "
            f"reject downstream"
        )
    if rate_scope not in ("per_host", "global"):
        raise ValueError(
            f"rate_scope must be 'per_host' or 'global', got {rate_scope!r} "
            f"- refusing to write an unrecognized rate_limit.scope that "
            f"rate_limits.resolve_rate_scope() would fall back from"
        )

    info = RateLimitInfo(
        stated_by_program=True,
        requests_per_second=requests_per_second,
        source_text=scope.get("rate_limit", {}).get("source_text"),
        extracted_by="human",
        resolution="confirmed",
        scope=rate_scope,
        resolved_by=resolved_by,
    )
    scope["rate_limit"] = info.to_dict()
    return scope


def check_run_not_blocked(scope: dict) -> None:
    """
    Raise if scope's rate_limit block is missing (R2) or in "pending"
    resolution - mirrors RunState.load_scope()'s existing verified_by_human
    gate (raises ValueError rather than returning a bool) so callers get the
    same fail-loud contract for both gates. Intended to be called alongside
    load_scope() before a run starts.

    (R2) A scope.json with NO rate_limit block at all now BLOCKS the run. A
    run requires an affirmative rate decision: previously, an absent block
    was treated as "not_applicable" and ran at the conservative default
    silently, which meant a human who forgot to transcribe a program's
    stated limit ran OVER it with no warning. To get the conservative
    default the human must now set resolution="not_applicable" explicitly,
    forcing a conscious "did the program state a limit?" decision. The
    degrade-safely-to-default behavior remains - it just has to be *chosen*,
    not defaulted into by omission.
    """
    rate_limit = scope.get("rate_limit")
    if rate_limit is None:
        raise ValueError(
            "scope.json has no rate_limit block (R2). A run now requires an "
            "affirmative rate decision - omitting the block no longer "
            "silently falls back to the conservative default. Add a "
            "rate_limit block with resolution=\"not_applicable\" to accept "
            f"the conservative default ({CONSERVATIVE_DEFAULT_RPS} req/s per "
            "host), or resolution=\"confirmed\" with a requests_per_second "
            "and scope (per_host|global) for a program-stated limit. See "
            "RECON_DESIGN_REVIEW_RESOLUTIONS.md R2."
        )
    if rate_limit.get("resolution") == "pending":
        raise ValueError(
            "scope.json's rate_limit is unresolved (resolution='pending') - "
            f"program rules mentioned a rate limit but it could not be "
            f"confidently extracted (source_text={rate_limit.get('source_text')!r}, "
            f"best-guess requests_per_second={rate_limit.get('requests_per_second')!r}, "
            f"scope={rate_limit.get('scope')!r}). "
            "Refusing to start the run until a human confirms the correct "
            "rate limit via rate_limit_gate.resolve_pending() or a direct "
            "scope.json edit."
        )
