"""
Two-tier scope gate.

Tier 1 (this module, deterministic): unambiguous matches against scope.json's
in_scope/out_of_scope patterns are auto-admitted or auto-rejected. Everything
else falls through as ambiguous.

Tier 2 (llm_review.py, not yet built): ambiguous assets get an LLM judgment
call, but the LLM tier only ever produces "needs_review" - never an auto-admit.
That's enforced by the return type of classify_ambiguous() having no
"admitted" outcome, not by convention - see llm_review.py when it exists.

Fail-closed by design: anything not a clean match against in_scope is treated
as ambiguous, never silently admitted.
"""

import fnmatch
import ipaddress
from dataclasses import dataclass
from typing import Literal, Optional

MatchResult = Literal["in_scope", "out_of_scope", "ambiguous"]


@dataclass
class ScopePatterns:
    in_scope_domains: list[str]
    out_of_scope_domains: list[str]
    in_scope_ip_ranges: list[str]

    @classmethod
    def from_scope_dict(cls, scope: dict) -> "ScopePatterns":
        return cls(
            in_scope_domains=scope.get("in_scope", {}).get("domains", []),
            out_of_scope_domains=scope.get("out_of_scope", {}).get("domains", []),
            in_scope_ip_ranges=scope.get("in_scope", {}).get("ip_ranges", []),
        )


def _domain_matches_pattern(domain: str, pattern: str) -> bool:
    """
    Wildcard match, e.g. 'api.example.com' matches '*.example.com'.
    Exact match also counts (pattern with no wildcard).
    fnmatch handles both cases via its glob-style matching.
    """
    return fnmatch.fnmatch(domain.lower(), pattern.lower())


def _is_subdomain_of_or_equal(domain: str, base: str) -> bool:
    """
    True if domain == base, or domain is any subdomain beneath base.
    e.g. sub.legacy.example.com is a subdomain of legacy.example.com,
    even though it doesn't match a 'legacy.example.com' wildcard pattern
    literally - exclusions must propagate downward or a bare out-of-scope
    entry could be silently bypassed by anything nested under it.
    """
    domain = domain.lower().rstrip(".")
    base = base.lower().rstrip(".")
    return domain == base or domain.endswith("." + base)


def classify_domain(domain: str, patterns: ScopePatterns) -> MatchResult:
    """
    Deterministic classification of a discovered domain/subdomain against
    scope patterns. This is intentionally conservative:
      - explicit out_of_scope match always wins, even if a broader in_scope
        wildcard would also match (exclusions take priority). This includes
        anything nested BENEATH an out_of_scope entry, not just exact/
        wildcard-pattern matches against it - see _is_subdomain_of_or_equal.
      - a clean in_scope wildcard/exact match -> in_scope
      - anything else (doesn't match any known pattern at all, or matches
        in a way that isn't a simple domain-suffix match - e.g. this
        function does NOT attempt to resolve CNAMEs or detect third-party
        hosting) -> ambiguous, for the LLM tier to look at
    """
    domain = domain.strip().lower().rstrip(".")

    for pattern in patterns.out_of_scope_domains:
        if _domain_matches_pattern(domain, pattern):
            return "out_of_scope"
        # also exclude anything nested beneath a literal (non-wildcard)
        # out-of-scope domain, e.g. 'legacy.example.com' should also
        # exclude 'sub.legacy.example.com'
        if "*" not in pattern and _is_subdomain_of_or_equal(domain, pattern):
            return "out_of_scope"

    for pattern in patterns.in_scope_domains:
        if _domain_matches_pattern(domain, pattern):
            return "in_scope"

    return "ambiguous"


def reason_for_ambiguous(domain: str, patterns: ScopePatterns) -> str:
    """
    Human/LLM-readable reason a domain fell through to ambiguous, for the
    needs_review.json entry. Kept simple for now - just states no pattern
    matched. Can get smarter later (e.g. detecting near-misses, suggesting
    which in_scope pattern it's closest to) once we see real ambiguous
    cases from actual runs.
    """
    return (
        f"'{domain}' did not match any in_scope or out_of_scope domain "
        f"pattern in scope.json - needs human/LLM review before further "
        f"testing."
    )


def extract_host(url: str) -> str | None:
    """
    Pull the hostname out of a URL for scope classification, e.g.
    'https://www.zonetransfer.me/sitemap.xml' -> 'www.zonetransfer.me'.
    Returns None if the value doesn't look like a parseable URL at all
    (defensive - gau/waybackurls output is generally well-formed, but
    stage output should never crash the pipeline over a malformed line).
    Uses the standard library urlparse rather than a hand-rolled regex,
    since URL parsing has enough edge cases (ports, userinfo, IPv6 hosts)
    that it's not worth re-deriving.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        host = parsed.hostname  # already lowercased, strips port/userinfo
        return host
    except (ValueError, AttributeError):
        return None


def classify_url(url: str, patterns: ScopePatterns) -> MatchResult:
    """
    Classify a URL-type asset (from gau/waybackurls/katana/etc.) by
    extracting its host and running the same deterministic logic used for
    bare subdomains. If the host can't be extracted at all, fail closed -
    treat as ambiguous rather than guessing.
    """
    host = extract_host(url)
    if host is None:
        return "ambiguous"
    return classify_domain(host, patterns)


def reason_for_ambiguous_url(url: str) -> str:
    """Reason string for a URL-type asset that couldn't even be parsed for a host."""
    return (
        f"'{url}' could not be parsed to extract a hostname - needs "
        f"human/LLM review before further testing."
    )


# ---------------------------------------------------------------------------
# IP classification
#
# Deliberately NOT the same fail-closed logic as classify_domain(): an IP
# resolving from a known in-scope hostname is NOT treated as sufficient
# signal to auto-admit as in_scope, because of shared hosting/CDN risk - an
# in-scope host's IP can still be hosting unrelated third-party infrastructure
# on the same box (shared hosting, load balancers, CDN edge nodes). Testing
# that IP directly could mean touching something that isn't the target's,
# which is exactly what the scope gate exists to prevent. Most bug bounty
# programs that scope domains rather than IP ranges implicitly disallow
# direct IP testing for this reason.
#
# So classify_ip() only ever auto-admits via an explicit, deterministic
# match against scope.json's in_scope.ip_ranges (CIDR or exact single-IP
# entries) - a resolved-from-in-scope-host link is informational context
# passed separately to reason_for_ambiguous_ip(), never scope-gate signal.
# ---------------------------------------------------------------------------

def _ip_matches_range(ip: str, range_str: str) -> bool:
    """
    True if ip falls within range_str, which may be a CIDR block
    (e.g. '192.0.2.0/24') or a bare single IP (e.g. '192.0.2.5', treated
    as an exact match). Invalid ip or range_str values fail closed (return
    False) rather than raising - malformed scope.json entries or malformed
    discovered IPs should never crash the pipeline, and should never be
    silently treated as a match either.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    try:
        if "/" in range_str:
            network = ipaddress.ip_network(range_str, strict=False)
            return addr in network
        else:
            return addr == ipaddress.ip_address(range_str)
    except ValueError:
        return False


def classify_ip(ip: str, patterns: ScopePatterns) -> MatchResult:
    """
    Deterministic classification of a discovered IP against
    scope.json's in_scope.ip_ranges (CIDR blocks or exact IPs).

    There is no out_of_scope IP list in the current scope.json schema
    (only in_scope.ip_ranges exists - see ScopePatterns/state file schema),
    so this function only ever returns "in_scope" or "ambiguous", never
    "out_of_scope". An invalid/unparseable ip string is also treated as
    ambiguous, same fail-closed philosophy as an unparseable URL in
    classify_url().

    Deliberately does NOT consider whether the IP resolves from a known
    in-scope hostname - see module docstring above. Callers that have that
    context (e.g. stage 4 passing an IP pulled from an in-scope host's
    a_records) should pass it to reason_for_ambiguous_ip() so it's visible
    to the human/LLM reviewer, not use it to skip calling this function.
    """
    ip = ip.strip()

    for range_str in patterns.in_scope_ip_ranges:
        if _ip_matches_range(ip, range_str):
            return "in_scope"

    return "ambiguous"


def reason_for_ambiguous_ip(ip: str, resolved_from_host: Optional[str] = None) -> str:
    """
    Human/LLM-readable reason an IP fell through to ambiguous, for the
    needs_review.json entry. When resolved_from_host is given (the IP was
    pulled from a known in-scope hostname's DNS records, e.g. stage 3's
    a_records metadata), that link is surfaced as context for the
    reviewer - it is NOT treated as scope signal by classify_ip() itself,
    since the IP could still be shared hosting/CDN infrastructure not
    belonging to the target. Reviewer still has to make the call.
    """
    if resolved_from_host:
        return (
            f"'{ip}' did not match any in_scope.ip_ranges entry in "
            f"scope.json, but resolves from known in-scope host "
            f"'{resolved_from_host}' - could be dedicated infrastructure "
            f"or shared hosting/CDN not belonging to the target. Needs "
            f"human/LLM review before this IP is tested directly."
        )
    return (
        f"'{ip}' did not match any in_scope.ip_ranges entry in scope.json "
        f"- needs human/LLM review before further testing."
    )
