"""
A2: deterministic interest scoring — a finalizer (no traffic) that scores every
url and host asset from already-collected data, writing `interest_score` (int) +
`interest_signals` (dict signal→points, for explainability) onto asset metadata.
Feeds A1 (the attack-surface brief): the LLM becomes an editor of a ranked surface
rather than a from-scratch author. Boundary: A2 prioritizes, it never tests; the
score is agent-authored (trusted), a priority hint not a vuln claim.
"""

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# url path keywords → points (segment-boundary match, so /gitlab ≠ the "git" kw).
KEYWORD_WEIGHTS = {
    "admin": 5, "administration": 5, "api": 3, "graphql": 5, "swagger": 4,
    "actuator": 5, "upload": 4, "uploads": 4, "debug": 4, "internal": 4,
    "staging": 3, "dev": 2, "backup": 4, "config": 3, "console": 3,
    "redirect": 3, "token": 3, "oauth": 3, "sso": 3, "git": 5, "env": 5,
    "well-known": 1, "phpmyadmin": 5, "wp-admin": 5, "metrics": 2,
}
AUTH_WEIGHTS = {"gated": 3, "auth_surface": 2}
SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1, "unknown": 1}
SECRET_POINTS = 5
SERVICE_POINTS = 2
WAF_POINTS = 1
STANDARD_PORTS = {80, 443, 8080, 8443}


def _segments(path: str) -> list[str]:
    return [s for s in re.split(r"[/?#&=._]+", (path or "").lower()) if s]


def score_url(path: str, auth_status, has_params: bool) -> tuple[int, dict]:
    """Interest score + signal breakdown for a single url asset."""
    signals: dict = {}
    score = 0
    kw_hits = {seg: KEYWORD_WEIGHTS[seg] for seg in _segments(path) if seg in KEYWORD_WEIGHTS}
    if kw_hits:
        signals["keywords"] = kw_hits
        score += sum(kw_hits.values())
    if auth_status in AUTH_WEIGHTS:
        signals["auth"] = {auth_status: AUTH_WEIGHTS[auth_status]}
        score += AUTH_WEIGHTS[auth_status]
    if has_params:
        signals["has_params"] = 1
        score += 1
    return score, signals


def run_interest_scoring(state) -> dict:
    """Score every url + host asset in place. Returns a summary
    {scored, top:[(value,score)…]}. Idempotent."""
    assets = state.load_assets()
    endpoints = state.load_endpoints()
    parameters = state.load_parameters()
    findings = state.load_recon_findings()
    secrets = state.load_secrets()
    services = state.load_services()

    # url-keyed rollups from endpoints/params
    url_auth: dict[str, str] = {}
    for e in endpoints:
        cur = url_auth.get(e.url)
        # keep the most-interesting auth label seen for this url
        if e.auth_status and (cur is None or AUTH_WEIGHTS.get(e.auth_status, 0) > AUTH_WEIGHTS.get(cur, 0)):
            url_auth[e.url] = e.auth_status
    urls_with_params = {p.endpoint for p in parameters if p.endpoint}

    # host-keyed rollups
    asset_host = {a.asset_id: urlparse(a.value).hostname for a in assets if a.type == "url"}
    findings_by_host: dict[str, list] = {}
    for f in findings:
        findings_by_host.setdefault(f.host, []).append(f)
    secrets_by_host: dict[str, int] = {}
    for s in secrets:
        h = asset_host.get(s.asset_id)
        if h:
            secrets_by_host[h] = secrets_by_host.get(h, 0) + 1
    services_by_host: dict[str, int] = {}
    for sv in services:
        host = sv.host or sv.ip or sv.target
        if host and sv.port not in STANDARD_PORTS:
            services_by_host[host] = services_by_host.get(host, 0) + 1

    scored = 0
    top: list[tuple[str, int]] = []
    for a in assets:
        signals: dict = {}
        score = 0
        if a.type == "url":
            path = urlparse(a.value).path
            score, signals = score_url(path, url_auth.get(a.value), a.value in urls_with_params)
        elif a.type == "subdomain":
            hf = findings_by_host.get(a.value, [])
            if hf:
                fpts = sum(SEVERITY_WEIGHTS.get((f.severity or "unknown").lower(), 1) for f in hf)
                signals["findings"] = {"count": len(hf), "points": fpts}
                score += fpts
            nsec = secrets_by_host.get(a.value, 0)
            if nsec:
                signals["secrets"] = {"count": nsec, "points": nsec * SECRET_POINTS}
                score += nsec * SECRET_POINTS
            nsvc = services_by_host.get(a.value, 0)
            if nsvc:
                signals["nonstd_services"] = {"count": nsvc, "points": nsvc * SERVICE_POINTS}
                score += nsvc * SERVICE_POINTS
            if a.metadata.get("waf_suspected"):
                signals["waf_suspected"] = WAF_POINTS
                score += WAF_POINTS
        else:
            continue  # ip assets not scored in v1

        state.update_asset_metadata(a.asset_id, {"interest_score": score,
                                                 "interest_signals": signals})
        if score > 0:
            scored += 1
            top.append((a.value, score))

    top.sort(key=lambda t: t[1], reverse=True)
    logger.info("A2 interest scoring: %d asset(s) scored > 0 (top: %s)",
                scored, ", ".join(f"{v}={s}" for v, s in top[:5]) or "none")
    return {"scored": scored, "top": top[:10]}
