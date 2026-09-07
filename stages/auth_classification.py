"""
C4: Auth-surface classification — a DETERMINISTIC post-processing pass (NOT an
active stage). Sends zero traffic: every signal is already on disk (the endpoints
table + per-host httpx metadata). Labels each endpoint's `auth_status` and writes
a per-host `auth_model` summary, so primitive's authenticated-testing mode gets a
map of what is gated and where auth happens.

Vocabulary (extends the existing {NULL, "gated"} B1/B2 already write):
  - "gated"        — response-confirmed 401/403 (set by B1 ffuf / B2 spec security).
                     C4 NEVER downgrades this.
  - "auth_surface" — a login/register/oauth/sso/… endpoint (a heuristic path lead).
  - "public"       — a known-2xx endpoint with no auth signal.
  - NULL           — unknown (no signal); left as-is.
Precedence (fail-closed, no guessing): gated > auth_surface > public > NULL.
C4-set labels carry metadata `auth_classified_by="c4"` to mark them heuristic leads
vs response-confirmed gates. Boundary: recon classifies/prioritizes; primitive tests.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Auth-surface path keywords, matched on SEGMENT boundaries so /auth matches but
# /authors does not (the make-or-break correctness trap).
AUTH_SURFACE_KEYWORDS = frozenset({
    "login", "signin", "sign-in", "logon", "register", "signup", "sign-up",
    "oauth", "oauth2", "sso", "saml", "auth", "authorize", "authorization",
    "authentication", "authn", "session", "sessions", "logout", "signout",
    "sign-out", "token", "openid-configuration", "connect", "oidc",
})


def _segments(path: str) -> list[str]:
    """Path split into lowercase segments on URL separators (/, ., ?, &, =, _)."""
    return [s for s in re.split(r"[/?#&=._]+", (path or "").lower()) if s]


def classify_endpoint(path: str, current_auth_status, status_code) -> str | None:
    """Return the auth_status label C4 would set, or None to leave unchanged.
    Never downgrades a response-confirmed 'gated'."""
    if current_auth_status == "gated":
        return None  # response-confirmed; C4 must not touch it
    if any(seg in AUTH_SURFACE_KEYWORDS for seg in _segments(path)):
        if current_auth_status != "auth_surface":
            return "auth_surface"
        return None
    if current_auth_status in (None, "public"):
        if isinstance(status_code, int) and 200 <= status_code < 300:
            return "public" if current_auth_status is None else None
    return None


def run_auth_classification(state) -> dict:
    """Classify every endpoint's auth_status in place and write a per-host
    `auth_model` summary onto the host asset metadata. Returns a small summary
    dict {gated, auth_surface, public, hosts_labeled} for logging. Idempotent."""
    endpoints = state.load_endpoints()
    host_model: dict[str, dict] = {}
    counts = {"gated": 0, "auth_surface": 0, "public": 0}

    for e in endpoints:
        status_code = e.metadata.get("ffuf_status")  # the only per-endpoint status recon captures
        new_label = classify_endpoint(e.path, e.auth_status, status_code)
        effective = new_label or e.auth_status
        if new_label is not None:
            state.update_endpoint_auth_status(e.endpoint_id, new_label, classified_by="c4")
        if effective in counts:
            counts[effective] += 1
        hm = host_model.setdefault(e.host, {"gated": 0, "auth_surface": 0, "public": 0,
                                            "auth_surface_paths": []})
        if effective == "auth_surface":
            hm["auth_surface"] += 1
            if e.path not in hm["auth_surface_paths"]:
                hm["auth_surface_paths"].append(e.path)
        elif effective in ("gated", "public"):
            hm[effective] += 1

    # write the per-host auth_model onto the host (subdomain) asset — agent-authored,
    # trusted intel; not target_derived.
    host_assets = {a.value: a for a in state.load_assets() if a.type == "subdomain"}
    hosts_labeled = 0
    for host, model in host_model.items():
        asset = host_assets.get(host)
        if asset is None:
            continue
        state.update_asset_metadata(asset.asset_id, {"auth_model": model})
        hosts_labeled += 1

    summary = {**counts, "hosts_labeled": hosts_labeled}
    logger.info("C4 auth classification: %d gated, %d auth_surface, %d public endpoint(s); "
                "auth_model on %d host(s)", counts["gated"], counts["auth_surface"],
                counts["public"], hosts_labeled)
    return summary
