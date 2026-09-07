"""
F6: target profile summary — a deterministic one-page "know your target" digest
(size, tech stack, WAF/CDN posture, auth model, notable exposures, top-interest
surface), a small cousin of the A1 LLM brief that is useful today without any LLM.
Offline finalizer; aggregates what the pipeline already produced. Writes
target_profile.json + target_profile.md to the run dir.
"""

import json
import logging
from collections import Counter
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

STANDARD_PORTS = {80, 443, 8080, 8443}


def build_profile(state) -> dict:
    assets = state.load_assets()
    endpoints = state.load_endpoints()
    parameters = state.load_parameters()
    secrets = state.load_secrets()
    services = state.load_services()
    findings = state.load_recon_findings()

    hosts = [a for a in assets if a.type == "subdomain"]
    live_hosts = [a for a in hosts if "httpx_status_code" in a.metadata]
    urls = [a for a in assets if a.type == "url"]

    # tech stack (union of whatweb plugin names + httpx tech)
    tech = set()
    for h in hosts:
        ww = h.metadata.get("whatweb_tech")
        if isinstance(ww, dict):
            tech.update(k for k in ww if k not in ("IP", "Country", "Title", "HTTPServer"))
        for t in h.metadata.get("httpx_tech") or []:
            tech.add(t.split(":")[0] if isinstance(t, str) else t)

    # WAF/CDN posture (C3 + B1)
    behind_waf = {h.value: (h.metadata.get("waf_vendor") or h.metadata.get("waf_name"))
                  for h in hosts if h.metadata.get("is_behind_waf")}
    cdn = {h.value: h.metadata.get("cdn_name") for h in hosts if h.metadata.get("is_cdn")}
    waf_suspected = [h.value for h in hosts if h.metadata.get("waf_suspected")]

    # auth model (C4)
    auth_status_counts = Counter(e.auth_status for e in endpoints if e.auth_status)
    auth_surfaces = sorted({e.path for e in endpoints if e.auth_status == "auth_surface"})

    # notable exposures (C1 + C5)
    findings_by_sev = Counter(f.severity for f in findings)
    cve_candidates = sorted({f.template_id for f in findings if f.source == "cve-candidate"})

    # top-interest surface (A2)
    scored = [(a.value, a.metadata.get("interest_score", 0)) for a in assets
              if a.metadata.get("interest_score")]
    scored.sort(key=lambda t: t[1], reverse=True)

    nonstd = [f"{s.host or s.ip or s.target}:{s.port}" for s in services if s.port not in STANDARD_PORTS]

    return {
        "scope_size": {
            "subdomains": len(hosts), "live_hosts": len(live_hosts), "urls": len(urls),
            "endpoints": len(endpoints), "parameters": len(parameters),
            "secrets": len(secrets), "services": len(services), "recon_findings": len(findings),
        },
        "tech_stack": sorted(tech),
        "waf_cdn_posture": {"behind_waf": behind_waf, "cdn": cdn, "waf_suspected": waf_suspected},
        "auth_model": {"status_counts": dict(auth_status_counts), "auth_surfaces": auth_surfaces},
        "notable_exposures": {"findings_by_severity": dict(findings_by_sev), "cve_candidates": cve_candidates},
        "top_interest": scored[:15],
        "non_standard_ports": nonstd,
    }


def _render_markdown(p: dict) -> str:
    s = p["scope_size"]
    lines = ["# Target profile", "",
             "## Scope size",
             " · ".join(f"**{k}**: {v}" for k, v in s.items()), "",
             "## Tech stack", ", ".join(p["tech_stack"]) or "_none detected_", "",
             "## WAF / CDN posture"]
    wc = p["waf_cdn_posture"]
    lines.append(f"- behind WAF: {wc['behind_waf'] or 'none'}")
    lines.append(f"- CDN: {wc['cdn'] or 'none'}")
    if wc["waf_suspected"]:
        lines.append(f"- WAF-suspected (in-flight, B1): {wc['waf_suspected']}")
    lines += ["", "## Auth model",
              f"- endpoint auth_status: {p['auth_model']['status_counts'] or 'none labeled'}",
              f"- auth surfaces: {p['auth_model']['auth_surfaces'] or 'none'}", "",
              "## Notable exposures",
              f"- recon findings by severity: {p['notable_exposures']['findings_by_severity'] or 'none'}",
              f"- CVE candidates (unconfirmed): {p['notable_exposures']['cve_candidates'] or 'none'}", "",
              "## Top-interest surface (A2 score)"]
    lines += [f"- {v} — {score}" for v, score in p["top_interest"]] or ["_nothing scored_"]
    if p["non_standard_ports"]:
        lines += ["", "## Non-standard-port services", ", ".join(p["non_standard_ports"])]
    return "\n".join(lines) + "\n"


def run_target_profile(state) -> dict:
    """Build + write target_profile.json and target_profile.md into the run dir."""
    profile = build_profile(state)
    (state.run_dir / "target_profile.json").write_text(json.dumps(profile, indent=2))
    (state.run_dir / "target_profile.md").write_text(_render_markdown(profile))
    s = profile["scope_size"]
    logger.info("F6 target profile: %d live host(s), %d endpoint(s), %d finding(s), %d tech; "
                "written to target_profile.{json,md}",
                s["live_hosts"], s["endpoints"], s["recon_findings"], len(profile["tech_stack"]))
    return profile
