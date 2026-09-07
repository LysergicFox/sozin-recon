"""
C5: tech → CVE candidate flagging. Stage 9's whatweb (+ stage 4's httpx) collect
version-level fingerprints "for CVE correlation" and then do nothing. C5 turns a
detected (product, version) into candidate CVEs, written into the C1 `recon_findings`
table with source="cve-candidate" (no new table). OFFLINE, zero target traffic.

Data source (locked): an EXACT-version index harvested from the on-box nuclei-templates
`classification.cpe` (cpe:2.3:<part>:<vendor>:<product>:<version>:…) + cve-id + cvss-score
— ~1200 templates carry a *versioned* CPE (e.g. apache http_server 2.4.49 →
CVE-2021-41773). Product-only CPEs (version `*`) are excluded (they'd flood). Running
nuclei's CVE *templates* was rejected — they are exploit templates (LFI/RCE payloads),
a recon/primitive boundary violation. NVD feeds are the precision upgrade (not on box).

BOUNDARY: recon flags CANDIDATES from a version string; it never version-probes or
exploits. A candidate is a prioritized lead, NEVER a vuln claim (the report agent must
render it as unconfirmed). target_derived=1 (the version came from the target).
"""

import glob
import logging
import os
import re
from urllib.parse import urlparse

from state import ReconFinding

logger = logging.getLogger(__name__)

TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", os.path.expanduser("~/nuclei-templates"))

# cpe:2.3:a:vendor:product:version:...  (groups restricted to CPE-safe chars — no
# whitespace/commas, so a malformed multi-line block can't bleed tags into a group)
_CPE_RE = re.compile(r"cpe:2\.3:[aoh]:([a-z0-9._\-]+):([a-z0-9._\-]+):([a-z0-9][a-z0-9._\-]*):", re.I)
_CVE_RE = re.compile(r"cve-id:\s*(CVE-\d{4}-\d+)", re.I)
_CVSS_RE = re.compile(r"cvss-score:\s*([\d.]+)")
# a plausible version: has at least one dot-separated numeric component
_VERSION_OK = re.compile(r"^[a-z0-9][a-z0-9._\-]*\d")
# "nginx/1.29.8", "Apache/2.4.49", "OpenSSL 1.1.1" → (name, version)
_STRING_VER_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9\-]{1,})[/ ]v?(\d+(?:\.\d+)+)")


def _cvss_severity(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"


def build_cve_index(templates_dir: str = TEMPLATES_DIR) -> dict:
    """Harvest an exact-version {(name, version): [entry]} index from nuclei CVE
    templates' classification blocks. `name` is BOTH the CPE vendor and product (so
    a whatweb 'apache' token matches an apache/http_server CPE). ~1s cold; built
    fresh each run (no cache staleness). Entry: {cve, cvss, severity, vendor, product}."""
    index: dict = {}
    pattern = os.path.join(templates_dir, "http", "cves", "**", "*.yaml")
    n = 0
    for path in glob.glob(pattern, recursive=True):
        try:
            txt = open(path, errors="replace").read()
        except OSError:
            continue
        m = _CPE_RE.search(txt)
        if not m:
            continue
        vendor, product, version = m.group(1).lower(), m.group(2).lower(), m.group(3).lower()
        if not _VERSION_OK.match(version):
            continue
        cve_m = _CVE_RE.search(txt)
        if not cve_m:
            continue
        cvss = (_CVSS_RE.search(txt) or [None, None])[1]
        entry = {"cve": cve_m.group(1).upper(), "cvss": cvss, "severity": _cvss_severity(cvss),
                 "vendor": vendor, "product": product, "version": version}
        for name in {vendor, product}:
            index.setdefault((name, version), []).append(entry)
        n += 1
    logger.info("C5 CVE index: %d versioned CVE template(s) → %d (name,version) key(s)", n, len(index))
    return index


def extract_tech_versions(host_asset) -> list[tuple[str, str, str]]:
    """(token, version, evidence) tuples from a host's whatweb_tech (plugins dict)
    and httpx_tech (list). Tokens/versions lowercased."""
    out: list[tuple[str, str, str]] = []
    ww = host_asset.metadata.get("whatweb_tech")
    if isinstance(ww, dict):
        for plugin, info in ww.items():
            if not isinstance(info, dict):
                continue
            for v in info.get("version") or []:
                if isinstance(v, str) and v.strip():
                    out.append((plugin.lower(), v.strip().lower(), f"{plugin} {v.strip()}"))
            for s in info.get("string") or []:
                if isinstance(s, str):
                    for name, ver in _STRING_VER_RE.findall(s):
                        out.append((name.lower(), ver.lower(), f"{name}/{ver}"))
    for t in host_asset.metadata.get("httpx_tech") or []:
        if isinstance(t, str) and ":" in t:
            name, ver = t.split(":", 1)
            if ver.strip():
                out.append((name.strip().lower(), ver.strip().lower(), t))
    return out


def run_cve_candidates(state, index: dict | None = None, current_pass: int = 1) -> list:
    """Match detected tech versions against the CVE index and write cve-candidate
    ReconFindings into recon_findings. Returns the findings. EXACT version match only
    (high precision, few false positives)."""
    if index is None:
        index = build_cve_index()
    findings = []
    seen = set()  # (host, cve) dedup
    host_assets = [a for a in state.load_assets() if a.type == "subdomain"]
    asset_id_by_host = {a.value: a.asset_id for a in host_assets}
    for a in host_assets:
        for token, version, evidence in extract_tech_versions(a):
            for entry in index.get((token, version), []):
                key = (a.value, entry["cve"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(ReconFinding(
                    host=a.value, template_id=entry["cve"], source="cve-candidate",
                    asset_id=asset_id_by_host.get(a.value),
                    template_name=f"{entry['vendor']}:{entry['product']} {version}",
                    category="cve", severity=entry["severity"],
                    matched_at=evidence, status="new", target_derived=True,
                    raw_finding={"cve": entry["cve"], "cvss": entry["cvss"],
                                 "cpe_version": entry["version"], "evidence": evidence,
                                 "note": "CANDIDATE from version match — not a confirmed vuln"},
                    discovered_at_stage=9, discovered_in_pass=current_pass,
                ))
    if findings:
        state.add_recon_findings(findings)
        logger.info("C5: %d CVE candidate(s) flagged from tech versions (status=new, unconfirmed)",
                    len(findings))
    return findings
