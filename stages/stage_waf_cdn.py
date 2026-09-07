"""
Stage 4.5 (C3): WAF / CDN detection — label each live host so the hunting agents
"know the target" (primitive's rate-backpressure + technique selection depend on
it), instead of rediscovering it live. Two complementary tools:

  - cdncheck (ProjectDiscovery) — OFFLINE IP-range classification (cdn / waf /
    cloud name from local range data + DNS resolution; NO target traffic). One
    batched invocation for all hosts.
  - wafw00f — ACTIVE WAF-vendor fingerprint, one invocation per host. ⚠️ Verified
    2026-08-23: wafw00f sends ~2 requests INCLUDING an attack-signature probe
    (XSS/SQLi/traversal in the query string) to trigger the WAF. That is
    *fingerprinting the filter*, not exploiting the app — but it is active,
    attack-looking traffic, so it is scope-implied (R1: same host only) and run
    per-host (bounded). Recon DETECTS/LABELS the obstacle; it never engages/
    bypasses it (that's primitive).

Writes agent-authored, TRUSTED host metadata (NOT target_derived): is_behind_waf,
waf_vendor, is_cdn, cdn_name, cloud_name. Relationship to B1: `waf_suspected` (B1)
is an in-flight 403-flood breaker; C3's label is a pre-flight fingerprint — both
kept, orthogonal. origin-IP discovery is deferred (favicon→E1, ASN→F3).

Verified interfaces (2026-08-23):
  cdncheck -jsonl -resp (hosts on stdin) → {input, ip, cdn, cdn_name, waf,
    waf_name, cloud, cloud_name} (flags present when matched).
  wafw00f <url> -a -f json -o <file> → [{detected, firewall, manufacturer, ...}].
  Neither's exit code is a reliable signal — parse output, don't key on exit.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from state import RunState, timed
from stages.parallelism import bounded_parallel_map, DEFAULT_MAX_WORKERS

logger = logging.getLogger(__name__)

STAGE = 4.5
DEFAULT_TIMEOUT_SECONDS = 120
WAFW00F_WORKERS = DEFAULT_MAX_WORKERS  # (E5) parallel across hosts; each host keeps its own rate


def _run_tool(cmd, timeout=DEFAULT_TIMEOUT_SECONDS, stdin_text=None):
    logger.info("Running: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin_text)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        logger.warning("tool timed out after %ss: %s", timeout, " ".join(cmd))
        return "", f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def run_cdncheck(hosts: list[str], state: RunState) -> dict[str, dict]:
    """OFFLINE CDN/WAF/cloud classification for all hosts in one batched call.
    Returns {host: {is_cdn, cdn_name, is_behind_waf, waf_name, cloud_name}}."""
    if not hosts:
        return {}
    stdout, stderr, code = _run_tool(["cdncheck", "-jsonl", "-resp"], stdin_text="\n".join(hosts))
    state.save_raw(STAGE, "cdncheck", stdout)
    out: dict[str, dict] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        host = o.get("input")
        if not host:
            continue
        entry = {}
        if o.get("cdn"):
            entry["is_cdn"] = True
            entry["cdn_name"] = o.get("cdn_name")
        if o.get("waf"):
            entry["is_behind_waf"] = True
            entry["waf_name"] = o.get("waf_name")
        if o.get("cloud"):
            entry["cloud_name"] = o.get("cloud_name")
        if entry:
            out[host] = entry
    logger.info("cdncheck classified %d/%d host(s) (offline)", len(out), len(hosts))
    return out


def run_wafw00f(host: str, base: str, state: RunState) -> dict:
    """ACTIVE WAF-vendor fingerprint for one host (~2 requests incl. an
    attack-signature probe). Returns {is_behind_waf, waf_vendor} or {}."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        out_path = f.name
    _stdout, _stderr, _code = _run_tool(["wafw00f", f"{base}", "-a", "-f", "json", "-o", out_path])
    result = {}
    try:
        data = json.loads(Path(out_path).read_text() or "[]")
        detected = [d for d in data if isinstance(d, dict) and d.get("detected") and d.get("firewall")]
        if detected:
            # exclude the generic "Generic"/"None" firewall labels
            vendors = [d["firewall"] for d in detected if d["firewall"].lower() not in ("generic", "none")]
            if vendors:
                result = {"is_behind_waf": True, "waf_vendor": vendors[0] if len(vendors) == 1 else vendors}
    except (json.JSONDecodeError, ValueError, OSError):
        pass
    finally:
        Path(out_path).unlink(missing_ok=True)
    return result


def run_waf_cdn(live_hosts: list[str], state: RunState, current_pass: int, scope: dict,
                host_base: dict[str, str] | None = None) -> dict[str, dict]:
    """C3: per-host WAF/CDN metadata (cdncheck offline batch + wafw00f active
    per-host). Returns {host: metadata_update} for the caller to apply. R7: one
    host's wafw00f failure doesn't stop the others."""
    if not live_hosts:
        return {}
    logger.info("Seeding stage 4.5 (WAF/CDN) with %d live host(s)", len(live_hosts))
    updates: dict[str, dict] = {}
    with timed(state, "stage4_5.waf_cdn_total"):
        cdn_data = run_cdncheck(live_hosts, state)  # offline, batched
        # (E5) wafw00f per-host, parallel across hosts (each host keeps its own rate;
        # R7 per-host isolation lives inside bounded_parallel_map).
        def _waf_for(host):
            base = (host_base or {}).get(host) or f"https://{host}"
            return run_wafw00f(host, base, state)
        waf_results = bounded_parallel_map(_waf_for, live_hosts, workers=WAFW00F_WORKERS,
                                           label="stage 4.5 wafw00f")
        for host in live_hosts:
            update = dict(cdn_data.get(host, {}))
            waf = waf_results.get(host, {})
            # wafw00f's active vendor fingerprint takes precedence over cdncheck's
            # range-based waf_name for the vendor label; is_behind_waf = either.
            if waf.get("is_behind_waf"):
                update["is_behind_waf"] = True
                update["waf_vendor"] = waf["waf_vendor"]
            if update:
                updates[host] = update
    n_waf = sum(1 for u in updates.values() if u.get("is_behind_waf"))
    n_cdn = sum(1 for u in updates.values() if u.get("is_cdn"))
    logger.info("Stage 4.5 WAF/CDN: %d host(s) behind a WAF, %d behind a CDN", n_waf, n_cdn)
    return updates
