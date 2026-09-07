"""
F5: DNS/host breadth — reverse DNS (PTR) on discovered IPs to surface other
hostnames sharing an IP (some in-scope, most shared-hosting noise the scope gate
drops). Uses dnsx -ptr against default public resolvers (a DNS query stream, not
target traffic — rate-bounded by the DNS-resolver cap, like stage 3's dnsx/puredns).
New hostnames go through the scope gate like any discovery. vhost discovery and
NSEC walking are named-deferred (v1 = reverse DNS only).

Verified dnsx -ptr -json -silent 2026-08-23: per-IP {host:<ip>, ptr:[hostnames]}.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from state import Asset, RunState
from rate_limits import dnsx_rate_args

logger = logging.getLogger(__name__)

STAGE = 4  # a stage-4-band DNS breadth pass (produces subdomain candidates)


def _run_tool(cmd, timeout=300, stdin_text=None):
    logger.info("Running: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin_text)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        logger.warning("dnsx -ptr timed out after %ss", timeout)
        return "", "timeout", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def run_reverse_dns(ip_values: list[str], state: RunState, scope: dict,
                    current_pass: int = 1) -> list[Asset]:
    """dnsx -ptr over the IPs → new subdomain Assets (PTR hostnames) for the caller
    to scope-gate + add. Returns [] if no IPs / no PTRs."""
    if not ip_values:
        return []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(ip_values))
        ips_path = f.name
    rate = dnsx_rate_args(scope)
    logger.info("Seeding F5 reverse DNS with %d IP(s); %s", len(ip_values), rate.note)
    stdout, _stderr, _code = _run_tool(["dnsx", "-l", ips_path, "-ptr", "-json", "-silent",
                                        *rate.extra_args])
    state.save_raw(STAGE, "dnsx_ptr", stdout)
    Path(ips_path).unlink(missing_ok=True)

    seen: set[str] = set()
    assets: list[Asset] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        for hostname in obj.get("ptr") or []:
            host = (hostname or "").strip().rstrip(".").lower()
            if host and host not in seen:
                seen.add(host)
                assets.append(Asset(value=host, type="subdomain", discovered_by="dnsx_ptr",
                                    discovered_at_stage=STAGE, discovered_in_pass=current_pass))
    logger.info("F5 reverse DNS: %d PTR hostname(s) from %d IP(s)", len(assets), len(ip_values))
    return assets
