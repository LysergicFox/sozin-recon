"""
C2: screenshots — render each live in-scope host in headless Chrome (via httpx's
native -screenshot, already-wired tool) and save a PNG into the run dir. Visual
triage is how the interesting ~5% of hosts get found (login panels, admin
dashboards, dev/staging, default/error pages); the path is stored as host metadata
for the report agent and a future vision model (A2/A1).

Active traffic (a full page render per host) → scope-implied (R1, live in-scope
hosts only), rate-bounded (httpx -rl), R7 per-host isolation via the single
invocation guard. Screenshots are SENSITIVE-AT-REST (a rendered page can show
tokens/PII), so they land under the R8 chmod-700 run dir (gitignored).

Verified 2026-08-23: `httpx -screenshot -system-chrome -srd <dir>` writes
<dir>/screenshot/<host>/<hash>.png and emits JSON key `screenshot_path_rel`
(+ `screenshot_path` absolute). `-esb` keeps the base64 bytes out of the JSON.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from state import RunState, timed
from rate_limits import httpx_rate_args

logger = logging.getLogger(__name__)

STAGE = 9  # runs alongside the stage-9 per-host fingerprinting band (metadata only)
SCREENSHOT_TIMEOUT_SECONDS = 900


def _run_tool(cmd, timeout=SCREENSHOT_TIMEOUT_SECONDS):
    logger.info("Running: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        logger.warning("httpx screenshot timed out after %ss", timeout)
        return "", f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def run_screenshots(live_hosts: list[str], state: RunState, scope: dict,
                    host_base: dict[str, str] | None = None) -> dict[str, dict]:
    """Screenshot each live host via httpx headless Chrome. Returns
    {host: {"screenshot_path": <path relative to run dir>}}. Files land in the
    R8 run dir. R7: a whole-invocation failure yields no shots, not a crash."""
    if not live_hosts:
        return {}
    srd = state.run_dir / "screenshots"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        # screenshot the confirmed-live ORIGIN (scheme from httpx_final_url, like B1/B2)
        f.write("\n".join((host_base or {}).get(h) or f"https://{h}" for h in live_hosts))
        targets_path = f.name

    rate = httpx_rate_args(scope, host_count=len(live_hosts))
    logger.info("Seeding C2 screenshots with %d live host(s); %s", len(live_hosts), rate.note)
    updates: dict[str, dict] = {}
    with timed(state, "c2.screenshots_total"):
        try:
            stdout, _stderr, _code = _run_tool([
                "httpx", "-l", targets_path, "-json", "-silent",
                "-screenshot", "-system-chrome", "-esb",
                "-srd", str(srd), *rate.extra_args,
            ])
        except Exception:
            logger.exception("C2 screenshots failed - none captured this pass (R7)")
            stdout = ""
        finally:
            Path(targets_path).unlink(missing_ok=True)

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        host = obj.get("input") or obj.get("host")
        shot = obj.get("screenshot_path_rel") or obj.get("screenshot_path")
        if not host or not shot:
            continue
        # normalize to a path relative to the run dir when possible
        try:
            rel = str(Path(obj["screenshot_path"]).relative_to(state.run_dir))
        except (KeyError, ValueError):
            rel = f"screenshots/screenshot/{shot}"
        # host may be a URL (we seeded origins) — normalize to the bare host key
        from urllib.parse import urlparse
        key = urlparse(host).hostname or host
        updates[key] = {"screenshot_path": rel}

    logger.info("C2 screenshots: captured %d screenshot(s)", len(updates))
    return updates
