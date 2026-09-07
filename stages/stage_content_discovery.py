"""
Stage 6.5: content / endpoint discovery (B1) — ffuf directory/file brute force.

Realizes B1 of RECON_ENHANCEMENTS.md (Track B). The pipeline's first
content-discovery tool and the single largest source of `endpoint` records for
the future primitive agent. Each hit becomes a type="url" Asset (through the
scope gate) AND a Track-D `endpoint` record.

Why stage 6.5 (a fractional stage), not terminal stage 10 (revises the B1 design
doc's locked decision #2):
  - Runs AFTER katana (stage 6) and BEFORE jsluice (stage 7), so a ffuf-discovered
    `.js` file is mined by jsluice IN THE SAME PASS (stage 7 seeds from `.js` url
    assets in the graph) - removing the loop-until-stable dependency for that
    coverage. Katana does NOT re-crawl ffuf-discovered directories this pass (it
    seeds from hosts, not our url assets); that remains a named residual for a
    future stage-6 seed change or loop-until-stable.
  - 6.5 (over 5.5) also minimises WAF-ban blast radius: only stages 7/8/9 follow.
  - The fractional STAGE is a deliberate float. It flows cleanly into
    current_stage / discovered_at_stage / the raw filename (stage6.5_ffuf_*.json).
    Watch for any INTEGER-stage comparison added later (e.g. R14 loop logic).

Verified ffuf interface (2.1.0-dev, real runs 2026-08-23 — these bit prior stages
too, so they were confirmed, not assumed):
  - `-of json -o <file>`: top-level {commandline, config, results, time}; each hit
    in `results[]` with keys input.FUZZ, status, length, words, lines,
    `content-type` (HYPHENATED), redirectlocation ("" when none), url, host.
  - default `-mc` = 200-299,301,302,307,401,403,405,500 (401/403 matched → cheap
    auth_status="gated"; 404 not matched).
  - `-ac` filters the soft-404 catch-all (size/word/line based).
  - `-rate N`: precise process-wide req/s → per-host invocation = true per-host cap.
  - `-sf` (stop on 403 flood) and `-maxtime-job` both EXIT 0 and still write a
    (partial) file; the ONLY early-stop signal is a STDERR string. WAF detection
    keys on stderr + computed 403-ratio, NEVER exit code.
  - default (no `-or`) writes the -o file even with zero results; a hard kill may
    write nothing → the parser tolerates missing-or-empty.

Like every other stage, this module does NOT classify assets or write assets.db
itself — new assets, endpoint records, and per-host waf flags are returned to
main.py.
"""

import json
import logging
import re
import subprocess
from urllib.parse import urlparse

from state import Asset, RunState, Endpoint, timed
from rate_limits import ffuf_rate_args
from http_headers import header_args

logger = logging.getLogger(__name__)

STAGE = 6.5
DEFAULT_TIMEOUT_SECONDS = 1800   # content discovery is long; bounded wordlist + recursion keep timeouts rare
MAXTIME_JOB_SECONDS = 1200       # ffuf -maxtime-job per-host wall cap (also a WAF/abuse backstop)
RECURSION_DEPTH = 2              # capped — never run unbounded
THREADS = 40                    # ffuf default; -rate is the real ceiling regardless

# Curated v1 wordlist (SecLists). Kept a module constant so E3 (target-derived
# wordlists) can extend it later without a rewrite. A missing wordlist fails safe
# (logged, zero discovery), never crashes the stage. NOTE: the design doc assumed
# /usr/share/seclists, but on this box SecLists lives under ~/tools/SecLists
# (confirmed 2026-08-23); repoint here if it moves. Honour a SECLISTS_DIR env
# override so the path isn't hard-pinned to one machine.
import os as _os
_SECLISTS_DIR = _os.environ.get(
    "SECLISTS_DIR",
    _os.path.expanduser("~/tools/SecLists") if _os.path.isdir(_os.path.expanduser("~/tools/SecLists"))
    else "/usr/share/seclists",
)
WORDLIST_PATH = _os.path.join(_SECLISTS_DIR, "Discovery/Web-Content/raft-medium-directories.txt")

# Extension permutations appended to each FUZZ word (ffuf -e). Includes .js so the
# stage-7 jsluice same-pass chain is real, plus common leak/backup/config suffixes.
EXTENSIONS = [".js", ".json", ".txt", ".bak", ".old", ".zip", ".tar.gz",
              ".env", ".config", ".swp"]

# ffuf's stderr early-stop signals (exit code is 0 in BOTH cases — verified).
_WAF_403_FLOOD_SIGNAL = "unusual amount of 403 responses"
_WAF_MAXTIME_SIGNAL = "Maximum running time for this job reached"


def _sanitize(s: str) -> str:
    """Filesystem-safe token of a host for per-target raw filenames (R5). Same
    character class as stage 1/3/7."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def _run_tool(cmd: list[str], timeout: int = DEFAULT_TIMEOUT_SECONDS) -> tuple[str, str, int]:
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning("ffuf timed out after %ss: %s", timeout, " ".join(cmd))
        return "", f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def _parse_ffuf_json(path) -> list[dict]:
    """Read ffuf's `-of json -o` file into a list of hit dicts. Tolerates a
    missing file (hard kill / tool-not-found → no file) and an empty results
    list (a clean zero-hit scan still writes the file). Never raises."""
    try:
        if not path.exists():
            logger.warning("ffuf output file not written (%s) - treating as zero hits", path)
            return []
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("ffuf output %s unreadable (%r) - treating as zero hits", path, exc)
        return []
    return data.get("results", []) or []


def _detect_waf(stderr: str, results: list[dict]) -> dict:
    """Post-hoc WAF/early-stop determination for one host. Keys on ffuf's stderr
    strings (the only reliable early-stop signal — exit code is 0 either way) and
    reports the observed 403 block-ratio as intel. This is an AGENT-authored
    determination about the host (trusted metadata), NOT target-derived.

    B1 always RETREATS from a suspected WAF — it never engages/bypasses one; the
    flag is intel handed to primitive (see PRIMITIVE_WAF_HANDLING_DESIGN.md).
    ⚠️ Known blind spot: `-sf` keys on 403, so a 200-with-JS-challenge WAF won't
    trip it (shared open question with the primitive WAF doc)."""
    signal = None
    if _WAF_403_FLOOD_SIGNAL in stderr:
        signal = "403_flood"
    elif _WAF_MAXTIME_SIGNAL in stderr:
        signal = "maxtime"
    total = len(results)
    n403 = sum(1 for r in results if r.get("status") == 403)
    ratio = (n403 / total) if total else None
    return {"waf_suspected": signal is not None, "waf_signal": signal, "waf_block_ratio": ratio}


def run_ffuf(host: str, state: RunState, scope: dict, base: str | None = None) -> tuple[list[dict], dict]:
    """One ffuf invocation against a single host (decision 3: per-host invocation
    makes `-rate` a true per-host cap). Returns (hits, waf_flag).

    `base` is the scheme+authority to fuzz (e.g. "https://h.example.com" or
    "http://127.0.0.1:3000"), derived by the caller from the host's confirmed-live
    httpx_final_url. Real-run finding (2026-08-23): hardcoding https silently fails
    against http-only live hosts (e.g. a local test app) - so the scheme comes from
    what stage 4 actually confirmed, defaulting to https only when unknown."""
    base = base or f"https://{host}"
    seed = f"{base}/FUZZ"                              # FUZZ keyword = same-origin by construction (R1)
    out_path = state.raw_path(STAGE, f"ffuf_{_sanitize(host)}")   # R5 per-target raw file

    cmd = [
        "ffuf",
        "-u", seed,
        "-w", WORDLIST_PATH,
        "-e", ",".join(EXTENSIONS),
        "-recursion", "-recursion-depth", str(RECURSION_DEPTH),
        "-ac",                                         # auto-calibrate soft-404 / catch-all
        "-sf",                                         # stop on 403 flood (WAF breaker)
        "-maxtime-job", str(MAXTIME_JOB_SECONDS),      # per-host wall cap (WAF/abuse backstop)
        "-of", "json", "-o", str(out_path),
        "-noninteractive",
        "-s",                                          # silent: suppress the matched-path stdout echo
        "-t", str(THREADS),
        *ffuf_rate_args(scope).extra_args,             # -rate <n> (true per-host cap)
        *header_args(scope),                           # program-mandated headers on all target traffic
        # NO -r: do NOT follow redirects (R1 — a 30x is a recorded finding, not a chase)
    ]
    _stdout, stderr, _code = _run_tool(cmd)
    hits = _parse_ffuf_json(out_path)
    waf = _detect_waf(stderr, hits)
    if waf["waf_suspected"]:
        logger.warning("ffuf: WAF suspected on %s (signal=%s, 403-ratio=%s) - retreating (B1 never engages)",
                       host, waf["waf_signal"], waf["waf_block_ratio"])
    return hits, waf


def run_content_discovery(live_hosts: list[str], state: RunState, current_pass: int,
                          scope: dict, host_base: dict[str, str] | None = None
                          ) -> tuple[list[Asset], dict[str, list], dict[str, dict]]:
    """
    B1 content discovery over confirmed-live in-scope hosts.

    Returns (new_assets, records, waf_flags):
      - new_assets: list[Asset] type="url" for every discovered path, carrying
        curated ffuf_* metadata (NO body), for the caller to scope-gate + add.
      - records: {"endpoints": [Endpoint, ...]} — one endpoint per hit,
        target_derived=False (the path came from OUR wordlist). No
        parameters/secrets/services from this stage.
      - waf_flags: {host: {waf_suspected, waf_signal, waf_block_ratio}} for the
        caller to attach as trusted host metadata.
    Empty live_hosts → ([], {"endpoints": []}, {}).
    """
    if not live_hosts:
        return [], {"endpoints": []}, {}

    from pathlib import Path as _Path
    if not _Path(WORDLIST_PATH).exists():
        logger.error("ffuf wordlist not found at %s - skipping stage 6.5 content discovery "
                     "(install SecLists or repoint WORDLIST_PATH). Zero discovery, run continues.",
                     WORDLIST_PATH)
        return [], {"endpoints": []}, {}

    logger.info("Seeding stage 6.5 with %d confirmed-live in-scope host(s)", len(live_hosts))

    new_assets: list[Asset] = []
    endpoints: list[Endpoint] = []
    waf_flags: dict[str, dict] = {}

    with timed(state, "stage6_5.ffuf_total"):
        for host in live_hosts:
            try:
                hits, waf = run_ffuf(host, state, scope, base=(host_base or {}).get(host))
            except Exception:
                logger.exception("stage 6.5 ffuf failed for %s - skipping this host (R7)", host)
                continue                               # one host failing ≠ kill the stage
            waf_flags[host] = waf
            for h in hits:
                url = h.get("url")
                if not url:
                    continue
                status = h.get("status")
                length = h.get("length")
                content_type = h.get("content-type") or None   # HYPHENATED key (verified)
                # (real-run finding, Juice Shop) an app can return 5xx for many
                # unmatched paths (e.g. /api.bak, /rest.zip → Express error handler),
                # and ffuf's default -mc includes 500. Keep these hits (a 5xx can be a
                # lead) but FLAG them so jsluice/primitive/C4 can trivially skip
                # error responses without status-range logic.
                is_server_error = isinstance(status, int) and 500 <= status < 600
                asset_meta = {"ffuf_status": status, "ffuf_length": length,
                              "ffuf_content_type": content_type}
                ep_meta = {"ffuf_status": status, "ffuf_length": length}
                if is_server_error:
                    asset_meta["server_error"] = True
                    ep_meta["server_error"] = True
                asset = Asset(
                    value=url, type="url",
                    discovered_by="ffuf",
                    discovered_at_stage=STAGE, discovered_in_pass=current_pass,
                    metadata=asset_meta,
                )
                new_assets.append(asset)
                # Use the Asset's post-canonicalization value so persist_records'
                # parent lookup (which keys on canonical asset values) resolves.
                canon_url = asset.value
                parsed = urlparse(canon_url)
                endpoints.append(Endpoint(
                    url=canon_url, host=parsed.hostname or host, path=parsed.path or "/",
                    method="GET", content_type=content_type,
                    auth_status=("gated" if status in (401, 403) else None),
                    discovered_by="ffuf", target_derived=False,   # path came from OUR wordlist
                    discovered_at_stage=STAGE, discovered_in_pass=current_pass,
                    metadata=ep_meta,
                ))

    n_5xx = sum(1 for e in endpoints if e.metadata.get("server_error"))
    logger.info("Stage 6.5 content discovery: %d hit(s) across %d host(s) "
                "(%d flagged server_error/5xx); %d WAF-suspected host(s)",
                len(new_assets), len(live_hosts), n_5xx,
                sum(1 for w in waf_flags.values() if w["waf_suspected"]))
    return new_assets, {"endpoints": endpoints}, waf_flags
