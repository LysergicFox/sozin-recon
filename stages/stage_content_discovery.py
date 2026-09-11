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
from stages.parallelism import bounded_parallel_map, resolve_host_workers

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
WORDLIST_PATH = _os.path.join(_SECLISTS_DIR, "Discovery/Web-Content/quickhits.txt")

# Extension permutations appended to each FUZZ word (ffuf -e).
#
# Coverage right-size (2026-09-07, RECON_PERF_COVERAGE_FINDINGS): ffuf sends
# (1 + len(EXTENSIONS)) requests PER wordlist entry, so extensions multiply the
# request count. Under a per-host budget of ~rate x -maxtime-job (e.g. 2 req/s x
# 1200 s = 2,400 requests), a big dir-name list x 10 extensions blows the budget
# by ~100x and only ~1% of the space is ever tested.
#
# quickhits.txt is a list of COMPLETE, specific high-signal paths (.git/config,
# .env, .htpasswd, ...), not directory stems you append extensions to — so it is
# used WITHOUT -e. ~2,570 complete paths ≈ the budget → near-full coverage of a
# high-signal list instead of a sliver of a huge one. Extensions belong with a
# directory-name list (raft-medium-directories): if you repoint WORDLIST_PATH at
# one, restore a suitable EXTENSIONS set here and the -e flag returns automatically
# (it is emitted only when EXTENSIONS is non-empty — see run_ffuf()).
EXTENSIONS: list[str] = []

# ffuf's stderr early-stop signals (exit code is 0 in BOTH cases — verified).
_WAF_403_FLOOD_SIGNAL = "unusual amount of 403 responses"
_WAF_MAXTIME_SIGNAL = "Maximum running time for this job reached"

# Backstop for a WAF that 403-walls most probes WITHOUT tripping ffuf's `-sf`
# flood message (observed on a real run: an AWS ELB/WAF returned a steady 403
# stream `-sf`'s window tolerated, so `-sf` stayed quiet while ~98% of matched
# responses were 403). A near-total 403 ratio over a meaningful sample is itself
# a WAF signal, independent of the stderr message.
_WAF_403_RATIO_THRESHOLD = 0.9     # >=90% of matched responses are 403
_WAF_403_RATIO_MIN_SAMPLES = 20    # ...and enough matches that the ratio is meaningful

# Pre-flight JS-challenge / interstitial markers (case-insensitive substrings).
# These indicate the ENTIRE response is a challenge/soft-block wall (Cloudflare,
# DDoS-Guard, Imperva, etc.), so fuzzing the host just hammers a challenge page —
# and the `-sf` 403-flood breaker never fires because a challenge is served as 200.
# DELIBERATELY high-precision: NOT bare "captcha"/"recaptcha" (a reCAPTCHA widget
# on a real login form is a legit page, not a WAF wall) and NOT is_behind_waf alone
# (most real targets sit behind a WAF/CDN yet serve content normally). Checked
# against the host's stage-4 httpx_title + httpx_body_preview — data already
# collected, so this pre-flight sends NO extra traffic.
_JS_CHALLENGE_MARKERS = (
    "just a moment",                              # Cloudflare challenge <title>
    "attention required! | cloudflare",           # Cloudflare block page
    "checking your browser before accessing",     # Cloudflare / DDoS-Guard interstitial
    "cf-browser-verification",
    "challenge-platform",                          # Cloudflare challenge body
    "please enable javascript and cookies to continue",
    "verifying you are human",                     # Cloudflare Turnstile interstitial
    "ddos protection by",                          # DDoS-Guard
    "ddos-guard",
    "powered by incapsula",                        # Imperva Incapsula interstitial
    "_incapsula_resource",
)


def _challenge_signal(meta: dict) -> str | None:
    """Return the matched JS-challenge marker if the host's stage-4 httpx title or
    body preview looks like a WAF challenge/interstitial wall, else None. Used to
    RETREAT from a host before fuzzing it (B1 never engages a WAF). Only the
    challenge-wall markers above trip this — never is_behind_waf on its own."""
    haystack = " ".join(
        str(meta.get(k) or "") for k in ("httpx_title", "httpx_body_preview")
    ).lower()
    if not haystack.strip():
        return None
    for marker in _JS_CHALLENGE_MARKERS:
        if marker in haystack:
            return marker
    return None


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
    flag is intel handed to a downstream consumer.

    Three signals, in priority order:
      - `403_flood` — ffuf's `-sf` emitted its stderr flood message (also stops ffuf).
      - `maxtime`   — ffuf hit its `-maxtime-job` cap.
      - `403_ratio` — BACKSTOP: `-sf` stayed quiet but >=`_WAF_403_RATIO_THRESHOLD`
        of a meaningful sample (>=`_WAF_403_RATIO_MIN_SAMPLES`) of matched responses
        were 403 — a WAF 403-walling the scan without tripping `-sf`.

    `-sf` keys on 403 floods (a WAF serving 403s). The complementary
    200-with-JS-challenge case (a WAF serving a 200 challenge wall, which `-sf`
    can't see) is handled UP FRONT by the pre-flight _challenge_signal() check in
    run_content_discovery(): such a host is retreated-from before fuzzing, so it
    never reaches this post-hoc path."""
    signal = None
    if _WAF_403_FLOOD_SIGNAL in stderr:
        signal = "403_flood"
    elif _WAF_MAXTIME_SIGNAL in stderr:
        signal = "maxtime"
    total = len(results)
    n403 = sum(1 for r in results if r.get("status") == 403)
    ratio = (n403 / total) if total else None
    # Ratio backstop: a host 403-walling most probes without an `-sf` message.
    if (signal is None and ratio is not None
            and total >= _WAF_403_RATIO_MIN_SAMPLES
            and ratio >= _WAF_403_RATIO_THRESHOLD):
        signal = "403_ratio"
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
        # -e only when EXTENSIONS is non-empty (quickhits ships complete paths, so
        # extensions are off; a directory-name list would set them — see EXTENSIONS).
        *(["-e", ",".join(EXTENSIONS)] if EXTENSIONS else []),
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

    # PRE-FLIGHT RETREAT: a host whose stage-4 fingerprint already looks like a
    # JS-challenge / interstitial wall gets no ffuf at all — fuzzing it just hammers
    # a challenge page for the whole -maxtime-job window, and the `-sf` 403 breaker
    # can't see a 200 challenge. Uses already-collected metadata (no extra traffic).
    # B1 never engages a WAF; retreat is recorded as intel for primitive/the reviewer.
    meta_by_host = {a.value: a.metadata for a in state.load_assets() if a.type == "subdomain"}
    to_fuzz: list[str] = []
    for host in live_hosts:
        marker = _challenge_signal(meta_by_host.get(host, {}))
        if marker is not None:
            logger.warning("ffuf: RETREAT from %s - stage-4 fingerprint matches a JS-challenge/"
                           "interstitial wall (%r); B1 does not fuzz a challenged host", host, marker)
            waf_flags[host] = {"waf_suspected": True, "waf_signal": "js_challenge",
                               "waf_block_ratio": None}
        else:
            to_fuzz.append(host)
    if not to_fuzz:
        logger.info("stage 6.5: every live host retreated-from as WAF-challenged; no ffuf run")

    # Parallelize ffuf across DISTINCT hosts (each keeps its own per-host -rate; the
    # helper is R3-correct by construction and R7-isolates a per-host failure). The
    # network-bound ffuf runs concurrently; hit processing below stays serial.
    # resolve_host_workers() forces sequential (workers=1) under a global rate scope
    # so W concurrent hosts x per-host rate can't exceed the stated global ceiling.
    workers = resolve_host_workers(scope)
    with timed(state, "stage6_5.ffuf_total"):
        def _ffuf_one(host):
            return run_ffuf(host, state, scope, base=(host_base or {}).get(host))
        per_host = bounded_parallel_map(_ffuf_one, to_fuzz, workers=workers,
                                        label="stage 6.5 ffuf")
        for host in to_fuzz:                           # retreated hosts already have their waf_flag
            if host not in per_host:
                continue                               # failed + logged in the helper (R7)
            hits, waf = per_host[host]
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
