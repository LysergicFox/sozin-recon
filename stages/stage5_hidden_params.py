"""
Stage 5: Hidden parameter discovery (paramspider + x8).

Placement (locked): runs BEFORE crawling (stage 6). Neither tool depends on
katana's crawl output - paramspider mines wayback/otx/commoncrawl history,
x8 response-diff-fuzzes live hosts confirmed by stage 4.

Two tools, two output shapes:
  1. paramspider - mines historical parameterized URLs for a root domain →
     new type="url" Assets through the scope gate (same as gau/waybackurls).
  2. x8 - response-diff fuzzes a LIVE url to find which injected param names
     change the response. (Track D) x8's findings are now emitted as
     first-class `parameter` records (name, endpoint, method=GET,
     location=query, reflected=True) rather than an `x8_reflected_params`
     metadata blob on the url asset. The param NAMES come from OUR SecLists
     wordlist, not the target, so these records are target_derived=False.

Like every other stage, this module does NOT classify new assets or write
assets.db itself - paramspider's new url Assets and x8's Parameter records
are returned to the caller (main.py), which scope-gates the assets and
persists the records.
"""

import hashlib
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from collections import defaultdict

from state import Asset, RunState, timed, Parameter
from rate_limits import x8_rate_args
from http_headers import x8_header_args
from stages.parallelism import bounded_parallel_map, resolve_max_workers
from destructive_paths import is_destructive_path
from url_hygiene import is_malformed_url_asset

logger = logging.getLogger(__name__)

STAGE = 5
DEFAULT_TIMEOUT_SECONDS = 300

# --- x8 input right-sizing (2026-09-07, RECON_PERF_COVERAGE_FINDINGS) ---------
# The first content-rich run (ginandjuice.shop) seeded x8 with 177 live URLs on a
# single host, run serially → ~2.5h, much of it wasted: x8 fuzzes QUERY-param
# NAMES from a wordlist, so it is pointless against static assets (they don't
# process params) and redundant across many URLs sharing one path/handler. These
# reduce x8's input to the URLs actually worth fuzzing.

# Static / non-param-processing extensions x8 should skip. .js is handled by
# jsluice (stage 7), not param-fuzzed here.
_X8_SKIP_EXTENSIONS = {
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".pdf", ".zip", ".gz", ".tar",
    ".rss", ".xml", ".txt",
}
# Crawl/history-noise "URLs" (HTML fragments, stray backslashes) that aren't real
# endpoints — e.g. gau/wayback returned `/%3C/a%3E` (</a>). Detection is shared
# with ingestion (url_hygiene): path-scoped, so a legit endpoint carrying a payload
# in its QUERY (e.g. /?search=%3Cscript%3E...) is kept as an x8 target.
# SAFETY: skip param-fuzzing endpoints whose path names a state-changing action
# (delete/deactivate/reset-password/…) — recon is non-destructive, but x8 sends
# many requests at an endpoint, and an app acting on GET could be triggered. The
# token set + matcher are shared (destructive_paths) with the katana crawl guard.
# Backstop cap on distinct x8 targets per host after filtering/dedup (a pathological
# host shouldn't reintroduce the serial explosion). Generous; logs when it clamps.
MAX_X8_URLS_PER_HOST = 100


def _sanitize(text: str) -> str:
    """Filesystem-safe token for per-target raw-archive filenames (R5), mirroring
    stage 1/3/9's helpers so x8/paramspider raw files don't overwrite each other."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)


def x8_candidate_urls(live_urls: list[str]) -> list[str]:
    """Reduce the raw live-URL set to those worth x8 param-fuzzing:
      - drop static assets (extension) and crawl-noise fragments;
      - DEDUPE by (host, path): x8 discovers reflected param NAMES from a wordlist,
        so many URLs sharing one path/handler are redundant — one representative
        (first-seen) per (host, path) suffices, and the existing query string does
        not change which new param names the handler accepts;
      - cap per host at MAX_X8_URLS_PER_HOST as a backstop.
    Order-preserving (first-seen representative kept)."""
    seen_paths: set[tuple[str, str]] = set()
    per_host: dict[str, int] = defaultdict(int)
    out: list[str] = []
    for url in live_urls:
        if is_malformed_url_asset(url):
            continue
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        if is_destructive_path(path):
            logger.info("x8: SKIP %s - path signals a state-changing action; recon "
                        "does not actively probe destructive endpoints", url)
            continue
        if os.path.splitext(path)[1].lower() in _X8_SKIP_EXTENSIONS:
            continue
        key = (host, path)
        if key in seen_paths:
            continue
        if per_host[host] >= MAX_X8_URLS_PER_HOST:
            continue
        seen_paths.add(key)
        per_host[host] += 1
        out.append(url)
    return out


def _run_tool(cmd: list[str], timeout: int = DEFAULT_TIMEOUT_SECONDS, input_text: str | None = None) -> tuple[str, str, int]:
    import subprocess
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Tool timed out after %ss: %s", timeout, " ".join(cmd))
        return "", f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def _run_tool_in_dir(cmd: list[str], cwd: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> tuple[str, str, int]:
    """
    Same as _run_tool, but runs the subprocess with an explicit working
    directory. Needed for paramspider, which writes output to a fixed path
    (results/<domain>.txt) relative to cwd rather than accepting an
    output-path flag - see run_paramspider()'s docstring.
    """
    import subprocess
    logger.info("Running (cwd=%s): %s", cwd, " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Tool timed out after %ss: %s", timeout, " ".join(cmd))
        return "", f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def run_paramspider(domain: str, state: RunState) -> list[Asset]:
    """
    Mine historical parameterized URLs for a root domain via paramspider.

    paramspider (devanshbatham/ParamSpider, confirmed against the real
    installed tool) has NO -o/--output flag - it always writes to
    results/<domain>.txt relative to cwd. This function controls that by
    running paramspider with an explicit cwd in a temp directory, reads the
    file back, archives it, and returns new type="url" Assets for the
    caller to scope-gate.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        stdout, stderr, code = _run_tool_in_dir(
            ["paramspider", "-d", domain],
            cwd=tmpdir,
        )

        expected_path = Path(tmpdir) / "results" / f"{domain}.txt"
        try:
            with open(expected_path) as f:
                raw_output = f.read()
        except FileNotFoundError:
            logger.warning(
                "paramspider: expected output file not found at results/%s.txt "
                "(domain=%s, possibly zero results or a tool failure - stderr: %r)",
                domain, domain, stderr[:300],
            )
            raw_output = ""

    state.save_raw(STAGE, f"paramspider_{_sanitize(domain)}", raw_output)   # (R5) per-target

    assets = []
    for line in raw_output.splitlines():
        url = line.strip()
        if url:
            assets.append(Asset(
                value=url,
                type="url",
                discovered_by="paramspider",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,  # caller overwrites with real pass number
            ))

    logger.info("paramspider found %d parameterized URLs for %s", len(assets), domain)
    return assets


# x8 param wordlist. x8 runs the WHOLE list against EVERY candidate URL, so a big
# list dominates stage 5 (SecLists burp-parameter-names.txt = 6,453 names ≈
# ~1 min/endpoint → ginandjuice's ~83 endpoints ≈ ~80 min). We ship a CURATED
# common-web-param list WITH the repo (wordlists/params_common.txt, ~375 high-
# signal names incl. camelCase *Id variants) that covers the common params
# (search/category/postId/page/sort/filter/id/q/…) — the app-specific SecLists
# "top-55-apps" list (211) MISSES those, so it's not a usable smaller option.
# Compact + high-coverage keeps stage 5 fast without a coverage regression. For an
# exhaustive pass on high-interest hosts, swap to SecLists' burp-parameter-names
# (the deferred two-phase-depth idea). Resolved from the module path so it works
# both locally and in the /app Docker image.
_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_X8_WORDLIST = _REPO_ROOT / "wordlists" / "params_common.txt"


def run_x8(url: str, state: RunState, scope: dict, wordlist: Path = DEFAULT_X8_WORDLIST) -> list[str]:
    """
    Response-diff fuzz a single live URL via x8 to find parameter names that
    change the response (reflected/processed params - candidate injection
    points, not confirmed vulnerabilities). Returns a plain list of
    discovered param names, or empty on nothing/failure.

    scope is threaded for x8_rate_args() (x8 has no native requests/sec flag;
    -c/-d derive a delay). wordlist defaults to a real SecLists param-name
    list - without -w, x8 reports "wordlist len: 0" and finds nothing.
    x8's stdout with -O json has a human-readable preamble before the JSON
    array (locate by first '['); the real field is "found_params".
    """
    cmd = ["x8", "-u", url, "-O", "json"]
    if wordlist is not None:
        if not wordlist.exists():
            logger.error(
                "x8 wordlist not found at %s - proceeding without -w, x8 will "
                "have nothing to fuzz with. Check that SecLists is cloned.",
                wordlist,
            )
        else:
            cmd.extend(["-w", str(wordlist)])

    rate = x8_rate_args(scope)
    logger.info("x8 rate limit (%s): %s", url, rate.note)
    cmd.extend(rate.extra_args)
    cmd.extend(x8_header_args(scope))   # program-mandated headers on all target traffic

    stdout, stderr, code = _run_tool(cmd)
    # (R5) per-target raw filename so each URL's x8 output is preserved instead of
    # every run overwriting a single stage5_x8.json. Readable host + short URL hash
    # (the deduped candidate set already guarantees one URL per (host, path)).
    _p = urlparse(url)
    _tag = f"{_sanitize(_p.hostname or 'url')}_{hashlib.sha1(url.encode()).hexdigest()[:8]}"
    state.save_raw(STAGE, f"x8_{_tag}", stdout)

    if not stdout.strip():
        return []

    json_start = stdout.find("[")
    if json_start == -1:
        logger.warning("x8: no JSON array found in output for %s: %r", url, stdout[:200])
        return []

    try:
        obj = json.loads(stdout[json_start:])
    except json.JSONDecodeError:
        logger.warning("x8: could not parse output as JSON for %s: %r", url, stdout[:200])
        return []

    if isinstance(obj, list):
        results = obj
    elif isinstance(obj, dict):
        results = obj.get("results") or [obj]
    else:
        results = []

    params = []
    for result in results:
        if not isinstance(result, dict):
            continue
        for entry in result.get("found_params") or []:
            # x8's real found_params entries are DICTS, e.g.
            #   {"name": "category", "value": null, "diffs": "", "status": 200,
            #    "size": 11340, "reason_kind": "Reflected"}
            # (verified against real x8 output vs ginandjuice.shop, 2026-09-08 —
            # the original code assumed bare strings, which crashed add_parameters
            # with "type 'dict' is not supported" the first time x8 found anything).
            # Extract the name; tolerate a bare string too (defensive).
            name = entry.get("name") if isinstance(entry, dict) else entry
            if name:
                params.append(name)

    logger.info("x8 found %d reflected param(s) for %s", len(params), url)
    return params


def run_stage5(root_domains: list[str], live_urls: list[str],
               state: RunState, current_pass: int, scope: dict) -> tuple[list[Asset], dict[str, dict], dict[str, list]]:
    """
    Run the full stage 5 sequence: paramspider (per root domain) + x8 (per
    live URL).

    live_urls should come from the caller filtering assets.db to in_scope,
    stage-4-confirmed-live url assets.

    Returns a THREE-tuple (Track D added the third element):
      - new_assets: list[Asset] - paramspider's parameterized URLs, for the
        caller to scope-gate + add_assets().
      - metadata_updates: dict[str, dict] - kept for contract symmetry with
        stage 4/7; empty now that x8 findings are `parameter` records rather
        than an x8_reflected_params metadata blob.
      - records: dict[str, list] - {"parameters": [Parameter, ...]} from x8,
        for the caller to persist via persist_records() (which sets asset_id
        by matching the endpoint value). x8 param names come from our
        wordlist → target_derived=False; reflected=True (they changed the
        response).
    """
    new_assets: list[Asset] = []
    with timed(state, "stage5.paramspider"):
        for domain in root_domains:
            try:
                found = run_paramspider(domain, state)
                for a in found:
                    a.discovered_in_pass = current_pass
                new_assets.extend(found)
            except Exception:
                logger.exception("Stage 5 paramspider failed for domain %s", domain)
                continue

    # Right-size x8's input first: drop static assets + crawl-noise and dedupe by
    # (host, path) so we fuzz each real handler once instead of every historical
    # URL (the ginandjuice run seeded 177 URLs on one host, ~2.5h, mostly waste).
    x8_urls = x8_candidate_urls(live_urls)
    logger.info("x8: %d live URL(s) → %d candidate(s) after dropping static/noise + "
                "deduping by (host, path)", len(live_urls), len(x8_urls))

    # x8 is ACTIVE (it fuzzes params against the target) and multiple candidate URLs
    # can still share a host, so we CANNOT flat-parallelize across URLs — that would
    # run two x8 processes at one host and blow its per-host rate. Instead group URLs
    # by host and parallelize across DISTINCT hosts, keeping a single host's URLs
    # serial (each host still sees only its own x8 rate; aggregate = workers x rate
    # across distinct hosts, the same model as the other parallel stages).
    urls_by_host: dict[str, list[str]] = defaultdict(list)
    for url in x8_urls:
        urls_by_host[urlparse(url).hostname or ""].append(url)

    def _x8_for_host(host: str) -> list[Parameter]:
        host_params: list[Parameter] = []
        for url in urls_by_host[host]:                 # serial within one host
            try:
                params = run_x8(url, state, scope)
            except Exception:
                logger.exception("Stage 5 x8 failed for url %s", url)
                continue
            for name in params:
                host_params.append(Parameter(
                    name=name,
                    host=host,
                    endpoint=url,
                    method="GET",
                    location="query",
                    reflected=True,
                    discovered_by="x8",
                    target_derived=False,  # names come from our SecLists wordlist
                    discovered_at_stage=STAGE,
                    discovered_in_pass=current_pass,
                ))
        return host_params

    parameters: list[Parameter] = []
    with timed(state, "stage5.x8_total"):
        per_host = bounded_parallel_map(_x8_for_host, list(urls_by_host.keys()),
                                        workers=resolve_max_workers(scope),
                                        label="stage 5 x8 (per host)")
    for host in urls_by_host:
        parameters.extend(per_host.get(host, []))

    metadata_updates: dict[str, dict] = {}
    return new_assets, metadata_updates, {"parameters": parameters}
