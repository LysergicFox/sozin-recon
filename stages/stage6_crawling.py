"""
Stage 6: Crawling (Katana, JS-aware).

Runs katana against the current in-scope live host set, discovering new
URLs via HTML crawling AND JS-embedded endpoint parsing (-jc). Locked
design decisions (see /areas/hackbot.md):

  - -jc (js-crawl) IS enabled: this is a crawl-COMPLETENESS mechanism
    (katana parses JS files it encounters and feeds discovered endpoints
    back into its OWN crawl queue), catching endpoints that only exist as
    JS-embedded fetch calls/router paths an HTML-only crawl would miss.
    This is a DIFFERENT concern from stage 7's dedicated JS-artifact
    deep-dive (source maps, secret extraction, raw JS file archival) -
    the two are complementary, not overlapping.
  - No explicit depth/page caps (-d/-mdp left at katana's own defaults) -
    full crawl trusted to the pipeline's loop-until-stable safety net,
    consistent with how depth isn't artificially limited elsewhere.
  - (R1) crawl scope pinned to the root domain via `-fs rdn` (field-scope =
    root domain name) so the crawl does NOT follow external links off the
    target's own root domain. Before R1, katana ran with -jc -kf all and no
    crawl-scope flag at all, so it would happily crawl off-scope
    destinations linked from the target - real off-scope traffic the scope
    gate never authorized (the gate governs what enters assets.db, not what
    the tools TOUCH). Residual, named: -fs rdn honors the root domain but
    NOT scope.json's out_of_scope exclusions or multiple unrelated roots -
    a precise -crawl-scope/-crawl-out-scope regex derived from scope.json
    is a tracked follow-up; -fs rdn is the pragmatic floor now.
    VERIFIED 2026-08-23 against the real installed katana: `katana -h`
    shows `-fs, -field-scope` accepts `dn,rdn,fqdn` (or a custom regex) and
    `rdn` (root-domain-name) is even katana's own default. Behaviorally
    confirmed on a real zonetransfer.me run - every request endpoint stayed
    on zonetransfer.me; off-root links (digi.ninja, twitter, google) showed
    up only as extracted page CONTENT in the raw archive, never as crawl
    requests. Note -kf still EXTRACTS off-site links from a page (that's
    fine - it just doesn't REQUEST them). See
    RECON_DESIGN_REVIEW_RESOLUTIONS.md R1.
  - Response persistence follows the established two-tier pattern: FULL
    unfiltered katana JSONL always goes to raw/stage6_katana.json via
    save_raw() (maximal fidelity - this is where response.body and full
    response.headers live). assets.db metadata per crawled URL gets ONLY
    a small selective set (status_code, content_type, title if present,
    a curated security-relevant header allowlist) - body and full headers
    NEVER touch assets.db. Downstream primitive/escalation/validator
    agents act against the LIVE target when actually testing, not a
    stale crawled snapshot, so a full body/headers copy in the queryable
    asset graph provides little value while risking real bloat (bodies
    observed at 20KB+ on a single small test page during real-tool
    verification for this stage).

Real katana JSONL output shape (verified against the actual installed
tool BEFORE writing this module, per the lesson from stage 4/5's
tool-interface bugs) is DIFFERENT from httpx's flat structure: everything
nests under request.{method,endpoint,raw} and
response.{status_code,headers,body,content_length,raw} - NOT top-level
fields like httpx uses. There are TWO distinct line shapes discovered on
a real run against zonetransfer.me: a success line (has "response") and a
failure line (has "error" instead, NO "response" key at all - e.g. port
closed, connection refused, network unreachable). On that real run, 14 of
15 crawled targets failed and only 1 succeeded - expected given
zonetransfer.me's deliberately quirky DNS setup pointing at hosts that
don't all actually serve HTTPS, not a bug. _extract_metadata() handles
both shapes explicitly rather than assuming every line has a response.

(R7) run_stage6() wraps the katana invocation so a katana failure yields
no crawl results this pass rather than aborting the whole run - stage 6 is
a single-tool stage, so the "one tool failing shouldn't kill the run"
guard sits at the one call site.

Like every other stage, this module does NOT classify new assets itself -
newly-crawled URLs are returned to the caller (main.py) to run through
the scope gate, same separation stage 1/3/4/5 all use.
"""

import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from state import Asset, RunState
from rate_limits import katana_rate_args
from http_headers import header_args
from destructive_paths import crawl_out_scope_regex
from stages.parallelism import bounded_parallel_map, resolve_host_workers

logger = logging.getLogger(__name__)

STAGE = 6
DEFAULT_TIMEOUT_SECONDS = 900  # crawling is the slowest single-invocation step so far, no explicit -d/-mdp caps

# Curated allowlist of response headers worth persisting to assets.db
# metadata - deliberately small. Chosen for direct security relevance
# (server/tech fingerprinting, and headers that showed real reflected/
# unsanitized content during real-tool verification for this stage, e.g.
# X-Powered-By and X-Xss on zonetransfer.me's own response). Anything not
# in this list is still fully available in the raw archive, just not
# duplicated into the queryable asset graph.
INTERESTING_RESPONSE_HEADERS = {
    "server",
    "x-powered-by",
    "content-security-policy",
    "x-frame-options",
    "x-xss-protection",
    "x-xss",  # non-standard, observed on zonetransfer.me - kept since custom/
              # unusual header names are exactly the kind of signal worth surfacing
    "strict-transport-security",
    "access-control-allow-origin",
    "set-cookie",
}


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


def _extract_metadata(obj: dict) -> dict:
    """
    Pull the small curated field set out of a katana JSONL line for
    assets.db metadata. Real katana output (verified against installed
    tool) has TWO distinct line shapes:
      - success: {"request": {...}, "response": {status_code, headers,
        body, ...}}
      - failure: {"request": {...}, "error": "<connection error text>"}
        - NO "response" key at all in this case (confirmed on a real
          run against zonetransfer.me: 14 of 15 crawled targets failed
          with port-closed/connection-refused/network-unreachable errors,
          only 1 succeeded - zonetransfer.me is a deliberately quirky
          DNS test domain, so a high failure rate crawling every
          discovered subdomain over HTTPS is expected, not a bug)
    Extracts status_code, content_type (parsed out of headers since
    katana doesn't give it as its own top-level field), and the curated
    header allowlist for successes. For failures, surfaces the error
    string instead - without this, a failed crawl and a successful crawl
    with no interesting headers would be indistinguishable in assets.db
    (both would show empty metadata), which makes the data hard to
    trust/debug. Body and full headers are deliberately excluded from
    both cases - see module docstring.

    Note (R9): katana_headers and katana_error carry target-authored,
    attacker-influenceable content and are listed in
    state.TARGET_DERIVED_METADATA_KEYS - downstream consumers must treat
    them as untrusted / escape on render.
    """
    if "error" in obj:
        return {"katana_error": obj["error"]}

    response = obj.get("response") or {}
    headers = response.get("headers") or {}
    # header keys in real katana output were observed Title-Cased
    # (e.g. "Content-Type", "X-Powered-By") - normalize to lowercase for
    # a case-insensitive allowlist match regardless of casing variance
    headers_lower = {k.lower(): v for k, v in headers.items()}

    metadata = {
        "katana_status_code": response.get("status_code"),
        "katana_content_type": headers_lower.get("content-type"),
    }

    interesting_headers = {
        k: v for k, v in headers_lower.items() if k in INTERESTING_RESPONSE_HEADERS
    }
    if interesting_headers:
        metadata["katana_headers"] = interesting_headers

    return metadata


def run_katana(hosts: list[str], state: RunState, scope: dict) -> tuple[dict[str, dict], list[str]]:
    """
    Crawl live in-scope hosts via katana (JS-aware, -jc enabled). Returns:
      - a dict keyed by crawled URL -> metadata dict (status_code,
        content_type, curated headers) for the caller to attach via
        add_assets()/update_asset_metadata() as appropriate
      - a list of every URL katana visited during the crawl, for the
        caller to turn into new Asset objects and run through the scope
        gate (mirrors stage 1/5's "return new-asset values, caller
        classifies" pattern)
    Hosts katana can't reach simply produce no JSONL lines for that host -
    same "not present = couldn't confirm" convention used elsewhere.

    (R1) `-fs rdn` pins the crawl to the target's own root domain so
    katana does not chase external links off-scope. VERIFIED 2026-08-23
    against the real katana (`-fs` accepts dn/rdn/fqdn; rdn = root domain
    name, katana's default) and behaviorally on a real zonetransfer.me run
    (every requested endpoint stayed on zonetransfer.me). Residual: this
    honors the root domain but not out_of_scope exclusions or multiple
    unrelated roots - a precise scope.json-derived crawl-scope regex is a
    tracked follow-up (see module docstring / RESOLUTIONS R1).

    scope is the loaded scope.json dict, passed through for
    katana_rate_args() - see rate_limits.py. Note this only throttles
    request RATE, not crawl depth/breadth - -d/-mdp are still deliberately
    left at katana's own defaults per this module's existing design (see
    module docstring), a separate concern from how fast the crawl goes.
    """
    if not hosts:
        return {}, []

    # (R3 CLOSED) One katana invocation PER HOST, parallelized across distinct
    # hosts. With a single seed host per process, `-rl` is a true per-host cap
    # (no host can absorb a shared multi-host budget). resolve_host_workers()
    # collapses to sequential (workers=1) under a global rate scope so the
    # aggregate never exceeds the stated global ceiling.
    rate = katana_rate_args(scope)
    allowed_rps = int(rate.extra_args[1])   # (G1) -rl value = the authorized per-host rps (true per-host cap)
    workers = resolve_host_workers(scope)
    logger.info("katana rate limit (per host): %s; host workers=%d", rate.note, workers)

    def _crawl_one(host: str) -> tuple[dict[str, dict], list[str]]:
        # (G1) once the rate-guard has tripped, send no further target traffic
        if not state.ledger.guard_allows():
            logger.info("katana: skipping %s - request rate-guard tripped", host)
            return {}, []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(f"https://{host}")
            seeds_path = f.name
        local_meta: dict[str, dict] = {}
        local_urls: list[str] = []
        stdout = ""
        # (G1) time the crawl; crawled-endpoint count is a lower bound on requests sent
        # (katana also fetches robots/sitemap/JS it doesn't emit), sound for the tripwire.
        with state.ledger.measure(host, "katana", allowed_rps=allowed_rps, at_stage=STAGE) as inv:
            try:
                stdout, stderr, code = _run_tool([
                    "katana", "-list", seeds_path,
                    "-jsonl", "-silent",
                    "-jc",
                    "-kf", "all",
                    "-td",
                    "-fs", "rdn",  # (R1, VERIFIED) field-scope = root domain name - stay on the target's own root domain
                    # SAFETY: never FOLLOW a link whose path names a state-changing action
                    # (delete/logout/reset-password/…). katana follows app-provided, often
                    # already-tokened URLs, so following one can complete the action; -cos
                    # (crawl-out-scope) excludes them from being crawled. Shared token set with
                    # the x8 guard (destructive_paths).
                    "-cos", crawl_out_scope_regex(),
                    *rate.extra_args,
                    *header_args(scope),   # program-mandated headers on all target traffic
                ])
            finally:
                Path(seeds_path).unlink(missing_ok=True)

            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("katana: could not parse line as JSON: %r", line)
                    continue
                request = obj.get("request") or {}
                endpoint = request.get("endpoint")
                if not endpoint:
                    continue
                local_urls.append(endpoint)
                local_meta[endpoint] = _extract_metadata(obj)
            inv.requests = len(local_urls)   # (G1) crawled endpoints ~= requests (lower bound)

        state.save_raw(STAGE, f"katana_{host}", stdout)   # (R5) per-host archive, no collision
        return local_meta, local_urls

    # (R7) a per-host crawl failure is logged + skipped by the helper, not fatal.
    per_host = bounded_parallel_map(_crawl_one, hosts, workers=workers, label="stage 6 katana")

    metadata_by_url: dict[str, dict] = {}
    crawled_urls: list[str] = []
    for host in hosts:                       # stable seed order for determinism
        if host not in per_host:
            continue
        local_meta, local_urls = per_host[host]
        crawled_urls.extend(local_urls)
        metadata_by_url.update(local_meta)

    logger.info("katana crawled %d URL(s) across %d seed host(s)", len(crawled_urls), len(hosts))
    return metadata_by_url, crawled_urls


def run_stage6(known_in_scope_hosts: list[str], state: RunState, current_pass: int, scope: dict) -> list[Asset]:
    """
    Run the full stage 6 sequence: katana crawl over the current in-scope
    host set.

    known_in_scope_hosts should come from the caller filtering assets.db
    to scope_status == "in_scope" subdomain-type asset values - this
    function does not do that filtering itself, mirroring stage 3/4/5's
    "caller filters, stage consumes" convention.

    (R7) The single katana invocation is wrapped so a katana failure
    yields no new assets this pass rather than aborting the whole run -
    stage 6's "one tool failing shouldn't kill the run" guard sits here at
    its one call site.

    scope is the loaded scope.json dict, threaded through to run_katana()
    for rate-limit resolution.

    Returns new_assets: list[Asset] - every URL katana crawled, as
    type="url" Assets carrying the curated metadata directly on
    construction (status_code/content_type/headers), for the caller to
    run through the scope gate before add_assets(). Unlike stage 4/5,
    there's no separate metadata_updates return - katana-discovered URLs
    are essentially always NEW url assets (a crawl visiting a URL that's
    already a known asset is the normal re-discovery case, handled by
    add_assets()'s existing metadata-merge-on-duplicate behavior, not a
    special case this stage needs to reason about itself).
    """
    try:
        metadata_by_url, crawled_urls = run_katana(known_in_scope_hosts, state, scope)
    except Exception:
        logger.exception("stage 6 katana failed - no crawl results this pass (R7)")
        metadata_by_url, crawled_urls = {}, []

    new_assets = [
        Asset(
            value=url,
            type="url",
            discovered_by="katana",
            discovered_at_stage=STAGE,
            discovered_in_pass=current_pass,
            metadata=metadata_by_url.get(url, {}),
        )
        for url in crawled_urls
    ]

    return new_assets
