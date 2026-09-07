"""
Stage 9: Deep tech fingerprinting (whatweb).

Locked design (Aug 2026, see /areas/hackbot.md "Tech-stack fingerprinting"
section for full reasoning): httpx (stage 4, httpx_tech) and katana (stage
6, katana_tech) both already do Wappalyzer-class tech detection - broad
but shallow on version precision. whatweb's plugin-based approach (1800+
plugins) is added here as a genuinely complementary DEEPER fingerprinting
pass, specifically for the version-level precision that enables CVE
correlation downstream in the primitive agent. Own dedicated stage rather
than folded into stage 4/6, since it's a distinct concern (fingerprinting
depth, not host-liveness or crawling) and doesn't need crawled URLs or
discovered params - just a live host, seeded from stage 4's confirmed-live
host set, independent of stages 5-7.

Real CLI facts (whatweb 0.6.3, verified via --help and a real invocation -
also required a one-time environment fix: Ubuntu's whatweb 0.6.3-1 apt
package has two broken require_relative paths, patched via sed, see
toolchain notes in /areas/hackbot.md):
  - bare positional targets, or -i FILE for a target list
  - -a LEVEL for aggression (1/3/4, no 2). Level 3 is whatweb's own
    documented example for exact-version detection - the whole reason
    this tool exists in this pipeline, so level 3 is used here rather
    than the stealthier default of 1.
  - --log-json=FILE writes JSON output to a FILE, NOT stdout - this is
    the one tool in this whole pipeline that doesn't stream to stdout,
    so run_whatweb() below writes to a tempfile and reads it back,
    unlike every other stage's _run_tool() usage.

(R1) whatweb runs with `--follow-redirect=same-site` so that an in-scope
redirect is still fingerprinted but an OFF-DOMAIN redirect hop is NOT
chased and -a 3'd. Before R1, whatweb followed redirects with no scope
constraint, and its real zonetransfer.me run followed the chain all the way
onto digi.ninja (out of scope) and ran its full level-3 plugin battery
against it - genuinely many requests to a third party, exactly the fact
pattern the scope gate exists to prevent (the gate governs what enters
assets.db, not what the tools TOUCH). This is the aggressive-tool half of
R1's "hybrid" resolution; httpx's single benign redirect GET is kept
(stage 4), only whatweb (-a 3, many requests) and katana (unbounded crawl)
are constrained. VERIFIED 2026-08-23: `whatweb --help` lists the
--follow-redirect WHEN values as never/http-only/meta-only/same-site/always
(so `same-site` is real; `never` is the documented fallback if a future
build drops it), and a real zonetransfer.me run confirmed behaviorally -
whatweb produced only zonetransfer.me `target` entries (http/https), no
digi.ninja fingerprint entry, where the pre-R1 run had -a 3'd digi.ninja.
See RECON_DESIGN_REVIEW_RESOLUTIONS.md R1.

Real --log-json output shape (verified against a real run against
zonetransfer.me, not docs alone): a JSON ARRAY of per-target objects (NOT
JSONL like every other stage's tool output - parse as one document, not
line-by-line). Real per-object fields: target, http_status,
request_config, plugins (dict keyed by plugin name - e.g. "Apache",
"HTTPServer", "X-Powered-By" - most values are {"string": [...]}, some
are bare empty dicts {} for presence-only signals like "Apache"/"PHP"
with no version string attached). Confirmed real: the file has a slightly
odd but fully valid format with bare "," lines between objects
(json.loads() on the whole file handles this without any special-casing
- tested against the actual real output, not assumed).

Confirmed real and important for downstream handling: whatweb FOLLOWS
REDIRECTS and produces a SEPARATE target entry per hop, not one followed
chain - a single seed host can produce several entries. With R1's
same-site constraint, an off-domain hop is no longer fingerprinted
(confirmed on the real run), but any same-site redirect entries are still
preserved as plain redirect-chain context, NOT turned into new assets or
run through the scope gate (whatweb's job here is enrichment, not
discovery, which stage 4/6 already own). See run_stage9()'s docstring.

*** REAL BUG FOUND AND FIXED (Aug 19) - read before changing invocation
batching ***
The FIRST version of this module invoked whatweb ONCE with multiple
hosts as positional args, then tried to partition the single flat result
list back by host - WRONG and confirmed wrong on a real 4-host run:
whatweb's JSON output has no field indicating which seed host a given
result entry came from, so the partition dumped EVERY OTHER HOST's
entries into EVERY host's whatweb_redirect_chain. FIX: run_whatweb() now
invokes whatweb ONCE PER HOST (a loop), so each invocation's result list
is unambiguously that one host's own chain. Slower but correct.

(R7) run_whatweb()'s per-host loop is fault-isolated: one host's whatweb
invocation raising does not abort the rest of the host set (that host
simply gets an empty result list) - the "one tool failing shouldn't kill
the run" guard applied at per-host granularity, the natural unit here
since whatweb already runs once per host.

Also confirmed real: whatweb faithfully reports zonetransfer.me's
intentionally-hostile fake X-Powered-By header verbatim, including a
literal <script> tag in the string value. Plugin string values are
untrusted attacker-influenceable content (whatweb_tech is in
state.TARGET_DERIVED_METADATA_KEYS per R9) and must never be rendered
unescaped anywhere downstream.

Like every other stage, this module does NOT classify new assets itself
and does NOT write assets.db directly - metadata_by_host is returned to
the caller (main.py) to apply via update_asset_metadata(). Unlike those
stages, there IS no new-assets return value at all here - see module
docstring above for why redirect targets are deliberately not turned into
new assets.
"""

import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from state import RunState
from rate_limits import whatweb_rate_args

logger = logging.getLogger(__name__)

STAGE = 9
DEFAULT_TIMEOUT_SECONDS = 300
AGGRESSION_LEVEL = 3  # locked design decision - see module docstring
# (R1, VERIFIED 2026-08-23) constrain whatweb's redirect following to
# same-site so an off-domain hop is not -a 3'd. `same-site` confirmed a real
# --follow-redirect WHEN value (never/http-only/meta-only/same-site/always);
# documented fallback is --follow-redirect=never (see module docstring).
FOLLOW_REDIRECT_FLAG = "--follow-redirect=same-site"


def _run_tool(cmd: list[str], timeout: int = DEFAULT_TIMEOUT_SECONDS) -> tuple[str, str, int]:
    import subprocess
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Tool timed out after %ss: %s", timeout, " ".join(cmd))
        return "", f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def _host_matches(target_url: str, host: str) -> bool:
    """
    True if target_url's hostname matches host exactly. Used to find
    which of whatweb's (possibly several, per-redirect-hop) result
    entries belongs to the original seed host, so that entry's plugins
    populate whatweb_tech on the EXISTING subdomain asset rather than
    guessing which entry is "the real one" some other way.
    """
    try:
        return urlparse(target_url).hostname == host
    except (ValueError, AttributeError):
        return False


def _scan_one_host(host: str, state: RunState, scope: dict) -> list[dict]:
    """
    Run whatweb (-a 3, same-site redirects only per R1) against a SINGLE
    host, writing --log-json to a tempfile (whatweb writes JSON output to a
    FILE, not stdout - the one tool in this pipeline that works this way,
    see module docstring) and reading it back. Returns the parsed list of
    result dicts for just this host's scan (its own entry plus any
    same-site redirect hops it produced). Empty list if whatweb produced no
    output or a malformed file for this host (same "not present = couldn't
    confirm" convention used elsewhere).

    One invocation per host, not batched - see module docstring's "REAL
    BUG FOUND AND FIXED" section for why batching multiple hosts into one
    invocation is unsafe with whatweb's actual output format.

    scope is the loaded scope.json dict, passed through for
    whatweb_rate_args() - see rate_limits.py for the confirmed-real
    -t/--wait flags (whatweb has no native requests/sec flag) and why
    -a 3's "additional requests on plugin match" behavior makes this a
    real per-host request-volume concern, not just a formality.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json_output_path = f.name
    # remove the empty file whatweb needs to create itself - see original
    # reasoning, unchanged from the batched version
    Path(json_output_path).unlink(missing_ok=True)

    rate = whatweb_rate_args(scope)
    logger.info("whatweb rate limit (%s): %s", host, rate.note)

    cmd = ["whatweb", "-a", str(AGGRESSION_LEVEL), FOLLOW_REDIRECT_FLAG,
           f"--log-json={json_output_path}", *rate.extra_args, host]
    stdout, stderr, code = _run_tool(cmd)
    # archive raw stdout per-host too, filename suffix keeps them distinct
    # in the raw archive rather than one invocation overwriting another
    state.save_raw(STAGE, f"whatweb_stdout_{host}", stdout)

    if code != 0:
        logger.error("whatweb exited %d for host %s: %s", code, host, stderr[:2000])
        return []

    json_path = Path(json_output_path)
    if not json_path.exists():
        logger.warning("whatweb completed but produced no --log-json output file for %s", host)
        return []

    raw_json = json_path.read_text()
    state.save_raw(STAGE, f"whatweb_json_{host}", raw_json)
    json_path.unlink(missing_ok=True)

    try:
        results = json.loads(raw_json)
    except json.JSONDecodeError as e:
        logger.error("whatweb --log-json output could not be parsed for %s: %s", host, e)
        return []

    if not isinstance(results, list):
        logger.warning("whatweb --log-json output for %s was not a JSON array as expected: %r",
                        host, type(results))
        return []

    return results


def run_whatweb(hosts: list[str], state: RunState, scope: dict) -> dict[str, list[dict]]:
    """
    Run whatweb (-a 3) against each host in turn (one invocation per
    host - see module docstring's "REAL BUG FOUND AND FIXED" section).
    Returns dict[host, list[result_dict]] - each host's own unambiguous
    result list, ready for build_metadata_updates() with no cross-host
    attribution guessing needed.

    (R7) Each per-host scan is isolated: if _scan_one_host() raises for one
    host, that host gets an empty result list and the loop continues with
    the remaining hosts, rather than one bad host aborting the whole stage.

    scope is the loaded scope.json dict, threaded through to
    _scan_one_host() for rate-limit resolution.
    """
    results_by_host: dict[str, list[dict]] = {}
    for host in hosts:
        try:
            results_by_host[host] = _scan_one_host(host, state, scope)
        except Exception:
            logger.exception("stage 9 whatweb scan failed for host %s - continuing (R7)", host)
            results_by_host[host] = []

    total_entries = sum(len(r) for r in results_by_host.values())
    logger.info("whatweb scanned %d host(s) individually, got %d total result entr(y/ies) (including redirect hops)",
                len(hosts), total_entries)
    return results_by_host


def build_metadata_updates(results_by_host: dict[str, list[dict]]) -> dict[str, dict]:
    """
    Convert each host's own unambiguous result list (from run_whatweb(),
    already scoped to that one host - no cross-host mixing possible now
    that whatweb runs once per host) into a metadata update: the entry
    whose target hostname matches the host itself becomes whatweb_tech/
    whatweb_status; every other entry for that SAME host's scan (its own
    real same-site redirect hops) becomes whatweb_redirect_chain - NOT new
    assets, NOT scope-gated (see module docstring for why).

    Returns dict[host_value, metadata_update] for the caller to apply via
    update_asset_metadata() - a host with no results at all (whatweb
    couldn't reach it, or produced nothing) is simply absent from the
    returned dict, same "absent = nothing confirmed" convention used
    elsewhere. A host whose only entries are redirect hops with none
    matching the host itself gets ONLY whatweb_redirect_chain, no
    whatweb_tech - a real possible case (e.g. the seed host's first
    response IS the redirect, no separate "clean" entry for the bare
    host), not a bug.
    """
    updates: dict[str, dict] = {}

    for host, results in results_by_host.items():
        if not results:
            continue

        own_entry = None
        other_entries = []
        for result in results:
            target = result.get("target", "")
            if own_entry is None and _host_matches(target, host):
                own_entry = result
            else:
                other_entries.append(result)

        update: dict = {}
        if own_entry is not None:
            update["whatweb_tech"] = own_entry.get("plugins", {})
            update["whatweb_status"] = own_entry.get("http_status")

        chain = [
            {"target": r.get("target"), "http_status": r.get("http_status")}
            for r in other_entries
        ]
        if chain:
            update["whatweb_redirect_chain"] = chain

        if update:
            updates[host] = update

    return updates


def run_stage9(known_in_scope_hosts: list[str], state: RunState, scope: dict) -> dict[str, dict]:
    """
    Run the full stage 9 sequence: whatweb against the current in-scope
    live host set (one invocation per host - see module docstring),
    converted into per-host metadata updates.

    known_in_scope_hosts should come from the caller filtering assets.db
    to CONFIRMED-LIVE hosts (e.g. carrying httpx_status_code, same
    liveness-inference approach as get_live_urls_for_x8() in main.py) -
    this function does not do that filtering itself, mirroring every
    other stage's "caller filters, stage consumes" convention. Unlike
    stage 4/5/6/7, there is no new_assets return value - see module
    docstring for why redirect targets are deliberately not modeled as
    new assets here.

    scope is the loaded scope.json dict, threaded through to run_whatweb()
    for rate-limit resolution.

    Returns metadata_updates: dict[host_value, metadata_update] for the
    caller to apply via update_asset_metadata() to EXISTING subdomain
    assets - same "apply metadata to existing assets, no scope gate
    involved" pattern already used for stage 4's httpx/naabu updates and
    stage 5's x8 updates.
    """
    results_by_host = run_whatweb(known_in_scope_hosts, state, scope)
    return build_metadata_updates(results_by_host)
