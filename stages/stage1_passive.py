"""
Stage 1: Passive discovery.

Runs each passive-source tool against the root domain(s) from scope.json,
parses each tool's (differently-shaped) output, and normalizes results into
Asset objects. Raw output from every tool call is archived via
state.save_raw() before any parsing, so a parsing bug never loses data.

Tools run in this stage (matching the locked pipeline design):
  - subfinder    (subdomains, JSON output)
  - assetfinder  (subdomains, plain text output)
  - amass        (subdomains, plain text output - deeper/slower complement to subfinder)
  - gau           (historical URLs, plain text output)
  - waybackurls  (historical URLs, plain text output)
  - certspotter  (subdomains via certificate-transparency SANs, JSON HTTPS
                  API - see run_certspotter()'s docstring for why this is
                  Cert Spotter and not crt.sh, the tool originally named
                  for this slot)

(R5) Every runner suffixes its raw-archive filename with a sanitized token
of the root domain it ran against (via _sanitize()), so a multi-root scope
doesn't have each domain overwrite the previous domain's raw archive - the
same per-target filename discipline stage 9 already uses per host.
certspotter additionally suffixes per page (R11 pagination).

Deliberately NOT yet included: chaos (needs API key setup you may not have
done yet), GitHub secret scanning (gitleaks - confirmed 2026-08-22 as the
intended tool name, not yet wired into any stage), asnmap (likely needs a
new asset shape - CIDR/ASN isn't one of the current AssetType values,
that's a state.py design question, not just a new stage1 runner). Keeping
stage 1's cut to the tools most likely to "just work" so pipeline mechanics
get validated before adding every source.
"""

import subprocess
import json
import logging
import re
import shutil
import time
from pathlib import Path

from state import Asset, RunState

logger = logging.getLogger(__name__)

STAGE = 1
DEFAULT_TIMEOUT_SECONDS = 300  # per-tool ceiling; a hung tool shouldn't hang the whole stage

AMASS_CONFIG_DIR = Path.home() / ".config" / "amass"

CERTSPOTTER_API_URL = "https://api.certspotter.com/v1/issuances"
# (R11) Cert Spotter returns a bounded page of issuances per request and
# paginates via ?after=<last id>. Request an explicit page size and page
# with after= until a short/empty page signals the end. MAX_PAGES is a hard
# safety cap so a pathological/looping response (or an API that silently
# ignores after=) can't burn the whole ~10 req/hour anonymous budget - the
# no-new-ids guard in run_certspotter() also stops early in that case.
CERTSPOTTER_PAGE_LIMIT = 100
CERTSPOTTER_MAX_PAGES = 50


def _run_tool(cmd: list[str], timeout: int = DEFAULT_TIMEOUT_SECONDS) -> tuple[str, str, int]:
    """
    Run a CLI tool, capturing stdout/stderr. Returns (stdout, stderr, returncode).
    Does not raise on nonzero exit - callers decide what a failure means per tool,
    since some tools (e.g. subfinder with zero results) may exit nonzero without
    it being a real error.

    On a timeout, salvages whatever partial output the tool had already
    produced before being killed, rather than discarding it (fixed
    2026-08-22, surfaced while investigating an amass hang that recurred
    despite a confirmed-fresh config - see CHANGELOG). Previously this
    branch unconditionally returned ("", ...) on ANY timeout, meaning a
    tool that produced real, useful output right up until one slow step
    hung would still lose 100% of it - e.g. amass having already queried
    44 of 45 passive data sources successfully before one hangs.

    Confirmed via a real, direct test (not assumed from docs) that
    subprocess.run()'s TimeoutExpired exception carries whatever
    stdout/stderr the process had already produced in its .stdout/.stderr
    attributes. Non-obvious wrinkle also confirmed directly: even though
    this call passes text=True, those salvaged attributes come back as
    raw BYTES on timeout, not the decoded str the non-timeout return path
    gives - decoded explicitly below (errors="replace" rather than the
    default strict mode, since a multi-byte character split exactly at
    the kill boundary shouldn't turn a timeout into an additional
    UnicodeDecodeError crash on top of it) so this function's return type
    is consistently str regardless of which branch produced it.
    """
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as exc:
        partial_stdout = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        partial_stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
        if partial_stdout:
            logger.warning(
                "Tool timed out after %ss but had already produced %d byte(s) "
                "of output before being killed - salvaging it rather than "
                "discarding: %s",
                timeout, len(exc.stdout), " ".join(cmd),
            )
        else:
            logger.warning("Tool timed out after %ss: %s", timeout, " ".join(cmd))
        return partial_stdout, partial_stderr or f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def _sanitize(domain: str) -> str:
    """
    (R5) Turn a domain into a filesystem-safe token for per-target raw
    archive filenames, so a multi-root scope doesn't have each successive
    root overwrite the previous one's raw archive (mirrors stage 9's
    per-host whatweb_json_{host}). Any character outside [A-Za-z0-9._-] is
    replaced with an underscore - conservative, and enough for real
    domains (which are already restricted to a similar character set) plus
    any odd input without risking a path separator sneaking through.
    """
    return re.sub(r"[^A-Za-z0-9._-]", "_", domain)


def _is_subdomain_of_root(fqdn: str, root_domain: str) -> bool:
    """
    True if fqdn is root_domain itself, or a subdomain of it. Shared by
    every stage 1 source that needs to filter a broader result set down
    to "actually the target's own assets" - factored out 2026-08-22 when
    Cert Spotter was added, so it and amass's relationship parser share
    one definition instead of each keeping a private copy (Cert Spotter's
    real output made this filter non-optional - see run_certspotter()'s
    docstring for why a raw cert SAN list can't be trusted as-is).
    """
    fqdn = fqdn.rstrip(".")
    return fqdn == root_domain or fqdn.endswith("." + root_domain)


def run_subfinder(domain: str, state: RunState) -> list[Asset]:
    stdout, stderr, code = _run_tool(["subfinder", "-d", domain, "-silent", "-json"])
    state.save_raw(STAGE, f"subfinder_{_sanitize(domain)}", stdout)  # (R5) per-target filename

    assets = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            host = obj.get("host")
            if host:
                assets.append(Asset(
                    value=host,
                    type="subdomain",
                    discovered_by="subfinder",
                    discovered_at_stage=STAGE,
                    discovered_in_pass=1,  # caller overwrites with real pass number
                ))
        except json.JSONDecodeError:
            logger.warning("subfinder: could not parse line as JSON: %r", line)
    return assets


def run_assetfinder(domain: str, state: RunState) -> list[Asset]:
    stdout, stderr, code = _run_tool(["assetfinder", "--subs-only", domain])
    state.save_raw(STAGE, f"assetfinder_{_sanitize(domain)}", stdout)  # (R5) per-target filename

    assets = []
    for line in stdout.splitlines():
        host = line.strip()
        if host:
            assets.append(Asset(
                value=host,
                type="subdomain",
                discovered_by="assetfinder",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,
            ))
    return assets


def _clear_stale_amass_config(state: RunState) -> None:
    """
    Pre-flight check before every amass invocation.

    Root cause: a stale-but-structurally-valid ~/.config/amass cache
    directory (small sqlite graph db, no locks, no stale process holding
    it - all checked and ruled out on 2026-08-22) can cause amass to hang
    indefinitely on startup with zero log output, even with -v. The exact
    mechanism was never isolated despite checking db integrity, size,
    file locks, stale processes, and file contents - all came back clean.
    The one confirmed, reproducible fix is: the directory predating the
    current run indicates it's a leftover from a prior invocation, and
    clearing it lets amass rebuild a fresh one, which resolves the hang
    every time it's been tested.

    Rather than deleting (staleness alone isn't proof of a problem, and
    the two-tier persistence principle applies here too - don't destroy
    data you might want to inspect later), a stale config dir is moved
    to a timestamped backup and a warning is logged. Threshold: does the
    config dir predate run_state.json for the CURRENT run - i.e. was it
    last touched before this run started - rather than a fixed age like
    24h/7d, since a fixed age either false-positives on a long-running
    single session or false-negatives on a short one.

    Fails open: if anything here goes wrong (permissions, path
    weirdness), log and continue rather than blocking the stage - matches
    run_stage1's existing "one tool failing shouldn't kill the whole
    stage" philosophy.
    """
    try:
        if not AMASS_CONFIG_DIR.exists():
            return  # nothing to check - amass will create it fresh

        run_state_data = state.load_run_state()
        run_started_at = run_state_data.get("last_updated")

        config_mtime = AMASS_CONFIG_DIR.stat().st_mtime

        if run_started_at:
            from datetime import datetime
            run_started_epoch = datetime.fromisoformat(run_started_at).timestamp()
        else:
            # no run_state.json yet (first stage of a brand new run) -
            # treat "now" as the run start, so any pre-existing config
            # dir counts as predating this run
            run_started_epoch = time.time()

        if config_mtime < run_started_epoch:
            backup_path = AMASS_CONFIG_DIR.parent / f"amass.bak.{int(time.time())}"
            logger.warning(
                "~/.config/amass predates the current run (last modified %s) - "
                "this has previously caused amass to hang indefinitely with no "
                "log output. Moving it to %s and letting amass rebuild clean.",
                time.ctime(config_mtime), backup_path,
            )
            shutil.move(str(AMASS_CONFIG_DIR), str(backup_path))
        else:
            logger.info("~/.config/amass is current for this run - no action needed")

    except Exception:
        logger.exception(
            "amass config staleness check failed - continuing without clearing. "
            "If amass hangs, manually check/clear %s", AMASS_CONFIG_DIR,
        )


def _parse_amass_relationships(stdout: str, root_domain: str) -> list[Asset]:
    """
    Parse amass's plain-text relationship-graph output, one relationship
    per line in the form:

        <source> (<SourceType>) --> <relation> --> <target> (<TargetType>)

    e.g.:
        testing.zonetransfer.me (FQDN) --> cname_record --> www.zonetransfer.me (FQDN)
        zonetransfer.me (FQDN) --> a_record --> 5.196.105.14 (IPAddress)

    Confirmed against real amass v4.2.0 output on 2026-08-22 - this is
    NOT what -silent produces (confirmed empty stdout under -silent alone
    in this version); -v or plain invocation are required to get these
    lines at all. -oA was tried and abandoned: same text format, plus an
    unexplained hang during its file-write phase that didn't reproduce
    without it - not worth chasing further when stdout capture already
    covers the pipeline's needs.

    Design (locked in conversation 2026-08-22):
      - Only FQDNs that are subdomains of root_domain (including
        root_domain itself) become Asset(type="subdomain", ...) rows.
        This matches the recon/primitive boundary principle: recon
        captures raw discovered facts about the target's own assets,
        not every off-target entity that shows up in the passive graph.
        root_domain itself gets a synthetic Asset row here too (amass's
        graph treats it as just another FQDN node, and stage 1 otherwise
        never asserts the root domain as an asset at all - it's a real
        gap since the root domain is itself a valid stage 4 probing
        target, confirmed live via its own a_record in the same output).
      - a_record / aaaa_record targets belonging to an in-scope subdomain
        become Asset(type="ip", ...) rows, with metadata noting which
        subdomain they resolved from - mirrors how stage3's dnsx pass
        attaches record metadata rather than inventing a new asset shape.
      - cname_record targets, and mx_record/ns_record targets hanging
        off the root domain, are USEFUL CONTEXT but not modeled as their
        own Asset rows (a CNAME to someone else's CDN, or the domain's
        mail/DNS provider, isn't something stage 4 should ever try to
        live-probe as if it were the target's own asset). Instead they're
        folded into metadata on the asset (or the root domain's own
        synthetic asset, for mx/ns) they relate to - keep but flag
        clearly, not silently dropped.
      - Netblocks, ASNs, and RIR org relations (contains/announces/
        managed_by) are discarded entirely for now. They're
        infrastructure-ownership context, not assets this pipeline acts
        on (nothing probes, crawls, or checks a /22 netblock for
        takeover) - a deliberate future addition if ASN-level context
        becomes useful, not something to bolt onto this parser today.

    Returns a plain list[Asset] - same contract as every other stage 1
    runner, so run_stage1()'s uniform TOOL_RUNNERS loop doesn't need to
    special-case amass.
    """
    line_re = re.compile(
        r"^(?P<source>\S+)\s+\((?P<source_type>\w+)\)\s+-->\s+"
        r"(?P<relation>\w+)\s+-->\s+"
        r"(?P<target>\S+)\s+\((?P<target_type>\w+)\)\s*$"
    )

    # managed_by lines have a free-text RIR org name as the target (e.g.
    # "GOOGLE - Google LLC", "ASN-ROUTELABEL, NL") which breaks the \S+
    # target assumption above - confirmed against real output 2026-08-22.
    # These are ASN/RIR-org relations, already in the "discarded" category
    # by design (see docstring), so this pattern exists purely to
    # recognize and skip them WITHOUT counting them as unparsed/unexpected
    # lines - keeps the unparsed_lines warning meaningful for genuine
    # format changes instead of firing on every routine run.
    managed_by_re = re.compile(r"^\S+\s+\(ASN\)\s+-->\s+managed_by\s+-->\s+.+\(RIROrganization\)\s*$")

    # value -> Asset (built incrementally; cname/mx/ns/ip info merged
    # into the same object as we see more lines about it)
    assets_by_value: dict[str, Asset] = {}
    unparsed_lines = 0

    def get_or_create(value: str) -> Asset:
        if value not in assets_by_value:
            assets_by_value[value] = Asset(
                value=value,
                type="subdomain",
                discovered_by="amass",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,  # caller overwrites with real pass number
            )
        return assets_by_value[value]

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        m = line_re.match(line)
        if not m:
            if managed_by_re.match(line):
                # ASN -> managed_by -> RIR org name - expected format,
                # deliberately discarded (see docstring), not a parse failure
                continue
            unparsed_lines += 1
            logger.debug("amass: line did not match relationship format: %r", line)
            continue

        source = m.group("source")
        source_type = m.group("source_type")
        relation = m.group("relation")
        target = m.group("target")

        source_is_target_domain = source_type == "FQDN" and _is_subdomain_of_root(source, root_domain)

        if relation in ("a_record", "aaaa_record") and source_is_target_domain:
            # subdomain (or root domain) -> its own IP
            get_or_create(source)
            ip_asset = Asset(
                value=target,
                type="ip",
                discovered_by="amass",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,
                metadata={"resolved_from": source, "record_type": relation},
            )
            # unique key so an IP resolved from multiple sources doesn't
            # collide/overwrite in the dict
            assets_by_value[f"ip:{target}:{source}"] = ip_asset

        elif relation == "cname_record" and source_is_target_domain:
            # subdomain -> off-target (or on-target) CNAME - keep the
            # subdomain as an asset, fold the CNAME target into its
            # metadata rather than creating a separate asset for the
            # target (per locked design: useful context, not a new asset)
            asset = get_or_create(source)
            asset.metadata.setdefault("cname_targets", [])
            if target not in asset.metadata["cname_targets"]:
                asset.metadata["cname_targets"].append(target)

        elif relation in ("mx_record", "ns_record") and source == root_domain:
            # root domain's own mail/DNS provider hosts - fold into the
            # root domain's synthetic asset rather than creating separate
            # asset rows for someone else's infrastructure
            asset = get_or_create(source)
            key = "mx_hosts" if relation == "mx_record" else "ns_hosts"
            asset.metadata.setdefault(key, [])
            if target not in asset.metadata[key]:
                asset.metadata[key].append(target)

        elif source_type == "FQDN" and _is_subdomain_of_root(source, root_domain) and m.group("target_type") == "FQDN":
            # any other FQDN-to-FQDN relationship where the source is a
            # confirmed subdomain/root - still worth registering the
            # source as an asset even without a specific handler above
            get_or_create(source)

        # netblocks / ASNs / RIR orgs (contains, announces, managed_by) and
        # anything else not matched above: deliberately discarded per
        # locked design - not modeled as assets in this pass

    if unparsed_lines:
        logger.warning(
            "amass: %d line(s) did not match the expected relationship "
            "format and were skipped - amass output format may have "
            "changed; check raw/stage%s_amass_*.json",
            unparsed_lines, STAGE,
        )

    return list(assets_by_value.values())


AMASS_EXTERNAL_TIMEOUT_SECONDS = 600  # hard external kill via _run_tool()
AMASS_INTERNAL_TIMEOUT_MINUTES = 8    # amass's own -timeout, self-imposed ceiling


def run_amass(domain: str, state: RunState) -> list[Asset]:
    # Pre-flight: clear a stale config dir before it can cause the
    # indefinite-hang bug documented in _clear_stale_amass_config().
    _clear_stale_amass_config(state)

    # amass is slow - passive mode only for stage 1, keeps it fast;
    # active enumeration modes belong conceptually to stage 3, not here.
    #
    # Deliberately NOT using -silent: confirmed on 2026-08-22 that -silent
    # suppresses amass's relationship-graph result lines entirely in this
    # version (v4.2.0), giving the parser nothing to work with. Plain
    # invocation (no -silent, no -v) produces exactly the result lines
    # this parser needs without -v's extra "Querying X" progress noise.
    #
    # -timeout 8 added 2026-08-22 (see CHANGELOG "Amass hang recurs despite
    # confirmed-fresh config"): a direct manual run confirmed amass queries
    # ~45 separate third-party passive data sources per invocation, and a
    # later real pipeline run hung for the full external 600s timeout on
    # this exact command against this exact target, immediately followed
    # by a manual re-run of the identical command completing cleanly in
    # well under a minute - i.e. this looks like transient flakiness in
    # one of those ~45 third parties, not a structural bug in this
    # invocation. -timeout is amass's own real, confirmed-via---help flag
    # ("Number of minutes to let enumeration run before quitting") - set
    # here to 8 minutes, under AMASS_EXTERNAL_TIMEOUT_SECONDS's 10-minute
    # external kill, so amass gets a 2-minute head start to try to shut
    # itself down cleanly first.
    #
    # ⚠️ UNVERIFIED: whether amass's own -timeout cutoff actually emits
    # the relationship lines it had already gathered before quitting, the
    # way a graceful shutdown should, or whether it exits with nothing.
    # A real test of `-timeout 1` against zonetransfer.me couldn't
    # confirm this either way - enumeration against this tiny target
    # completes in well under a minute normally, so the 1-minute ceiling
    # never actually fired to be observed. Kept anyway as a cheap,
    # can't-hurt defense-in-depth addition (worst case: a no-op on fast
    # completions, exactly as observed; best case: shortens a genuine
    # hang and exits cleanly rather than needing the hard external kill).
    # The independently-VERIFIED fix for this same problem is
    # _run_tool()'s partial-output salvage on TimeoutExpired (see that
    # function's docstring) - that one doesn't depend on amass cooperating
    # at all, and covers the case where -timeout doesn't help.
    stdout, stderr, code = _run_tool(
        ["amass", "enum", "-passive", "-d", domain, "-timeout", str(AMASS_INTERNAL_TIMEOUT_MINUTES)],
        timeout=AMASS_EXTERNAL_TIMEOUT_SECONDS,
    )
    state.save_raw(STAGE, f"amass_{_sanitize(domain)}", stdout)  # (R5) per-target filename

    return _parse_amass_relationships(stdout, domain)


def run_gau(domain: str, state: RunState) -> list[Asset]:
    stdout, stderr, code = _run_tool(["gau", domain])
    state.save_raw(STAGE, f"gau_{_sanitize(domain)}", stdout)  # (R5) per-target filename

    assets = []
    for line in stdout.splitlines():
        url = line.strip()
        if url:
            assets.append(Asset(
                value=url,
                type="url",
                discovered_by="gau",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,
            ))
    return assets


def run_waybackurls(domain: str, state: RunState) -> list[Asset]:
    stdout, stderr, code = _run_tool(["waybackurls", domain])
    state.save_raw(STAGE, f"waybackurls_{_sanitize(domain)}", stdout)  # (R5) per-target filename

    assets = []
    for line in stdout.splitlines():
        url = line.strip()
        if url:
            assets.append(Asset(
                value=url,
                type="url",
                discovered_by="waybackurls",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,
            ))
    return assets


def run_certspotter(domain: str, state: RunState) -> list[Asset]:
    """
    Query Cert Spotter's public certificate-transparency issuances API
    for `domain`, via a plain curl GET - there's no CLI binary for this,
    it's an HTTPS JSON API (design call made 2026-08-22: curl through the
    existing _run_tool() subprocess wrapper, same pattern as every other
    stage 1 tool, rather than adding a Python HTTP client dependency).

    This slot in stage 1 was originally locked as "crt.sh direct query"
    (see README's known-gaps history) but crt.sh was hard-down (502 from
    its own nginx, on both a wildcard and bare-domain query) at the exact
    time this was being built. Cert Spotter was substituted instead:
    same certificate-transparency data source in spirit, a very similar
    JSON API shape, generally better historical uptime than crt.sh's
    single-maintainer service. crt.sh itself is NOT wired in anywhere -
    flagged in the README as a possible future addition (e.g. as a
    fallback source alongside Cert Spotter) if its reliability improves,
    not abandoned outright.

    include_subdomains=true broadens the query beyond exact matches on
    `domain` itself; expand=dns_names asks the API to inline each cert's
    full SAN list as a JSON array directly on the issuance object, rather
    than requiring a second per-cert lookup.

    (R11) PAGINATION. Cert Spotter returns a bounded page of issuances per
    request; a domain with many certificates is silently under-enumerated
    by a single query. This now pages with ?after=<last issuance id>,
    requesting limit=CERTSPOTTER_PAGE_LIMIT per page and stopping when a
    page comes back empty or shorter than the requested limit (the
    end-of-pages signal), or when CERTSPOTTER_MAX_PAGES is hit (hard safety
    cap given the ~10 req/hour anonymous rate limit). A no-new-issuance-ids
    guard also stops early if after= is ever ignored by the API and the
    same page is returned repeatedly, so a broken/unsupported after= can't
    loop. Each page's raw response is archived separately (R5 + R11:
    per-domain, per-page filename) per the two-tier persistence pattern, so
    a parsing improvement later can be replayed against exactly what each
    page returned without re-querying.

    ⚠️ UNVERIFIED against the live API in THIS change: the after= parameter
    name, the limit= parameter, and whether a short page reliably signals
    the last page are implemented from Cert Spotter's documented pagination
    contract, not confirmed on a real multi-page domain (the ~10 req/hour
    anonymous limit makes iterating on this live expensive). The
    no-new-ids guard makes an incorrect assumption fail safe (stop early)
    rather than loop. Confirm against a real domain with enough certs to
    page before trusting completeness - flagged in RESOLUTIONS R11 /
    CHANGELOG until then.

    Real per-issuance response shape (verified via a live query against
    zonetransfer.me on 2026-08-22): a JSON array of issuance objects, each
    with id, tbs_sha256, cert_sha256, dns_names (list[str]), pubkey_sha256,
    not_before, not_after, revoked (bool).

    Confirmed real and important: a single cert's dns_names can list many
    domains that share nothing with the target but a CA/SAN bundle -
    zonetransfer.me's own real certs list digi.ninja, digininja.org,
    vuln-demo.com, iot-cert.space alongside zonetransfer.me and
    www.zonetransfer.me. Only dns_names entries that are actually
    subdomains of `domain` (or `domain` itself) become assets here - see
    _is_subdomain_of_root() - so this doesn't flood assets.db with
    off-target noise the scope gate would just mark out_of_scope anyway.

    Wildcard SAN entries (e.g. "*.example.com") have the "*." stripped
    before the subdomain check; if the remainder passes it, it becomes an
    asset with metadata noting it came from a wildcard SAN - kept but
    flagged, not silently dropped, matching amass's cname/mx/ns handling.

    A non-list JSON response (Cert Spotter's rate-limit/error shape is a
    JSON OBJECT with "code"/"message" keys) or a non-JSON response (an HTML
    error page) end pagination for this run and are treated as
    zero-further-results: logged as a warning, not raised, so a transient
    API problem doesn't take down the rest of stage 1.
    """
    assets_by_value: dict[str, Asset] = {}
    seen_ids: set = set()
    total_certs = 0
    pages_fetched = 0
    after = None

    for page_num in range(CERTSPOTTER_MAX_PAGES):
        url = (
            f"{CERTSPOTTER_API_URL}?domain={domain}"
            f"&include_subdomains=true&expand=dns_names&limit={CERTSPOTTER_PAGE_LIMIT}"
        )
        if after is not None:
            url += f"&after={after}"

        stdout, stderr, code = _run_tool(
            ["curl", "-s", "--max-time", "20", url],
            timeout=30,
        )
        # (R5 + R11) per-domain, per-page raw archive filename so neither a
        # multi-root scope nor multi-page pagination overwrites earlier
        # archives.
        state.save_raw(STAGE, f"certspotter_{_sanitize(domain)}_p{page_num}", stdout)
        pages_fetched += 1

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning(
                "certspotter: page %d response was not valid JSON (likely a "
                "transient API error or outage) - stopping pagination, "
                "returning what was gathered. See "
                "raw/stage%s_certspotter_%s_p%d.json for the actual response.",
                page_num, STAGE, _sanitize(domain), page_num,
            )
            break

        if not isinstance(parsed, list):
            # Cert Spotter's own error shape is a JSON object, e.g.
            # {"code": "too-many-requests", "message": "..."} - most likely
            # the ~10 req/hour anonymous rate limit
            logger.warning(
                "certspotter: page %d expected a JSON list of issuances, got "
                "%s - likely a rate-limit or API error response: %r. Stopping "
                "pagination.",
                page_num, type(parsed).__name__, parsed,
            )
            break

        if not parsed:
            # empty page = no more results
            break

        # (R11) guard against after= being ignored: if a page contributes
        # no issuance id we haven't already seen, we're looping on the same
        # data - stop rather than burn the rate budget.
        page_ids = [iss.get("id") for iss in parsed if isinstance(iss, dict)]
        if not any(pid not in seen_ids for pid in page_ids):
            logger.warning(
                "certspotter: page %d returned no new issuance ids - after= "
                "may not be honored by the API; stopping pagination to avoid "
                "a loop.", page_num,
            )
            break
        seen_ids.update(pid for pid in page_ids if pid is not None)

        total_certs += len(parsed)
        for issuance in parsed:
            if not isinstance(issuance, dict):
                continue
            for dns_name in issuance.get("dns_names", []):
                from_wildcard = dns_name.startswith("*.")
                value = dns_name[2:] if from_wildcard else dns_name
                value = value.rstrip(".")
                if not value or not _is_subdomain_of_root(value, domain):
                    continue

                if value in assets_by_value:
                    if from_wildcard:
                        assets_by_value[value].metadata["from_wildcard_san"] = True
                    continue

                metadata = {"from_wildcard_san": True} if from_wildcard else {}
                assets_by_value[value] = Asset(
                    value=value,
                    type="subdomain",
                    discovered_by="certspotter",
                    discovered_at_stage=STAGE,
                    discovered_in_pass=1,
                    metadata=metadata,
                )

        # (R11) end-of-pages: a page shorter than the requested limit is
        # the last page. Otherwise advance after= to this page's last id.
        last_id = page_ids[-1] if page_ids else None
        if last_id is None or len(parsed) < CERTSPOTTER_PAGE_LIMIT:
            break
        after = last_id

    logger.info(
        "certspotter: %d certificate(s) across %d page(s), %d in-scope-shaped "
        "hostname(s) kept",
        total_certs, pages_fetched, len(assets_by_value),
    )
    return list(assets_by_value.values())


TOOL_RUNNERS = [
    run_subfinder,
    run_assetfinder,
    run_amass,
    run_gau,
    run_waybackurls,
    run_certspotter,
]


def run_stage1(root_domains: list[str], state: RunState, current_pass: int) -> list[Asset]:
    """
    Run all stage 1 tools against every root domain in scope, normalize,
    and return the combined asset list (with discovered_in_pass corrected
    to the actual current pass number - each runner stubs it to 1).
    Does NOT write to assets.json itself - that's the caller's job via
    state.add_assets(), after scope classification happens.
    """
    all_assets: list[Asset] = []

    for domain in root_domains:
        for runner in TOOL_RUNNERS:
            try:
                found = runner(domain, state)
                for a in found:
                    a.discovered_in_pass = current_pass
                all_assets.extend(found)
                logger.info("%s found %d assets for %s", runner.__name__, len(found), domain)
            except Exception:
                logger.exception("Stage 1 tool %s failed for domain %s", runner.__name__, domain)
                # one tool failing shouldn't kill the whole stage - continue with the rest
                continue

    return all_assets
