"""
Stage 4: Live host probing (httpx) + port scanning (naabu).

Unlike stage 3 (tools chained in sequence, each feeding the next), stage 4's
two tools are independent probes over the same input set and don't feed each
other:

  1. httpx  - for every in_scope host, get status/tech/title/redirect
              final destination/response hashes. This is metadata
              enrichment on EXISTING assets, not new-asset discovery -
              EXCEPT when httpx's final_url points at a host not already
              in assets.db, which per the locked design decision (see
              /areas/hackbot.md) becomes a NEW asset that re-enters the
              scope gate, same as stage 1/3's pattern.
  2. naabu  - port scan against the same host set. Per the locked design
              decision, naabu is fed BOTH the hostnames AND the IPs already
              captured in stage 3's dnsx metadata (a_records), whichever
              naabu resolves/scans faster for a given target - naabu accepts
              a mixed host/IP input list natively, so this is one invocation
              with a de-duplicated combined list, not two separate runs.

(R7) Because the two probes are genuinely independent, run_stage4() isolates
them: if httpx raises, naabu still runs (and vice versa), and the stage
returns whatever partial results it got rather than aborting the whole run.
This is the "apply stage 1's per-tool try/except-and-continue uniformly"
half of R7 - stage 4 is NOT all-or-nothing the way stage 3's within-leg
chains are, so each probe gets its own guard.

IP handling: naabu port findings for a target that matches a known
hostname's value are attached as metadata on that HOST asset (keyed by
hostname). naabu findings for a bare IP with NO corresponding hostname
asset in the known-hosts set (e.g. a shared-hosting neighbor IP, or an IP
pulled from stage 3's a_records where the resolving hostname wasn't
scanned this pass) are now materialized as standalone type="ip" Asset
objects - resolved by scope_gate.classify_ip(), same "stage returns new
assets, caller applies scope decision + add_assets()" pattern used
everywhere else, NOT silently dropped as in the first version of this
module. See scope_gate.py's IP classification section for why an IP
resolving from a known in-scope host is NOT auto-admitted (shared
hosting/CDN risk) - that link is passed through as context on the new
Asset's metadata (resolved_from_host) for the human/LLM reviewer, not
used to skip classification.

Like stage 3, this stage does NOT classify new assets itself - it returns
new Asset objects (redirect-discovered hosts, IP-only naabu findings) for
the caller (main.py) to run through the scope gate, and returns metadata
updates for existing assets for the caller to apply via
state.update_asset_metadata(). Keeping stage modules decoupled from
scope-gate/state specifics is the same separation stage 3 uses.
"""

import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from state import Asset, RunState, timed
from rate_limits import httpx_rate_args, naabu_rate_args
from http_headers import header_args

logger = logging.getLogger(__name__)

STAGE = 4
DEFAULT_TIMEOUT_SECONDS = 600

# naabu's default top-ports scan. Swap for -p - (full range) once the
# pipeline is validated and runtime budget is being tuned deliberately,
# same philosophy as stage 3's wordlist size note.
DEFAULT_NAABU_TOP_PORTS = "1000"


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


def run_httpx(hosts: list[str], state: RunState, scope: dict) -> tuple[dict[str, dict], list[str]]:
    """
    Probe live hosts via httpx (status/tech/title/redirect chain/response
    hash, TLS cert SAN). Returns:
      - a dict keyed by the ORIGINAL requested hostname -> metadata dict,
        for the caller to attach via update_asset_metadata()
      - a list of NEW hostnames discovered only via redirect chains (i.e.
        httpx followed a redirect to a host not in `hosts`) - the caller
        is responsible for turning these into Asset objects and running
        them through the scope gate, per the locked redirect-handling
        design decision.
    Hosts httpx can't reach are simply absent from the metadata dict, same
    "not present = couldn't confirm" convention as stage 3's dnsx pass.

    (R1) httpx KEEPS -follow-redirects: a single GET to a redirect target
    is benign and load-bearing (redirect-discovered hosts are a real
    discovery source, and the discovered host is scope-gated before any
    LATER stage touches it, so there's no compounding off-scope traffic).
    The one residual off-scope GET is the named, accepted cost of the R1
    "hybrid" resolution - unlike whatweb (-a 3, many requests) and katana
    (unbounded crawl), which R1 DOES constrain. See
    RECON_DESIGN_REVIEW_RESOLUTIONS.md R1.

    scope is the loaded scope.json dict (see state.RunState.load_scope()),
    passed through so httpx_rate_args() can resolve the effective req/s
    ceiling (program-stated or conservative default) - see rate_limits.py.
    """
    if not hosts:
        return {}, []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        hosts_path = f.name

    rate = httpx_rate_args(scope, host_count=len(hosts))
    logger.info("httpx rate limit: %s", rate.note)

    stdout, stderr, code = _run_tool([
        "httpx", "-l", hosts_path,
        "-json", "-silent",
        "-status-code", "-title", "-tech-detect",
        "-follow-redirects", "-location",
        "-hash", "sha256",
        "-tls-grab",
        # (E1) richer enrichment on the SAME invocation (rate model unchanged):
        # favicon-hash (origin correlation, feeds C3), body-preview, asn, cdn
        # label (feeds C3/C4/A2), jarm. Verified real httpx JSON keys 2026-08-23:
        # body_preview, cdn/cdn_name/cdn_type, jarm_hash (NOT "jarm"); favicon &
        # asn are present only when available (favicon served / ASN data on box).
        "-favicon", "-body-preview", "-asn", "-cdn", "-jarm",
        *rate.extra_args,
        *header_args(scope),   # program-mandated headers (e.g. X-HackerOne) on all target traffic
    ])
    state.save_raw(STAGE, "httpx", stdout)

    requested_hosts = set(hosts)
    metadata_by_host = {}
    redirect_discovered_hosts = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("httpx: could not parse line as JSON: %r", line)
            continue

        input_host = obj.get("input") or obj.get("host")
        if not input_host:
            continue

        # real httpx JSON shape (verified against actual installed
        # version's output, not assumed - see /areas/hackbot.md for the
        # original wrong assumptions this replaced):
        #   - hash is {"body_sha256": ..., "header_sha256": ...}, NOT a
        #     flat value or hash.sha256
        #   - there is NO "chain" field at all (list of URLs/dicts was an
        #     incorrect assumption) - only "chain_status_codes" (a plain
        #     list of ints, no URLs/hosts in it) and "final_url"
        hash_obj = obj.get("hash") if isinstance(obj.get("hash"), dict) else {}
        md = {
            "httpx_status_code": obj.get("status_code"),
            "httpx_title": obj.get("title"),
            "httpx_tech": obj.get("tech", []),
            "httpx_body_hash": hash_obj.get("body_sha256"),
            "httpx_header_hash": hash_obj.get("header_sha256"),
            "httpx_final_url": obj.get("final_url") or obj.get("url"),
            "httpx_chain_status_codes": obj.get("chain_status_codes", []),
            "httpx_tls_san": obj.get("tls", {}).get("subject_an", []) if isinstance(obj.get("tls"), dict) else [],
        }
        # (E1) enrichment keys — only set when httpx actually returned them
        # (favicon needs a served /favicon.ico; asn needs ASN data on the box).
        # body_preview is TARGET-AUTHORED → untrusted (in TARGET_DERIVED_METADATA_KEYS);
        # favicon_hash / cdn / asn / jarm are computed/observed → trusted intel.
        for src_key, dst_key in (
            ("body_preview", "httpx_body_preview"),
            ("favicon", "httpx_favicon_hash"),
            ("favicon_url", "httpx_favicon_url"),
            ("asn", "httpx_asn"),
            ("cdn", "httpx_cdn"),
            ("cdn_name", "httpx_cdn_name"),
            ("cdn_type", "httpx_cdn_type"),
            ("jarm_hash", "httpx_jarm"),
        ):
            if obj.get(src_key) is not None:
                md[dst_key] = obj.get(src_key)
        metadata_by_host[input_host] = md

        # redirect discovery: httpx's JSON has no host-level chain field
        # to walk (see comment above) - final_url is the only reliable
        # signal of where the request actually ended up, so check just
        # that rather than a non-existent "chain" list
        final_url = obj.get("final_url") or obj.get("url")
        if final_url:
            host = urlparse(final_url).hostname
            if host and host not in requested_hosts:
                redirect_discovered_hosts.add(host)

    logger.info("httpx probed %d/%d requested hosts, discovered %d new host(s) via redirects",
                len(metadata_by_host), len(hosts), len(redirect_discovered_hosts))

    return metadata_by_host, sorted(redirect_discovered_hosts)


def run_naabu(hosts: list[str], ips: list[str], state: RunState, scope: dict) -> dict[str, list[int]]:
    """
    Port scan via naabu against a de-duplicated combined list of hostnames
    AND IPs (per the locked design decision - naabu is fed both, since
    naabu natively resolves hostnames itself and it's cheaper to let it
    dedupe/scan whichever's faster than to pre-resolve ourselves). naabu's
    own JSON output reports whichever host/IP form was scanned per result;
    both forms are used as dict keys so the caller can look up either way.
    Returns dict keyed by host-or-ip -> sorted, de-duplicated list of open
    ports. Deduping matters because naabu can emit more than one raw result
    line for the same target+port (observed on the real zonetransfer.me
    run - see inline comment below), so ports are collected into a set
    internally before being sorted back into a list.

    scope is the loaded scope.json dict, passed through for
    naabu_rate_args() - see run_httpx()'s docstring for the same pattern.
    """
    combined = sorted(set(hosts) | set(ips))
    if not combined:
        return {}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(combined))
        targets_path = f.name

    rate = naabu_rate_args(scope, host_count=len(combined))
    logger.info("naabu rate limit: %s", rate.note)

    stdout, stderr, code = _run_tool([
        "naabu", "-list", targets_path,
        "-json", "-silent",
        "-top-ports", DEFAULT_NAABU_TOP_PORTS,
        *rate.extra_args,
    ], timeout=900)  # port scanning a large combined host+IP list is the slow step in this stage
    state.save_raw(STAGE, "naabu", stdout)

    ports_by_target: dict[str, set[int]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("naabu: could not parse line as JSON: %r", line)
            continue

        target = obj.get("host") or obj.get("ip")
        port = obj.get("port")
        if target is None or port is None:
            continue
        # naabu can emit more than one line for the same target+port (e.g.
        # once per resolved A record when a hostname target has multiple,
        # or once under "host" and once under "ip" for the same result) -
        # dedupe with a set rather than accumulating raw appends, or the
        # same port shows up repeated in metadata (caught during the real
        # zonetransfer.me run: naabu_open_ports came back as
        # [80, 443, 80, 443] instead of [80, 443])
        ports_by_target.setdefault(target, set()).add(int(port))

    Path(targets_path).unlink(missing_ok=True)

    logger.info("naabu found open ports on %d/%d scanned target(s)",
                len(ports_by_target), len(combined))
    return {target: sorted(ports) for target, ports in ports_by_target.items()}


def run_stage4(known_in_scope_hosts: list[Asset], state: RunState, current_pass: int, scope: dict) -> tuple[list[Asset], dict[str, dict]]:
    """
    Run the full stage 4 sequence: httpx (probing) + naabu (port scan) over
    the current in_scope host set.

    known_in_scope_hosts should come from the caller filtering assets.db to
    scope_status == "in_scope" subdomain-type assets (mirrors stage 3's
    known_in_scope_subdomains convention) - this function does not do that
    filtering itself.

    (R7) httpx and naabu are independent probes, so each is wrapped in its
    own try/except: one failing degrades the result (you lose that probe's
    contribution) rather than aborting the stage/run. A failed httpx yields
    no metadata and no redirect-discovered hosts; a failed naabu yields no
    port data - in both cases the other probe's results still flow through.

    scope is the loaded scope.json dict (state.RunState.load_scope()) -
    threaded through to run_httpx()/run_naabu() so their rate-limit
    resolution can see the program-stated ceiling if one was confirmed.
    Caller is responsible for having already checked
    rate_limit_gate.check_run_not_blocked(scope) before the run started -
    this function doesn't re-check that gate itself, same as it doesn't
    re-check verified_by_human on every stage call.

    Returns a tuple:
      - new_assets: list[Asset] - redirect-discovered hosts (type=subdomain)
        AND IP-only naabu findings with no matching hostname asset
        (type=ip), all not yet in assets.db, for the caller to run through
        the scope gate before add_assets(). Mirrors stage 1/3's "return new
        assets, caller classifies" pattern. IP assets carry
        resolved_from_host in their metadata when the IP came from a known
        in-scope host's a_records, for the reviewer's context - see
        scope_gate.classify_ip()'s docstring for why that link does NOT
        get used to auto-admit the IP here.
      - metadata_updates: dict[str, dict] - keyed by EXISTING asset value
        (hostname), for the caller to apply via
        state.update_asset_metadata(asset_id, metadata_update). Stage 4
        doesn't have asset_id directly from a bare hostname list, so it
        returns by value and leaves the value->asset_id lookup to the
        caller, which already holds the Asset objects it passed in.
    """
    hostnames = [a.value for a in known_in_scope_hosts]
    hostnames_set = set(hostnames)

    # pull IPs already captured in stage 3's dnsx metadata (a_records),
    # per the locked design decision to feed naabu both hosts and IPs.
    # Track which host each IP resolves from so IP-only naabu findings can
    # carry that context if the IP turns out to have no matching hostname
    # asset in this pass's known_in_scope_hosts set.
    known_ips: set[str] = set()
    ip_resolved_from_host: dict[str, str] = {}
    for asset in known_in_scope_hosts:
        a_records = asset.metadata.get("a_records") or []
        for ip in a_records:
            known_ips.add(ip)
            ip_resolved_from_host.setdefault(ip, asset.value)

    # (R7) isolate the two independent probes so one failing doesn't lose
    # the other's results or abort the run.
    httpx_metadata: dict[str, dict] = {}
    redirect_hosts: list[str] = []
    try:
        with timed(state, "stage4.httpx"):
            httpx_metadata, redirect_hosts = run_httpx(hostnames, state, scope)
    except Exception:
        logger.exception("stage 4 httpx failed - continuing with naabu results only (R7)")

    naabu_ports: dict[str, list[int]] = {}
    try:
        with timed(state, "stage4.naabu"):
            naabu_ports = run_naabu(hostnames, sorted(known_ips), state, scope)
    except Exception:
        logger.exception("stage 4 naabu failed - continuing with httpx results only (R7)")

    # merge httpx + naabu results into one metadata-update dict keyed by
    # hostname, same shape stage 3 uses when merging dnsx records into
    # existing Asset.metadata
    metadata_updates: dict[str, dict] = {}
    for host in hostnames:
        update = {}
        if host in httpx_metadata:
            update.update(httpx_metadata[host])
        if host in naabu_ports:
            update["naabu_open_ports"] = naabu_ports[host]
        if update:
            metadata_updates[host] = update

    # new assets from redirect discovery - returned for the caller to
    # classify via the scope gate, never auto-admitted here
    new_assets = [
        Asset(
            value=host,
            type="subdomain",
            discovered_by="httpx_redirect",
            discovered_at_stage=STAGE,
            discovered_in_pass=current_pass,
        )
        for host in redirect_hosts
    ]

    # naabu results keyed by a target that ISN'T one of the known
    # hostnames are bare-IP findings with nowhere to attach as metadata -
    # materialize them as standalone type="ip" assets instead of dropping
    # them. resolved_from_host is attached when we know which in-scope
    # host's a_records this IP came from, purely as reviewer context (see
    # run_stage4's docstring / scope_gate.classify_ip()).
    for target, ports in naabu_ports.items():
        if target in hostnames_set:
            continue  # already merged into metadata_updates above
        ip_metadata = {"naabu_open_ports": ports}
        resolved_from = ip_resolved_from_host.get(target)
        if resolved_from:
            ip_metadata["resolved_from_host"] = resolved_from
        new_assets.append(Asset(
            value=target,
            type="ip",
            discovered_by="naabu",
            discovered_at_stage=STAGE,
            discovered_in_pass=current_pass,
            metadata=ip_metadata,
        ))

    return new_assets, metadata_updates
