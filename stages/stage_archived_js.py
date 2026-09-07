"""
Stage 11: archived JS mining (B4) - resurrect endpoints/params/secrets from the
Wayback Machine's archived `.js` bodies. Realizes B4 of RECON_ENHANCEMENTS.md
(Track B). Full design: design_docs/RECON_B4_ARCHIVED_JS_MINING_DESIGN.md.

gau/waybackurls (stage 1) already pull the target's historical URLs, but nothing
mines the historical JS BODIES. Old JS routinely holds endpoints removed from the
live app and secrets since rotated (still informative: naming schemes, internal
hosts, provider IDs). B11 fetches archived `.js` snapshots and runs jsluice over
them - the EXACT same extraction as stage 7's live JS (reused runners), producing
the same Track-D endpoint/parameter/secret records, distinguished only by
provenance (source=wayback + snapshot timestamp).

PASSIVE-TOWARD-THE-TARGET: B11 sends ZERO packets to the target. Both halves - the
CDX API query (which snapshots exist) and the raw-snapshot fetch (the archived
body) - hit web.archive.org, a third-party archive, exactly like gau/waybackurls/
paramspider already do. So there is NO rate_limits.py entry (that module protects
the TARGET); the courtesy owed is toward the archive (MAX_SNAPSHOTS_PER_HOST +
sequential fetches). A consequence: B11 does NOT require a host to be live - a host
dead TODAY may hold the archived `.js` that reveals a removed endpoint, which is
the whole point. So it seeds ALL in-scope subdomains, not just confirmed-live ones
(the one deliberate divergence from B1/B2).

Every record is target_derived=1 (the archived body is target-AUTHORED text, merely
stored by a third party) - untrusted-by-default (R9), same as live jsluice (stage 7)
and B2.

Real-interface facts VERIFIED before this parser (2026-08-24, CONTRIBUTING
discipline - each bit a prior stage):
  - CDX (`https://web.archive.org/cdx/search/cdx?url=<host>/*&output=json&fl=...&
    filter=statuscode:200&filter=mimetype:.*javascript.*&collapse=digest`): JSON is
    a list-of-lists whose FIRST ROW IS A HEADER (skipped); `fl` order honored.
    ** collapse=digest is ADJACENCY-ONLY ** - identical bodies captured
    non-adjacently survive, so we ALSO dedup by digest client-side. The regex
    mimetype filter catches application/javascript, application/x-javascript, and
    text/javascript. CDX is intermittently slow / returns HTTP 000 - so a failed or
    non-JSON response DEGRADES to zero-snapshots-this-run (logged, not raised),
    certspotter-style. Plain http:// timed out; HTTPS works (hence CDX_API_URL).
  - Raw-snapshot `id_` form (`.../web/<ts>id_/<original>`) returns the UNMODIFIED
    body (verified: raw jQuery source, no toolbar); the un-suffixed replay form
    injects wayback wrapper JS/HTML (3 markers) that would poison jsluice. `id_` is
    mandatory.
  - jsluice reads LOCAL FILE paths as positional args (stage 7 only ever passed
    remote URLs); it resolves nothing itself, so relative endpoints must be
    resolved against a base_url = the ORIGINAL archived URL (else they'd resolve
    onto the local temp path - the central B4 correctness trap). `-u` is jsluice's
    --unique flag, NOT a fetch flag (stage 7's docstring wrongly implied fetch).

Like every stage, this module does NOT classify or write assets.db - it returns
new assets + records to main.py.
"""

import json
import logging
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlencode

from state import Asset, RunState, Endpoint, Parameter, Secret, secret_fingerprint, timed
from stages.stage7_js_extraction import (
    run_jsluice_urls, run_jsluice_secrets, _sanitize, _jsluice_secret_value,
)

logger = logging.getLogger(__name__)

STAGE = 11
# HTTPS: plain http://web.archive.org/cdx timed out on real runs (2026-08-24).
CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
# id_ = the raw, unmodified archived body (no wayback toolbar). Verified mandatory.
SNAPSHOT_URL_FMT = "https://web.archive.org/web/{timestamp}id_/{original}"
# catches application/javascript, application/x-javascript, text/javascript.
_JS_MIMETYPE_FILTER = "mimetype:.*javascript.*"

MAX_SNAPSHOTS_PER_HOST = 500      # bound a pathological history (archive courtesy)
FETCH_TIMEOUT_SECONDS = 30        # per-snapshot fetch ceiling (web.archive.org is slow)
CDX_TIMEOUT_SECONDS = 60          # per-host CDX query ceiling
INTER_FETCH_DELAY_SECONDS = 0.0   # optional politeness delay toward the archive
# a polite, identifiable UA toward the free public archive (not the target)
USER_AGENT = "sozin-recon/0 (archived-JS mining; polite third-party archive read)"


def _http_get(url: str, timeout: int) -> tuple[bytes, int]:
    """GET with our UA; returns (body_bytes, status). Raises on network error /
    HTTP error (caller decides whether to degrade or R7-skip)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(), getattr(resp, "status", 200) or 200


def query_cdx_js(host: str, state: RunState) -> list[dict]:
    """Phase 1: list unique archived `.js` snapshots for one host via the CDX API.
    Returns [{original, timestamp, digest, mimetype}], capped, digest-deduped.
    DEGRADES to [] (logged, not raised) on any CDX failure/timeout/non-JSON -
    web.archive.org is flaky and one host's outage must not abort the stage."""
    params = [
        ("url", f"{host}/*"),
        ("output", "json"),
        ("fl", "original,timestamp,mimetype,statuscode,digest"),
        ("filter", "statuscode:200"),
        ("filter", _JS_MIMETYPE_FILTER),
        ("collapse", "digest"),
        # headroom over the cap: collapse is adjacency-only, so we over-fetch then
        # dedup+cap client-side below.
        ("limit", str(MAX_SNAPSHOTS_PER_HOST * 4)),
    ]
    url = f"{CDX_API_URL}?{urlencode(params)}"
    try:
        body, status = _http_get(url, CDX_TIMEOUT_SECONDS)
    except Exception as exc:  # URLError, timeout, HTTPError, ...
        logger.warning("stage 11 CDX query failed for %s (%s) - 0 snapshots this run", host, exc)
        return []

    text = body.decode("utf-8", errors="replace")
    state.save_raw(STAGE, f"cdx_{_sanitize(host)}", text)

    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("stage 11 CDX returned non-JSON for %s (rate-limit/HTML error page?) - 0 snapshots", host)
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []  # header-only or empty

    header = rows[0]
    idx = {name: i for i, name in enumerate(header)}
    if "original" not in idx or "timestamp" not in idx or "digest" not in idx:
        logger.warning("stage 11 CDX header for %s missing expected fields: %r - 0 snapshots", host, header)
        return []

    snaps: list[dict] = []
    seen_digests: set[str] = set()
    for row in rows[1:]:
        try:
            original = row[idx["original"]]
            timestamp = row[idx["timestamp"]]
            digest = row[idx["digest"]]
        except (IndexError, KeyError):
            continue
        statuscode = row[idx["statuscode"]] if "statuscode" in idx else "200"
        if statuscode != "200":
            continue
        # client-side digest dedup - collapse=digest is ADJACENCY-only (real finding).
        if digest in seen_digests:
            continue
        seen_digests.add(digest)
        snaps.append({
            "original": original,
            "timestamp": timestamp,
            "digest": digest,
            "mimetype": row[idx["mimetype"]] if "mimetype" in idx else "",
        })
        if len(snaps) >= MAX_SNAPSHOTS_PER_HOST:
            logger.info("stage 11 CDX: hit MAX_SNAPSHOTS_PER_HOST=%d for %s", MAX_SNAPSHOTS_PER_HOST, host)
            break

    logger.info("stage 11 CDX: %d unique .js snapshot(s) for %s", len(snaps), host)
    return snaps


def fetch_snapshot(snap: dict, state: RunState):
    """Phase 2: fetch the raw (`id_`) archived body → a `.js` file under the R8
    chmod-700 run dir (suffixed by original URL + timestamp, R5 - nothing
    overwrites), which doubles as jsluice's local input. Returns the file Path.
    Raises on empty/non-200 (caller R7-skips just this snapshot)."""
    url = SNAPSHOT_URL_FMT.format(timestamp=snap["timestamp"], original=snap["original"])
    body, status = _http_get(url, FETCH_TIMEOUT_SECONDS)
    if status != 200 or not body:
        raise ValueError(f"empty/non-200 archived snapshot (status={status}) for {url}")
    # save_raw hardcodes a .json extension, so write the .js body directly.
    name = f"stage{STAGE}_wayback_body_{_sanitize(snap['original'])}_{snap['timestamp']}.js"
    path = state.raw_dir / name
    path.write_bytes(body)
    return path


def run_archived_js_mining(in_scope_hosts: list[str], state: RunState,
                           current_pass: int, scope: dict) -> tuple[list[Asset], dict[str, list]]:
    """
    Returns (new_assets, records):
      - new_assets: type="url" Assets - each archived `.js` URL itself (minted so
        it is scope-gated and can parent its secrets) + each endpoint URL jsluice
        resolves from an archived body. discovered_by="wayback_jsluice".
      - records: {"endpoints", "parameters", "secrets"} - all target_derived=True,
        each carrying source=wayback provenance metadata.
    Empty in_scope_hosts -> ([], {empty lists}). Fault isolation at BOTH the
    per-host CDX call and the per-snapshot mine (R7).
    """
    new_assets: list[Asset] = []
    endpoints: list[Endpoint] = []
    parameters: list[Parameter] = []
    secrets: list[Secret] = []

    if not in_scope_hosts:
        return new_assets, {"endpoints": endpoints, "parameters": parameters, "secrets": secrets}

    with timed(state, "stage11.archived_js_total"):
        for host in in_scope_hosts:
            try:
                snapshots = query_cdx_js(host, state)
            except Exception:
                logger.exception("stage 11 CDX query failed for %s - skipping host (R7)", host)
                continue

            for snap in snapshots:
                original = snap["original"]
                timestamp = snap["timestamp"]
                try:
                    body_path = fetch_snapshot(snap, state)
                    url_findings = run_jsluice_urls(str(body_path), state, base_url=original, stage=STAGE)
                    raw_secrets = run_jsluice_secrets(str(body_path), state, base_url=original, stage=STAGE)
                except Exception:
                    logger.exception("stage 11 snapshot mine failed for %s - skipping snapshot (R7)", original)
                    continue

                prov = {"source": "wayback", "snapshot_timestamp": timestamp, "archived_url": original}

                # mint the archived .js URL itself as a url asset (scope-gated; parents its secrets)
                new_assets.append(Asset(
                    value=original, type="url", discovered_by="wayback_jsluice",
                    discovered_at_stage=STAGE, discovered_in_pass=current_pass,
                ))

                for f in url_findings:
                    resolved = f["url"]
                    method = f["method"]
                    parsed = urlparse(resolved)
                    host_of = parsed.hostname or ""
                    path_of = parsed.path or ""
                    new_assets.append(Asset(
                        value=resolved, type="url", discovered_by="wayback_jsluice",
                        discovered_at_stage=STAGE, discovered_in_pass=current_pass,
                    ))
                    endpoints.append(Endpoint(
                        url=resolved, host=host_of, path=path_of, method=method,
                        discovered_by="wayback_jsluice", target_derived=True,
                        discovered_at_stage=STAGE, discovered_in_pass=current_pass,
                        metadata=dict(prov),
                    ))
                    for name in f["queryParams"]:
                        if name:
                            parameters.append(Parameter(
                                name=name, host=host_of, endpoint=resolved, method=method,
                                location="query", reflected=None, discovered_by="wayback_jsluice",
                                target_derived=True, discovered_at_stage=STAGE,
                                discovered_in_pass=current_pass, metadata=dict(prov),
                            ))
                    for name in f["bodyParams"]:
                        if name:
                            parameters.append(Parameter(
                                name=name, host=host_of, endpoint=resolved, method=method,
                                location="body", reflected=None, discovered_by="wayback_jsluice",
                                target_derived=True, discovered_at_stage=STAGE,
                                discovered_in_pass=current_pass, metadata=dict(prov),
                            ))

                # secrets are per-snapshot (per body), like stage 7's per-js-url loop.
                # raw_log_ref must match what run_jsluice_secrets wrote (base=original, stage=11).
                raw_ref = f"raw/stage{STAGE}_jsluice_secrets_{_sanitize(original)}.json"
                for s in raw_secrets:
                    value = _jsluice_secret_value(s)
                    secrets.append(Secret(
                        kind=str(s.get("kind") or s.get("type") or "unknown"),
                        fingerprint=secret_fingerprint(value),
                        raw_log_ref=raw_ref,
                        severity=s.get("severity"),
                        validated=None,  # set downstream by primitive, never recon
                        discovered_by="wayback_jsluice",
                        target_derived=True,
                        discovered_at_stage=STAGE,
                        discovered_in_pass=current_pass,
                        # source_url (a location, safe) lets persist_records link
                        # asset_id to the minted archived-.js url asset; the raw
                        # value stays only in the raw archive, never in assets.db.
                        metadata={"source_url": original, **prov},
                    ))

                if INTER_FETCH_DELAY_SECONDS:
                    time.sleep(INTER_FETCH_DELAY_SECONDS)

    logger.info("stage 11 archived JS: %d url asset(s), %d endpoint(s), %d parameter(s), %d secret(s)",
                len(new_assets), len(endpoints), len(parameters), len(secrets))
    return new_assets, {"endpoints": endpoints, "parameters": parameters, "secrets": secrets}
