"""
Stage 7: JS discovery + extraction.

Two-part JS discovery (locked design):
  1. Reuse stage 6's already-crawled type="url" assets ending in .js.
  2. Active probe of common framework build-output paths (BUNDLER_PATHS)
     against every in-scope host, via httpx, to catch JS files a generic
     crawl might have missed.

Extraction: jsluice (BishopFox/jsluice) urls mode AND secrets mode, run
directly against JS file URLs (jsluice fetches remote URLs itself).

(Track D) jsluice output is now promoted to first-class source records
rather than url-asset metadata:
  - urls mode: each finding's resolved `url` still becomes a type="url"
    Asset (the scope-gated location graph is unchanged), AND an `endpoint`
    record (url + method), AND `parameter` records for the queryParams/
    bodyParams jsluice reports (B3 - previously discarded). These are
    target-authored → target_derived=True.
  - secrets mode: each finding becomes a `secret` record holding a capped
    fingerprint + a raw_log_ref pointer, NEVER the raw value (which stays
    only in the per-source raw archive). `validated` is left for primitive.

Real jsluice CLI/output (verified against the installed tool):
  jsluice <urls|secrets> [options] [url...]  → JSONL, one object per line.
  urls-mode fields: url, queryParams, bodyParams, method, type, filename.
  -u/--unique is urls-mode only. secrets mode has not been observed firing
  on a real file (a plausible zero) - the secret dict shape is UNVERIFIED,
  so the full finding is preserved in the raw archive and the `secret`
  record's metadata is left empty (only kind/severity are lifted into
  columns) to avoid leaking an unrecognized value field into assets.db.

(Track D sub-fix, R5-style) jsluice raw archives are now suffixed per
source JS URL (jsluice_urls_{sanitized}, jsluice_secrets_{sanitized}) so
each file's raw survives and `secret.raw_log_ref` points at a stable
location - the previous fixed filenames overwrote each other per JS file.

Like every other stage, this module does NOT classify assets or write
assets.db itself - new assets and records are returned to main.py.
"""

import json
import logging
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from state import Asset, RunState, timed, Parameter, Endpoint, Secret, secret_fingerprint
from rate_limits import httpx_rate_args

logger = logging.getLogger(__name__)

STAGE = 7
DEFAULT_TIMEOUT_SECONDS = 300

# Hand-curated list of common framework/bundler build-output paths (v1,
# flagged to revisit with a more authoritative source later).
BUNDLER_PATHS = [
    "/_next/static/",
    "/static/js/",
    "/assets/",
    "/assets/js/",
    "/dist/",
    "/dist/js/",
    "/build/",
    "/build/static/js/",
    "/js/",
    "/scripts/",
    "/public/js/",
    "/bundle.js",
    "/main.js",
    "/app.js",
    "/vendor.js",
]

# candidate keys that might hold the raw secret VALUE in a jsluice secrets
# finding (shape UNVERIFIED). Used only to compute the fingerprint; none of
# these are ever copied into the `secret` record's metadata.
_SECRET_VALUE_KEYS = ("secret", "value", "match", "token", "key", "data", "raw")


def _sanitize(s: str) -> str:
    """(Track D) filesystem-safe token of a source URL for per-source raw
    archive filenames (so jsluice raw files don't overwrite each other and
    raw_log_ref points somewhere stable). Same character class as stage 1/3."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def _jsluice_secret_value(finding: dict) -> str:
    """Best-effort extraction of the raw secret string from a jsluice secrets
    finding, for fingerprinting ONLY. Shape is UNVERIFIED, so this checks a
    few plausible keys and falls back to the whole finding serialized - the
    fingerprint is irreversible either way, so a wrong guess still yields a
    stable, non-leaking dedup key."""
    for k in _SECRET_VALUE_KEYS:
        v = finding.get(k)
        if isinstance(v, str) and v:
            return v
    return json.dumps(finding, sort_keys=True)


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


def probe_bundler_paths(hosts: list[str], state: RunState, scope: dict) -> list[str]:
    """
    Actively probe BUNDLER_PATHS against every in-scope host via httpx, to
    catch JS files a generic crawl might have missed. Returns live JS file
    URLs (only status 200 + a javascript content-type counts - a real run
    caught every nonexistent path 301-redirecting to a generic fallback,
    producing 45 false positives).

    host_count for httpx_rate_args is the real per-invocation TARGET count
    (len(hosts) * len(BUNDLER_PATHS)), not len(hosts) - httpx's -rl caps the
    whole invocation and each (host, path) is a distinct request.
    """
    if not hosts:
        return []

    # (G1) once the rate-guard has tripped, send no further target traffic
    if not state.ledger.guard_allows():
        logger.info("bundler probe: skipping - request rate-guard tripped")
        return []

    targets = []
    for host in hosts:
        for path in BUNDLER_PATHS:
            targets.append(f"https://{host}{path}")

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        targets_path = f.name

    rate = httpx_rate_args(scope, host_count=len(targets))
    allowed_rps = int(rate.extra_args[1])   # (G1) the -rl value = authorized aggregate rps for this invocation
    logger.info("bundler probe httpx rate limit: %s", rate.note)

    # (G1) ~15 probes/host in one whole-invocation-rl call: recorded for telemetry, but
    # evaluate_rate=False - the volume is below the safety-relevant threshold and a multi-
    # host invocation can't be attributed per host (true enforcement rides with Phase B).
    with state.ledger.measure("bundler-probe", "httpx-bundler", allowed_rps=allowed_rps,
                              at_stage=STAGE, evaluate_rate=False) as inv:
        stdout, stderr, code = _run_tool([
            "httpx", "-l", targets_path,
            "-json", "-silent",
            "-status-code",
            "-mc", "200",
            *rate.extra_args,
        ])
        inv.requests = len(targets)   # ~1 probe request per (host, path)
    state.save_raw(STAGE, "bundler_probe_httpx", stdout)

    found_urls = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("bundler probe httpx: could not parse line as JSON: %r", line)
            continue
        content_type = (obj.get("content_type") or "").lower()
        if content_type and "javascript" not in content_type and "ecmascript" not in content_type:
            continue
        url = obj.get("url") or obj.get("input")
        if url:
            found_urls.append(url)

    Path(targets_path).unlink(missing_ok=True)

    logger.info("bundler path probe found %d live JS candidate(s) across %d host(s)",
                len(found_urls), len(hosts))
    return found_urls


def run_jsluice_urls(js_url: str, state: RunState,
                     base_url: str | None = None, stage: float = STAGE) -> list[dict]:
    """
    Run jsluice's urls mode against a single JS source. (Track D / B3)
    Returns one dict per finding: {url (resolved), method, queryParams,
    bodyParams} - previously this threw away everything but url, discarding
    exactly the param/method context Track D wants.

    `js_url` is what jsluice actually reads: a remote URL (stage 7, jsluice
    fetches it) OR a LOCAL FILE PATH (B4/stage 11, an archived body already on
    disk - jsluice reads local files as positional args, verified 2026-08-24).
    `base_url` is the URL relative paths resolve against and the raw-archive is
    named by; it defaults to `js_url` (stage-7 behavior unchanged). B4 passes
    the ORIGINAL archived .js URL here so a relative endpoint resolves onto the
    target host, not the local temp path (the central B4 correctness trap).
    `stage` sets the raw-archive prefix (7 for live JS, 11 for archived).
    """
    base = base_url or js_url
    stdout, stderr, code = _run_tool(["jsluice", "urls", "-u", js_url])
    state.save_raw(stage, f"jsluice_urls_{_sanitize(base)}", stdout)

    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("jsluice urls: could not parse line as JSON: %r", line)
            continue
        raw_url = obj.get("url")
        if not raw_url:
            continue
        findings.append({
            "url": urljoin(base, raw_url),
            "method": (obj.get("method") or "GET").upper(),
            "queryParams": obj.get("queryParams") or [],
            "bodyParams": obj.get("bodyParams") or [],
        })

    logger.info("jsluice urls found %d resolved URL(s) in %s", len(findings), base)
    return findings


def run_jsluice_secrets(js_url: str, state: RunState,
                        base_url: str | None = None, stage: float = STAGE) -> list[dict]:
    """
    Run jsluice's secrets mode against a single JS source (remote URL for
    stage 7, or a LOCAL FILE PATH for B4/stage 11). Returns the raw list of
    secret-finding dicts jsluice emits (shape UNVERIFIED - never observed
    firing on a real file). Raw archive is per-source (R5-style), named by
    `base_url` (default js_url) and prefixed by `stage`, so the full findings
    survive and the `secret` records built downstream can point raw_log_ref at
    this file. NOT passed -u (a urls-mode uniqueness flag).
    """
    base = base_url or js_url
    stdout, stderr, code = _run_tool(["jsluice", "secrets", js_url])
    state.save_raw(stage, f"jsluice_secrets_{_sanitize(base)}", stdout)

    secrets = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("jsluice secrets: could not parse line as JSON: %r", line)
            continue
        secrets.append(obj)

    if secrets:
        logger.info("jsluice secrets found %d potential secret(s) in %s", len(secrets), base)
    return secrets


def run_stage7(known_in_scope_hosts: list[str], known_js_urls: list[str],
               state: RunState, current_pass: int, scope: dict) -> tuple[list[Asset], dict[str, dict], dict[str, list]]:
    """
    Run the full stage 7 sequence: bundler-path probe + jsluice urls/secrets
    over the combined, deduplicated JS-file set.

    Returns a THREE-tuple (Track D added the third element):
      - new_assets: list[Asset] - bundler-probed JS files (discovered_by=
        bundler_probe) + jsluice resolved endpoint URLs (discovered_by=
        jsluice), type="url", for the caller to scope-gate + add_assets().
      - metadata_updates: dict[str, dict] - kept for contract symmetry;
        empty now that jsluice secrets are `secret` records, not a
        jsluice_secrets metadata blob.
      - records: dict[str, list] - {"endpoints": [...], "parameters": [...],
        "secrets": [...]} for the caller to persist via persist_records()
        (which sets asset_id and drops out-of-scope records). jsluice-derived
        endpoints/params are target_derived=True; secrets store fingerprint +
        raw_log_ref only, never the raw value.
    """
    with timed(state, "stage7.bundler_probe"):
        bundler_found = probe_bundler_paths(known_in_scope_hosts, state, scope)

    known_js_set = set(known_js_urls)
    new_bundler_js_urls = [u for u in bundler_found if u not in known_js_set]
    all_js_urls_to_process = sorted(known_js_set | set(new_bundler_js_urls))

    new_assets: list[Asset] = []
    for url in new_bundler_js_urls:
        new_assets.append(Asset(
            value=url,
            type="url",
            discovered_by="bundler_probe",
            discovered_at_stage=STAGE,
            discovered_in_pass=current_pass,
        ))

    endpoints: list[Endpoint] = []
    parameters: list[Parameter] = []
    secrets: list[Secret] = []

    with timed(state, "stage7.jsluice_total"):
        for js_url in all_js_urls_to_process:
            # (G1) jsluice FETCHES each remote JS URL (target traffic) - stop after a trip.
            if not state.ledger.guard_allows():
                logger.info("stage 7: rate-guard tripped - stopping jsluice fetches")
                break
            try:
                url_findings = run_jsluice_urls(js_url, state)
            except Exception:
                logger.exception("Stage 7 jsluice urls failed for %s", js_url)
                url_findings = []

            for f in url_findings:
                resolved_url = f["url"]
                method = f["method"]
                new_assets.append(Asset(
                    value=resolved_url,
                    type="url",
                    discovered_by="jsluice",
                    discovered_at_stage=STAGE,
                    discovered_in_pass=current_pass,
                ))
                parsed = urlparse(resolved_url)
                host = parsed.hostname or ""
                path = parsed.path or ""
                endpoints.append(Endpoint(
                    url=resolved_url, host=host, path=path, method=method,
                    discovered_by="jsluice", target_derived=True,
                    discovered_at_stage=STAGE, discovered_in_pass=current_pass,
                ))
                for name in f["queryParams"]:
                    if name:
                        parameters.append(Parameter(
                            name=name, host=host, endpoint=resolved_url, method=method,
                            location="query", reflected=None, discovered_by="jsluice",
                            target_derived=True, discovered_at_stage=STAGE,
                            discovered_in_pass=current_pass,
                        ))
                for name in f["bodyParams"]:
                    if name:
                        parameters.append(Parameter(
                            name=name, host=host, endpoint=resolved_url, method=method,
                            location="body", reflected=None, discovered_by="jsluice",
                            target_derived=True, discovered_at_stage=STAGE,
                            discovered_in_pass=current_pass,
                        ))

            try:
                raw_secrets = run_jsluice_secrets(js_url, state)
            except Exception:
                logger.exception("Stage 7 jsluice secrets failed for %s", js_url)
                raw_secrets = []

            raw_ref = f"raw/stage{STAGE}_jsluice_secrets_{_sanitize(js_url)}.json"
            for s in raw_secrets:
                value = _jsluice_secret_value(s)
                secrets.append(Secret(
                    kind=str(s.get("kind") or s.get("type") or "unknown"),
                    fingerprint=secret_fingerprint(value),
                    raw_log_ref=raw_ref,
                    severity=s.get("severity"),
                    validated=None,  # set downstream by primitive, never recon
                    discovered_by="jsluice",
                    target_derived=True,
                    discovered_at_stage=STAGE,
                    discovered_in_pass=current_pass,
                    # metadata deliberately carries the source JS url (a
                    # location, safe) so main can resolve asset_id; the raw
                    # finding (incl. any value field) stays only in the raw
                    # archive, never in assets.db.
                    metadata={"source_url": js_url},
                ))

    metadata_updates: dict[str, dict] = {}
    return new_assets, metadata_updates, {
        "endpoints": endpoints,
        "parameters": parameters,
        "secrets": secrets,
    }
