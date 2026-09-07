"""
Stage 8: High-signal checks - subdomain takeover detection.

Tool: nuclei v3.11.1, full -tags takeover template set (locked design, see
/areas/hackbot.md) - confirmed real via `nuclei -tl -tags takeover` to
include both the dns/ category (detect-dangling-cname, azure-takeover-
detection, elasticbeanstalk-takeover, servfail-refused-hosts) and the full
http/takeovers/ provider-fingerprint library (60+ service-specific
templates - Bitbucket, Ghost, GitHub, AWS S3, etc.). Broader coverage was
chosen deliberately over a hand-curated narrow subset.

Confirmed-real CLI facts (nuclei v3.11.1): -l for a target list file,
-tags takeover for template selection, -jsonl for JSONL stdout, -silent to
suppress non-finding noise, -rl for per-second rate limit (same flag
family as httpx/naabu).

⚠️ (R3) nuclei's -rl is a WHOLE-INVOCATION ceiling, not a real per-host
cap: the full takeover set is 60+ templates, so one host can absorb the
entire aggregate budget. This is the same whole-invocation limitation
originally flagged only for katana, generalized to nuclei by the R3
resolution - flagged, not fixed this pass (see rate_limits.nuclei_rate_args).

Confirmed-real behavior: an empty-findings run against zonetransfer.me +
www.zonetransfer.me returned empty stdout with exit code 0 - there is no
sentinel/marker line for "no findings", empty output IS the zero-findings
signal.

*** UNVERIFIED PARSER - READ BEFORE TOUCHING ***
Unlike every stage 4-7 tool integration, this module's JSONL parsing was
NOT built from a real positive-finding sample. A throwaway-GitHub-Pages-
custom-domain test was attempted specifically to generate one, but was
blocked: Jared doesn't own a domain to point DNS at, and buying one just
for this wasn't judged worth it given how rare/low-priority real takeover
findings are. This is an explicit, logged deviation from this project's
normal "verify real tool output before writing parser code" discipline -
not an oversight.

parse_nuclei_jsonl() below is built defensively from nuclei's documented
finding schema: template-id, info.{name,severity}, type, host, matched-at,
extracted-results. It checks both hyphenated and underscored key variants
where plausible, defaults missing optional fields instead of raising, and
skips (rather than crashes on) any line that isn't valid JSON. None of
that has been confirmed against real nuclei takeover output. Specific
known risk areas: exact field names/casing may differ from what's
assumed; non-zero exit code handling is inferred from general CLI
convention only, not observed; and TakeoverFinding.asset_id linkage
depends on nuclei's host field exact-string-matching an existing asset
value, which will silently fail (asset_id stays None) if nuclei's host
field carries a scheme/port a bare hostname in assets.db doesn't have.

KEEP THIS FLAGGED AS UNVERIFIED until a real positive finding - on a live
bug bounty target, or an opportunistic future test case - confirms or
corrects the assumptions above. Don't let this quietly pass as "tested"
the way stages 4-7 are.
"""

import json
import logging
import tempfile
from pathlib import Path

from state import RunState, TakeoverFinding, ReconFinding
from rate_limits import nuclei_rate_args

logger = logging.getLogger(__name__)

STAGE = 8

# (C1) Detection-only nuclei tag set. Include: presence/exposure fingerprints.
# Exclude: default-logins + any credential-submitting / write / exploit /
# fuzzing / dos template — that is active auth testing / exploitation, i.e.
# primitive's guarded territory, NOT recon's. `exposed-tokens` is DEFERRED to
# E4/D3 (those templates extract a credential value → the never-store-raw-secret
# rule). Verified 2026-08-23: real nuclei v3.11.1 JSONL positive uses top-level
# `template-id`/`matched-at`/`type` and `info.{name,severity,tags(list)}` — the
# same fields parse_nuclei_jsonl() already reads; C1 adds `info.tags` → category.
DETECTION_INCLUDE_TAGS = "exposures,misconfiguration,exposed-panels"
DETECTION_EXCLUDE_TAGS = "default-logins,intrusive,fuzzing,dos"

# nuclei raw-finding keys dropped before persisting a ReconFinding (heavy, and
# they can carry target-authored / sensitive bytes — full verbatim stays only in
# the R8 chmod-700 raw archive).
_RECON_RAW_TRIM_KEYS = {"request", "response", "curl-command"}
DEFAULT_TIMEOUT_SECONDS = 600  # nuclei's full takeover template set (60+
                                 # templates) against a multi-host target
                                 # list is a heavier single invocation than
                                 # most other stages' per-tool calls; no
                                 # real-world timing observed yet to tune
                                 # this further


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


def run_nuclei_takeover(hosts: list[str], state: RunState, scope: dict) -> str:
    """
    Run nuclei's full -tags takeover template set against hosts. Returns
    raw stdout (JSONL, one finding per line - confirmed-real empty string
    for zero findings, exit code 0).

    scope is the loaded scope.json dict, passed through for
    nuclei_rate_args().

    Nonzero exit code is treated as a real failure - this branch is
    UNVERIFIED (see module docstring), inferred from general CLI
    convention rather than an observed real nuclei failure.
    """
    if not hosts:
        return ""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        targets_path = f.name

    rate = nuclei_rate_args(scope, host_count=len(hosts))
    logger.info("nuclei takeover rate limit: %s", rate.note)

    cmd = ["nuclei", "-l", targets_path, "-tags", "takeover", "-jsonl", "-silent", *rate.extra_args]

    stdout, stderr, code = _run_tool(cmd)
    state.save_raw(STAGE, "nuclei_takeover", stdout)

    Path(targets_path).unlink(missing_ok=True)

    if code != 0:
        logger.error("nuclei exited %d: %s", code, stderr[:2000])
        # UNVERIFIED: real nuclei nonzero-exit behavior hasn't been
        # observed. Logging and returning empty rather than raising, so a
        # single bad run doesn't hard-crash the whole stage - matches
        # this stage's overall defensive posture given the unverified
        # parser below. Revisit once a real failure case is seen.
        return ""

    return stdout


def parse_nuclei_jsonl(raw_output: str) -> list[dict]:
    """
    Parse nuclei JSONL output into normalized finding dicts.

    *** UNVERIFIED - see module docstring. *** Built defensively from
    nuclei's documented schema, not a real positive sample. Blank lines
    are skipped; a line that fails to parse as JSON is logged and skipped
    rather than crashing the whole batch (same "one bad line shouldn't
    lose everything else" posture as every other JSONL-parsing stage in
    this pipeline - stage6/stage7 use the identical pattern). Missing
    optional fields default rather than raise.
    """
    findings = []
    for i, line in enumerate(raw_output.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("nuclei takeover: could not parse line %d as JSON: %r", i, line)
            continue

        info = obj.get("info", {})
        findings.append({
            "host": obj.get("host", ""),
            "template_id": obj.get("template-id", obj.get("template_id", "")),
            "template_name": info.get("name", ""),
            "severity": info.get("severity", "unknown"),
            "matched_at": obj.get("matched-at", obj.get("matched_at", "")),
            "type": obj.get("type", ""),
            "raw_finding": obj,
        })

    if findings:
        logger.info("nuclei takeover: parsed %d finding(s)", len(findings))
    return findings


def run_nuclei_detection(hosts: list[str], state: RunState, scope: dict) -> str:
    """(C1) Run the DETECTION-ONLY nuclei set (exposures/misconfig/panels, with
    default-logins/intrusive/fuzzing/dos excluded) against hosts. Returns raw
    JSONL stdout (empty string = zero findings, exit 0 — the confirmed signal).
    Separate invocation from takeover so each is R7-isolated and the raw archives
    don't collide. Same rate model (nuclei -rl); ⚠️ the R3 whole-invocation gap is
    worse here (larger template set) — flagged, bounded by the stage timeout."""
    if not hosts:
        return ""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        targets_path = f.name
    rate = nuclei_rate_args(scope, host_count=len(hosts))
    logger.info("nuclei detection rate limit: %s", rate.note)
    cmd = ["nuclei", "-l", targets_path,
           "-tags", DETECTION_INCLUDE_TAGS, "-etags", DETECTION_EXCLUDE_TAGS,
           "-jsonl", "-silent", *rate.extra_args]
    stdout, stderr, code = _run_tool(cmd)
    state.save_raw(STAGE, "nuclei_detection", stdout)
    Path(targets_path).unlink(missing_ok=True)
    if code != 0:
        logger.error("nuclei detection exited %d: %s", code, stderr[:2000])
        return ""
    return stdout


def parse_nuclei_detection_jsonl(raw_output: str) -> list[dict]:
    """Parse detection JSONL into normalized dicts. Uses the same real field names
    parse_nuclei_jsonl() reads (verified against real nuclei v3.11.1 output), plus
    `info.tags` (a LIST) → `category`, and TRIMS request/response/curl-command from
    the retained raw finding. One bad line is skipped, not fatal."""
    findings = []
    for i, line in enumerate(raw_output.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("nuclei detection: could not parse line %d as JSON: %r", i, line)
            continue
        info = obj.get("info", {}) or {}
        tags = info.get("tags")
        category = ",".join(tags) if isinstance(tags, list) else (tags or "")
        trimmed = {k: v for k, v in obj.items() if k not in _RECON_RAW_TRIM_KEYS}
        findings.append({
            "host": obj.get("host", ""),
            "template_id": obj.get("template-id", obj.get("template_id", "")),
            "template_name": info.get("name", ""),
            "category": category,
            "severity": info.get("severity", "unknown"),
            "matched_at": obj.get("matched-at", obj.get("matched_at", "")),
            "raw_finding": trimmed,
        })
    if findings:
        logger.info("nuclei detection: parsed %d finding(s)", len(findings))
    return findings


def run_stage8_detection(hosts: list[str], state: RunState, current_pass: int, scope: dict,
                         asset_lookup: dict[str, str] | None = None) -> list[ReconFinding]:
    """(C1) Detection-only nuclei → ReconFinding list for the caller to persist via
    state.add_recon_findings(). R7-isolated from the takeover run (a failure here
    does not lose takeover findings). asset_id linked by exact host match."""
    try:
        raw = run_nuclei_detection(hosts, state, scope)
    except Exception:
        logger.exception("stage 8 nuclei detection failed - no recon findings this pass (R7)")
        raw = ""
    parsed = parse_nuclei_detection_jsonl(raw)
    asset_lookup = asset_lookup or {}
    return [
        ReconFinding(
            host=p["host"], template_id=p["template_id"], source="nuclei",
            asset_id=asset_lookup.get(p["host"]),
            template_name=p["template_name"], category=p["category"],
            severity=p["severity"], matched_at=p["matched_at"],
            status="new", target_derived=True, raw_finding=p["raw_finding"],
            discovered_at_stage=STAGE, discovered_in_pass=current_pass,
        )
        for p in parsed
    ]


def run_stage8(hosts: list[str], state: RunState, current_pass: int, scope: dict,
               asset_lookup: dict[str, str] | None = None) -> list[TakeoverFinding]:
    """
    Full stage 8 sequence: run nuclei against hosts, parse, return
    TakeoverFinding objects for the caller to store via
    state.add_takeover_findings(). Mirrors stage 7's "this module doesn't
    write assets.db itself, caller applies the result" separation, except
    stage 8 produces findings rather than new Assets - there's no new
    asset to run through the scope gate here, every host is already a
    known in-scope asset by construction.

    (R7) The single nuclei invocation is wrapped so a nuclei failure
    (beyond the nonzero-exit case run_nuclei_takeover() already swallows -
    e.g. a tempfile/OS error) yields zero findings this pass rather than
    aborting the whole run. Stage 8 is a single-tool stage, so the guard
    sits at this one call site.

    scope is the loaded scope.json dict, threaded through to
    run_nuclei_takeover() for rate-limit resolution.

    asset_lookup optionally maps hostname -> asset_id for FK linkage
    (UNVERIFIED naive exact-string match - see module docstring). A host
    with no match in asset_lookup still produces a finding, just with
    asset_id=None rather than being dropped.
    """
    try:
        raw = run_nuclei_takeover(hosts, state, scope)
    except Exception:
        logger.exception("stage 8 nuclei failed - no takeover findings this pass (R7)")
        raw = ""

    parsed = parse_nuclei_jsonl(raw)

    asset_lookup = asset_lookup or {}
    findings = [
        TakeoverFinding(
            host=p["host"],
            template_id=p["template_id"],
            asset_id=asset_lookup.get(p["host"]),
            template_name=p["template_name"],
            severity=p["severity"],
            matched_at=p["matched_at"],
            type=p["type"] if p["type"] in ("dns", "http") else "http",
            raw_finding=p["raw_finding"],
            discovered_at_stage=STAGE,
            discovered_in_pass=current_pass,
        )
        for p in parsed
    ]
    return findings
