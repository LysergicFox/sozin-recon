#!/usr/bin/env python3
"""
Recon agent entrypoint - stages 1, 3, 4, 5, 6, 7, 8, 9.

Runs the staged pipeline once (no loop-until-stable yet), scope-gating each
stage's discoveries into assets.db and persisting Track-D source records
(parameters/endpoints/secrets/services) alongside. See RECON_AGENT_DESIGN.md
for the architecture and RECON_TRACK_D_DESIGN.md for the source-record model.

Usage:
    python3 main.py --run-dir   /path/to/run_directory
    python3 main.py --target-dir /path/to/bugbounty/targets/<platform>/<target>

With --run-dir, run_directory/scope.json must already exist. With --target-dir,
the target folder's canonical scope.json is copied into a freshly created,
timestamped run dir at <target>/runs/run_<UTC-ts>_<shortid>/ and the run happens
there - this is the layout sozin-dashboard consumes (one target folder, many
runs under runs/). Either way scope.json must have verified_by_human: true and an
affirmative rate_limit block (R2).
"""

import argparse
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from state import RunState, Asset, ReviewItem, Service
from scope_gate import (
    ScopePatterns, classify_domain, classify_url, classify_ip,
    reason_for_ambiguous, reason_for_ambiguous_url, reason_for_ambiguous_ip,
    extract_host,
)
from rate_limit_gate import check_run_not_blocked
from http_headers import required_headers
from url_hygiene import is_malformed_url_asset
from stages.stage1_passive import run_stage1
from stages.stage3_active_dns import run_stage3
from stages.stage4_live_probing import run_stage4
from stages.stage5_hidden_params import run_stage5
from stages.stage6_crawling import run_stage6
from stages.stage_content_discovery import run_content_discovery
from stages.stage7_js_extraction import run_stage7
from stages.stage8_takeover import run_stage8, run_stage8_detection
from stages.stage9_whatweb import run_stage9
from stages.stage_api_discovery import run_api_discovery
from stages.stage_archived_js import run_archived_js_mining
from stages.auth_classification import run_auth_classification
from stages.secret_classification import run_secret_classification
from stages.interest_scoring import run_interest_scoring
from stages.url_clustering import run_url_clustering
from stages.target_profile import run_target_profile
from stages.reverse_dns import run_reverse_dns
from stages.stage_waf_cdn import run_waf_cdn
from stages.stage_screenshots import run_screenshots
from stages.cve_candidates import run_cve_candidates
from logging_setup import setup_logging_with_banner

logger = setup_logging_with_banner("recon_agent", version="v0")


def extract_root_domains(scope: dict) -> list[str]:
    """
    Pull bare root domains out of scope.json's in_scope.domains, stripping a
    leading '*.' - tools want 'example.com', not '*.example.com'.
    """
    domains = scope.get("in_scope", {}).get("domains", [])
    roots = []
    for d in domains:
        if d.startswith("*."):
            roots.append(d[2:])
        else:
            roots.append(d)
    seen = set()
    result = []
    for r in roots:
        if r not in seen:
            seen.add(r)
            result.append(r)
    return result


def apply_scope_gate(assets: list[Asset], patterns: ScopePatterns, state: RunState) -> list[Asset]:
    """
    Classify every asset via the deterministic tier. in_scope/out_of_scope get
    their scope_status set directly; ambiguous assets queue for human review.

    Branch by asset.type: url AND js_file -> classify_url (R13); ip ->
    classify_ip; everything else (subdomain) -> classify_domain.

    Review-queue insertion is de-duplicated (R10) by (now canonical, R6)
    value, within batch and against the existing queue; fail-closed preserved.
    """
    review_items = []

    for asset in assets:
        if asset.type in ("url", "js_file"):
            result = classify_url(asset.value, patterns)

            if result == "in_scope":
                asset.scope_status = "in_scope"
                asset.scope_decision_by = "deterministic"
            elif result == "out_of_scope":
                asset.scope_status = "out_of_scope"
                asset.scope_decision_by = "deterministic"
            else:
                asset.scope_status = "needs_review"
                asset.scope_decision_by = None
                host = extract_host(asset.value)
                reason = (
                    reason_for_ambiguous(host, patterns)
                    if host is not None
                    else reason_for_ambiguous_url(asset.value)
                )
                review_items.append(ReviewItem(
                    asset_id=asset.asset_id,
                    value=asset.value,
                    reason=reason,
                ))
            continue

        if asset.type == "ip":
            result = classify_ip(asset.value, patterns)

            if result == "in_scope":
                asset.scope_status = "in_scope"
                asset.scope_decision_by = "deterministic"
            else:
                asset.scope_status = "needs_review"
                asset.scope_decision_by = None
                resolved_from_host = asset.metadata.get("resolved_from_host")
                review_items.append(ReviewItem(
                    asset_id=asset.asset_id,
                    value=asset.value,
                    reason=reason_for_ambiguous_ip(asset.value, resolved_from_host=resolved_from_host),
                ))
            continue

        result = classify_domain(asset.value, patterns)

        if result == "in_scope":
            asset.scope_status = "in_scope"
            asset.scope_decision_by = "deterministic"
        elif result == "out_of_scope":
            asset.scope_status = "out_of_scope"
            asset.scope_decision_by = "deterministic"
        else:
            asset.scope_status = "needs_review"
            asset.scope_decision_by = None
            review_items.append(ReviewItem(
                asset_id=asset.asset_id,
                value=asset.value,
                reason=reason_for_ambiguous(asset.value, patterns),
            ))

    if review_items:
        existing_review = state.load_review_queue()
        seen = {i.value for i in existing_review}
        deduped_new = []
        for item in review_items:
            if item.value in seen:
                continue
            seen.add(item.value)
            deduped_new.append(item)
        if deduped_new:
            state.save_review_queue(existing_review + deduped_new)

    return assets


def persist_records(state: RunState, records: dict) -> None:
    """
    (Track D) Persist source records returned by a stage. For each record:
    set asset_id by matching its parent-asset VALUE, and DROP the record if
    that parent is out_of_scope (so third-party jsluice endpoints/params
    don't bloat the source tables - records inherit their parent's scope). A
    record whose parent value matches no asset is kept with asset_id=None.

    MUST be called AFTER the stage's new assets have gone through
    run_stage_and_report()/add_assets(), so parent lookups resolve. Persists
    via the RunState add_* methods (INSERT OR IGNORE dedup).
    """
    if not records:
        return

    scope_by_value = {a.value: (a.asset_id, a.scope_status) for a in state.load_assets()}

    def _link(parent_value):
        """Return (keep, asset_id). keep=False only when the parent asset
        exists and is out_of_scope."""
        if parent_value is None:
            return True, None
        info = scope_by_value.get(parent_value)
        if info is None:
            return True, None
        asset_id, status = info
        if status == "out_of_scope":
            return False, None
        return True, asset_id

    params_keep = []
    for p in records.get("parameters", []):
        keep, aid = _link(p.endpoint)
        if keep:
            p.asset_id = aid
            params_keep.append(p)

    endpoints_keep = []
    for e in records.get("endpoints", []):
        keep, aid = _link(e.url)
        if keep:
            e.asset_id = aid
            endpoints_keep.append(e)

    secrets_keep = []
    for s in records.get("secrets", []):
        keep, aid = _link(s.metadata.get("source_url"))
        if keep:
            s.asset_id = aid
            secrets_keep.append(s)

    services_keep = []
    for sv in records.get("services", []):
        aid = None
        dropped = False
        for candidate in (sv.ip, sv.host, sv.target):
            if candidate is None:
                continue
            info = scope_by_value.get(candidate)
            if info is None:
                continue
            a_id, status = info
            if status == "out_of_scope":
                dropped = True
                break
            aid = a_id
            break
        if not dropped:
            sv.asset_id = aid
            services_keep.append(sv)

    if params_keep:
        state.add_parameters(params_keep)
    if endpoints_keep:
        state.add_endpoints(endpoints_keep)
    if secrets_keep:
        state.add_secrets(secrets_keep)
    if services_keep:
        state.add_services(services_keep)

    logger.info(
        "Persisted source records: %d parameter(s), %d endpoint(s), %d secret(s), %d service(s)",
        len(params_keep), len(endpoints_keep), len(secrets_keep), len(services_keep),
    )


def drop_malformed_url_assets(found: list[Asset], stage_num: int) -> list[Asset]:
    """Ingestion hygiene: drop url/js_file assets whose value is crawl/history
    noise (HTML fragments, stray backslashes) rather than a real endpoint — see
    url_hygiene.is_malformed_url_asset. Applied ONCE here, before scope-gating,
    so noise never bloats assets.db, the review queue, or downstream stages.
    Order-preserving; non-url asset types pass through untouched. Every drop is
    logged (capped sample + total) so the filter stays auditable."""
    clean: list[Asset] = []
    dropped: list[str] = []
    for a in found:
        if a.type in ("url", "js_file") and is_malformed_url_asset(a.value):
            dropped.append(a.value)
            continue
        clean.append(a)
    if dropped:
        SAMPLE = 10
        logger.info(
            "Stage %s: dropped %d malformed url asset(s) at ingestion "
            "(crawl/history noise, not real endpoints); showing up to %d: %s",
            stage_num, len(dropped), SAMPLE, dropped[:SAMPLE],
        )
    return clean


def run_stage_and_report(stage_num: int, stage_name: str, found: list[Asset],
                          patterns: ScopePatterns, state: RunState) -> list[Asset]:
    """
    Shared tail-end for any stage: scope-gate the raw discoveries, merge into
    assets.db via de-dupe, log a breakdown, update run_state. Returns the
    genuinely-new assets.
    """
    logger.info("Stage %s (%s) raw discovery count (pre-dedupe, pre-scope): %d",
                stage_num, stage_name, len(found))

    found = drop_malformed_url_assets(found, stage_num)
    found = apply_scope_gate(found, patterns, state)
    newly_added = state.add_assets(found)
    logger.info("Newly added assets after de-dupe: %d", len(newly_added))

    in_scope_count = sum(1 for a in newly_added if a.scope_status == "in_scope")
    review_count = sum(1 for a in newly_added if a.scope_status == "needs_review")
    out_count = sum(1 for a in newly_added if a.scope_status == "out_of_scope")
    logger.info(
        "Breakdown: %d in_scope, %d needs_review, %d out_of_scope",
        in_scope_count, review_count, out_count,
    )

    state.update_run_state(current_stage=stage_num, status="stage_complete")
    return newly_added


def get_live_urls_for_x8(state: RunState) -> list[str]:
    """
    In-scope url assets whose HOST matches a hostname stage 4 confirmed live
    (carries httpx_status_code). Factored out so a stage-5-only re-run shares
    this exact logic.
    """
    all_assets = state.load_assets()
    live_hostnames = {
        a.value for a in all_assets
        if a.type == "subdomain" and "httpx_status_code" in a.metadata
    }
    return [
        a.value for a in all_assets
        if a.type == "url" and a.scope_status == "in_scope"
        and extract_host(a.value) in live_hostnames
    ]


def run_stage5_and_report(root_domains: list[str], patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """
    Full stage 5 sequence: paramspider (new url assets) + x8 (parameter
    records). x8 findings are Track-D `parameter` records now, not metadata.
    """
    live_urls = get_live_urls_for_x8(state)
    logger.info("Seeding stage 5 with %d root domain(s) for paramspider, %d live url(s) for x8",
                len(root_domains), len(live_urls))

    logger.info("--- Stage 5: hidden parameter discovery (paramspider + x8) ---")
    stage5_new_assets, stage5_metadata_updates, stage5_records = run_stage5(
        root_domains, live_urls, state, current_pass=1, scope=scope
    )

    # metadata_updates is empty now (x8 → parameter records), but keep the
    # application path for contract symmetry with stage 4/7.
    url_assets_by_value = {a.value: a for a in state.load_assets() if a.type == "url"}
    for url_value, metadata_update in stage5_metadata_updates.items():
        matching_asset = url_assets_by_value.get(url_value)
        if matching_asset is None:
            logger.warning("Stage 5 metadata for %r isn't a known url asset - skipping", url_value)
            continue
        state.update_asset_metadata(matching_asset.asset_id, metadata_update)

    run_stage_and_report(5, "hidden parameter discovery", stage5_new_assets, patterns, state)
    persist_records(state, stage5_records)


def run_stage6_and_report(patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """Full stage 6 sequence: katana crawl → new url assets."""
    all_assets = state.load_assets()
    known_in_scope_hosts = [
        a.value for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
    ]
    logger.info("Seeding stage 6 with %d known in-scope host(s)", len(known_in_scope_hosts))

    logger.info("--- Stage 6: crawling (katana, JS-aware) ---")
    stage6_new_assets = run_stage6(known_in_scope_hosts, state, current_pass=1, scope=scope)
    run_stage_and_report(6, "crawling", stage6_new_assets, patterns, state)


def _live_hosts_with_origins(state: RunState) -> tuple[list[str], dict[str, str]]:
    """Confirmed-live in-scope hosts (stage-9 filter) + each host's confirmed-live
    ORIGIN (scheme+authority) from stage 4's httpx_final_url. Shared by the active
    per-host stages (B1 content discovery, B2 API discovery) so both fuzz/probe the
    scheme httpx actually confirmed (http OR https), not a hardcoded https.

    SCOPE GUARD (real-run fix, 2026-08-24): the final_url origin is adopted ONLY
    when it resolves to the SAME host as the asset (a same-host http->https
    redirect). If the target redirected OFF-host — e.g. zonetransfer.me ->
    https://digi.ninja — the redirect target is deliberately left OUT of host_base,
    so the consuming active stages fall back to their own `https://{asset}` default
    and never point ffuf/wafw00f/etc. at the redirected-away, un-admitted host. R1
    accepts only httpx's single benign GET following an off-scope redirect; the
    aggressive per-host tools must not inherit that redirect target."""
    from urllib.parse import urlparse
    live = [
        a for a in state.load_assets()
        if a.type == "subdomain" and a.scope_status == "in_scope"
        and "httpx_status_code" in a.metadata
    ]
    hosts = [a.value for a in live]
    host_base: dict[str, str] = {}
    for a in live:
        fu = a.metadata.get("httpx_final_url")
        if fu:
            pr = urlparse(fu)
            # pr.hostname == a.value gates out off-host redirects (the scope leak);
            # same-host, scheme-or-port-only differences are kept (the reason this
            # origin map exists — confirming http vs https).
            if pr.scheme and pr.netloc and pr.hostname == a.value:
                host_base[a.value] = f"{pr.scheme}://{pr.netloc}"
    return hosts, host_base


def _apply_waf_flags(state: RunState, waf_flags: dict[str, dict]) -> None:
    """(B1) Attach per-host WAF intel from stage 6.5 as host metadata. These are
    AGENT-authored determinations about the host (trusted), NOT target-derived, so
    they are plain metadata, not entries in TARGET_DERIVED_METADATA_KEYS. The flag
    is the handoff primitive consumes when deciding whether to engage a filter."""
    if not waf_flags:
        return
    host_assets_by_value = {a.value: a for a in state.load_assets() if a.type == "subdomain"}
    applied = 0
    for host, waf in waf_flags.items():
        matching_asset = host_assets_by_value.get(host)
        if matching_asset is None:
            logger.warning("Stage 6.5 WAF flag for %r isn't a known host asset - skipping", host)
            continue
        state.update_asset_metadata(matching_asset.asset_id, {
            "waf_suspected": waf["waf_suspected"],
            "waf_signal": waf["waf_signal"],
            "waf_block_ratio": waf["waf_block_ratio"],
        })
        applied += 1
    logger.info("Applied stage 6.5 WAF flags to %d host(s)", applied)


def run_content_discovery_and_report(patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """
    Full stage 6.5 (B1) sequence: ffuf content discovery over confirmed-live
    in-scope hosts → new url assets + Track-D endpoint records + per-host WAF
    flags. Seeded exactly like stage 9 (in-scope subdomains that stage 4 confirmed
    live via httpx_status_code); brute-forcing a host not serving HTTP is wasted
    traffic. Runs BEFORE stage 7 so discovered .js is jsluice-mined same-pass.
    """
    live_hosts, host_base = _live_hosts_with_origins(state)
    logger.info("Seeding stage 6.5 with %d confirmed-live in-scope host(s)", len(live_hosts))

    logger.info("--- Stage 6.5: content / endpoint discovery (ffuf) ---")
    new_assets, records, waf_flags = run_content_discovery(
        live_hosts, state, current_pass=1, scope=scope, host_base=host_base)

    run_stage_and_report(6.5, "content discovery", new_assets, patterns, state)
    persist_records(state, records)                    # links endpoint.url → the just-added url asset
    _apply_waf_flags(state, waf_flags)


def run_screenshots_and_report(patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """(C2) Screenshot each confirmed-live host via httpx headless Chrome; store the
    per-host screenshot path (relative to the R8 run dir) as trusted host metadata
    for report/vision triage. Active (a page render/host), rate-bounded, R7-isolated."""
    live_hosts, host_base = _live_hosts_with_origins(state)
    logger.info("--- C2: screenshots (httpx headless Chrome) ---")
    updates = run_screenshots(live_hosts, state, scope, host_base=host_base)
    host_assets_by_value = {a.value: a for a in state.load_assets() if a.type == "subdomain"}
    applied = 0
    for host, update in updates.items():
        asset = host_assets_by_value.get(host)
        if asset is None:
            continue
        state.update_asset_metadata(asset.asset_id, update)
        applied += 1
    logger.info("Applied C2 screenshot metadata to %d host(s)", applied)


def run_waf_cdn_and_report(patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """Full stage 4.5 (C3) sequence: cdncheck (offline CDN/WAF/cloud classification)
    + wafw00f (active per-host WAF-vendor fingerprint) → trusted host metadata
    (is_behind_waf/waf_vendor/is_cdn/cdn_name/cloud_name). Runs right after liveness
    so the "know your target" label is available to the later active stages."""
    live_hosts, host_base = _live_hosts_with_origins(state)
    logger.info("--- Stage 4.5 (C3): WAF/CDN detection (cdncheck + wafw00f) ---")
    updates = run_waf_cdn(live_hosts, state, current_pass=1, scope=scope, host_base=host_base)
    host_assets_by_value = {a.value: a for a in state.load_assets() if a.type == "subdomain"}
    applied = 0
    for host, update in updates.items():
        asset = host_assets_by_value.get(host)
        if asset is None:
            logger.warning("Stage 4.5 WAF/CDN metadata for %r isn't a known host asset - skipping", host)
            continue
        state.update_asset_metadata(asset.asset_id, update)
        applied += 1
    logger.info("Applied stage 4.5 WAF/CDN metadata to %d host(s)", applied)


def run_stage10_and_report(patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """
    Full stage 10 (B2a) sequence: OpenAPI/Swagger discovery over confirmed-live
    in-scope hosts → new url assets (the spec URL + each described endpoint) plus
    Track-D endpoint + parameter records (target_derived=1 — the schema is
    target-authored). Terminal stage: a record-only producer with no downstream
    recon consumer. Introspection/GraphQL (B2b) lands as a follow-up.
    """
    live_hosts, host_base = _live_hosts_with_origins(state)
    logger.info("Seeding stage 10 with %d confirmed-live in-scope host(s)", len(live_hosts))

    logger.info("--- Stage 10: API-schema discovery (OpenAPI/Swagger) ---")
    new_assets, records = run_api_discovery(
        live_hosts, state, current_pass=1, scope=scope, host_base=host_base)

    run_stage_and_report(10, "API-schema discovery", new_assets, patterns, state)
    persist_records(state, records)                    # links endpoint/param.url → the just-added url assets


def run_archived_js_and_report(patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """
    Full stage 11 (B4) sequence: Wayback CDX + jsluice over archived `.js` bodies
    → new url assets + Track-D endpoint/parameter/secret records (target_derived=1,
    source=wayback). Terminal stage, runs after stage 7 so a live-and-archived
    endpoint dedups to the stage-7 row (INSERT OR IGNORE keep-first) and an
    archived-ONLY endpoint (removed from live) surfaces fresh — B4's whole point.

    Seeds ALL in-scope subdomains, NOT `_live_hosts_with_origins` — B4 sends no
    target traffic, so a dead-today host's archived JS is still worth mining
    (the deliberate divergence from B1/B2, design decision 5).
    """
    all_assets = state.load_assets()
    in_scope_hosts = [
        a.value for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
    ]
    logger.info("Seeding stage 11 with %d in-scope host(s) (live or not)", len(in_scope_hosts))

    logger.info("--- Stage 11: archived JS mining (wayback CDX + jsluice) ---")
    new_assets, records = run_archived_js_mining(in_scope_hosts, state, current_pass=1, scope=scope)

    run_stage_and_report(11, "archived JS mining", new_assets, patterns, state)
    persist_records(state, records)                    # links endpoint/param/secret → parent url asset


def run_stage7_and_report(patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """
    Full stage 7 sequence: bundler probe + jsluice → new url assets, plus
    Track-D endpoint/parameter/secret records.
    """
    all_assets = state.load_assets()
    known_in_scope_hosts = [
        a.value for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
    ]
    known_js_urls = [
        a.value for a in all_assets
        if a.type == "url" and a.scope_status == "in_scope" and a.value.split("?")[0].endswith(".js")
    ]
    logger.info("Seeding stage 7 with %d known in-scope host(s), %d known in-scope .js url(s)",
                len(known_in_scope_hosts), len(known_js_urls))

    logger.info("--- Stage 7: JS discovery + extraction (jsluice) ---")
    stage7_new_assets, stage7_metadata_updates, stage7_records = run_stage7(
        known_in_scope_hosts, known_js_urls, state, current_pass=1, scope=scope
    )

    # metadata_updates is empty now (jsluice secrets → secret records), but
    # keep the application path for contract symmetry.
    url_assets_by_value = {a.value: a for a in state.load_assets() if a.type == "url"}
    for js_url, metadata_update in stage7_metadata_updates.items():
        matching_asset = url_assets_by_value.get(js_url)
        if matching_asset is None:
            logger.warning("Stage 7 metadata for %r isn't a known url asset - skipping", js_url)
            continue
        state.update_asset_metadata(matching_asset.asset_id, metadata_update)

    run_stage_and_report(7, "JS discovery + extraction", stage7_new_assets, patterns, state)
    persist_records(state, stage7_records)


def run_stage8_and_report(state: RunState, scope: dict) -> None:
    """Full stage 8 sequence: nuclei takeover detection → takeover_findings."""
    all_assets = state.load_assets()
    known_in_scope_hosts = [
        a.value for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
    ]
    asset_lookup = {
        a.value: a.asset_id for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
    }
    logger.info("Seeding stage 8 with %d known in-scope host(s)", len(known_in_scope_hosts))

    logger.info("--- Stage 8: high-signal checks (nuclei takeover detection) ---")
    stage8_findings = run_stage8(known_in_scope_hosts, state, current_pass=1, scope=scope, asset_lookup=asset_lookup)

    if stage8_findings:
        state.add_takeover_findings(stage8_findings)
        logger.warning(
            "Stage 8 found %d potential takeover finding(s) - UNVERIFIED "
            "parser, manually confirm before treating as ground truth",
            len(stage8_findings),
        )
    else:
        logger.info("Stage 8: no takeover findings")

    # (C1) detection-only nuclei (exposures/misconfig/panels) → recon_findings POIs
    logger.info("--- Stage 8 (C1): detection-only nuclei (exposures/misconfig/panels) ---")
    detection_findings = run_stage8_detection(known_in_scope_hosts, state, current_pass=1,
                                              scope=scope, asset_lookup=asset_lookup)
    if detection_findings:
        state.add_recon_findings(detection_findings)
        logger.info("Stage 8 (C1): %d recon finding(s) recorded (status=new)", len(detection_findings))
    else:
        logger.info("Stage 8 (C1): no detection findings")

    state.update_run_state(current_stage=8, status="stage_complete")


def run_stage9_and_report(state: RunState, scope: dict) -> None:
    """Full stage 9 sequence: whatweb deep fingerprint → metadata on hosts."""
    all_assets = state.load_assets()
    live_hosts = [
        a.value for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
        and "httpx_status_code" in a.metadata
    ]
    logger.info("Seeding stage 9 with %d confirmed-live host(s)", len(live_hosts))

    logger.info("--- Stage 9: deep tech fingerprinting (whatweb -a 3) ---")
    stage9_metadata_updates = run_stage9(live_hosts, state, scope)

    host_assets_by_value = {a.value: a for a in all_assets if a.type == "subdomain"}
    for host_value, metadata_update in stage9_metadata_updates.items():
        matching_asset = host_assets_by_value.get(host_value)
        if matching_asset is None:
            logger.warning(
                "Stage 9 returned whatweb metadata for %r but it's not in the "
                "known host-assets set - skipping", host_value,
            )
            continue
        state.update_asset_metadata(matching_asset.asset_id, metadata_update)
    logger.info("Applied stage 9 whatweb metadata updates to %d existing host(s)",
                len(stage9_metadata_updates))

    state.update_run_state(current_stage=9, status="stage_complete")


def run_pipeline(root_domains: list[str], patterns: ScopePatterns, state: RunState, scope: dict) -> None:
    """
    The stage-by-stage pipeline body, factored out of main() so main() can
    wrap it in the R7 error-status guard.
    """
    state.update_run_state(current_stage=1, current_pass=1, status="running")
    # A run re-run into an existing dir must not inherit a prior attempt's error
    # (update_run_state is merge-only). Start clean.
    state.clear_run_error()

    logger.info("--- Stage 1: passive discovery ---")
    stage1_found = run_stage1(root_domains, state, current_pass=1, scope=scope)
    run_stage_and_report(1, "passive discovery", stage1_found, patterns, state)

    all_assets = state.load_assets()
    known_in_scope_subdomains = [
        a.value for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
    ]
    logger.info("Seeding stage 3 with %d known in-scope subdomains", len(known_in_scope_subdomains))

    logger.info("--- Stage 3: active DNS resolution + brute force ---")
    stage3_found = run_stage3(root_domains, known_in_scope_subdomains, state, current_pass=1, scope=scope)
    run_stage_and_report(3, "active DNS + brute force", stage3_found, patterns, state)

    all_assets = state.load_assets()
    known_in_scope_hosts = [
        a for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
    ]
    logger.info("Seeding stage 4 with %d known in-scope hosts", len(known_in_scope_hosts))

    logger.info("--- Stage 4: live host probing (httpx + naabu) ---")
    stage4_new_assets, stage4_metadata_updates = run_stage4(known_in_scope_hosts, state, current_pass=1, scope=scope)

    for host_value, metadata_update in stage4_metadata_updates.items():
        matching = [a for a in known_in_scope_hosts if a.value == host_value]
        if not matching:
            logger.warning(
                "Stage 4 returned metadata for %r but it's not in the "
                "known-hosts set passed in - skipping", host_value,
            )
            continue
        state.update_asset_metadata(matching[0].asset_id, metadata_update)
    logger.info("Applied stage 4 metadata updates to %d existing host(s)", len(stage4_metadata_updates))

    run_stage_and_report(4, "live host probing", stage4_new_assets, patterns, state)

    # (Track D / D4) promote naabu's open ports to first-class `service`
    # records - from host metadata_updates and from IP-only naabu assets -
    # so R12's non-standard ports become probeable records. naabu_open_ports
    # metadata is kept as a per-host summary. persist_records links each
    # service to its host/ip asset and drops out-of-scope ones.
    stage4_services = []
    for host_value, mu in stage4_metadata_updates.items():
        for port in mu.get("naabu_open_ports", []) or []:
            stage4_services.append(Service(
                target=host_value, host=host_value, port=port, proto="tcp",
                discovered_by="naabu", target_derived=False,
                discovered_at_stage=4, discovered_in_pass=1,
            ))
    for a in stage4_new_assets:
        if a.type == "ip":
            for port in a.metadata.get("naabu_open_ports", []) or []:
                stage4_services.append(Service(
                    target=a.value, ip=a.value, port=port, proto="tcp",
                    discovered_by="naabu", target_derived=False,
                    discovered_at_stage=4, discovered_in_pass=1,
                ))
    persist_records(state, {"services": stage4_services})

    # (F5) reverse DNS on discovered IPs → new subdomain candidates (scope-gated).
    all_ip_values = [a.value for a in state.load_assets()
                     if a.type == "ip" and a.scope_status in ("in_scope", "needs_review")]
    if all_ip_values:
        logger.info("--- F5: reverse DNS (dnsx -ptr) on %d discovered IP(s) ---", len(all_ip_values))
        ptr_assets = run_reverse_dns(all_ip_values, state, scope, current_pass=1)
        run_stage_and_report(4, "reverse DNS (F5)", ptr_assets, patterns, state)

    run_waf_cdn_and_report(patterns, state, scope)   # stage 4.5 (C3) WAF/CDN detection

    run_stage5_and_report(root_domains, patterns, state, scope)

    run_stage6_and_report(patterns, state, scope)

    run_content_discovery_and_report(patterns, state, scope)   # stage 6.5 (B1)

    run_stage7_and_report(patterns, state, scope)

    # (E4) OFFLINE secret classification — label stage-7 secrets by kind/provider
    # from their R8 raw archives; ZERO network (never validates — primitive's job).
    logger.info("--- E4: offline secret classification (kind/provider, no network) ---")
    run_secret_classification(state)

    run_stage8_and_report(state, scope)

    run_stage9_and_report(state, scope)

    run_screenshots_and_report(patterns, state, scope)   # C2 screenshots (httpx headless Chrome)

    # (C5) OFFLINE tech→CVE candidate flagging from stage-9 version fingerprints →
    # recon_findings (source=cve-candidate); runs before A2 so it can score them.
    logger.info("--- C5: tech→CVE candidate flagging (offline, unconfirmed leads) ---")
    run_cve_candidates(state)

    run_stage10_and_report(patterns, state, scope)   # stage 10 (B2a) API-schema discovery

    run_archived_js_and_report(patterns, state, scope)   # stage 11 (B4) archived-JS mining

    # (C4) deterministic auth-surface classification finalizer — no traffic, labels
    # endpoints.auth_status + writes per-host auth_model over already-collected data.
    logger.info("--- C4: auth-surface classification (deterministic, no traffic) ---")
    run_auth_classification(state)

    # (F1) URL clustering — mark representative samples of templated URL floods.
    logger.info("--- F1: URL clustering (deterministic, no traffic) ---")
    run_url_clustering(state)

    # (A2) deterministic interest scoring finalizer — ranks the surface for A1.
    logger.info("--- A2: interest scoring (deterministic, no traffic) ---")
    run_interest_scoring(state)

    # (F6) target profile digest — a deterministic "know your target" summary
    # (small cousin of the A1 LLM brief); runs last, aggregating everything above.
    logger.info("--- F6: target profile digest (deterministic, no traffic) ---")
    run_target_profile(state)

    state.update_run_state(status="stage_complete", passes_completed=1)
    logger.info("Stages 1, 3, 4, 5, 6, 6.5, 7, 8, 9, 10, and 11 complete. See %s and %s", state.assets_db_path, state.review_path)


def _new_run_name() -> str:
    """A time-sortable, collision-resistant run-dir name: run_<UTC-ts>_<shortid>.

    The UTC timestamp prefix means a lexical sort of runs/ is a chronological
    sort, so sozin-dashboard can pick the latest run from the dir name alone
    (without opening run_state.json). The short uuid suffix disambiguates two
    runs started within the same second.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"run_{ts}_{uuid.uuid4().hex[:6]}"


def resolve_run_dir(args) -> Path:
    """Turn the CLI args into the concrete run dir to use.

    --run-dir: used verbatim (legacy/manual path). scope.json is expected to
      already be inside it.
    --target-dir: a bug-bounty target folder holding the canonical scope.json.
      We create <target>/runs/run_<UTC-ts>_<shortid>/, chmod it 700 up front
      (R8 - it will hold secrets), and copy the canonical scope.json into it so
      RunState.load_scope() finds it. The target-root scope.json is the
      authorization of record; the run gets an immutable snapshot copy.
    """
    if args.target_dir:
        target_dir = Path(args.target_dir).resolve()
        if not target_dir.is_dir():
            print(f"error: --target-dir {target_dir} is not a directory", file=sys.stderr)
            sys.exit(2)
        canonical_scope = target_dir / "scope.json"
        if not canonical_scope.exists():
            print(f"error: no scope.json in target folder {target_dir} "
                  f"(run /scope-tos-parser for this target first)", file=sys.stderr)
            sys.exit(2)
        run_dir = target_dir / "runs" / _new_run_name()
        run_dir.mkdir(parents=True, exist_ok=False)
        run_dir.chmod(0o700)
        shutil.copy2(canonical_scope, run_dir / "scope.json")
        return run_dir
    return Path(args.run_dir)


def handback_run_dir(run_dir: Path) -> None:
    """Deployment aid: when the pipeline runs as root inside the Docker image, the
    run dir it creates is root-owned and (per R8) chmod 700 — unreadable from the
    host, so the operator can't `sqlite3 assets.db` / read `raw/` without sudo.
    If `SOZIN_RUNDIR_UID` (and optionally `SOZIN_RUNDIR_GID`, default = UID) is set,
    recursively hand the run dir back to that owner so a host run is byte-for-byte
    like a local (non-Docker) run: same **700 mode**, host-user-owned. Opt-in and
    best-effort — a no-op when unset (a local run already owns its files), and it
    never fails the run (a chown error is logged, not raised). Only ownership
    changes; the 700 mode is untouched."""
    uid_raw = os.environ.get("SOZIN_RUNDIR_UID")
    if not uid_raw:
        return
    try:
        uid = int(uid_raw)
        gid = int(os.environ.get("SOZIN_RUNDIR_GID", uid_raw))
    except ValueError:
        logger.warning("SOZIN_RUNDIR_UID/GID not integers (%r/%r) - skipping run-dir hand-back",
                       uid_raw, os.environ.get("SOZIN_RUNDIR_GID"))
        return
    try:
        os.chown(run_dir, uid, gid)
        for child in run_dir.rglob("*"):
            os.chown(child, uid, gid)
        logger.info("Handed run dir back to uid:gid %d:%d - host-readable (mode 700 preserved)", uid, gid)
    except OSError as exc:
        logger.warning("Could not hand run dir back to %d:%d (%r) - leaving as-is", uid, gid, exc)


def main():
    parser = argparse.ArgumentParser(description="Recon agent - stages 1, 3, 4, 5, 6, 7, 8, 9")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--run-dir", help="Path to an existing run directory containing scope.json")
    src.add_argument("--target-dir", help="Path to a target folder containing the canonical "
                     "scope.json; a new timestamped dir under <target>/runs/ is created and used")
    args = parser.parse_args()

    run_dir = resolve_run_dir(args)
    logger.info("Run directory: %s", run_dir)
    state = RunState(run_dir)

    logger.info("Loading scope from %s", state.scope_path)
    scope = state.load_scope()
    patterns = ScopePatterns.from_scope_dict(scope)

    logger.info("Checking rate_limit gate")
    check_run_not_blocked(scope)

    root_domains = extract_root_domains(scope)
    if not root_domains:
        logger.error("No in_scope domains found in scope.json - nothing to do")
        sys.exit(1)
    logger.info("Root domains for this run: %s", root_domains)

    # Program-mandated request headers (e.g. HackerOne's X-HackerOne Test Plan
    # header) are injected into every target-facing tool's requests. Log once so
    # an operator can confirm the RoE requirement is actually in force this run.
    _req_headers = required_headers(scope)
    if _req_headers:
        logger.info("Injecting %d required header(s) on all target traffic: %s",
                    len(_req_headers), ", ".join(_req_headers))

    # (R7) Any unhandled exception during the run marks run_state "error"
    # (with the failing stage) before re-raising. Pre-run gate refusals
    # above propagate as-is (a run that never started isn't an errored run).
    try:
        run_pipeline(root_domains, patterns, state, scope)
    except Exception as exc:
        try:
            current_stage = state.load_run_state().get("current_stage")
        except Exception:
            current_stage = None
        state.update_run_state(status="error", failed_at_stage=current_stage, error=repr(exc))
        logger.exception("Recon run failed at stage %s - run_state.json marked 'error'", current_stage)
        raise
    finally:
        # Hand the run dir back to the host user (Docker deployment aid) whether the
        # run finished or errored, so its partial output is inspectable either way.
        handback_run_dir(run_dir)


if __name__ == "__main__":
    main()
