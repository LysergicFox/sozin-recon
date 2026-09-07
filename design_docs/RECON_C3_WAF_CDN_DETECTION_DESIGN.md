# C3 — WAF/CDN detection & pre-flight labeling (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN-LOCKED, NOT BUILT.** Realizes **C3** of `RECON_ENHANCEMENTS.md`
(Phase 3, Track C — "signal quality & prioritization"). Adds a **pre-flight**
per-host label — *which* WAF vendor, *whether* a CDN fronts the host, and
*candidate origin IPs* behind that CDN — using **wafw00f** (WAF fingerprint) and
**cdncheck** (CDN/cloud IP-range classification). Pure per-host **metadata
enrichment** in the shape of stage 9 (whatweb): no new assets, no new sibling
records, no scope-gate participation.

This is the counterpart to two already-built pieces:

- **B1's in-flight `waf_suspected` breaker** (stage 6.5,
  `stage_content_discovery.py`) — an *observed-mid-run* 403-flood retreat signal.
  C3 is the *pre-flight vendor label*. **They are complementary, not duplicative**
  (see §Relationship to B1).
- **Primitive's offensive WAF bypass** (`PRIMITIVE_WAF_HANDLING_DESIGN.md`) — C3
  *characterizes* the obstacle (vendor, CDN, origin candidates) so primitive's
  bounded budget goes further; C3 **never engages or bypasses** it. The single
  highest-value item C3 delivers to that work is **origin-IP candidates** — the
  best "bypass" is not bypassing at all (hit the origin directly, no filter
  engaged).

Written to the same discipline every existing stage was: **verify the real tool
interface before writing the parser**, fail-closed, rate-bounded per-host,
fault-isolated (R7), scope-safe (R1). **Nothing here is coded yet, and neither
tool is installed on this box** (see §Verification & prerequisites).

---

## Why C3, and the "know your target" payload

Recon today tells the downstream agents *what tech* a host runs (stage 9
whatweb) but never labels the **defensive posture in front of it**. Primitive's
design (`PRIMITIVE_WAF_HANDLING_DESIGN.md`) leans on exactly three unbuilt recon
signals, and C3 supplies two of them plus seeds the third:

1. **WAF vendor label** — Cloudflare ≠ Akamai ≠ Imperva ≠ ModSecurity/CRS ≠
   AWS WAF. Turns primitive's blind payload mutation into *targeted* technique
   selection, so its flat-100 request budget isn't spent rediscovering the
   vendor live.
2. **CDN-fronted flag** — whether the host sits behind a CDN at all (governs
   primitive's rate-backpressure interpretation: a challenge from a CDN edge is
   a different signal than a 403 from the origin app).
3. **Origin-IP candidates** — the boundary-clean, highest-value contribution:
   surface IPs the host resolves to that are **not** in any CDN range, so
   primitive can consider hitting the origin directly and sidestep the filter
   entirely. C3 *flags candidates*; it never *confirms* an origin (that needs an
   active Host-header probe → primitive) and never does the heavier correlation
   (favicon → E1, ASN expansion → F3).

C3 is **low-traffic** (wafw00f sends a handful of fingerprint probes per host;
cdncheck is largely offline IP-range matching), which is what makes early
pre-flight placement cheap and safe.

---

## Locked decisions (recommended; Jared's calls flagged)

1. **Two tools, distinct jobs, both per-host-loop.**
   - **wafw00f** → WAF *vendor* fingerprint (`is_behind_waf`, `waf_vendor`).
     Sends active fingerprint probes → gets a rate translation + per-host loop +
     R7 isolation, exactly like whatweb.
   - **cdncheck** → CDN/cloud/WAF **IP-range** classification (`is_cdn`,
     `cdn_name`) and the raw material for `origin_ip_candidates`. Largely
     **offline** (matches IPs against embedded/updatable range lists); the only
     network it may touch is DNS *resolution* of a hostname, which is a resolver,
     not the target — so it needs no target-rate translation (confirm it doesn't
     actively probe the target — §Verification).
   - *Alternative considered:* `httpx -cdn`/`-asn` (E1) overlaps cdncheck's CDN
     flag. **Not chosen as the primary** because E1 is a separate roadmap item
     and cdncheck gives a first-class provider name + the offline range data
     origin-candidate flagging needs. If E1 lands first, C3 may consume its
     `-cdn` output instead of re-invoking cdncheck — noted, not designed here.

2. **New PRE-FLIGHT fractional stage — recommend stage 4.5** (after stage 4
   httpx confirms live hosts + origins, before stage 5 x8). ← **Jared call;
   recommended 4.5.**
   - *Rationale:* C3 is a **pre-flight** labeler by definition — "know your
     target *before* you touch it." Placing it right after liveness makes
     `waf_vendor`/`is_cdn` present in host metadata for the **entire** rest of
     the run (and for primitive), and it is the prerequisite for the deferred
     idea of B1 (stage 6.5) reading the label to pre-emptively back off
     (§Relationship to B1). It seeds from the exact `_live_hosts_with_origins`
     set `main.py` already builds and needs nothing from crawl/JS. Low traffic,
     so early placement is safe.
   - *Cost, named (inherited from B1's decision #2):* a **float `STAGE`** is a
     latent footgun for any integer-stage comparison added later (e.g. loop
     logic). B1 already lives at 6.5 and accepted this; C3 at 4.5 is consistent.
   - *Alternative Jared may pick — a terminal integer stage (11).* By B2's own
     logic, a producer with **no same-pass recon consumer** (C3 v1 does NOT wire
     B1 to read the label) is defensible as a clean terminal integer stage,
     avoiding the float footgun. The trade: the label would not be available to
     the active stages during the run, only to primitive afterward — which
     forfeits the "pre-flight informs the pipeline" value that is C3's whole
     point. **Recommendation stands at 4.5 (pre-flight).**

3. **Pure per-host metadata enrichment — NO new assets, NO new sibling records.**
   Mirrors stage 9 (whatweb) exactly: C3 returns `dict[host, metadata_update]`;
   the caller applies it via `update_asset_metadata` to the **existing**
   subdomain asset. No `run_stage_and_report` scope-gate step (nothing new is
   discovered), no `persist_records` (no endpoint/param/secret/service).
   `origin_ip_candidates` are stored as a **host-metadata list**, **not** minted
   as new `ip` assets — they are *unconfirmed* candidates, and minting assets
   would imply confirmed, scope-gated discovery C3 has not done. (If a candidate
   already exists as a stage-4 `ip` asset, fine; C3 does not create new ones.)

4. **All C3 metadata is AGENT-authored / trusted — NOT `target_derived`.** Like
   B1's `waf_suspected`, C3's labels are *our determinations about the host*
   derived from a tool's fingerprint database, not attacker-controlled free text
   echoed verbatim. The vendor/CDN name is a bounded, enum-like label from
   wafw00f/cdncheck's own signature set — contrast `whatweb_tech`, which echoes a
   raw attacker-influenceable header string (and *is* in
   `TARGET_DERIVED_METADATA_KEYS`). So the new keys are **NOT** added to
   `TARGET_DERIVED_METADATA_KEYS`. (Caveat to honor in the parser: store only the
   tool's *classified* vendor label, never a raw response snippet — keep the
   trusted/untrusted line clean by construction.)

5. **Origin-IP discovery in v1 = cheap, offline candidate flagging only.**
   `origin_ip_candidates` = IPs the host is associated with (from stage-4
   DNS/httpx/naabu data already in `assets.db`, and any IPs cdncheck resolves)
   that cdncheck classifies as **NOT** in a CDN range. Rationale: a host
   resolving to both a Cloudflare IP and a non-CDN IP makes the non-CDN IP a
   strong origin candidate — a genuine signal cdncheck can produce with no active
   origin probing. **Deferred (explicitly):** favicon-hash correlation (**E1**),
   ASN/IP-range expansion (**F3**), historical-DNS origin lookup (F5-adjacent),
   and any **active confirmation** of a candidate origin (sending a request with
   the site's `Host` header to see if the IP serves it — that is active testing →
   **primitive**, or at minimum a later item; C3 never probes a candidate).

6. **Seed: confirmed-live in-scope hosts + origins** — reuse
   `_live_hosts_with_origins(state)` verbatim (the shared B1/B2 helper). wafw00f
   needs the scheme httpx actually confirmed (http vs https); cdncheck needs the
   hostname/IPs. A host not serving HTTP is not worth fingerprinting.

---

## Where it slots in `main.py`

Add `run_waf_cdn_detection_and_report(state, scope)` and call it **pre-flight**,
after stage 4 completes and before stage 5:

```python
run_stage4_and_report(...)          # httpx liveness + naabu ports → live hosts + origins
run_waf_cdn_detection_and_report(state, scope)   # NEW — stage 4.5 (C3) pre-flight label
run_stage5_and_report(root_domains, patterns, state, scope)
```

The reporter mirrors `run_stage9_and_report` (metadata-only), NOT
`run_content_discovery_and_report` (which scope-gates + persists records):

```python
def run_waf_cdn_detection_and_report(state: RunState, scope: dict) -> None:
    """Stage 4.5 (C3): pre-flight WAF/CDN labeling over confirmed-live in-scope
    hosts. Metadata-only enrichment (like stage 9 whatweb) — no new assets, no
    records. Labels waf_vendor/is_behind_waf/cdn_name/is_cdn/origin_ip_candidates
    (all AGENT-authored, trusted, NOT target_derived)."""
    live_hosts, host_base = _live_hosts_with_origins(state)
    logger.info("Seeding stage 4.5 with %d confirmed-live in-scope host(s)", len(live_hosts))

    logger.info("--- Stage 4.5: WAF/CDN detection (wafw00f + cdncheck) ---")
    metadata_updates = run_waf_cdn_detection(live_hosts, state, scope, host_base=host_base)

    host_assets_by_value = {a.value: a for a in state.load_assets() if a.type == "subdomain"}
    for host_value, metadata_update in metadata_updates.items():
        matching_asset = host_assets_by_value.get(host_value)
        if matching_asset is None:
            logger.warning("Stage 4.5 WAF/CDN metadata for %r isn't a known host asset - skipping", host_value)
            continue
        state.update_asset_metadata(matching_asset.asset_id, metadata_update)
    logger.info("Applied stage 4.5 WAF/CDN labels to %d host(s)", len(metadata_updates))
    state.update_run_state(current_stage=4, status="stage_complete")   # keep integer run_state; 4.5 is a sub-step
```

(Note the `current_stage` bookkeeping: `run_state` currently stores integer
stages; B1 at 6.5 already faces this. Keep `current_stage=4` for the run_state
row and let the log line carry the 4.5 label, OR extend run_state to accept the
float — a small Jared call, same one B1 deferred.)

---

## The stage module — `stages/stage_waf_cdn_detection.py`

### Return contract

```python
def run_waf_cdn_detection(live_hosts: list[str], state: RunState, scope: dict,
                          host_base: dict[str, str] | None = None
                          ) -> dict[str, dict]:
    """
    Pre-flight WAF/CDN labeling over confirmed-live in-scope hosts.

    Returns dict[host, metadata_update] for the caller to apply via
    update_asset_metadata() to the EXISTING subdomain asset (stage-9 pattern).
    A host with no determination is simply absent (the "absent = couldn't
    confirm" convention). metadata_update keys (all trusted, agent-authored):
      - is_behind_waf: bool | None      # wafw00f
      - waf_vendor: str | None          # wafw00f firewall name, None if none/unknown
      - is_cdn: bool | None             # cdncheck
      - cdn_name: str | None            # cdncheck provider name
      - origin_ip_candidates: list[str] # non-CDN IPs associated with the host (may be [])
    Empty live_hosts → {}.
    """
```

### Per-host loop (R7) + graceful tool-absence

```python
for host in live_hosts:
    update = {}
    try:
        update.update(run_wafw00f(host, state, scope, base=(host_base or {}).get(host)))
    except Exception:
        logger.exception("stage 4.5 wafw00f failed for %s - skipping WAF label (R7)", host)
    try:
        update.update(run_cdncheck(host, state, scope))
    except Exception:
        logger.exception("stage 4.5 cdncheck failed for %s - skipping CDN label (R7)", host)
    if update:
        updates[host] = update
```

Fault isolation is at **per-tool, per-host** granularity: wafw00f failing for a
host still lets cdncheck label it, and one host failing never aborts the stage.
**Tool-not-installed fails safe** (like B1's missing-wordlist path): if the
binary isn't on `PATH`, `_run_tool` returns a not-found marker, the parser yields
`{}` for that tool, the run continues, and the absence is logged — C3 is
enrichment, never a hard dependency.

### Two-tier persistence (R5/R8)

Full raw output per host per tool → the chmod-700 run dir with per-target
suffixes so nothing is overwritten across hosts:
`raw/stage4.5_wafw00f_{host}.json`, `raw/stage4.5_cdncheck_{host}.json`. Only the
curated labels reach `assets.db`.

### Module constants

```python
STAGE = 4.5
DEFAULT_TIMEOUT_SECONDS = 120     # both tools are fast; bounded so a hung host can't stall the run
```

---

## ⚠️ Tool-interface facts to confirm BEFORE the parser (NEITHER TOOL INSTALLED)

`command -v wafw00f cdncheck` → **not found** on this box (2026-08-23). **Both are
prerequisites**, and per CONTRIBUTING's verify-real-tool discipline the parser is
written only *after* a real `--help` + a real run. The exact facts to confirm
(the shapes below are **unverified expectations from general knowledge, flagged
as such** — do not trust them until a real run confirms, exactly as every prior
stage caught real bugs this way):

**wafw00f** (`pip install wafw00f` / distro pkg):
- The **JSON output flag + shape.** Expected: `wafw00f <url> -o <file> -f json`
  writing a list of `{url, detected: bool, firewall: "<vendor>", manufacturer:
  "<org>"}`. **Confirm** the real flag names (`-f`/`--format`, `-o`/`--output`),
  whether JSON goes to file or stdout, and the exact keys (`firewall`?
  `trigger_url`? a `detected` bool vs a "No WAF" string sentinel?).
- **How "no WAF detected" is signalled** in JSON (empty `firewall`? a specific
  string? absent object?) — the label logic keys on this.
- **`-a`/`--findall`** (report all matching WAFs, not just the first) — decide
  whether to enable; if multiple, `waf_vendor` policy (first vs list).
- **Request volume + redirect behavior.** How many probes per host (rate concern
  — §Rate). Whether it follows redirects off-origin (R1 concern — confirm and
  constrain like whatweb's `--follow-redirect` if so).
- **Exit codes** (does "no WAF" exit non-zero? — don't key the WAF/no-WAF
  decision on exit code, mirror B1's "stderr/parsed-output, never exit code"
  lesson).

**cdncheck** (`go install .../cmd/cdncheck` — a ProjectDiscovery tool):
- **Input mode + JSON output.** Expected: reads hosts/IPs from stdin or `-i`,
  `-json` for structured output, `-resp` to include the matched provider,
  category flags `-cdn`/`-waf`/`-cloud`. **Confirm** the real flags and the JSON
  shape (`{input, ip, cdn: bool, cdn_name, waf, waf_name, cloud, ...}`? exact key
  names).
- **Does it resolve DNS itself, or expect IPs?** (Determines whether C3 feeds it
  the hostname or the stage-4 IPs.) If it resolves, that's a resolver hit, not a
  target hit — **confirm it does NOT actively probe the target host** (if it only
  matches IP ranges + resolves DNS, no target-rate translation is needed).
- **Offline vs network for the range data** (embedded ranges? a periodic
  `-update` fetch from ProjectDiscovery?) — note any network dependency so the
  run doesn't silently degrade offline.
- **What it emits per input for origin work:** the resolved IP(s) and the
  CDN/not-CDN verdict per IP — that per-IP verdict is exactly what
  `origin_ip_candidates` filters on (keep the non-CDN IPs).

Real-run discipline (CONTRIBUTING step): install both → `--help` → one real run
against a **known CDN-fronted host** → capture real JSON shapes → write the
parsers → mocked tests → real run → fix → confirming run.

---

## Rate — `wafw00f_rate_args(scope)` in `rate_limits.py`

wafw00f sends multiple fingerprint requests per host, so like whatweb (which has
no native req/s flag) it belongs with the **sequential per-host** rate shape
(Shape 2): one host per invocation, the per-host number applies directly, a
GLOBAL scope needs no special handling. **Confirm wafw00f's real throttle knob**
(a delay/`--wait`-style flag? threads?) during verification — if it has no
throttle at all, the per-host-invocation + small fixed probe count is the bound,
and that fact is documented in the helper's note (same honesty as whatweb's
`-t`/`--wait` note). **cdncheck needs no target-rate translation** (offline
IP-range matching; DNS resolution only — protect-the-target rule from
CONTRIBUTING #7 is satisfied because it doesn't hit the target).

---

## Relationship to B1 (`waf_suspected`) — complement, do NOT duplicate

Two WAF signals now coexist, and they answer **different questions**:

| | Source | When | Signal | Nature |
|---|---|---|---|---|
| `waf_suspected` (+`waf_signal`, `waf_block_ratio`) | **B1** stage 6.5, ffuf `-sf` | **in-flight**, observed during discovery | "this host actively 403-flooded us" | observed behavior |
| `is_behind_waf` / `waf_vendor` | **C3** stage 4.5, wafw00f | **pre-flight**, before any active fuzzing | "this host is fronted by *Cloudflare/Akamai/…*" | fingerprint identity |
| `is_cdn` / `cdn_name` / `origin_ip_candidates` | **C3** stage 4.5, cdncheck | pre-flight | "CDN-fronted; here are non-CDN origin candidates" | IP-range classification |

They are **orthogonal and both retained** — C3 does not touch, overwrite, or
subsume `waf_suspected`, and B1 does not touch C3's keys. Realistic divergence:

- `is_behind_waf=true, waf_suspected=false` — C3 fingerprinted a WAF vendor, but
  B1's discovery never tripped a 403 flood (the WAF let brute-force through, or
  answered with 200-challenges — the shared blind spot both docs flag).
- `is_behind_waf=false/None, waf_suspected=true` — B1 got flooded but wafw00f
  couldn't name a vendor (custom/unknown filter).

Primitive reads **both** as intel (`PRIMITIVE_WAF_HANDLING_DESIGN.md`): the
vendor label drives *technique selection*, `waf_suspected` + the origin
candidates drive *whether to attempt bypass at all vs. hit the origin*.

**Deferred, noted without over-designing:** because C3 (4.5) runs *before* B1
(6.5), B1 *could* on a later pass read `is_behind_waf`/`waf_vendor` to
pre-emptively lower its rate or narrow its wordlist on a known-WAF host. **C3 v1
does NOT wire this** — B1's in-flight `-sf` breaker already covers the safety
case, and adding a pre-flight-back-off coupling now would over-design a seam
neither agent needs yet. C3 v1's job is to *put the label in host metadata*; who
consumes it is the label's future, not C3's build scope.

---

## Boundary — recon detects and labels; it never engages the WAF

C3 holds the **same line B1 holds**: it *characterizes* the obstacle and stops
there.

- **wafw00f** sends benign fingerprint requests to *identify* the filter — the
  same active-but-non-exploit posture as whatweb's `-a 3` plugin battery. It does
  **not** send evasion payloads, probe what the filter blocks, or attempt any
  bypass. Fingerprinting ≠ bypassing.
- **cdncheck** *classifies IP ranges* — no target traffic beyond DNS resolution.
- **origin_ip_candidates is a *flag*, not a *probe*.** C3 lists non-CDN IPs the
  host resolves to; it never sends a Host-header request to a candidate to
  *confirm* it serves the site. Confirming an origin, and *using* it to bypass
  the WAF, is primitive's guarded, budgeted, authorized territory
  (`PRIMITIVE_WAF_HANDLING_DESIGN.md` §"Where recon sets this up"). **Recon
  characterizes the obstacle and finds candidate paths around it; primitive
  defeats it.**

This is precisely the recon/primitive split `RECON_ENHANCEMENTS.md`'s boundary
notes name: "the best 'bypass' is not bypassing" (origin discovery) is a *pure
recon* contribution, and it stays clean only because C3 flags candidates without
engaging.

---

## R-inheritance (metadata-enrichment stage)

- **R1 (scope covers traffic).** wafw00f fingerprints only the seeded in-scope
  host; **confirm its redirect behavior** and constrain off-origin following like
  whatweb if needed (§tool-facts). cdncheck sends no target traffic. No new
  assets are minted, so there is no scope-gate step to get wrong (enrichment, not
  discovery — the stage-9 property).
- **R3 (per-host rate).** wafw00f runs one host per invocation → the per-host
  number applies directly (§Rate). cdncheck is offline → N/A.
- **R5 (per-target raw files).** `raw/stage4.5_wafw00f_{host}.json`,
  `raw/stage4.5_cdncheck_{host}.json`.
- **R7 (fault isolation).** Per-tool, per-host try/except; tool-not-installed
  fails safe to `{}`; nothing aborts the run.
- **R8 (at-rest hygiene).** Raw output lands in the chmod-700 run dir by
  construction (RunState owns it).
- **R9 / provenance.** C3's labels are **agent-authored/trusted** (our
  classification from the tool's signature DB) → **NOT** in
  `TARGET_DERIVED_METADATA_KEYS`, same as `waf_suspected`. The parser stores only
  the classified label, never a raw target response snippet, so the trusted line
  holds by construction.

---

## Verification & prerequisites

- **PREREQUISITE — install both tools.** `command -v wafw00f cdncheck` → not
  found (2026-08-23). Install (`pip install wafw00f`; `go install
  github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest` — confirm the real
  module path) before build. Neither is in `logging_setup.py`'s highlighter list
  yet; add them when wired.
- **Verification target — a known Cloudflare-fronted host** (a domain you control
  behind Cloudflare, or a consented target). Confirm wafw00f names the vendor
  ("Cloudflare (Cloudflare Inc.)") and cdncheck reports `is_cdn=true`,
  `cdn_name=cloudflare`. For `origin_ip_candidates`, ideally a host that resolves
  to **both** a CDN IP and a non-CDN origin IP, to confirm the non-CDN filter
  actually surfaces the candidate.
- **A no-WAF, no-CDN control host** (e.g. the local Juice Shop / a plain VPS) to
  confirm the negative path yields `is_behind_waf=false`, `is_cdn=false`,
  `origin_ip_candidates=[<its own IP>]` (or `[]`) — not false positives.
- Discipline: real `--help` + real runs → capture shapes → parser → mocked tests
  → real run → fix → confirming run.

---

## Tests (mocked — `testing/test_waf_cdn_detection.py`)

Mirror `test_stage9`-style metadata-update assertions (no scope gate, no
records):

- **wafw00f positive**: mocked JSON naming a WAF → `is_behind_waf=True`,
  `waf_vendor="Cloudflare"`. **Negative**: "no WAF" JSON → `is_behind_waf=False`,
  `waf_vendor=None`.
- **cdncheck positive**: mocked JSON with a CDN verdict → `is_cdn=True`,
  `cdn_name="cloudflare"`; a host resolving to one CDN IP + one non-CDN IP →
  `origin_ip_candidates=["<non-cdn ip>"]` (CDN IP excluded). **Negative**: no-CDN
  verdict → `is_cdn=False`, candidates = the host's own IP(s) or `[]`.
- **Per-tool, per-host fault isolation (R7)**: wafw00f raising for a host still
  yields cdncheck's label for that host; one host raising doesn't stop others.
- **Tool-not-installed**: `_run_tool` FileNotFound → that tool contributes `{}`,
  run continues, host still gets the other tool's label.
- **Trusted provenance**: assert the new keys are **NOT** in
  `TARGET_DERIVED_METADATA_KEYS` and that `_apply`-path writes them via
  `update_asset_metadata`.
- **Per-target raw filenames** `stage4.5_wafw00f_{host}.json` /
  `stage4.5_cdncheck_{host}.json` (R5).
- **Empty live_hosts → `{}`.**

**`testing/run_stage4_5_only.py`** — standalone re-runner mirroring the other
`run_stage*_only.py` scripts (imports `run_waf_cdn_detection_and_report`; never
duplicates its logic — CONTRIBUTING "standalone re-run scripts import").

---

## Doc cascade (flush when built)

- **`STATE_SCHEMA.md`** — the five new host-metadata keys (`is_behind_waf`,
  `waf_vendor`, `is_cdn`, `cdn_name`, `origin_ip_candidates`), all agent-authored
  / trusted (**NOT** in `TARGET_DERIVED_METADATA_KEYS`); the new
  `raw/stage4.5_{wafw00f,cdncheck}_{host}.json` lines; note the
  `waf_suspected` (B1) vs `is_behind_waf` (C3) complement.
- **`README.md`** — stage 4.5 in the pipeline flow + state-file table; the
  pre-flight-label + metadata-only (no new assets) property.
- **`pipeline_schematic.mermaid`** — a WAF/CDN-label node between stage 4 and 5,
  feeding host metadata (and, dashed/future, informing B1 + primitive).
- **`CONTRIBUTING.md`** — reaffirm verify-real-tool + fail-closed + rate-audit for
  the two new tools (wafw00f, cdncheck).
- **`CHANGELOG.md`** — DESIGN → BUILT entry (incl. the "neither installed at
  design time" prerequisite note).
- **`RECON_ENHANCEMENTS.md`** — flip **C3** from roadmap to BUILT; update the
  Phase-3 row; note origin-candidate flagging shipped, favicon (E1)/ASN (F3)
  correlation still deferred.
- **`PRIMITIVE_WAF_HANDLING_DESIGN.md`** — update its "Where recon sets this up"
  list: C3's vendor label + origin candidates now exist (its reconciliation no
  longer leans on an entirely-unbuilt C3).
- **`RECON_AGENT_DESIGN.md`** — fold stage 4.5 into the stage inventory (larger
  edit; may defer with the Track-D fold already owed).

---

## Explicitly OUT of scope for C3 v1 (so the building agent doesn't over-reach)

- **Offensive WAF bypass / evasion** — primitive's guarded territory
  (`PRIMITIVE_WAF_HANDLING_DESIGN.md`). C3 detects and labels, never engages.
- **Active origin confirmation** — sending a Host-header request to a candidate
  IP to prove it serves the site. That is active testing → primitive (or a later
  recon item); C3 only *flags* candidates.
- **Favicon-hash origin correlation** — that's **E1** (richer httpx `-favicon`);
  C3 consumes it later if built, does not implement it.
- **ASN / IP-range origin expansion** — that's **F3** (`asnmap`, needs a CIDR/ASN
  asset type — a `state.py` question).
- **Historical-DNS origin lookup** — deferred (F5-adjacent).
- **The 200-challenge WAF blind spot** — a challenge-based WAF (Cloudflare/Akamai
  Bot Manager/DataDome) answering `200`+JS-challenge is the **shared open
  question** flagged in both `RECON_B1_CONTENT_DISCOVERY_DESIGN.md` and
  `PRIMITIVE_WAF_HANDLING_DESIGN.md` (Open Q1). wafw00f *may* fingerprint the
  vendor even when B1's `-sf` (403-keyed) misses the flood — a partial mitigation
  worth confirming on a real challenge WAF — but *solving* the 200-challenge
  detection problem is NOT C3's job. Named, not closed.
- **Wiring B1 to consume the pre-flight label** (pre-emptive back-off) — the
  label is put in metadata; the consuming coupling is deferred (§Relationship to
  B1).
- **New `ip` assets for origin candidates** — candidates are unconfirmed
  metadata, not scope-gated discovered assets.

---

## Open questions for Jared

1. **Stage number: 4.5 (pre-flight, recommended) vs terminal 11.** 4.5 makes the
   label available to the whole run (the pre-flight value) at the cost of another
   float `STAGE`; 11 avoids the float but forfeits pre-flight availability. Which
   trade?
2. **`run_state.current_stage` and floats.** Keep it integer (log-only 4.5) or
   extend run_state to store the float? (Same call B1 deferred at 6.5.)
3. **wafw00f `--findall`** (all matching WAFs) — enable it, and if a host reports
   multiple, is `waf_vendor` the first match or a list?
4. **cdncheck install path/version** to pin, and whether to run its range-data
   `-update` in the build or accept the embedded ranges (offline determinism vs
   freshness).
5. **`origin_ip_candidates` source breadth for v1** — only IPs already in
   `assets.db` (stage-4 naabu/httpx), or also whatever cdncheck resolves? (More
   sources = more candidates but more to verify the parser against.)

---

## See also

- `RECON_ENHANCEMENTS.md` — C3 sketch + Track-C sequencing (this realizes it);
  E1 favicon / F2 cloud / F3 ASN are the deferred origin-discovery siblings.
- `RECON_B1_CONTENT_DISCOVERY_DESIGN.md` — the in-flight `waf_suspected` breaker
  C3's pre-flight label complements; shares the 200-challenge blind spot.
- `PRIMITIVE_WAF_HANDLING_DESIGN.md` — the offensive-bypass consumer; C3 supplies
  its vendor label + origin candidates. C3 detects; primitive engages.
- `stage9_whatweb.py` — the per-host metadata-enrichment pattern C3 mirrors
  (per-host loop, metadata updates, no new assets, no records).
- `stage_content_discovery.py` / `main._apply_waf_flags` — B1's `waf_suspected`
  path C3 sits beside.
- `state.py` — `TARGET_DERIVED_METADATA_KEYS` (C3's labels stay OUT of it),
  `update_asset_metadata`, `raw_path`.
- `rate_limits.py` — where `wafw00f_rate_args` lands; whatweb is the
  per-host-loop, no-native-rate precedent.
- `CONTRIBUTING.md` — verify-real-tool-before-parser + fail-closed + the
  before-you-build-a-stage 11-point checklist this doc answers.
</content>
</invoke>
