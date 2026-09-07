# C5 — tech → CVE candidate flagging (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN (locked).** Realizes **C5** of `RECON_ENHANCEMENTS.md` (Phase 3,
Track C — "signal quality & prioritization"). Closes the standing gap named in
`stage9_whatweb.py`'s own docstring: stage 9 collects version-level fingerprints
*explicitly "for CVE correlation"*, stores them as `whatweb_tech` host metadata,
**and then nothing consumes them.** C5 consumes them.

C5 turns a fingerprinted `(product, version)` into a **candidate CVE**, written as
a **point-of-interest into the SAME `recon_findings` table C1 just built** — no new
table — with `source="cve-candidate"`. It is a **prioritized lead, not a vulnerability
claim**: recon flags candidates *offline*; primitive confirms them *live*.

This doc follows the same discipline every prior stage did (verify-real-tool /
verify-real-data before the parser, fail-closed, fault-isolated, provenance-tagged).
Nothing here is coded yet.

---

## The boundary IS the whole feature (candidate, not claim)

C5 sits exactly on the recon/primitive line, and the line is what makes it safe:

- **Recon says:** "this host advertises Apache 2.4.49; Apache 2.4.49 is associated
  with CVE-2021-41773 (CVSS 7.5). Here is a lead."
- **Recon does NOT say:** "this host is vulnerable to CVE-2021-41773." It never sends
  the path-traversal payload that would confirm it. **primitive** does that, under its
  guard/budget, and sets the confirmed status.

This is a stronger boundary than C1's even. C1 (detection nuclei) sends a benign
*detection* request. **C5 sends NO target traffic at all** — it is a pure **offline
correlation pass** over data stages 4 and 9 already collected. Zero new requests, zero
new scope surface, zero WAF/abuse risk. The only thing C5 touches is `assets.db` and a
local CVE dataset.

> **Wording contract for the report agent / A1 brief.** A `recon_findings` row with
> `source="cve-candidate"` is a **candidate**. Its `severity` is the *CVE's* CVSS
> band, **not** a confirmed severity on this host. It must be rendered as
> "candidate CVE (unconfirmed) — version-string match, needs primitive confirmation,"
> never as "finding" or "vulnerability." `status` stays `new` until primitive promotes
> or dismisses it. The version evidence is **attacker-influenceable** (see Provenance),
> which is the second reason it is a candidate and not a claim.

---

## The CVE-data-source decision (the hard call — resolved with verification)

Three options were on the table; each was checked against what is actually on this box.

### (b) — run nuclei's CVE templates (`-tags cve`) against the host — **REJECTED**

Verified locally (`~/nuclei-templates`, nuclei v3.11.1): **4,316 CVE templates**, and
they are **exploit templates, not detection templates.** Concrete evidence — the very
first HTTP CVE template inspected, `CVE-2017-15647`, actively sends an LFI payload and
matches on leaked `/etc/passwd` contents:

```
path: "{{BaseURL}}/cgi-bin/webproc?getpage=/etc/passwd&var:language=en_us&var:page=wizardfifth"
matchers: regex "root:.*:0:0:"
```

That is *exploitation*, i.e. **primitive's guarded, refuse-capable territory** — the
exact line `RECON_ENHANCEMENTS.md` and C1 draw. A `-tags cve` run cannot be trusted to
stay detection-only (unlike C1's curated `exposures,misconfiguration,exposed-panels`
set, which are presence-fingerprints); many CVE templates *submit the exploit* to
decide the match. Restricting to "detection-only CVE templates" is not a reliable
partition nuclei exposes, and even the attempt sends version-specific probes C5 is
explicitly forbidden from sending. **Rejected on the boundary.**

### (a) — offline `(tech, version)` → CVE mapping from a local dataset — **RECOMMENDED**

Purely offline, no traffic, cleanest "flag candidate" posture, and it is the *only*
option that respects "recon sends no version-specific probe." The design question
becomes *which* offline dataset, and here verification matters:

- **Canonical, high-precision source: the NVD feeds (CVE + CPE-match).** NVD's
  CPE-match criteria carry real **version ranges**
  (`versionStartIncluding`/`versionEndExcluding`), which is what "version-level
  correlation" actually needs — "Apache `>=2.4.0 <2.4.51` → CVE-2021-41773," not just
  "Apache → some CVEs." **This is the recommended long-term source.**
  **⚠️ Prerequisite, flagged (this gates C5's high-signal form):** *no* NVD/CPE/vulners
  dataset is present on the box today (verified: no `nvdcve*`, `official-cpe*`,
  `vulners*.db`; no `searchsploit`; no `cvss`/`nvdlib`/`cpe` Python libs). Acquiring,
  shipping, and **periodically refreshing** an offline NVD/CPE index (or a distilled
  subset) is a build-time prerequisite, with a staleness policy (a CVE feed is only as
  good as its last sync). This is C5's analog of B2's "stand up a real spec server"
  prerequisite — named, not assumed.

- **Verified on-box BOOTSTRAP source: harvest the local `nuclei-templates`
  classification blocks.** This is the useful discovery from verification. **3,160**
  CVE templates carry a `classification.cpe:`, **3,944** carry `cvss-score:`, **3,579**
  carry `metadata.product:` — e.g. `CVE-2021-41773` ships
  `cpe:2.3:a:apache:http_server:2.4.49:*`, `cvss-score: 7.5`, `cve-id: CVE-2021-41773`,
  `product: http_server`, plus `epss-score`. These YAML files are a **product→CVE index
  already on disk**, harvestable **offline at build time with zero traffic and zero
  acquisition** — we read the *metadata*, we never *run* the template. It lets C5 be
  built and verified end-to-end **today**, before the NVD feed lands.
  **⚠️ Known limitation, named:** the harvested `cpe` version field is **usually `*`**
  (product-level, no version range) — the template confirms the version *by
  exploiting*, so it doesn't encode a version range. So the nuclei-metadata index
  under-filters by version (see "Signal-quality make-or-break" below). Use it as the
  bootstrap that proves the pipeline; upgrade to the NVD/CPE feed for real version-range
  precision.

**Recommendation:** build C5 against an **offline mapping (a)**, coded against a small
**dataset-adapter interface** so the *source* is swappable. Ship v1 wired to the
**verified on-box `nuclei-templates` classification harvest** (bootstrap — offline,
already present, proves the seam), and **name the NVD/CPE feed as the precision upgrade**
whose acquisition/refresh is the flagged prerequisite. This mirrors the project's
existing move (C5 reuses C1's table; likewise C5 reuses a dataset already on the box)
and keeps the boundary pristine.

---

## Provenance: `target_derived=1`, and it drives the design

The `(product, version)` evidence comes from `whatweb_tech` / `httpx_tech` — **target-
authored, attacker-influenceable** metadata (`whatweb_tech` is already in
`state.TARGET_DERIVED_METADATA_KEYS`, R9). The real zonetransfer.me run proved this:
whatweb faithfully reported a **fabricated** `X-Powered-By: Sparkles!` header. A target
can *lie about its version* — claim a vulnerable version it isn't running, or hide a
vulnerable one — so:

- Every C5 `recon_findings` row is **`target_derived=1`**. The `matched_at`/evidence is
  untrusted; the future A1 brief treats it as **delimited data, never instructions**.
- The CVE-id/CVSS/CPE come from *our* offline dataset (trusted), but the **match
  evidence** (the version string) is target-controlled. A spoofed version yields a bogus
  candidate — **which is fine, because it is a candidate primitive confirms**, not a
  claim. This is precisely why C5 flags candidates and does not assert vulns.

---

## Signal-quality make-or-break: version-match discipline

This is C5's central real-world trap, the analog of B2's SPA-catch-all and B1's
soft-404. **Flagging product-level without version-matching floods primitive with
noise.** whatweb detecting bare "WordPress" must NOT emit hundreds of WordPress CVEs;
that defeats the "prioritized lead" purpose and burns primitive's budget.

**Locked policy: emit a candidate only when a version comparison actually succeeds.**

1. **Exact/range match (emit):** the fingerprint carries a concrete version AND the
   dataset entry constrains a version (NVD range, or a nuclei `cpe` with a concrete
   version like `...:http_server:2.4.49:*`). Compare with a real version comparator
   (`packaging.version` / PEP 440-ish, with a documented fallback for non-semver
   vendor strings). Emit only if the fingerprinted version falls in/at the affected
   set. `version_match_type = "exact"` / `"range"`.
2. **Product-only entry (suppress by default):** dataset entry has `cpe` version `*`
   (no range) — cannot version-filter → **do not emit** in v1, to protect signal.
   Exception: a small curated **high-value product allowlist** (Jared-call) where mere
   presence of an outdated-prone product is worth a lead even without a range
   (`version_match_type = "product-only"`, clearly labeled lower-priority). Off by
   default.
3. **No version fingerprinted (suppress):** whatweb/httpx gave a product but no version
   → nothing to correlate → no candidate (the fingerprint just isn't precise enough).

EPSS (`epss-score`, present in the nuclei metadata) is retained in `raw_finding` as a
**ranking** signal for A2/A1 — not a gate.

---

## Input: `whatweb_tech` (stage 9) + `httpx_tech` (stage 4) — real shapes

**`whatweb_tech`** — verified real shape (zonetransfer.me run): a dict keyed by plugin
name; values are `{"string": [...]}`, sometimes `{"version": [...], "string": [...]}`,
sometimes bare `{}` (presence-only). Version-bearing examples look like
`"HTTPServer": {"string": ["Apache/2.4.49"]}` or a plugin with an explicit
`"version": ["2.4.49"]`. Parsing needed:

- Prefer an explicit `version` sub-key; else regex a version token out of the `string`
  value (`Apache/2.4.49`, `PHP/7.4.3`, `jQuery 1.7.2`).
- Map the whatweb **plugin name / product string** → a **CPE product** (a small curated
  synonym table: `HTTPServer:Apache` → `apache:http_server`, `WordPress` →
  `wordpress:wordpress`, `jQuery` → `jquery:jquery`, …). This name→CPE normalization is
  the fiddly part and, like every parser here, must be built against **real** whatweb
  output on a **versioned** target (the zonetransfer sample carries no versions — see
  Verification).
- ⚠️ **Verify the `version` sub-key on a real versioned run before trusting it.** The
  standing sample has none; whatweb's plugins *do* emit versions (`-a 3` is chosen in
  stage 9 precisely for exact-version detection), but the exact JSON shape of a
  version-bearing plugin value must be confirmed on a real target, not assumed.

**`httpx_tech`** — from stage 4 (`obj.get("tech", [])`): a Wappalyzer-class **list**
of tech labels, broad but **version-shallow** (often no version). C5 uses it as a
**secondary** source: a product name with no version feeds the "no version → suppress"
path unless whatweb supplied the version for the same host/product. httpx_tech is not
currently in `TARGET_DERIVED_METADATA_KEYS`; C5 treats any evidence it consumes as
target-derived regardless (the row is `target_derived=1` either way).

---

## Locked decisions (recommended; Jared's calls flagged)

1. **Reuse `recon_findings` — NO new table.** C5 writes rows with **`source=
   "cve-candidate"`** (vs C1's `"nuclei"`) via the existing
   `state.add_recon_findings(...)` / `load_recon_findings(...)`. The table's `source`
   column was designed for exactly this. Column mapping in §Output.
2. **Offline mapping (option a), source-adapter interface.** v1 wired to the **on-box
   `nuclei-templates` classification harvest** (verified present); **NVD/CPE feed** is
   the named precision upgrade (prerequisite: acquire/ship/refresh). Reject `-tags cve`
   run (boundary).
3. **Emit only on a successful version comparison** (§Signal-quality). Product-only
   entries suppressed by default; curated high-value allowlist is a Jared-call, off by
   default.
4. **New offline correlation step AFTER stage 10, not folded into stage 9** (§Placement).
   Integer step, not fractional. Stage number is a **Jared-call; recommended 11.**
5. **`target_derived=1`** on every row; evidence is untrusted (§Provenance).
6. **Dedup via the existing `UNIQUE(host, template_id, matched_at)`** by putting the
   **evidence string in `matched_at`** (e.g. `whatweb_tech:apache/2.4.49`) — so the same
   host + same CVE + same evidence collapses to one row, and a *different* version
   fingerprint for the same CVE is a distinct lead. Clean reuse, no schema change.

---

## Placement — new offline step after stage 10, not folded into stage 9

**Fold into stage 9? No.** Stage 9 is an active **whatweb subprocess** stage (per-host
loop, rate args, R1 redirect discipline, R7 subprocess isolation). C5 is **offline
correlation** with a *different concern* (mapping, not fingerprinting) and *no
subprocess and no traffic*. Mixing them violates the single-concern separation every
stage keeps, and would couple C5's dataset logic to whatweb's invocation path.

**A new step, after stage 10.** C5 must run after stage 9 (it reads `whatweb_tech`) and
naturally after stage 4 (`httpx_tech`); running it after the current terminal stage 10
(B2) means **all** tech metadata is already persisted. Because it sends no traffic, C5
does **not** need the active-stage machinery (rate/R1/WAF) — it is closer in shape to
`main.py`'s inline Track-D **service-promotion block** (pure post-processing over
persisted data) than to an active stage. Still, model it as a clean
`run_cve_candidates_and_report(state, scope)` function so the **standalone re-runner**
pattern (`testing/run_stageN_only.py`) works and it can re-run over an existing
`assets.db` cheaply. **Recommended stage number 11** (integer — deliberately avoids the
fractional-stage footgun B1 flagged at 6.5); Jared-call.

---

## Output — `recon_findings` rows (the table reuse, columnized)

| `recon_findings` column | C5 value |
|---|---|
| `source` | `"cve-candidate"` |
| `template_id` | the **CVE id** (e.g. `CVE-2021-41773`) |
| `template_name` | short CVE title from the dataset (e.g. "Apache HTTP Server 2.4.49 — Path Traversal") |
| `category` | `"cve"` |
| `severity` | CVSS band: `critical` (≥9.0) / `high` (7.0–8.9) / `medium` (4.0–6.9) / `low` (0.1–3.9) / `unknown` |
| `matched_at` | evidence string, e.g. `whatweb_tech:apache/2.4.49` (also the dedup key) |
| `status` | `"new"` |
| `target_derived` | `1` (version evidence is target-authored/attacker-influenceable) |
| `host` / `asset_id` | the fingerprinted host; `asset_id` linked by exact host-string match (same `asset_lookup` pattern stage 8 / C1 use; no match → `None`, row kept) |
| `raw_finding` | the match detail (JSON) — see below |
| `discovered_at_stage` | `11` (or the chosen step number) |

`raw_finding` (the audit trail the report agent renders from):

```json
{
  "cve_id": "CVE-2021-41773",
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
  "vendor": "apache", "product": "http_server",
  "fingerprinted_version": "2.4.49",
  "version_match_type": "exact",
  "evidence_source": "whatweb_tech", "evidence_plugin": "HTTPServer",
  "epss_score": 0.9,
  "dataset_source": "nuclei-templates-classification",
  "candidate": true,
  "note": "UNCONFIRMED version-string match — primitive confirms"
}
```

---

## Where it slots in `main.py`

```python
run_stage10_and_report(patterns, state, scope)      # B2 API-schema discovery (terminal today)
run_cve_candidates_and_report(state, scope)         # NEW — C5 offline tech→CVE correlation
state.update_run_state(status="stage_complete", passes_completed=1)
```

`run_cve_candidates_and_report` mirrors `run_stage8_and_report`'s C1 block:

```python
def run_cve_candidates_and_report(state, scope):
    all_assets = state.load_assets()
    hosts = [a for a in all_assets
             if a.type == "subdomain" and a.scope_status == "in_scope"
             and "httpx_status_code" in a.metadata]          # confirmed-live, same filter
    asset_lookup = {a.value: a.asset_id for a in hosts}
    findings = run_cve_candidates(hosts, state, current_pass=1,
                                  asset_lookup=asset_lookup)   # offline; no scope/rate needed
    if findings:
        state.add_recon_findings(findings)                    # SAME table as C1
        logger.info("C5: %d CVE candidate(s) flagged (status=new, source=cve-candidate)",
                    len(findings))
    state.update_run_state(current_stage=11, status="stage_complete")
```

No `persist_records` (C5 produces `recon_findings`, not Track-D source records). No
scope gate on new assets (C5 mints no assets — it annotates existing hosts with leads).

---

## The module — `stages/stage_cve_candidates.py`

```python
def run_cve_candidates(hosts, state, current_pass, asset_lookup=None
                       ) -> list[ReconFinding]:
    """Offline: for each confirmed-live in-scope host, extract (product, version)
    pairs from whatweb_tech + httpx_tech, look each up in the offline CVE dataset,
    and emit a ReconFinding(source='cve-candidate') per version-matched CVE.
    NO target traffic. R7: a per-host failure skips that host, never aborts."""
```

- **`extract_tech_versions(host_asset) -> list[TechVersion]`** — parse `whatweb_tech`
  (version sub-key or regex from `string`) + `httpx_tech`; normalize plugin/label →
  CPE product via the curated synonym table. Verified against real versioned output.
- **`cve_dataset` adapter** — `lookup(product, version) -> list[CveEntry]`. v1 impl:
  index built once from `~/nuclei-templates/**/cves/**.yaml` `classification` blocks
  (cpe/cvss-score/cve-id + metadata vendor/product/epss). Swappable for an NVD/CPE feed
  impl. Path is a module constant (like B1's `WORDLIST_PATH`) so it is configurable.
- **`version_in_affected(fingerprinted, entry) -> bool`** — the emit gate (exact/range;
  product-only suppressed per §Signal-quality).
- Per-host `try/except` (R7). Build `ReconFinding(source="cve-candidate", ...)`.

---

## Boundary — recon flags candidates offline; primitive confirms live

C5 sends **no target traffic**: no version-specific probe, no exploit, no credential,
no confirmation request. It reads persisted fingerprints and a local dataset and writes
leads. A flagged `CVE-2021-41773` candidate is an **`endpoint`-less lead**: primitive,
under its guard and budget, sends the actual path-traversal probe to confirm or refute,
and sets the confirmed status downstream. Recon characterizes the *possibility*;
primitive establishes the *fact*. Same line C1 (detection-only) and B1/B2 hold — C5 is
the strictest of them, since it is entirely offline.

---

## Verification

**Real-data discipline (BEFORE the parser, per CONTRIBUTING):**
- **whatweb version shape:** run whatweb `-a 3` against a **versioned** target (a local
  container advertising a concrete `Server:`/app version — the standing zonetransfer.me
  sample carries NO versions) and capture the real JSON shape of a version-bearing
  plugin value (`version` sub-key vs `string` token) before writing
  `extract_tech_versions`.
- **Dataset correctness:** confirm the offline lookup on a **known pair** —
  `apache:http_server 2.4.49 → CVE-2021-41773` (verified present in
  `~/nuclei-templates` with `cpe:2.3:a:apache:http_server:2.4.49` + `cvss-score: 7.5`).
  Confirm the CPE→CVE join and the version comparator agree on this pair.

**Real-run end-to-end:**
- Point the pipeline at a host running a **known-outdated** tech (e.g. Apache 2.4.49) →
  assert exactly one `recon_findings` row `source="cve-candidate"`,
  `template_id="CVE-2021-41773"`, `category="cve"`, `severity="high"`,
  `target_derived=1`, `status="new"`.
- **Negative control (critical):** point at a **patched/current** version of the same
  tech → assert **no** candidate row (proves the version gate suppresses, not floods).

**Mocked tests — `testing/test_cve_candidates.py`** (mirror `test_track_d.py`):
- Synthetic `whatweb_tech={"HTTPServer":{"string":["Apache/2.4.49"]}}` + a stub dataset
  containing the CVE-2021-41773 entry → one candidate row with the fields above.
- **Version gate:** fingerprint 2.4.62 (patched) vs a 2.4.49-only entry → **zero rows**.
- **Product-only suppression:** dataset entry with `cpe` version `*` and no allowlist →
  zero rows; same entry with the product on the allowlist → one `product-only` row.
- **No version fingerprinted:** `whatweb_tech={"WordPress":{}}` → zero rows.
- **Provenance:** every emitted row `target_derived=1`; a fabricated version string
  still only ever yields `status="new"` (candidate, not claim).
- **Dedup:** two runs of the same host/CVE/evidence → one row (`UNIQUE(host,
  template_id, matched_at)`); a different fingerprinted version → a distinct row.
- **asset_id linkage:** host match → asset_id; no match → None, row kept.
- **R7:** one host raising in the loop doesn't lose the others.
- **Source distinctness:** C5 rows (`source="cve-candidate"`) and C1 rows
  (`source="nuclei"`) coexist in `recon_findings` and `load_recon_findings` round-trips
  both.

**`testing/run_cve_candidates_only.py`** — standalone re-runner importing
`run_cve_candidates_and_report` from `main.py` (never reimplements it), for iterating on
a run dir that already has `whatweb_tech`/`httpx_tech` in `assets.db`.

---

## Doc cascade (flush when built)
- **`STATE_SCHEMA.md`** — `recon_findings` now also holds `source="cve-candidate"` rows
  (category `cve`, severity from CVSS, evidence in `matched_at`, `target_derived=1`); no
  schema change (table reuse); note the offline CVE dataset location + adapter.
- **`README.md`** — new offline correlation step (stage 11) in the pipeline flow; note
  it sends no traffic and consumes stage 4/9 tech metadata.
- **`pipeline_schematic.mermaid`** — a tech→CVE-candidate node reading `whatweb_tech`/
  `httpx_tech`, writing `recon_findings`.
- **`CONTRIBUTING.md`** — the offline CVE dataset joins the verify-real-*data* list
  (dataset correctness confirmed on a known pair before trust); note the NVD-feed
  prerequisite among the deferred tools.
- **`CHANGELOG.md`** — C5 entry; the stage-9 "collects for CVE correlation then does
  nothing" gap closed.
- **`RECON_ENHANCEMENTS.md`** — flip **C5** from roadmap to BUILT; update the Phase-3
  row.
- **`RECON_AGENT_DESIGN.md`** — fold the new step into the stage inventory (with the
  Track-D / stage-10 fold already owed).

---

## Explicitly OUT of scope for C5 v1
- **Confirming any CVE** (sending the exploit/version-specific probe) — that is
  primitive's guarded territory; C5 flags candidates only.
- **Running `nuclei -tags cve`** or any exploit template — rejected on the boundary
  (verified exploit content).
- **Product-only flagging by default** — suppressed to protect signal; behind a curated
  allowlist only (Jared-call, off by default).
- **Shipping/refreshing the NVD/CPE feed** — the precision upgrade; its acquisition +
  staleness policy is the named prerequisite, deferred behind the on-box bootstrap.
- **Non-HTTP service CVEs** (Track-D `service` records / naabu ports) — C5 v1 correlates
  web tech (whatweb/httpx) only; service-banner CVE correlation is a later extension.
- **A promotion workflow** that moves `status` beyond `new` — consumers/primitive drive
  transitions (same as C1).
- **Secret/version data leaving the box** — C5 is offline by construction; any dataset
  refresh is a build-time step, not a run-time network call.

---

## Open questions for Jared
1. **Dataset for v1:** ship against the on-box `nuclei-templates` classification harvest
   (verified present, product-level precision) as bootstrap, and defer the NVD/CPE feed
   (true version ranges) as the acquisition-gated upgrade? (Recommended.) Or block C5
   until the NVD feed is acquired, for version precision from day one?
2. **Product-only allowlist:** which products (if any) are worth a *presence* lead
   without a version range (e.g. WordPress, Jira, Exchange)? Default is empty (suppress
   all product-only).
3. **Stage number:** integer **11** (recommended) for the offline correlation step, or a
   different slot?
4. **httpx_tech into `TARGET_DERIVED_METADATA_KEYS`?** C5 tags rows `target_derived=1`
   regardless, but should the R9 registry list `httpx_tech` too for consistency (it
   currently lists only `whatweb_tech`)?
5. **Severity source:** derive the band purely from CVSS base score (recommended), or
   also factor EPSS into a combined priority the A2 interest-score consumes?

---

## See also
- `RECON_C1_NUCLEI_POI_DESIGN.md` — the `recon_findings` table + `ReconFinding` C5
  reuses; the `source` column designed for this (`"cve-candidate"`).
- `RECON_ENHANCEMENTS.md` — C5 sketch + the recon/primitive boundary notes.
- `stages/stage9_whatweb.py` — the `whatweb_tech` producer (C5's input); the docstring
  naming the "for CVE correlation" purpose C5 realizes.
- `stages/stage8_takeover.py` — C1's `run_stage8_detection` → `ReconFinding` pattern C5
  mirrors (offline, no subprocess).
- `RECON_B1_/B2_..._DESIGN.md` — the format/quality template; the verify-real-data and
  "central trap" (soft-404 / SPA-catch-all → C5's version-match gate) discipline.
- `PRIMITIVE_AGENT_DESIGN.md` — the consumer that *confirms* the candidate C5 flags.
- `CONTRIBUTING.md` — verify-real-data-before-parser, fail-closed, R7, provenance.
