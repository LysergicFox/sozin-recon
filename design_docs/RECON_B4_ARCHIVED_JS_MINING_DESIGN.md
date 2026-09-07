# B4 — archived JS mining (design-lock)

**Status: ✅ BUILT + real-run verified 2026-08-24 (terminal stage 11).** Shipped as
`stages/stage_archived_js.py`, wired into `main.run_pipeline` after stage 10; the
stage-7 jsluice runners were extended with backward-compatible `base_url`/`stage` params.
Tests: `testing/test_archived_js.py` (13 mocked) + `testing/run_stage11_only.py`; all 23
suites green. Interface facts verified before the parser (CDX list-of-lists w/ header row,
`collapse=digest` adjacency-only → client-side digest dedup, `id_` unmodified body vs. the
toolbar-injecting replay form, jsluice-reads-local-file / `-u`=`--unique`), and the full
stage confirmed end-to-end on `demo.owasp-juice.shop` (11 wayback-provenance endpoints
resurrected from archived Angular bundles, all linked to parent url assets; a transient
archive fetch failure was R7-isolated). The design below is the as-built spec.

Written to the same discipline every existing stage was — **verify the real interface
(Wayback CDX + the raw-snapshot URL form) before writing the parser**, fail-closed,
fault-isolated (R7), untrusted-by-default. Realizes **B4** of `RECON_ENHANCEMENTS.md`
(Phase 2, Track B — "coverage: the testable surface *on* the hosts"). Sibling to
`RECON_B1_CONTENT_DISCOVERY_DESIGN.md` / `RECON_B2_API_SCHEMA_DISCOVERY_DESIGN.md`; reuses
their record/persist/per-source-loop patterns.

gau/waybackurls (stage 1) already pull the target's *historical URLs*, but nothing
mines the historical **JS bodies**. Old JS routinely contains endpoints that were
removed from the live app and secrets that were rotated but are still informative
(naming schemes, internal hostnames, provider identification). B4 fetches archived
`.js` snapshots from the Wayback Machine and runs jsluice over them — **the exact
same extraction as stage 7's live JS**, producing the same Track-D
`endpoint`/`parameter`/`secret` records, distinguished only by provenance
(`source=wayback` + snapshot timestamp).

---

## The one insight that reframes B4: this is passive-toward-the-target

**B4 sends ZERO packets to the target.** Both halves of its work — the Wayback
**CDX API** query (which snapshots exist) and the **raw-snapshot fetch** (the
archived body) — hit `web.archive.org`, a **third-party archive**, exactly like
paramspider already queries wayback/otx/commoncrawl (stage 5) and gau/waybackurls
query the archive (stage 1). Those tools are explicitly documented in
`rate_limits.py` as needing **no target-facing rate limit**, "they query ARCHIVE
APIs, not the target directly."

This places B4 in a fundamentally different bucket from its Track-B siblings:

- **B1/B2 are active-traffic stages** — they inherit the whole R1/R3 rate-and-scope
  burden because they fuzz/probe the live host.
- **B4 is passive-toward-the-target** — it inherits the *provenance* and
  *untrusted-data* discipline (like stage 7's live JS), but **not** the
  target-facing rate model. `rate_limits.py` has no B4 entry and needs none. The
  courtesy rate that *does* apply is toward **the archive**, not the target — a new
  and separate consideration (see §Archive courtesy).

A useful consequence: because we never touch the live host, **B4 does not require a
host to be live.** A subdomain that is dead *today* may hold exactly the archived
`.js` that reveals a removed endpoint — that is the whole point. So B4's seed is
**in-scope hosts regardless of `httpx_status_code`**, unlike B1/B2/stage-9 which
require confirmed-live.

---

## Provenance distinction that drives the design

The archived JS body is **target-authored** — the target wrote that JavaScript, it
was merely stored by a third party. So every record B4 produces is
**`target_derived=1`**, identical to stage 7's live jsluice output (an archived
endpoint path, a string that looks like a secret, a param name are all
attacker-influenceable text). B4 output is therefore **untrusted-by-default** (R9):
it carries `target_derived=1`, and the future A1 brief must treat it as delimited
data, never instructions. This is the same rule live jsluice (stage 7) and B2 both
already follow.

Provenance is *enriched*, not changed: each B4 record additionally carries
`metadata = {"source": "wayback", "snapshot_timestamp": "<14-digit ts>",
"archived_url": "<original .js URL>"}` so a consumer can tell a live finding from a
resurrected one, and can date it.

---

## Locked decisions (recommended; Jared's calls flagged)

1. **Source of archived `.js` URLs: query the Wayback CDX API directly, per
   in-scope host — NOT filter the existing gau/waybackurls `url` assets.**
   Rationale: to fetch a *specific archived body* we need the **snapshot
   timestamp** (to build the `.../<timestamp>id_/<original>` raw URL) and ideally
   the **content digest** (to dedup identical captures). A plain `.js` `url` asset
   left behind by gau/waybackurls carries **only the original URL — no timestamp,
   no digest** — so it cannot address a snapshot. The CDX API is the authoritative
   source of `(original, timestamp, mimetype, statuscode, digest)` tuples and
   supports server-side filtering + `collapse=digest` dedup. *Named residual:* the
   existing `.js` `url` assets could be a cheap secondary seed, but CDX already
   returns everything they would, plus the timestamp we actually need, so v1 uses
   **CDX only**. ← recommended.

2. **Fetch the archived body ourselves (direct `urllib`/`curl`), write it to a temp
   file, then run jsluice over the LOCAL file** — rather than handing jsluice the
   wayback URL to fetch itself. Two reasons, both correctness: **(a)** we must use
   the **raw-snapshot (`id_`) form** so Wayback returns the *unmodified original
   body*; the default replay form injects the Wayback toolbar HTML/JS into the
   response, which would poison jsluice. Controlling the fetch guarantees we get
   `id_`. **(b)** jsluice resolves relative URLs against the URL it was given; if
   that were the wayback URL, every relative endpoint would resolve to
   `web.archive.org/...` and be attributed to the wrong host (then dropped by the
   scope gate). Fetching to a file lets us pass jsluice a **`base_url` = the
   ORIGINAL target URL** for resolution. Mirrors B2's "direct fetch because we need
   the BODY" decision. ← recommended.

3. **Reuse `stage7.run_jsluice_urls()` / `run_jsluice_secrets()`, extended with two
   backward-compatible optional params: `base_url=None` (default = the source arg,
   preserving stage-7 behavior) and `stage=STAGE` (default 7).** B4 calls them with
   the temp file path as the source, `base_url=<original .js URL>`, and `stage=11`
   so the raw archive + `raw_log_ref` land under stage 11, not overwriting stage 7.
   This keeps a **single jsluice extraction implementation** (CONTRIBUTING:
   "standalone re-run scripts import, never duplicate" — same spirit for shared
   extraction logic). ← recommended; small refactor of stage 7 named explicitly.
   *Alternative Jared may pick:* copy the two ~20-line runners into the B4 module to
   avoid touching stage 7. Rejected — two jsluice parsers drift.

4. **New TERMINAL stage — stage 11** (after B2's stage 10). ← **Jared call;
   recommended 11.** Rationale: like B2, B4 is a **record-only producer with no
   downstream *recon* consumer** (stage 7 seeds from live `.js` assets, not archived
   ones; stages 8/9/10 seed from hosts). No same-pass consumer ⇒ no fractional-stage
   pressure ⇒ a **clean integer terminal stage** is right (B2's exact reasoning). It
   runs after stage 10 purely for tidiness (all record producers cluster at the
   end). *Alternative Jared may pick:* stage 7.5, pairing it visually with live JS
   mining — rejected: reintroduces the float-`STAGE` footgun B1 flagged, for no
   benefit, since nothing consumes B4 same-pass. Recommendation stands at terminal
   **stage 11**.

5. **Seed set: ALL in-scope `subdomain` assets — NOT gated on `httpx_status_code`.**
   The single deliberate divergence from B1/B2 (§"passive-toward-the-target"
   above): B4 never touches the live host, so a host being dead now does not make
   its archived JS worthless — it makes it *more* interesting. Also seed the root
   domain(s). ← recommended.

6. **CDX filtering: `.js` by mimetype AND URL suffix, `statuscode:200`,
   `collapse=digest`, capped per host.** Filter server-side to JavaScript
   (`mimetype:application/javascript` OR an `original` suffix of `.js` — confirm
   both are needed; some captures mislabel mimetype), keep only `200` captures
   (a 404's archived body is the target's error page, not JS), and `collapse=digest`
   so N identical captures of the same file collapse to one fetch. A **hard per-host
   cap** (`MAX_SNAPSHOTS_PER_HOST`, e.g. 500) bounds a pathological history. ←
   recommended; confirm exact filter/collapse syntax on real CDX (interface fact).

7. **Records: `endpoint`/`parameter`/`secret`, `target_derived=1`, identical
   construction to stage 7**, plus the `source=wayback` provenance metadata
   (decision above). Secrets keep the D3 rule by construction (reused runner):
   **fingerprint + `raw_log_ref`, never the raw value.** ← recommended.

8. **Archive courtesy: a self-imposed modest fetch cap (sequential or low
   concurrency + a small inter-fetch delay), NOT the target rate model.** A
   `MAX_SNAPSHOTS_PER_HOST` ceiling plus sequential fetches keeps us a polite
   client of a free public service. This is explicitly *not* a `rate_limits.py`
   entry (that module protects the *target*). ← recommended. *Jared call:* exact
   cap / delay values.

---

## ⚠️ Interface facts to confirm on REAL data BEFORE writing the parser

The CONTRIBUTING non-negotiable — every prior stage was bitten by a real behavior
`--help` didn't reveal (paramspider's missing `-o`, x8's preamble, katana's two
line shapes, the bundler probe's 301-as-JS, ffuf's hyphenated `content-type`). B4's
three unknowns are the archive's two interfaces plus one jsluice behavior:

- **Wayback CDX API query shape.** Confirm against a real query:
  `http://web.archive.org/cdx/search/cdx?url=<host>/*&output=json&fl=original,timestamp,mimetype,statuscode,digest&filter=statuscode:200&filter=mimetype:application/javascript&collapse=digest`.
  Verify: (a) the JSON shape is a list-of-lists whose **first row is a header row**
  (must be skipped); (b) `fl=` field names and order; (c) `matchType`/`url=host/*`
  vs `url=host*` prefix semantics; (d) `filter=` regex syntax and whether mimetype
  filtering alone misses `.js` served as `text/plain` (hence the belt-and-suspenders
  suffix check); (e) `collapse=digest` really deduplicates identical bodies; (f)
  pagination / result caps for a large host (does CDX truncate? need `limit=` /
  `resumeKey`?) — mirror stage 1 certspotter's pagination discipline if so.

- **Raw-snapshot URL form.** Confirm `https://web.archive.org/web/<timestamp>id_/<original>`
  returns the **unmodified original JS body** — no Wayback toolbar, no rewritten
  URLs, no injected `<script>`. Verify `id_` (identity) is the correct modifier and
  compare against `if_`; confirm the un-suffixed replay URL *does* inject wrapping
  (the reason decision 2 fetches `id_`). This is the make-or-break correctness point
  for B4 — a poisoned body yields garbage endpoints/secrets.

- **jsluice over a local file + resolution base.** Confirm jsluice **accepts a local
  file path** as its positional arg (stage 7 only ever passed it remote URLs), and
  confirm that relative URLs in the JS resolve against the arg it was given —
  establishing the need for the `base_url` override (decision 3). If jsluice cannot
  read a local file, fall back to passing it the `id_` wayback URL directly and
  **re-base** resolved `web.archive.org/...` URLs back onto the original host in the
  parser (uglier; prefer the file path).

Real-run discipline unchanged: verify these three → write the parser → mocked
tests → real run → fix → confirming run.

---

## Where it slots in `main.py`

Add `run_archived_js_and_report(patterns, state, scope)` and call it last in
`run_pipeline()`, after `run_stage10_and_report(...)`:

```python
run_stage10_and_report(patterns, state, scope)          # stage 10 (B2)
run_archived_js_and_report(patterns, state, scope)      # NEW — stage 11 (B4)
state.update_run_state(status="stage_complete", passes_completed=1)
```

`run_archived_js_and_report` mirrors `run_stage10_and_report`, but seeds from ALL
in-scope subdomains (decision 5), so it does **not** use `_live_hosts_with_origins`
(which filters on `httpx_status_code`):

```python
def run_archived_js_and_report(patterns, state, scope):
    all_assets = state.load_assets()
    in_scope_hosts = [
        a.value for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
    ]                                                    # decision 5: NOT live-gated
    logger.info("Seeding stage 11 with %d in-scope host(s) (live or not)", len(in_scope_hosts))

    logger.info("--- Stage 11: archived JS mining (wayback CDX + jsluice) ---")
    new_assets, records = run_archived_js_mining(in_scope_hosts, state, current_pass=1, scope=scope)

    run_stage_and_report(11, "archived JS mining", new_assets, patterns, state)
    persist_records(state, records)                      # links endpoint/param/secret → parent asset
```

`persist_records` needs **no change**: it links `endpoint.url`/`parameter.endpoint`
to a parent `url` asset by value and links `secret` via `metadata["source_url"]`,
dropping out-of-scope parents — the same path stage 7 uses. B4 must set
`secret.metadata["source_url"]` to the **original** `.js` URL (a location, safe),
exactly as stage 7 does, so the archived secret links to its parent asset.

---

## The stage module — `stages/stage_archived_js.py`

### Return contract

```python
def run_archived_js_mining(in_scope_hosts: list[str], state: RunState,
                           current_pass: int, scope: dict
                           ) -> tuple[list[Asset], dict[str, list]]:
    """
    Returns (new_assets, records):
      - new_assets: list[Asset] — each endpoint URL jsluice resolves from an
        archived body, as type="url" (so it enters the scope-gated location graph
        exactly like stage 7's jsluice URLs). The archived .js URLs themselves are
        the ORIGINAL target URLs (already url assets from stage 1, or minted here).
      - records: {"endpoints": [...], "parameters": [...], "secrets": [...]} —
        all target_derived=True, each carrying source=wayback provenance metadata.
    Empty in_scope_hosts → ([], {"endpoints": [], "parameters": [], "secrets": []}).
    """
```

### Two-phase per-host loop (R7 fault isolation at BOTH levels)

```python
for host in in_scope_hosts:
    try:
        snapshots = query_cdx_js(host, state, scope)     # phase 1: list .js snapshots
    except Exception:
        logger.exception("stage 11 CDX query failed for %s — skipping host (R7)", host)
        continue
    for snap in snapshots:                                # snap = {original, timestamp, digest}
        try:
            body_path = fetch_snapshot(snap, state)       # phase 2: id_ raw fetch → temp file + R5 raw archive
            url_findings = run_jsluice_urls(body_path, state,
                                            base_url=snap["original"], stage=STAGE)
            raw_secrets  = run_jsluice_secrets(body_path, state,
                                            base_url=snap["original"], stage=STAGE)
        except Exception:
            logger.exception("stage 11 snapshot mine failed for %s — skipping snapshot (R7)",
                             snap.get("original"))
            continue
        ... build Asset + Endpoint + Parameter + Secret records, stamping
            metadata={"source":"wayback","snapshot_timestamp":snap["timestamp"],
                      "archived_url":snap["original"]} ...
```

Fault isolation sits at **both** the per-host CDX call and the per-snapshot fetch,
so one dead snapshot or one host's CDX outage never aborts the stage — finer than
stage 7's per-JS-file guard because B4 has a second failure surface (the fetch).
The whole stage body is additionally wrapped in `run_archived_js_and_report` the
way every stage is.

### Record construction

Identical to `stage7.run_stage7`'s inner loop (endpoints from findings, query/body
params, secrets via `secret_fingerprint` + `raw_log_ref`), with two additions:
- `discovered_by="wayback_jsluice"` (distinguish the producer from live `jsluice`).
- the `source=wayback` provenance metadata block on every record.
`discovered_at_stage=11`, `target_derived=True` throughout.

### Two-tier persistence (R5)

- The **fetched archived body** is archived verbatim per snapshot:
  `raw/stage11_wayback_body_{sanitized(original)}_{timestamp}.js` (suffix by BOTH
  original URL and timestamp — a file can have many captures; nothing overwrites).
- jsluice's raw output lands under `raw/stage11_jsluice_urls_{...}` /
  `stage11_jsluice_secrets_{...}` via the reused runners' `stage=11` arg.
- The CDX response per host: `raw/stage11_cdx_{sanitized(host)}.json`.
- `assets.db` gets only curated records; **no raw body, no raw secret value** ever
  reaches it — the reused D3 secret path guarantees this.

### Module constants

```python
STAGE = 11
CDX_API_URL = "http://web.archive.org/cdx/search/cdx"
SNAPSHOT_URL_FMT = "https://web.archive.org/web/{timestamp}id_/{original}"  # id_ = raw body
MAX_SNAPSHOTS_PER_HOST = 500          # bound a pathological history (archive courtesy)
FETCH_TIMEOUT_SECONDS = 30            # per-snapshot fetch ceiling (web.archive.org is slow)
CDX_TIMEOUT_SECONDS = 60             # per-host CDX query ceiling
INTER_FETCH_DELAY_SECONDS = 0.0      # optional politeness delay toward the archive (Jared call)
```

---

## Dedup vs. live JS (the payoff, and it's automatic)

The Track-D tables already enforce the right behavior via `INSERT OR IGNORE`:

- `endpoints` is `UNIQUE(url, method)`. Stage 7 (live JS) runs **before** stage 11.
  So an endpoint that exists in BOTH live and archived JS is inserted by stage 7
  (live wins, keep-first) and the stage-11 duplicate is silently ignored — correct,
  the live record is the more authoritative one.
- An endpoint that exists **only** in archived JS — i.e. it was *removed* from the
  live app — has no stage-7 row, so stage 11 inserts it fresh, stamped
  `source=wayback`. **This is exactly B4's reason to exist:** the resurrected,
  removed-from-live endpoints surface as new `endpoint` rows a consumer can tell
  apart by provenance.
- `secrets` is `UNIQUE(asset_id, fingerprint)` — a rotated-but-identical string
  dedups; a distinct historical secret is a new row.

No custom dedup code; the constraints do it. The design note that matters:
**stage 11 must run after stage 7** so live findings win the keep-first race
(satisfied by the terminal placement, decision 4).

---

## Rate / archive courtesy (NOT the target rate model)

**No `rate_limits.py` entry** — B4 sends no target traffic (§"passive-toward-the-
target"). The courtesy owed is to `web.archive.org`:

- `MAX_SNAPSHOTS_PER_HOST` + `collapse=digest` bound total fetches.
- Sequential per-snapshot fetches (optionally an `INTER_FETCH_DELAY_SECONDS`) keep
  us a polite client of a free service — the same spirit as certspotter's respect
  for its anonymous budget, but toward the archive, not the target.
- If web.archive.org ever throttles us (429 / slowdowns), that is an
  archive-politeness problem to tune here, **not** a target-protection concern —
  the exact distinction `rate_limits.py` already draws for paramspider.

---

## R-inheritance

- **R1 (scope covers traffic) — trivially satisfied: no target traffic exists.**
  Records are still scope-bounded: `persist_records` drops any endpoint/param/secret
  whose parent `url`/host asset is `out_of_scope`, so an archived off-scope endpoint
  never bloats the tables. B4 seeds only in-scope hosts to begin with.
- **R3 (per-host target rate) — N/A**, no per-host target requests (contrast B1/B2,
  which actively resolve R3).
- **R5 (per-target raw files)** — per-host CDX, per-snapshot body, per-source
  jsluice output, all suffixed (host / original+timestamp) so nothing overwrites.
- **R7 (fault isolation)** — two-level try/except (per-host CDX, per-snapshot mine).
- **R8 (at-rest hygiene)** — archived bodies and raw jsluice secret output land in
  the chmod-700 run dir by construction (RunState owns it); this matters *more* for
  B4 because archived JS is a rich secret source.
- **R9 / untrusted-by-default** — every record `target_derived=1`; the archived body
  is target-authored text; the A1 brief must treat it as delimited data. Secrets
  never store the raw value (reused D3 path).

---

## Boundary — recon discovers, it does not test

B4 **reads a public third-party archive and extracts strings from it.** It does not
send a request to the target, submit input, use a credential, or confirm a
vulnerability. A resurrected `/api/internal/debug` endpoint or a rotated AWS key
fingerprint is a **lead** handed to primitive as a Track-D record — primitive tests
it (and sets `secret.validated`) under its guard; recon never does. Fetching an
archived body is **not** testing the live target — it is the archive-mining side of
recon that gau/waybackurls/paramspider already occupy, extended from URLs to bodies.
The recon/primitive line is exactly where stage 7 draws it; B4 draws it in the same
place over older data.

---

## Verification target (PREREQUISITE — named, like B1/B2's target need)

B4 needs a host with **archived `.js` history in the Wayback Machine** — thin
targets (`zonetransfer.me`) will have little or none. Two-part plan:

- **Interface verification (CDX shape + `id_` raw form + jsluice-over-file):** run
  the real CDX query and a real `id_` fetch against a **high-traffic public domain
  guaranteed to have archived JS** (any large, long-lived site). Reading a public
  archive of any site is a third-party read — the same read paramspider already
  performs — so this confirms the *API shapes* without target traffic. Capture a
  real CDX JSON (header row + tuples), a real `id_` body (confirm no toolbar
  injection), and a real jsluice run over that body.
- **Pipeline verification (end-to-end):** run the full stage against a **consented,
  in-scope target that has archived `.js`** — pick one by first running the CDX
  `.js` query across candidate scopes and choosing whichever returns real
  JavaScript captures. Confirm records land with `source=wayback` provenance, that
  a live-and-archived endpoint dedups to the stage-7 row, and that an archived-only
  endpoint appears fresh.

---

## Tests

**Mocked tier — `testing/test_archived_js.py`** (mirror `test_track_d.py` /
`test_api_discovery.py`):

- Mock CDX JSON (header row + several `.js` tuples, plus a non-`.js` /
  non-`200` row that must be filtered) → assert only `.js` `200` snapshots are
  fetched, header row skipped, `collapse`-style duplicates handled.
- Mock a fetched archived body + a mocked jsluice `urls` JSONL → assert `endpoint`
  + `parameter` records built with `target_derived=1`, `discovered_by=
  "wayback_jsluice"`, and `metadata` carrying `source=wayback` +
  `snapshot_timestamp` + `archived_url`.
- **`base_url` correctness:** a relative URL in the mocked jsluice output resolves
  against the **original** target URL, NOT `web.archive.org` (the central
  correctness trap — assert the host attribution).
- Mock a jsluice `secrets` finding → a `secret` record with a fingerprint +
  `raw_log_ref` pointing at `raw/stage11_...`, and **no raw value** anywhere in the
  record (D3).
- **Dedup:** an archived endpoint equal to a pre-existing (stage-7) `endpoints` row
  is ignored by `INSERT OR IGNORE`; an archived-only endpoint is inserted fresh.
- Per-host + per-snapshot fault isolation (R7): one host's CDX raising, and one
  snapshot's fetch raising, each skip only that unit.
- Per-source raw filenames (R5): `stage11_cdx_{host}.json`,
  `stage11_wayback_body_{original}_{ts}.js`.
- Via `main.persist_records`: an archived endpoint whose parent url asset is
  `out_of_scope` is dropped; an in-scope parent gets `asset_id` linked; a secret
  links via `metadata["source_url"]`.
- Seed is **not** gated on `httpx_status_code` (a dead-but-in-scope host is still
  queried) — the deliberate divergence from B1/B2.

**Real-tool verification (BEFORE the parser, per CONTRIBUTING):** the three
interface facts above (CDX query shape, `id_` raw-body form, jsluice-over-file +
resolution base), then a confirming second run.

**`testing/run_stage11_only.py`** — standalone re-runner importing
`run_archived_js_and_report` from `main.py` (never reimplementing it), for
iterating on a run dir that already has in-scope hosts in `assets.db`.

---

## Doc cascade (flush when built)

- **`STATE_SCHEMA.md`** — `endpoints`/`parameters`/`secrets` now also produced by
  `wayback_jsluice` (stage 11, `target_derived=1`); the `source=wayback` +
  `snapshot_timestamp` + `archived_url` metadata convention; new
  `raw/stage11_cdx_{host}.json` / `stage11_wayback_body_{...}.js` /
  `stage11_jsluice_*_{...}` raw files.
- **`README.md`** — stage 11 in the pipeline flow + state-file table; note the
  archive-source (no target traffic), the not-live-gated seed, and the
  runs-after-stage-7-so-live-wins dedup property.
- **`pipeline_schematic.mermaid`** — an archived-JS node feeding
  endpoints/parameters/secrets, drawn off the archive, not the target.
- **`stage7_js_extraction.py`** — note the backward-compatible `base_url` / `stage`
  params added to `run_jsluice_urls` / `run_jsluice_secrets` for B4 reuse.
- **`CONTRIBUTING.md`** — reaffirm verify-real-tool (CDX + `id_` form) for the new
  archive-mining stage; add wayback CDX / `id_` snapshot to the verified-vs-
  UNVERIFIED tool ledger.
- **`CHANGELOG.md`** — DESIGN → BUILT entry.
- **`RECON_ENHANCEMENTS.md`** — flip **B4** from roadmap to BUILT; update the
  Phase-2 row.
- **`RECON_AGENT_DESIGN.md`** — fold stage 11 into the stage inventory (with the
  Track-D + stage-6.5 + stage-10 fold already owed).

---

## Explicitly OUT of scope for B4 v1 (so the building agent doesn't over-reach)

- **Live secret validation** — recon never sends a secret to its provider; archived
  secrets are `validated=None`, set downstream by primitive (E4 / D3 rule). B4
  merely resurrects and fingerprints them.
- **Non-JS archived bodies** — B4 mines `.js` only. Archived HTML/JSON/source maps
  are a plausible follow-up, not this pass (named residual).
- **`.map` / source-map reconstruction** — recovering original source from archived
  sourcemaps is a distinct capability; out of scope.
- **Secret classification by provider (E4)** — B4 stores `kind` as jsluice reports
  it (reused runner); trufflehog-style offline provider labeling is E4's job.
- **Other archive sources** — v1 is the Wayback Machine (CDX) only; commoncrawl /
  OTX / urlscan archives are opportunistic future breadth, not this pass.
- **Target-derived wordlists / active fetching of the *live* body** — B4 fetches
  from the archive, never the target; if a `.js` no longer exists live, that is a
  feature (removed endpoints), not a gap to fill by hitting the host.
- **A `rate_limits.py` entry** — B4 sends no target traffic; archive courtesy is a
  self-imposed cap in the module, not a target rate translation.

---

## See also

- `RECON_B1_CONTENT_DISCOVERY_DESIGN.md` / `RECON_B2_API_SCHEMA_DISCOVERY_DESIGN.md`
  — the sibling Track-B stages; reuse their seed / per-host-loop / raw / record
  patterns (B4 diverges only on: no target traffic, not-live-gated seed).
- `stage7_js_extraction.py` — the live-JS extraction B4 reuses verbatim
  (`run_jsluice_urls` / `run_jsluice_secrets`, `secret_fingerprint`, the record
  construction) over archived bodies.
- `stage1_passive.py` / `stage5_hidden_params.py` — the existing archive-querying
  precedent (gau/waybackurls/paramspider hit wayback, no target rate limit).
- `RECON_TRACK_D_DESIGN.md` — the `endpoint`/`parameter`/`secret` tables B4 fills.
- `rate_limits.py` (paramspider/jsluice "no change needed" note) — why an
  archive-querying tool takes no target-facing rate limit.
- `RECON_ENHANCEMENTS.md` — B4 sketch + Track-B sequencing + the boundary/safety
  notes this inherits.
- `PRIMITIVE_AGENT_DESIGN.md` §10 — `source_sink_map`, the consumer of these
  records; primitive sets `secret.validated`, never recon.
- `CONTRIBUTING.md` — verify-real-tool-before-parser discipline B4 follows.
