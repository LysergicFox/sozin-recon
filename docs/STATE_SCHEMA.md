# State file schema reference

Every pipeline run is a directory on disk. This is the authoritative,
quick-lookup reference for what's in it — pulled directly from `state.py`.
If `state.py` changes, this file is out of sync until updated by hand.

```
run_directory/
├── scope.json
├── assets.db
├── needs_review.json
├── run_state.json
├── target_profile.json / target_profile.md      # F6 digest
├── target_derived_paths.txt / _params.txt        # E3 wordlists
├── diff.json                                      # E2 (written by run_diff.py)
├── screenshots/screenshot/<host>/<hash>.png       # C2 (R8 sensitive-at-rest)
└── raw/
    └── stageN_toolname.json
```

> **Recon enhancement roadmap: Tracks C/D/E built + most of A/B/F, 2026-08-23.**
> `assets.db` gains a general **`recon_findings`** POI table (C1 nuclei detection + C5
> CVE candidates) and a layer of **enrichment metadata** on assets (E1 httpx fields, C3
> WAF/CDN, C2 screenshot path, C4 auth model, A2 interest score, F1 clusters). All are
> documented in "recon_findings" and "Asset enrichment metadata" below.

> **Recon design review (R1–R16): schema-affecting fixes CODED 2026-08-23.**
> `rate_limit` required-affirmative + `scope` (R2/R4), canonicalized `(type,value)`
> (R6), reachable `error` status (R7), per-target raw filenames (R5),
> target-derived metadata registry (R9), run-dir hygiene (R8) — all implemented,
> marked **(R#, implemented)** inline below.

> **Track D (source records): BUILT 2026-08-23.** `assets.db` now also holds four
> first-class source-record tables — `parameters`, `endpoints`, `secrets`,
> `services` — facts *about* a location, FK-linked to their parent asset. See the
> "Track D source-record tables" section below. Settles R13 (locations vs records).

---

## `scope.json`

Input allowlist. **Read-only** from the recon agent's point of view.

```jsonc
{
  "verified_by_human": true,          // gates run start — see state.py load_scope()
  "in_scope": {
    "domains": ["*.example.com"],     // wildcard or bare; extract_root_domains() strips "*."
    "ip_ranges": ["203.0.113.0/24"]
  },
  "rate_limit": {                     // (R2) REQUIRED — use "not_applicable" for the default
    "stated_by_program": true,
    "requests_per_second": 5,
    "scope": "per_host",              // (R4) "per_host" (default) | "global"
    "source_text": "please limit automated scanning to 5 req/s",
    "extracted_by": "human",          // "llm_flag" | "human" | null
    "resolution": "confirmed",        // "confirmed" | "pending" | "not_applicable"
    "resolved_by": null
  }
}
```

**Gates at run start (`main.py`), both fail loud (raise):**
- `verified_by_human` must be `true`, or `RunState.load_scope()` raises.
- `rate_limit.resolution` must not be `"pending"`, or `check_run_not_blocked()` raises.
- **(R2, implemented)** an **absent `rate_limit` block blocks the run** — set
  `resolution: "not_applicable"` explicitly for the conservative default.
- **(R4, implemented) `rate_limit.scope`** — `per_host` (default) is scaled by host
  count; `global` is passed through unscaled. Unresolved reading → `"pending"`.

---

## `assets.db` (SQLite)

The living asset graph (the scope-gated *location* layer) plus the Track-D
source-record tables and `takeover_findings`.

**Table: `assets`** — locations: `subdomain` / `url` / `ip` (`js_file` reserved,
unused).

| Column | Type | Notes |
|---|---|---|
| `asset_id` | TEXT PK | UUID |
| `value` | TEXT | domain/url/ip string; **(R6) canonicalized at ingestion** |
| `type` | TEXT | `subdomain` \| `url` \| `ip` \| `js_file` |
| `discovered_by` | TEXT (JSON array) | every contributing tool, e.g. `["assetfinder","amass"]` |
| `discovered_at_stage` / `discovered_in_pass` | INTEGER | |
| `scope_status` | TEXT | `in_scope` \| `needs_review` \| `out_of_scope` |
| `scope_decision_by` | TEXT, nullable | `deterministic` \| `llm_flag` \| `human` |
| `parent_asset_id` | TEXT, nullable | |
| `metadata` | TEXT (JSON) | per-tool enrichment; some keys **target-derived / untrusted (R9)** |

`UNIQUE(type, value)` — de-dupe key. **(R6, implemented)** `value` is canonicalized
at ingestion (lowercase scheme+host, strip default ports, drop fragments, lowercase
subdomains; path+query untouched). **(R9, implemented)**
`state.TARGET_DERIVED_METADATA_KEYS` names attacker-authored metadata keys
(whatweb_tech, whatweb_redirect_chain, katana_headers, katana_error,
jsluice_secrets [legacy], httpx_title, httpx_tls_san). `discovered_by` is a JSON
array (unioned on merge). `add_assets()` merges metadata+discovered_by on duplicate
rows; **stale metadata keys never clear** (flagged).

**Table: `takeover_findings`** — one row per nuclei takeover match, FK →
`assets.asset_id`, no UNIQUE (history wanted across passes). ⚠️ parser UNVERIFIED
against a real positive finding.

---

## Track D source-record tables

Facts *about* a location, not locations. FK-linked to a parent asset; **they inherit
their parent asset's scope** (a param on an in-scope url is in-scope by construction)
— `main.persist_records()` sets `asset_id` and DROPS records whose parent is
out_of_scope. All four carry a per-row **`target_derived`** provenance flag (is the
*value* target-authored?) — x8/naabu/ffuf = 0, jsluice/openapi/graphql/wayback_jsluice = 1 — plus `discovered_by`,
`discovered_at_stage`, `discovered_in_pass`, `metadata` (JSON), and `asset_id`
(nullable FK). Source records are **not** counted toward the (future)
loop-until-stable stability sum. `add_*`/`load_*` on `RunState`; INSERT OR IGNORE
dedup on the UNIQUE key.

- **`parameters`** (D1) — `name`, `host`, `endpoint`, `method`, `location`
  (`query`|`body`|`path`|`header`), `reflected` (INTEGER/NULL — 1 only when x8
  confirmed it changes the response, NULL when merely observed), `inferred_type`.
  `UNIQUE(host, endpoint, name, method, location)`. Producers: x8 (stage 5,
  target_derived 0, reflected 1), jsluice (stage 7, B3 query/body params,
  target_derived 1, reflected NULL), **openapi/graphql (stage 10, B2,
  target_derived 1 — spec parameters / GraphQL field args, reflected NULL)**, and
  **wayback_jsluice (stage 11, B4 — query/body params from archived JS,
  target_derived 1, reflected NULL, `source=wayback` provenance metadata)**.
- **`endpoints`** (D2) — `url`, `host`, `path`, `method`, `auth_status`
  (nullable, C4 later), `content_type` (nullable). `UNIQUE(url, method)`.
  **Now heavily populated by Track B:** ffuf (stage 6.5, B1, target_derived 0 —
  path from our wordlist; metadata `ffuf_status`/`ffuf_length`/`ffuf_content_type`,
  `server_error=True` on 5xx; `auth_status="gated"` on 401/403); openapi (stage 10,
  B2a, target_derived 1, `auth_status` from the spec's `security`); graphql (stage 10,
  B2b, target_derived 1 — one endpoint per GraphQL endpoint, POST, metadata carries
  the `graphql_queries`/`graphql_mutations`→args catalog); **wayback_jsluice (stage 11,
  B4, target_derived 1 — endpoints resurrected from archived `.js`; metadata carries
  `source=wayback` + `snapshot_timestamp` + `archived_url`; runs after stage 7 so a
  live+archived endpoint keeps the stage-7 row, an archived-only one surfaces fresh)**.
  Also jsluice (stage 7).
- **`secrets`** (D3) — `kind`, `provider` (nullable, E4 later), `fingerprint`
  (capped `first4…last4|len=N|sha256=<16hex>` — **the raw value NEVER enters
  assets.db**), `raw_log_ref` (pointer to the per-source raw archive), `severity`
  (nullable), `validated` (nullable — **set downstream, never by recon**).
  `UNIQUE(asset_id, fingerprint)`. `target_derived` always 1. Producers: jsluice
  (stage 7) and **wayback_jsluice (stage 11, B4 — secrets from archived `.js`, `source=wayback`
  metadata; `metadata["source_url"]` = the archived `.js` URL, the parent-link)**. The raw
  finding lives only in the chmod-700 raw archive.
- **`services`** (D4) — `target` (the ip-or-host naabu reported), `host` / `ip`
  (nullable), `port`, `proto` (tcp default). `UNIQUE(target, port, proto)`.
  Producer: naabu (stage 4), built in `main`. Makes R12's non-standard open ports
  probeable records instead of dead-end metadata.

---

## `recon_findings` (C1 + C5) — general POI / lead table

A general findings table (cousin of `takeover_findings`) for promotable recon *leads*,
with a status lifecycle. `add_recon_findings()` / `load_recon_findings()`; INSERT OR
IGNORE dedup on **`UNIQUE(host, template_id, matched_at)`**.

- Columns: `finding_id` (PK), `asset_id` (FK, nullable), `host`, `source`
  (`"nuclei"` = C1 detection | `"cve-candidate"` = C5), `template_id`, `template_name`,
  `category`, `severity`, `matched_at`, `status`
  (`new`|`triaged`|`promoted`|`dismissed`, default `new`), `target_derived` (1 —
  matched_at/evidence is target-authored), `raw_finding` (JSON — for C1, TRIMMED of
  nuclei's request/response/curl-command; for C5, cvss/cpe_version/evidence + a "not a
  confirmed vuln" note), `discovered_at_stage`/`discovered_in_pass`/`discovered_at`.
- **C1** (stage 8): detection-only nuclei (`exposures`/`misconfiguration`/`exposed-panels`;
  excludes default-logins/intrusive). **C5** (offline, post-stage-9): exact-version tech→CVE
  candidates from the nuclei-template CPE index — **unconfirmed leads**, never vuln claims.

## Asset enrichment metadata (roadmap items)

Beyond the R9 target-derived registry, the enhancement stages write these metadata keys
onto assets (all agent-authored/**trusted** unless noted):

- **E1 (stage 4, host):** `httpx_favicon_hash`/`httpx_favicon_url`, `httpx_asn`,
  `httpx_cdn`/`httpx_cdn_name`/`httpx_cdn_type`, `httpx_jarm`; `httpx_body_preview`
  (**target-derived** — in `TARGET_DERIVED_METADATA_KEYS`).
- **C3 (stage 4.5, host):** `is_behind_waf`, `waf_vendor`, `waf_name`, `is_cdn`,
  `cdn_name`, `cloud_name`.
- **B1 (stage 6.5):** on host — `waf_suspected`/`waf_signal`/`waf_block_ratio`; on url
  asset + endpoint — `ffuf_status`/`ffuf_length`/`ffuf_content_type`, `server_error` (5xx flag).
- **C2 (host):** `screenshot_path` (relative to run dir).
- **C4 (endpoint):** `auth_status` ∈ `public`/`gated`/`auth_surface`/NULL (+ `auth_classified_by="c4"`);
  on host — `auth_model` (per-host summary).
- **A2 (url + host):** `interest_score` (int) + `interest_signals` (explainable breakdown).
- **F1 (url):** `url_cluster` (template), `cluster_size`, `cluster_representative`.
- **E4 (secrets):** fills `kind`/`provider` offline (never `validated` — that's set downstream, not by recon).
- **B2 (stage 10, url asset + endpoint):** `openapi_spec`/`openapi_method`; GraphQL endpoint
  metadata `graphql`, `graphql_queries`/`graphql_mutations` (operation→args catalog).

---

## `needs_review.json`

Queue of assets the scope gate couldn't confidently classify. Fed by
`apply_scope_gate()`; **(R10, implemented)** insertion deduped by canonical (R6)
value, within batch and against the existing queue. All ambiguous results land here
until the LLM tier exists.

---

## `run_state.json`

```jsonc
{
  "run_id": "…",
  "current_stage": 11,
  "current_pass": 3,                 // advances with each loop pass (loop-until-stable)
  "status": "stable",                // "running" | "paused_needs_review" | "stage_complete" | "stable" | "error"
  "passes_completed": 3,             // number of loop passes actually run
  "pass_deltas": [                   // per-pass stability trail (loop-until-stable) — the exit reason, auditable
    { "pass": 1, "delta": 80 },      // delta = genuinely-new ASSETS that pass (records excluded)
    { "pass": 2, "delta": 7 },
    { "pass": 3, "delta": 0 }        // delta==0 → converged → status "stable"
  ],
  "last_updated": "…",
  "failed_at_stage": null            // (R7) set alongside status="error" on an unhandled crash
}
```

**(R7, implemented)** `main()` wraps the pipeline so an unhandled exception sets
`status="error"` + `failed_at_stage` before re-raising. Paired with per-tool fault
isolation across stages 3/4/6/8/9.

**Loop-until-stable (R14, implemented).** The pipeline runs PRE-LOOP {1} once →
LOOP {3,4,F5,5,6,6.5,7} repeated until the convergence guard fires → FINALIZE
{4.5,8,9,10,11,+offline finalizers} once. `current_pass`/`passes_completed`
advance with the loop; `pass_deltas` records each pass's new-asset count.
Termination: `delta == 0` → `"stable"` (a true fixed point — now reachable);
else the hard pass cap (`run_options.max_passes`, default 4) or the
diminishing-returns floor (`max(3, 2% × graph)`) → `"stage_complete"`. `delta`
counts genuinely-new ASSETS only (Track-D records don't create new seeds). See
`RECON_LOOP_DESIGN.md`.

---

## `raw/stageN_toolname.json`

One file per tool invocation, verbatim. **(R5, implemented)** per-target suffix on
multi-target loops: stage 1 (`stage1_subfinder_{domain}`), stage 3
(`stage3_puredns_bruteforce_{domain}`), stage 7 jsluice
(`stage7_jsluice_urls_{source}`, `stage7_jsluice_secrets_{source}` — Track D added
this so `secret.raw_log_ref` points at a stable per-source file), certspotter per
page (R11), stage 9 per host, **stage 6.5 ffuf (`stage6.5_ffuf_{host}` — B1, note the
fractional stage in the filename)**, **stage 10 (`stage10_openapi_{host}`,
`stage10_graphql_{host}` — B2)**, **stage 11 (`stage11_cdx_{host}` per-host CDX response;
`stage11_wayback_body_{sanitized_original}_{ts}.js` the fetched archived body — note the
`.js` extension, not `.json`; `stage11_jsluice_urls_{original}` / `stage11_jsluice_secrets_{original}`
— B4)**, **stage 4.5 (`stage4.5_cdncheck` — C3)**, **stage 4 (`stage4_dnsx_ptr` — F5)**, and
**stage 8 (`stage8_nuclei_detection` — C1, separate from `stage8_nuclei_takeover`)**.

**(loop-until-stable, D6)** On a multi-pass run, a stage that re-runs on a later
pass would otherwise overwrite its own pass-1 raw archive (which
`secret.raw_log_ref` points at). So **pass 1 keeps the historical filename
byte-for-byte** (e.g. `raw/stage5_x8_{tag}.json`) and **pass ≥ 2 appends `__p{N}`**
(`raw/stage5_x8_{tag}__p2.json`, `raw/stage6.5_ffuf_{host}__p3.json`). Pass-1
layout is unchanged, so existing consumers are unaffected; each pass's raw output
is preserved.

Host assets (`subdomain`) also gain agent-authored, **trusted** metadata keys from
these stages: `waf_suspected`/`waf_signal`/`waf_block_ratio` (B1 — NOT in
`TARGET_DERIVED_METADATA_KEYS`).

---

## Run directory hygiene — applies to RECON now (R8)

**(R8, implemented 2026-08-23)** `RunState.__init__` chmods the run dir `0700` on
every open; `.gitignore` keeps run dirs out of the repo. Sensitive-at-rest today
(stage 7 secrets, and now the `secrets` table's `raw_log_ref` targets). At-rest
encryption stays deferred (preserves `sqlite3`/`cat` inspectability).

---

## Recon agent — planned additions (roadmap)

Track D (D1–D4, above) is **BUILT**. Still planned (`RECON_ENHANCEMENTS.md`):

- **`recon_findings` / POI table (C1)** — general detection leads (detection-only
  nuclei).
- **`recon_summary` artifact (A1)** — curated attack-surface brief from the
  (unbuilt) final review pass.
- `endpoint` heavy population from content/API discovery (Track B); `secret`
  `provider` from the offline classifier (E4); `service`-seeded probing (R12).

---

## Schema change checklist

If you change any shape above in `state.py`, update in the same sitting:
1. This file.
2. `README.md`'s state-file table.
