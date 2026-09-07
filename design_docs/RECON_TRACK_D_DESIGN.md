# Track D — first-class source data model (design-lock)

**Status: IMPLEMENTED + VERIFIED 2026-08-23** (design locked the same day, then
built in the same sitting). Realizes Track D of `RECON_ENHANCEMENTS.md` (Phase 1).
Promotes the units the hunting agents consume from ad-hoc `assets.db` metadata
keys into first-class, queryable **sibling tables**, making the recon→primitive
`source_sink_map` seam literal. Also settles R13 (what is an Asset vs a finding vs
a source record).

**Build outcome (2026-08-23).** All four tables + producers landed; mocked suite
`testing/test_track_d.py` (9 tests) green; real `zonetransfer.me` run populated
`services` = 5 (incl. non-standard ports 81/4000/8080, all FK-linked to the host
asset), confirming D4/R12; `parameters`/`endpoints`/`secrets` = 0 on that target
(no in-scope JS, no x8 hits — expected, not a defect). `secret_fingerprint`
verified irreversible and never storing the raw value. Doc cascade flushed
2026-08-23 (STATE_SCHEMA, README, CHANGELOG, CONTRIBUTING, R13 resolution).

## Locked decisions (Jared calls, 2026-08-23)

1. **Sibling tables**, not new `AssetType`s. `assets` stays the scope-gated
   location graph (subdomain/url/ip); source records get their own tables, FK to a
   parent asset — same shape as `takeover_findings`.
2. **Model + rewire existing producers** this pass: x8 + jsluice params →
   `parameter`; jsluice secrets → `secret`; naabu ports → `service`; jsluice
   endpoints (with method) → `endpoint`. `endpoint` table is defined but only
   lightly populated (heavy population waits for Track B content/API discovery).
3. **Secrets stored as fingerprint + ref** — never the raw value in `assets.db`.
4. **Forward-only** — new runs populate records; legacy metadata keys stay
   readable; no backfill migration (lazy posture, matching R6/discovered_by).

## R13 settled

- **Assets** = *locations* in the scope graph: `subdomain`, `url`, `ip`. Scope-
  gated, deduped on canonical `(type,value)`.
- **Source records** = *facts about* a location: parameter/endpoint/secret/
  service. Not independently scope-gated — they inherit their parent asset's
  scope (a param on an in-scope url is in-scope by construction). Not gate-entered.
- `js_file` stays a **reserved, unused** AssetType (JS files are `url` assets;
  their secrets/endpoints become records). No producer emits it; keep-and-reserve
  per the R13 resolution.

## Schema (new sibling tables in `state.py` / `assets.db`)

Common columns on all four: `*_id` TEXT PK (uuid), `asset_id` TEXT nullable (FK →
`assets.asset_id`, the parent location), `discovered_by` TEXT, `target_derived`
INTEGER (0/1 — is the *value* target-authored?), `discovered_at_stage` INT,
`discovered_in_pass` INT, `metadata` TEXT JSON. Provenance for sibling tables is
this per-row `target_derived` flag (the R9 keyed registry stays for `assets.db`
metadata); `STATE_SCHEMA.md` documents which producers set it.

- **`parameters`** — `name`, `host`, `endpoint` (url where observed), `method`,
  `location` (`query`|`body`|`path`|`header`), `reflected` (nullable bool — True
  when x8 confirmed it changes the response, null when merely observed).
  `UNIQUE(host, endpoint, name, method, location)`.
- **`endpoints`** — `url` (canonical), `host`, `path`, `method`, `auth_status`
  (nullable — public|gated, filled by C4 later), `content_type` (nullable).
  `UNIQUE(url, method)`.
- **`secrets`** — `kind` (jsluice kind now; E4 provider later), `provider`
  (nullable), `fingerprint` (capped: `first4…last4|len=N|sha256=<16hex>` of the
  value — **never the raw value**), `raw_log_ref` (pointer to the per-source raw
  archive holding the full finding), `severity` (nullable), `validated` (nullable
  — **set downstream by primitive, never recon**). `UNIQUE(asset_id, fingerprint)`.
  `target_derived` always 1.
- **`services`** — `target` (the ip-or-host string naabu reported), `host`
  (nullable), `ip` (nullable), `port` INT, `proto` (tcp default). `UNIQUE(target,
  port, proto)`. `target_derived` 0 (port facts are tool-derived).

`RunState` gains `add_parameters/add_endpoints/add_secrets/add_services` (INSERT
OR IGNORE on the UNIQUE key, return genuinely-new) + `load_*` for each, mirroring
`add_assets`/`add_takeover_findings`. A `secret_fingerprint(value)` helper does
the capping. Source records are **not** counted toward the (future) loop-until-
stable stability sum — they're enrichment, not new locations.

## Producer rewiring (forward-only)

- **stage 4 (naabu) → `service` records.** `main` builds Service rows from the
  naabu ports it already applies (host `metadata_updates` + new ip assets), FK to
  the host/ip asset. `naabu_open_ports` host metadata is **kept** as a convenience
  summary (nothing to lose; the R7 test relies on it). Makes R12's non-standard
  ports probeable records.
- **stage 5 (x8) → `parameter` records.** `run_stage5` returns x8 params as
  Parameter rows (`method=GET`, `location=query`, `reflected=True`,
  `discovered_by=x8`, `target_derived=0` — names come from our SecLists wordlist).
  The `x8_reflected_params` metadata key is **dropped** (records supersede it;
  nothing consumes the key today).
- **stage 7 (jsluice) → `parameter` + `endpoint` + `secret` records (B3 rides
  along).** `run_jsluice_urls` stops discarding data — returns
  `{url, method, queryParams, bodyParams}` per finding. `run_stage7` then emits:
  the resolved `url` asset (unchanged, keeps the scope-gated location graph); an
  `endpoint` record (url+method, `target_derived=1`); `parameter` records for each
  query/body param (`target_derived=1`, `reflected=null`); and `secret` records
  from `run_jsluice_secrets` (fingerprint+ref, full finding stays in raw).
  `jsluice_secrets` metadata key **dropped**.
  - **Sub-fix (R5-style, required for `raw_log_ref`):** stage 7's jsluice raw
    archives are currently fixed filenames (`jsluice_urls`/`jsluice_secrets`),
    overwritten per JS file. Suffix them per sanitized source URL so each file's
    raw survives and `raw_log_ref` points at a stable location.
- **`main` persists records.** A small `persist_records(state, records)` helper
  dispatches to the `add_*` methods; called from `run_stage5_and_report`,
  `run_stage7_and_report`, and the stage-4 block. `main` sets `asset_id` by
  looking up the parent asset value after `add_assets` (nullable if unmatched).
  Stage return contracts gain a third element `records: dict[str,list]`
  (`{"parameters":[...], ...}`); the `run_stage*_only.py` scripts are unaffected
  (they call the `_and_report` wrappers in `main`).

## Boundary / safety

- Recon **discovers/enriches** only: `endpoint` `auth_status` and `parameter`
  `reflected` are observations; `secret.validated` is **primitive's** to set.
  Recon never sends a secret anywhere.
- New record values are untrusted-by-default: jsluice-derived names/paths/secrets
  carry `target_derived=1`; the A1 brief (future) treats them as delimited data.
- Secrets never hit `assets.db` in the clear (fingerprint+ref); full value lives
  only in the chmod-700 raw archive (R8).

## Tests (mocked tier) — all green 2026-08-23

- `RunState` add/load/dedup for each table; `secret_fingerprint` caps and is
  irreversible; **a `secrets` row never contains the raw value**.
- stage 5: x8 → Parameter rows (`target_derived=0`, reflected=True).
- stage 7: jsluice urls → endpoint + query/body parameter rows (`target_derived=1`);
  jsluice secrets → secret rows (fingerprint set, raw value absent); per-source raw
  filename suffix.
- stage 4 / main: naabu ports → service rows FK'd to host/ip assets.
- Real run (`zonetransfer.me`): services=5 populated incl. non-standard ports; a
  confirming second run.

## Doc cascade — FLUSHED 2026-08-23

`STATE_SCHEMA.md` (four new tables + `target_derived` provenance note),
`README.md` (pipeline-flow + state-file table), `CHANGELOG.md` (compact entry),
`CONTRIBUTING.md` (source-record discipline), `RECON_DESIGN_REVIEW_RESOLUTIONS.md`
(R13 → settled-by-Track-D). Still to fold (larger edit, deferred):
`RECON_AGENT_DESIGN.md`; `pipeline_schematic.mermaid` nodes (low priority).

## See also
`RECON_ENHANCEMENTS.md` (Track D sketch + sequencing), `STATE_SCHEMA.md`
(planned-additions section this replaces), `PRIMITIVE_AGENT_DESIGN.md` §10
(`source_sink_map`, the consumer).
