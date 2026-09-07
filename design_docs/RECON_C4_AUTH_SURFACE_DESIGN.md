# C4 — auth-surface classification (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN-LOCKED, NOT BUILT.** Realizes **C4** of `RECON_ENHANCEMENTS.md`
(Phase 3, Track C — "signal quality & prioritization"). Recon already captures
status codes but never labels **public vs auth-gated** endpoints or identifies
**login/register/OAuth/SSO** surfaces. C4 closes that gap. It is **mostly free —
the data is already on disk** (the `endpoints` table, `url` assets, and per-host
httpx/katana metadata); C4 just reads it and writes labels back.

This doc is written to the same discipline every prior item followed
(`CONTRIBUTING.md`): design-locked before code, fail-closed, provenance-aware,
and — the one twist that makes C4 different from B1/B2 — **it sends no traffic**,
so the "verify the real tool before the parser" rule is replaced by "verify
against real *collected* data before trusting the heuristic." Nothing here is
coded yet.

---

## The one architectural decision that shapes everything: post-processing, not a stage

**C4 is a deterministic post-processing enrichment pass, NOT a new active stage.**
This is the central locked decision and it is different from B1/B2 (both of which
are traffic-sending stages that inherit the full R1–R16 review).

Why post-processing:

- **The data is already on disk.** Every signal C4 needs was collected by earlier
  stages: `endpoints.auth_status` (B1/B2 already set `"gated"` on 401/403 and on
  spec `security`), `endpoints.path` + `endpoints.metadata.ffuf_status`, the
  parent `url` assets, and per-host metadata (`httpx_status_code`,
  `httpx_final_url`, `httpx_chain_status_codes`, `katana_status_code`,
  `katana_headers`). C4 issues **zero new requests**.
- **No traffic ⇒ no R1/R3/R5/R7-tool-isolation surface.** C4 mints no `url`
  assets, so it needs no scope gate; it calls no external tool, so it needs no
  rate translation, no per-target raw file, no per-host tool try/except. Framing
  it as an "active stage" would drag in machinery it structurally cannot use and
  would misrepresent its risk profile (it has none — it reads and labels).
- **It is enrichment of existing records, not discovery.** C4 updates the
  `auth_status` column on rows that already exist and writes a per-host
  `auth_model` summary. `discovered_at_stage` / `target_derived` / the scope gate
  are all discovery concepts that do not apply to a classifier.

So C4 is implemented as `run_auth_classification_and_report(state)`, called **last
in `run_pipeline()` after stage 10**, exactly where `_apply_waf_flags` and the
stage-4 service promotion already sit — a thin main-side applier over a **pure,
trivially-testable classification function**. It is tagged **stage 11 in
`run_state.current_stage` for ordering/bookkeeping only**, and documented as a
**no-traffic enrichment pass**, not an active stage.

> **Jared call #1 — the stage tag.** Recommended: tag it `current_stage = 11`
> purely so `run_state` reflects that the enrichment ran, while the docs make
> clear it sends no traffic. *Alternative:* leave `current_stage` at 10 and treat
> C4 as an unnumbered finalizer (like the stage-4 service promotion, which has no
> stage number of its own). Recommendation: give it 11 for observability; it costs
> nothing and a loop-until-stable (R14) run wants a marker that enrichment
> completed. Do **not** use a fractional stage — there is no same-pass consumer
> forcing one (contrast B1's 6.5).

---

## Provenance distinction that drives the design

C4 **creates no records** and therefore sets **no `target_derived` flag** — every
endpoint it labels keeps whatever provenance its producer set (ffuf `td=0`,
jsluice/openapi/graphql `td=1`). What C4 writes is an **agent-authored
classification**: the keyword list and the precedence rules are *ours*, exactly
like B1's wordlist is ours. Two consequences, both locked:

1. **The label is agent-authored even when the path is target-authored.** A
   keyword match on an OpenAPI-derived `/oauth/authorize` (path is `td=1`) still
   yields an *agent-authored* `"auth_surface"` label. To keep this legible
   downstream, every C4-written label carries `metadata.auth_classified_by =
   "c4"` so A2/A1 can distinguish a recon heuristic lead from B1/B2's
   response-confirmed `"gated"`.
2. **Confidence is not uniform, and C4 records which kind it is.** A `"gated"`
   from a real 401/403 is a **confirmed** gate (the target's own response). An
   `"auth_surface"` from a path keyword is a **heuristic lead** (a path *called*
   `/login` is not proof of a login). C4 never conflates the two — see the
   precedence rules — and the `auth_classified_by`/`auth_keyword` metadata makes
   the basis auditable.

The host-level `auth_model` summary C4 writes is an **agent-authored
determination** (trusted metadata, **not** added to
`TARGET_DERIVED_METADATA_KEYS`). ⚠️ *Nuance, named:* the summary embeds path
strings whose provenance follows their source endpoint (a `td=1` openapi path
stays untrusted content). Downstream A1 already treats endpoint values by their
per-record flag; the `auth_model` render must therefore treat embedded paths as
**delimited data**, not instructions — the same rule B2 output carries.

---

## The `auth_status` vocabulary (locked, additive, non-destructive)

Today `auth_status ∈ {NULL, "gated"}`. C4 extends it to a small controlled set,
and **must reconcile with B1/B2, which already write `"gated"` — C4 builds ON that
signal, it does not fight it.**

| value | meaning | who sets it | confidence |
|---|---|---|---|
| `"gated"` | 401/403 response, or spec `security` requirement | **B1/B2 (existing)**, C4 never overwrites | **confirmed** (target's response) |
| `"public"` | reachable without auth **and** not itself an auth surface | C4 | inferred from a positive-reachability signal |
| `"auth_surface"` | the endpoint **is** an authentication entry point (login/register/oauth/sso/…) | C4 | **heuristic lead** (path keyword) |
| `NULL` | no confident signal — unclassified | default | — (fail-closed) |

**Locked precedence (C4 fills only where it has a basis; fail-closed otherwise):**

1. **Existing `"gated"` is never downgraded.** If a row already reads `"gated"`
   (B1/B2 wrote it), C4 **keeps `"gated"`** and, if the path *also* matches an
   auth keyword (e.g. `/oauth/token` that returned 401), records
   `metadata.auth_surface_hint = True` + `auth_keyword` — preserving *both* facts
   without clobbering the confirmed gate.
2. **Else, auth-surface keyword match → `"auth_surface"`.** Keyword beats
   "public" deliberately: `/login` normally returns 200 and is publicly
   reachable, but it is *where auth happens*, which is the more useful label.
3. **Else, a positive-reachability signal → `"public"`.** Signals: an endpoint
   `ffuf_status` in 2xx, or OpenAPI `security == []` (explicitly public), or a
   host/endpoint 2xx in captured metadata.
4. **Else → leave `NULL`.** No guessing "public" without evidence — a 5xx, a
   `server_error` flag, or a bare row with no status stays `NULL`. This is the
   `CONTRIBUTING.md` fail-closed rule applied to a classifier.

> **Jared call #2 — vocabulary names.** Recommended `public` / `gated` /
> `auth_surface`. These are strings in a nullable TEXT column (no migration; the
> column and its `NULL`/`"gated"` values already exist). If you prefer
> `login_surface` or splitting `auth_surface` into `login` vs `oidc_metadata`,
> say so before build — it only changes a constant.

---

## Signals — in-scope v1 vs deferred (all v1 signals already on disk)

**In-scope v1** (zero new requests — read from existing state):

- **Status codes already captured.** The existing `"gated"` (B1/B2), each
  endpoint's `ffuf_status` / `openapi security`, and per-host `httpx_status_code`
  / `httpx_chain_status_codes`. These drive rules 1, 3, 4 above.
- **Path / keyword heuristics for auth surfaces** — the make-or-break piece.
  Match `endpoint.path` (case-insensitive, **word-boundary / segment-aware**)
  against a curated constant:
  `/login /signin /sign-in /log-in /register /signup /sign-up /auth /authorize
  /oauth /oauth2 /sso /saml /session /logout /signout /token /connect/authorize
  /idp /adfs /.well-known/openid-configuration /.well-known/oauth-authorization-server`.
  **⚠️ The central correctness trap (mirrors B2's SPA-catch-all warning):** a
  naive substring match labels `/authors`, `/registered-users`, `/tokenizer` as
  auth surfaces. v1 **must** match on path *segments* / word boundaries
  (`/auth` matches `…/auth` and `…/auth/…`, never `/authors`). This is the one
  place a real-data pass will bite — verify it against the Juice Shop run.
- **Redirect-to-login (host-level only in v1).** If a host's `httpx_final_url`
  path (after `httpx_chain_status_codes` shows a 30x) matches an auth keyword,
  the host **redirects unauthenticated users to login** → recorded in the host
  `auth_model`, not per-endpoint (ffuf does not follow redirects, so this is a
  host posture signal, not an endpoint label).

**Deferred (named residuals, not silently dropped):**

- **`WWW-Authenticate` header — NOT currently captured, so genuinely unavailable.**
  Confirmed during design: it is neither in httpx's captured metadata nor in
  katana's `INTERESTING_RESPONSE_HEADERS` allowlist (`stage6_crawling.py`). C4 v1
  cannot key on it. *Residual:* add `www-authenticate` to katana's allowlist
  and/or capture it via **E1 (richer httpx)**, then C4.1 keys `"gated"` +
  scheme (Basic/Bearer/Negotiate) on it. Named, not built.
- **Set-Cookie session-cookie inference** — captured in `katana_headers` but a
  weak/noisy signal for "auth happens here"; deferred.
- **Body-content heuristics** (an actual `<form action=login>` / password field) —
  recon does not store bodies (two-tier persistence). Deferred to **C2
  screenshots** + the **A1** LLM pass, which see rendered content.
- **Parsing `/.well-known/openid-configuration` contents** into the concrete
  `authorization_endpoint` / `token_endpoint` it advertises — that is
  schema-parsing (B2-shaped), not classification. C4 v1 labels the well-known URL
  itself `"auth_surface"`; extracting the OIDC endpoints it names is deferred
  (fold into B2 or a C4.2). Named.
- **Minting endpoint rows for auth-surface `url` assets not yet in `endpoints`** —
  see the url-asset note below; v1 folds them into the host `auth_model` but does
  not create records.

---

## Where the labels land

1. **`endpoints.auth_status`** (existing column) — the per-endpoint label, filled
   in place per the precedence rules. Plus endpoint `metadata` additions:
   `auth_classified_by="c4"`, `auth_keyword=<matched>` (when applicable),
   `auth_surface_hint=True` (when a `"gated"` row also keyword-matches).
2. **Host-level `auth_model`** — a new **agent-authored** metadata key on each
   in-scope `subdomain` asset (via `update_asset_metadata`, the path stage 4/9/B1
   already use). A compact "where auth happens" map, which is exactly what
   primitive's authenticated-testing mode (R2-14) and A2's interest scoring want:

   ```python
   auth_model = {
       "has_auth_surface": bool,
       "auth_surface_paths": [...],      # de-duped, capped; provenance per source endpoint
       "gated_endpoint_count": int,
       "public_endpoint_count": int,
       "unknown_endpoint_count": int,
       "redirects_to_login": bool,       # from httpx_final_url + chain
       "login_redirect_path": str | None,
       "classified_at_stage": 11,
   }
   ```

3. **No change to the `url` asset beyond its host's `auth_model`.** v1 does **not**
   add a per-url metadata flag (avoids duplicating the endpoint label). ⚠️ *Named
   residual:* katana (stage 6) mints `url` assets but not `endpoint` rows (only
   jsluice/ffuf/openapi do), so an auth surface that exists only as a crawled
   `url` asset (e.g. a `/login` katana found) would be missing from the
   `endpoints` table. **v1 scans in-scope `url` assets for auth-keyword matches so
   they still surface in the host `auth_model`**, but does **not** promote them to
   `endpoint` records (that would make C4 a producer, muddying "pure
   enrichment"). *Jared call #3:* optionally let C4 mint a minimal `endpoint` row
   for a clear auth-keyword `url` asset with no existing endpoint (target_derived
   inherited from the producing source — katana links are `td=1`). Recommended:
   defer to keep C4 a clean enricher; the `auth_model` scan already gives the
   where-auth-happens map its completeness.

---

## Where it slots in `main.py`

```python
run_stage10_and_report(patterns, state, scope)   # stage 10 (B2) API-schema discovery
run_auth_classification_and_report(state)         # C4 — auth-surface enrichment (NO traffic)
state.update_run_state(status="stage_complete", passes_completed=1)
```

The applier mirrors `_apply_waf_flags` — load, call the pure function, write back:

```python
def run_auth_classification_and_report(state: RunState) -> None:
    """C4 — deterministic auth-surface classification over already-collected
    data. Sends NO traffic. Enriches endpoints.auth_status in place (never
    downgrading an existing 'gated') and writes a per-host auth_model summary."""
    endpoints = state.load_endpoints()
    assets = state.load_assets()
    host_meta = {a.value: a.metadata for a in assets if a.type == "subdomain"}
    url_assets = [a for a in assets if a.type == "url"]

    ep_updates, host_models = classify_auth_surface(endpoints, url_assets, host_meta)

    for endpoint_id, auth_status, meta_update in ep_updates:
        state.update_endpoint_auth_status(endpoint_id, auth_status, meta_update)  # NEW state method

    host_by_value = {a.value: a for a in assets if a.type == "subdomain"}
    for host, model in host_models.items():
        if host in host_by_value:
            state.update_asset_metadata(host_by_value[host].asset_id, {"auth_model": model})

    state.update_run_state(current_stage=11, status="stage_complete")
    logger.info("C4 auth classification: %d endpoint label(s) written, %d host auth_model(s)",
                len(ep_updates), len(host_models))
```

Wrap the body in the same R7-spirit guard the other finalizers have (a classifier
bug must not error the whole run after 10 stages of real work completed).

### New `state.py` method (the only API C4 needs)

`add_endpoints` is `INSERT OR IGNORE` — it will **not** update an existing row, so
C4 needs a targeted updater. The `auth_status` **column already exists** (no
schema/migration change — this is a new *method*, D2's column was reserved "for
C4" from the start):

```python
def update_endpoint_auth_status(self, endpoint_id: str, auth_status: str | None,
                                metadata_update: dict | None = None) -> None:
    """(C4) Set an endpoint's auth_status and merge metadata, by endpoint_id.
    Used only by the C4 enrichment pass; leaves target_derived/discovered_* as
    the producing stage set them."""
```

Merge-not-replace on metadata (like `update_asset_metadata`), so `ffuf_status`
etc. survive.

---

## Boundary — recon classifies, it does not test

C4 is **the purest recon-side item on the roadmap**: it sends nothing, touches
nothing, and confirms nothing. It **labels already-collected data**.

- **A path keyword match is a heuristic LEAD, not a confirmed auth surface.** C4
  never sends a request to `/login` to see if it's really a login; it records that
  the path *looks like* one (`auth_classified_by="c4"`, `auth_keyword=…`).
  Primitive confirms; C4 prioritizes. This is the same line C1 (detection-only)
  and C5 (CVE *candidates*) hold.
- **`"gated"` is the target's own confirmation, not ours.** C4 preserves B1/B2's
  response-derived `"gated"` untouched — it only *adds* labels where there was no
  confident signal.
- **Recon never authenticates, submits a credential, or tests a gate.** Mapping
  *where* auth happens is the input to primitive's authenticated-testing mode;
  *doing* auth is primitive's guarded, refuse-capable territory.

---

## R-inheritance (what actually applies to a no-traffic pass)

- **R1 (scope covers traffic)** — trivially satisfied: no traffic. C4 only reads
  in-scope assets/records already admitted by the gate; it mints none.
- **R3 (per-host rate)** — N/A (no requests).
- **R5 (per-target raw)** — N/A (no tool output to archive).
- **R7 (fault isolation)** — the applier is wrapped so a classifier bug marks
  nothing and does not error a completed run; it is deliberately all-or-nothing
  *within* the pass (a pure function over in-memory rows — there is no per-host
  tool to isolate).
- **R8 (at-rest hygiene)** — inherited by construction: C4 writes only into the
  existing `assets.db` in the chmod-700 run dir; it introduces no new sensitive
  artifact.
- **R9 / untrusted-by-default** — C4 writes agent-authored labels; the host
  `auth_model` embeds target-authored path strings that keep their source
  provenance, and A1 must render them as delimited data (see the provenance
  section).

---

## Verification (the no-tool analogue of "verify the real tool first")

C4 has no external tool, so `CONTRIBUTING.md` step 3's "run the real CLI" becomes
**"run over a real `assets.db` and confirm the labels are sane."**

- **Real-data pass over the existing Juice Shop run** (B1 stage 6.5 + B2 stage 10
  already populated its `endpoints` table). Confirm: `/rest/user/login`,
  `/login`-type paths → `"auth_surface"`; rows B1 marked `"gated"` on 401/403 stay
  `"gated"` (never downgraded); public 2xx endpoints → `"public"`; **no false
  `"auth_surface"` on `/authors`-style paths** (the segment-boundary trap); the
  host `auth_model` counts add up to the endpoint total.
- **Mocked test list** — a fixed set of `Endpoint` rows exercising every
  precedence branch (see Tests). Because the classifier is a **pure function**, no
  subprocess mocking is needed — this is simpler than B1/B2's mocked-ffuf tier.
- **Confirming second pass** (definition-of-done step 5): re-run C4 over the same
  db and assert **idempotence** — labels don't churn, `"gated"` still preserved,
  no duplicate `auth_model` growth.

---

## Tests — `testing/test_auth_classification.py`

Pure-function tier (`classify_auth_surface`), mirroring `test_track_d.py` shape:

- **Keyword → `auth_surface`**: `/login`, `/oauth/authorize`,
  `/.well-known/openid-configuration` → `"auth_surface"` + `auth_keyword` set.
- **Segment-boundary trap**: `/authors`, `/registered`, `/tokenizer`,
  `/logout-history` classified by their *other* signals, **never**
  `"auth_surface"` from a substring. (The make-or-break assertion.)
- **`"gated"` never downgraded**: an endpoint already `"gated"` whose path also
  matches `/oauth/token` stays `"gated"`, gains `auth_surface_hint=True` +
  `auth_keyword`.
- **Precedence**: keyword beats a 2xx (`/login` 200 → `auth_surface`, not
  `public`); a 2xx non-keyword → `public`; a 5xx / `server_error` / no-status row
  → stays `NULL` (fail-closed, no guessing).
- **OpenAPI reconciliation**: `security != []` row is already `"gated"` (untouched);
  `security == []` non-keyword → `"public"`.
- **Host `auth_model`**: counts (gated/public/unknown) sum correctly;
  `has_auth_surface` reflects the endpoint + url-asset keyword scan;
  `redirects_to_login=True` when `httpx_final_url` path matches a keyword.
- **Idempotence**: running the classifier twice yields identical labels.
- **Empty inputs**: no endpoints / no assets → no updates, no crash.

Plus a thin `main`-level test that `update_endpoint_auth_status` persists and
`update_asset_metadata` carries `auth_model`, and a
`testing/run_auth_classification_only.py` re-runner (imports
`run_auth_classification_and_report`, per the standalone-re-run rule — never
reimplements it).

---

## Doc cascade (flush when built)

- **`STATE_SCHEMA.md`** — `endpoints.auth_status`: note the full vocabulary
  (`public`/`gated`/`auth_surface`/NULL), C4 as the producer of `public`/
  `auth_surface`, the `auth_classified_by`/`auth_keyword`/`auth_surface_hint`
  metadata keys, and the new **agent-authored** host `auth_model` key (NOT in
  `TARGET_DERIVED_METADATA_KEYS`). Note `update_endpoint_auth_status` as the new
  RunState method (no schema change — column pre-existed).
- **`README.md`** — the C4 enrichment pass in the pipeline flow (a no-traffic
  finalizer after stage 10); the `auth_model` host key in the state-file table.
- **`pipeline_schematic.mermaid`** — an auth-classification node reading the
  `endpoints` table + host metadata and writing labels back (dashed/no-traffic
  style, distinct from the active stages).
- **`CONTRIBUTING.md`** — note the no-traffic-enrichment pattern: an item that
  reads collected data needs the "verify against a real `assets.db`" analogue of
  verify-real-tool, and fail-closed still governs (NULL over a guess).
- **`CHANGELOG.md`** — DESIGN → BUILT entry.
- **`RECON_ENHANCEMENTS.md`** — flip **C4** from roadmap to BUILT; note it feeds
  A2/A1 and primitive's authenticated-testing mode.
- **`RECON_AGENT_DESIGN.md`** — fold the enrichment pass into the inventory (with
  the Track-D / stage-6.5 / stage-10 folds already owed).

---

## Explicitly OUT of scope for C4 v1 (so the building agent doesn't over-reach)

- **Any new request.** C4 reads on-disk data only. If you find yourself adding an
  httpx/urllib call, you have left C4 and entered E1/B2 territory.
- **`WWW-Authenticate`-based labeling** — the header isn't captured yet (E1 /
  katana-allowlist residual).
- **Parsing OIDC/OAuth metadata contents** into concrete authorize/token endpoints
  (B2-shaped; deferred).
- **Minting `endpoint` records** for auth-surface `url` assets (v1 folds them into
  `auth_model` only; promotion is Jared call #3).
- **Body/screenshot-based login detection** (C2 + A1's rendered-content view).
- **Confirming a gate or a login** by sending auth — primitive's guarded territory.
- **Interest scoring off these labels** — that's **A2** consuming C4, not C4.

---

## Open questions genuinely needing Jared

1. **Stage tag** — tag the pass `current_stage = 11` for observability, or leave
   `current_stage` at 10 and treat C4 as an unnumbered finalizer? (Recommended:
   11; no fractional stage — no same-pass consumer forces one.)
2. **Vocabulary names** — `public` / `gated` / `auth_surface` as locked, or split
   `auth_surface` (e.g. `login` vs `oidc_metadata`)? Cheap to change before build.
3. **Promote auth-surface `url` assets to `endpoint` rows?** v1 recommends *no*
   (keeps C4 a pure enricher; `auth_model` still captures them). Reverse only if
   you want `/login`-only-as-url-asset to be a first-class testable `endpoint`
   record for primitive.

---

## See also

- `RECON_ENHANCEMENTS.md` — the C4 sketch + Track C sequencing (this realizes it);
  **A2** interest scoring is C4's primary consumer, **A1** the LLM brief downstream.
- `RECON_TRACK_D_DESIGN.md` — the `endpoints` table + `auth_status` column C4 fills.
- `RECON_B1_CONTENT_DISCOVERY_DESIGN.md` / `RECON_B2_API_SCHEMA_DISCOVERY_DESIGN.md`
  — the producers that already write `"gated"`; C4 builds on that, never fights it.
- `STATE_SCHEMA.md` — `endpoints.auth_status` semantics + host metadata keys.
- `PRIMITIVE_AGENT_DESIGN.md` — the authenticated-testing mode (R2-14) whose
  need for a "what's gated / where auth happens" map drives C4.
- `CONTRIBUTING.md` — design-locked-before-code + fail-closed discipline C4 follows.
