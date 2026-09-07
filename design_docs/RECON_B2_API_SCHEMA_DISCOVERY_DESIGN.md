# B2 — API-schema discovery (design-lock)

**Status: BUILT + REAL-RUN VERIFIED 2026-08-23** (`stages/stage_api_discovery.py`,
`testing/test_api_discovery.py`, wired as terminal stage 10). Both halves shipped:
**B2a — OpenAPI/Swagger** (verified vs local Swagger Petstore 2.0 + 3.0) and **B2b —
GraphQL introspection** (verified vs a local graphql-core server). Resolved
open-questions at build: **direct urllib fetch** (not httpx — we need the spec BODY);
**PyYAML present** so YAML specs are in v1; **GraphQL modeling** — all fields share
`url`+POST so "one endpoint per field" collides with `UNIQUE(url,method)`, resolved to
ONE endpoint + the query/mutation→args catalog in metadata + distinct arg names as body
params. graphw00f engine-fingerprint stays deferred (not installed). Realizes **B2** of `RECON_ENHANCEMENTS.md`
(Phase 2, Track B). Two capabilities that both turn a *machine-readable API
description* into first-class Track-D `endpoint` + `parameter` records:

1. **B2a — OpenAPI/Swagger discovery.** Probe common spec paths on live hosts;
   when one is a real spec (not an SPA catch-all), parse every path × method ×
   parameter into records. **Deterministic, no external tool** (httpx fetch +
   Python json/yaml parse).
2. **B2b — GraphQL discovery.** Detect a GraphQL endpoint, run a **read-only
   introspection query** where enabled, parse the schema's queries/mutations/
   types/args into records. `graphw00f` engine-fingerprint is **optional
   enrichment, deferred** (not installed on this box).

> **The single highest signal-per-request in recon.** An OpenAPI doc or an
> introspectable GraphQL endpoint hands primitive a *complete, typed* source/sink
> map — every endpoint, parameter, and type — for a handful of requests, with **no
> brute force**. Contrast B1 (thousands of requests to guess paths): B2 asks the
> app to describe itself.

**Recommended build order: B2a first, then B2b.** B2a is deterministic and
verifiable against a local real OpenAPI spec today; B2b needs a live
introspection target and (optionally) a new tool. Ship B2a, then B2b as a
follow-up. This doc locks both; the build spec below is complete for B2a and
design-complete for B2b.

---

## Provenance distinction that drives the whole design

**B1's discovered paths were `target_derived=0`** — the *path string* came from
OUR wordlist. **B2 is the opposite: the schema content is TARGET-AUTHORED**, so
every record B2 produces is **`target_derived=1`**. An OpenAPI `description`, a
GraphQL type name, an example value — all attacker-controllable text. This makes
B2 output **untrusted-by-default** (R9): it carries `target_derived=1`, and the
future A1 brief must treat it as delimited data, never instructions. This is the
same rule jsluice output (stage 7, `target_derived=1`) already follows.

---

## Locked decisions (recommended; Jared's calls flagged)

1. **No external tool for B2a.** Fetch spec candidates with **httpx** (already
   wired; same pattern as stage 7's bundler probe), parse with Python
   `json`/`yaml`. Rationale: an OpenAPI/Swagger doc is just JSON or YAML; a tool
   adds nothing and a parser we control is testable. `swagger-cli`/`openapi-spec-
   validator` are unwired alternatives (validation, not needed for extraction).
2. **B2b introspection is a direct POST**, not a tool — the standard
   introspection query as a JSON body to the detected GraphQL endpoint. **graphw00f
   (engine fingerprint) is optional and DEFERRED** (not installed; introspection
   works without it). ← *Jared call: install graphw00f later for the engine label,
   or skip.*
3. **New TERMINAL stage — stage 10** (after B1 at 6.5, after stage 9). ← **Jared
   call; recommended 10.** Rationale: B2 is a **record-only producer** — nothing
   downstream *in recon* consumes its output (stage 7 jsluice seeds from `.js`
   assets, not API endpoints; stages 8/9 seed from hosts). So unlike B1 (which
   fed jsluice, forcing the 6.5 placement), B2 has **no same-pass consumer**, so a
   clean integer terminal stage is right — no fractional-stage footgun. It runs
   after B1 so any spec B1 happened to surface as a `url` asset is already known
   (not required, just tidy).
4. **Seed: confirmed-live in-scope hosts** — the exact B1/stage-9 filter
   (`subdomain` + `in_scope` + `httpx_status_code`), and **reuse B1's scheme
   derivation** (origin from `httpx_final_url`, not hardcoded https — the real-run
   fix from B1). Brute-forcing a host not serving HTTP is wasted traffic.
5. **Records:**
   - **OpenAPI** → one `endpoint` per (path, method) with `content_type` from the
     operation's response/requestBody media type, `auth_status="gated"` when the
     operation carries a non-empty `security` requirement (else `None`); one
     `parameter` per declared parameter (`location` from `in:` → query/path/
     header/body) and per requestBody schema property (`location="body"`).
     `reflected=None` (recon never confirms reflection — primitive does).
   - **GraphQL** → one `endpoint` per top-level Query/Mutation field
     (`url = <graphql endpoint>`, `method="POST"`, `path=/graphql`,
     `metadata.graphql_operation = "query:<field>"` / `"mutation:<field>"`); one
     `parameter` per field argument (`location="body"`, name = arg name).
     Mutations are recorded as endpoints but **never executed** (introspection
     only — see boundary).
   - All `target_derived=1`, `discovered_by="openapi"` / `"graphql"`.
6. **Same-origin (R1) by construction.** B2a probes only the seeded host's own
   paths; B2b posts introspection only to the in-scope host's own GraphQL
   endpoint. A spec that *references* external servers (`servers:`/`host:` fields)
   is recorded as metadata but its endpoints are **still scoped to the seeded
   host** — B2 never emits an endpoint for an off-scope host (the scope gate would
   drop it anyway; we don't even mint it). ← locked: do not follow `servers:` to
   other origins.
7. **Two-tier persistence (R5).** The full fetched spec / introspection response
   is archived verbatim per host (`raw/stage10_openapi_{host}.json`,
   `raw/stage10_graphql_{host}.json`); records carry only curated fields. If a
   spec embeds a secret-looking value, the D3 secret rule applies (fingerprint +
   raw_log_ref, never the raw value) — **out of scope for v1** (flagged), specs
   rarely embed live secrets; revisit with E4.

---

## SPA catch-all is the central real-world trap (verified)

Probing `/swagger.json` on **OWASP Juice Shop returned `200 text/html`** — the
Angular SPA's index page, NOT a spec. **A naive "200 = found a spec" check
produces pure garbage** (exactly the soft-404 lesson B1's `-ac` and stage 7's
bundler-probe 301 both learned). So B2a's find-a-spec test is **content-based, not
status-based**:

- Require `Content-Type` to be JSON/YAML (`application/json`, `application/yaml`,
  `text/yaml`, `+json`) **AND** the parsed body to contain a **spec marker**:
  a top-level `"openapi"` (3.x) or `"swagger"` (2.0) key, plus a `paths` object.
- HTML bodies, or JSON without those markers, are **rejected** — logged, not
  recorded. This is the make-or-break correctness point for B2a.

For GraphQL, the analogous check: a real introspection response has
`data.__schema.types` (a non-empty list); anything else (HTML, an error object, a
disabled-introspection message) is rejected.

---

## Where it slots in `main.py`

Add `run_stage10_and_report(patterns, state, scope)` and call it last in
`run_pipeline()`, after `run_stage9_and_report(...)`:

```python
run_stage9_and_report(state, scope)
run_stage10_and_report(patterns, state, scope)   # NEW — B2 API-schema discovery
state.update_run_state(status="stage_complete", passes_completed=1)
```

`run_stage10_and_report` mirrors `run_content_discovery_and_report`: seed = live
in-scope hosts + host_base origins (reuse the B1 helper logic), call
`run_stage_and_report(10, "api-schema discovery", new_assets, patterns, state)`
(new url assets = the spec/graphql URLs themselves), then `persist_records`.

---

## The stage module — `stages/stage_api_discovery.py`

### Return contract
```python
def run_api_discovery(live_hosts, state, current_pass, scope, host_base=None
                      ) -> tuple[list[Asset], dict[str, list]]:
    """(new_assets, {"endpoints":[...], "parameters":[...]}). Empty hosts → ([], {...empty}).
       new_assets: the spec/graphql URLs as type="url" (so they're in the graph
       + scope-gated); records: endpoints+parameters parsed from the spec/schema."""
```
Per-host loop with try/except (R7); httpx rate args on the candidate-probe fetch.

### OpenAPI candidate paths (v1 constant; E3 can extend)
```
/swagger.json /openapi.json /v2/api-docs /v3/api-docs /api-docs
/swagger/v1/swagger.json /api-docs/swagger.json /api/swagger.json
/openapi.yaml /swagger.yaml /.well-known/openapi.json
```

### GraphQL candidate endpoints
```
/graphql /api/graphql /v1/graphql /graphql/console /query
```

### ⚠️ Tool/format-interface facts to confirm on REAL data before the parser
(the CONTRIBUTING non-negotiable — every prior stage was bitten):
- **OpenAPI 2.0 vs 3.x shape differ:** 2.0 has top-level `swagger:"2.0"`,
  `basePath`, `host`, parameters incl. `in:"body"` with a `schema`; 3.x has
  `openapi:"3.x"`, `servers:[]`, `requestBody.content.<media>.schema`,
  `components.schemas`, `$ref` resolution. **Confirm both against a real spec**
  (e.g. the canonical Swagger Petstore 2.0 + a 3.0 spec). Handle `$ref` (at least
  local `#/components/...` / `#/definitions/...`).
- **YAML specs exist** — confirm the YAML path parses (PyYAML available? if not,
  JSON-only v1 and defer YAML, named).
- **GraphQL introspection response shape:** confirm `data.__schema.types[]`,
  each with `name`, `kind`, `fields[]` (each `name`, `args[]`), and that
  `queryType`/`mutationType` name the roots — against a **real** introspection
  result from a live GraphQL server. Confirm the exact standard introspection
  query string the server accepts (GET vs POST; `application/json` body).
- Confirm httpx can fetch a raw spec body for us (it truncates? need `-body-
  preview` vs full body — stage 7 used httpx for liveness only; here we need the
  BODY, so likely fetch with a direct request, not httpx `-json` liveness). ←
  **decide during build:** httpx `-body`/`-store-response` vs a plain fetch.

### Rate / R-inheritance
- `httpx_rate_args` for the candidate-probe fetch (N candidates/host = the real
  per-invocation target count, like stage 7's bundler probe). The introspection
  POST is one request/host. Per-host loop (R7). Same-origin (R1). Per-target raw
  (R5). At-rest hygiene (R8).

---

## Boundary — recon discovers, it does not test

- **Introspection is a read-only discovery query**, explicitly on the recon side
  (the roadmap says so). B2 reads the schema; it **never sends a real query/
  mutation** against the data, uses a credential, or tests a resolver. A
  discovered mutation `deleteUser(id)` is recorded as an `endpoint` **lead** for
  primitive — B2 never calls it.
- OpenAPI fetch is a GET of a public description document. If a spec is behind
  auth (401/403), B2 records that it exists (auth-gated) and does **not** attempt
  to authenticate.
- Everything B2 ingests is target-authored → `target_derived=1`, R9 provenance,
  untrusted by the A1 brief.

---

## Verification targets (PREREQUISITE — named, like B1's fuzzable-target need)

**Juice Shop exposes neither a real OpenAPI doc nor GraphQL** (confirmed
2026-08-23: `/swagger.json` → SPA `text/html`; no `/graphql`). So B2 needs:
- **B2a:** a host serving a **real OpenAPI spec** — stand up a tiny local server
  serving the canonical **Swagger Petstore** spec (2.0 AND a 3.0 variant) at
  `/swagger.json` / `/openapi.json`, or point at a consented public spec host.
- **B2b:** a **live GraphQL endpoint with introspection enabled** — a small local
  GraphQL server (or a consented public introspection endpoint) to capture a real
  introspection response and verify the parser.

Real-run discipline unchanged: verify the real spec/introspection shapes → write
parser → mocked tests → real run → fix → confirming run.

---

## Tests (mocked)
- **OpenAPI 2.0**: a real Petstore-shaped 2.0 doc → endpoints (path×method,
  auth_status from `security`) + parameters (query/path/header/body,
  target_derived=1); `$ref` body schema resolved to param names.
- **OpenAPI 3.x**: `requestBody.content.<media>.schema` + `components.schemas`
  `$ref` → body params; `servers:` NOT followed off-host.
- **SPA-catch-all rejection**: `200 text/html` (Juice Shop shape) and JSON
  without `openapi`/`swagger`+`paths` → **zero records** (the central trap).
- **GraphQL introspection**: a real `data.__schema` → endpoints per query/mutation
  field + parameters per arg; a disabled-introspection/error body → zero records.
- Per-host fault isolation (R7); `httpx_rate_args` shape; per-target raw filenames
  (R5); persist_records drops out-of-scope parents, links in-scope; empty hosts.

## Doc cascade (flush when built)
- `STATE_SCHEMA.md` — `endpoints`/`parameters` producers `openapi`/`graphql`
  (`target_derived=1`); new `raw/stage10_openapi_{host}.json` /
  `stage10_graphql_{host}.json`; `endpoint.metadata.graphql_operation`.
- `README.md` — stage 10 in the flow + state-file table.
- `pipeline_schematic.mermaid` — API-discovery node feeding endpoints/parameters.
- `CHANGELOG.md` — DESIGN → BUILT entry.
- `RECON_ENHANCEMENTS.md` — flip **B2** to BUILT; update the "if only three
  things" line (B1+B2 done).
- `RECON_AGENT_DESIGN.md` — fold stage 10 into the stage inventory (with the
  Track-D + stage-6.5 fold already owed).

## Explicitly OUT of scope for B2 v1
- **Executing** any GraphQL query/mutation or OpenAPI operation (that's primitive).
- **Authenticating** to reach a protected spec.
- **graphw00f** engine fingerprint (deferred; not installed).
- **YAML specs** if PyYAML is absent (JSON-only v1, named).
- **$ref across files / remote $ref** (local `#/...` refs only in v1).
- **Secret extraction from spec example values** (D3/E4 territory; flagged).
- **Following `servers:`/`host:` to other origins** (R1 — same-origin only).

## See also
- `RECON_B1_CONTENT_DISCOVERY_DESIGN.md` — the sibling Track-B stage; reuse its
  seed + scheme-derivation + per-host-loop + raw/rate patterns.
- `RECON_TRACK_D_DESIGN.md` — the `endpoint`/`parameter` tables B2 fills.
- `RECON_ENHANCEMENTS.md` — B2 sketch + Track-B sequencing.
- `PRIMITIVE_AGENT_DESIGN.md` §10 — `source_sink_map`, the consumer of these records.
- `CONTRIBUTING.md` — verify-real-tool/format-before-parser discipline.
