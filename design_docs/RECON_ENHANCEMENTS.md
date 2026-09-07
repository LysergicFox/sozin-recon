# Recon agent — enhancement roadmap

**Status: ALMOST FULLY BUILT.** ✅ **Tracks B, C, D, E COMPLETE** (B1/B2/B3/B4); ✅
**A2, F1/F5/F6** built + verified (23 test suites green). The per-item sections +
sequencing table below carry ✅ markers. **Remaining:** **A1** (attack-surface brief —
recon's first LLM, needs the LLM env/endpoint) and **F2/F3/F4** (cloud_enum / asnmap /
chaos-github — credential-gated: AWS keys / a ProjectDiscovery PDCP key / a GitHub token). This is the forward-looking companion to
`RECON_AGENT_DESIGN.md` (what recon *is*) and
`RECON_DESIGN_REVIEW_RESOLUTIONS.md` (correctness/safety change orders). Those
two ask "is recon correct and safe." This doc asks a different question:

> **Does recon hand the hunting agents (primitive → escalation → validator →
> report) the richest, best-prioritized attack surface it could?**

The recurring answer from the review: **recon finds *hosts and locations* well,
but under-produces *testable surface*, and hands what it finds to primitive as a
flat `assets.db` dump rather than a prioritized brief.** The enhancements below
close that, organized into six tracks (A–F) and sequenced into phases.

Per `CONTRIBUTING.md`'s design-locked-before-code discipline, each item here was
design-locked (its own build spec in `design_docs/RECON_<item>_…`, or the module
docstring) before implementation. **Almost all of it is now built** — only A1 and
F2/F3/F4 remain (see the status header).

---

## The organizing insight

Recon's value to the other agents is **maximizing high-quality sources and
pre-prioritizing them**, while staying on the recon side of the recon/primitive
boundary (recon *discovers and enriches*; primitive *tests and exploits*). Three
structural facts shape the roadmap:

1. **The handoff is a flat dump.** Primitive's `source_sink_map` is supposed to
   consume recon's "sources," but today those live as ad-hoc metadata keys
   (`x8_reflected_params`, `jsluice_secrets`, `katana_headers`) scattered across
   rows. The seam is aspirational, not literal. **(Track D closes this for
   params/endpoints/secrets/services — BUILT 2026-08-23.)**
2. **Recon finds where things live, not what's on them.** It enumerates
   subdomains → live hosts → params → crawled URLs → JS, but never does content
   discovery or API-schema discovery — where most testable surface actually is.
3. **A designed judgment point is unbuilt.** `README.md` names *two* fixed LLM
   points — the scope-gate ambiguous tier *and* a "final review pass" — and
   **neither exists** (`main.py` ends at stage 9 with no LLM call). That review
   pass is the natural home for a curated attack-surface brief.

So the roadmap builds bottom-up: a real data model (D) → more and better data in
it (B, C) → distilled into a brief (A) → widened and made continuous (E, F).

---

## Track A — the attack-surface brief (realize the "final review pass")  ·  A2 ✅ BUILT, A1 REMAINS

**Highest leverage for "results for other agents."** Depends on Track D.

**A1 — Curated attack-surface brief.** Build the designed-but-unbuilt final
review pass as an LLM (or hybrid deterministic+LLM) step after stage 9 that
distills the raw asset graph into a prioritized brief primitive/escalation
consume directly: interesting endpoints, params with context, secrets, tech +
versions, auth-gated areas, and a per-asset *interest score*. This is the
capstone — it consumes everything the other tracks produce.
- *Why / who:* primitive spends a bounded budget (its flat-100 request ceiling);
  a prioritized brief makes that budget go far further. Escalation gets a
  ranked surface to chain from. Report gets a coverage narrative.
- *Boundary:* the brief *prioritizes*, it does not *test*. It ranks candidates;
  primitive confirms them.
- *Consistency:* this is one of the two LLM judgment points the locked
  architecture already reserves — building it is finishing the design, not
  expanding scope.
- **⚠️ Injection surface (inherits primitive §9).** A1 is recon's **first LLM
  that reads target-derived content** — page titles, headers, whatweb plugin
  strings (the real run captured a literal `<script>`), jsluice output. That
  makes the review pass a stored-prompt-injection target. It must adopt
  primitive's discipline: target-derived text enters the prompt as
  **clearly-delimited data, never as instructions**, backed by the R9
  provenance markers (now including Track D's per-record `target_derived` flag);
  the pass must not follow directives embedded in the content it summarizes.
  This is the recon-side instance of the cross-agent untrusted-data lock
  `CONTRIBUTING.md` already tracks.
- *Form:* a queryable artifact (a `recon_summary` table / JSON) plus a
  human-readable render, versioned as a stable recon→primitive contract.

**A2 — Interest scoring.** A deterministic pre-score feeding A1: keyword signals
(`admin`, `api`, `dev`, `staging`, `internal`, `upload`, `redirect`, `debug`,
`graphql`, `.git`, `swagger`), auth-gating, tech-with-known-CVEs, secrets
present, non-standard ports. Cheap, explainable, and it makes the LLM pass an
*editor* rather than a *from-scratch author*.

---

## Track B — coverage: the testable surface *on* the hosts

**Biggest raw-coverage jump.** Active traffic — inherits the R1/R3/rate-model
safety concerns; sequence after the Phase-0 safety fixes.

**B1 — Content/endpoint discovery (ffuf). ✅ BUILT + REAL-RUN VERIFIED 2026-08-23**
(stage 6.5, `stages/stage_content_discovery.py`; local Juice Shop). One ffuf invocation
per host (true per-host `-rate`); hits → `url` assets + `endpoint` records; 5xx flagged
`server_error`; WAF 403-flood → `-sf` → `waf_suspected` (retreat). See
`RECON_B1_CONTENT_DISCOVERY_DESIGN.md`. Original sketch below.

There was no directory/file brute-forcing anywhere in the pipeline — no hunt for `/admin`,
`/.git/`, `/.env`, backups, `/api/v*`, `/actuator`, `/swagger.json`. `ffuf` is
*already in `logging_setup.py`'s highlighter list* — anticipated, never wired.
Fits recon's established active-but-non-exploit posture (stage 3 brute-forces
DNS; stage 5's x8 fuzzes params).
- *Why / who:* the single largest new source of endpoints for primitive's
  `source_sink_map`.
- *Design notes:* seed from the in-scope live-host set; recursion with a depth
  cap; extension lists; response-filtering (size/word/status) to beat catch-all
  pages — the same 200-vs-301 lesson stage 7's bundler probe already learned.
  Rate-limited via the R3-corrected per-host model. New `endpoint` records (D2,
  table now exists).
- **Highest-traffic addition, named.** B1 is the single largest increase in
  recon's active-traffic footprint (thousands of requests per host) and the
  most likely to trip a WAF or a program's abuse threshold — so it is the most
  rate/scope-sensitive item on this roadmap and the one that most depends on
  the Phase-0 fixes (R1, R3, plus C3's WAF signal to back off). Do not add it
  before those land.
- *Boundary/safety:* active discovery traffic — scope-gated (R1 same-origin
  discipline) and rate-bounded like every other active tool.

**B2 — API-schema discovery. ✅ BUILT + REAL-RUN VERIFIED 2026-08-23** (stage 10,
`stages/stage_api_discovery.py`). B2a OpenAPI/Swagger probing (content-based spec
detection, not status; 2.0 + 3.0; verified vs Swagger Petstore) and B2b **GraphQL
introspection** (read-only query; verified vs a local graphql-core server; graphw00f
fingerprint deferred). Records `target_derived=1` (schema is target-authored). See
`RECON_B2_API_SCHEMA_DISCOVERY_DESIGN.md`. A discovered schema is the highest
signal-per-request in all of recon.
- *Why / who:* an OpenAPI doc or an introspectable GraphQL endpoint hands
  primitive a *complete, typed* source/sink map for free — every endpoint,
  parameter, and type, without brute force.
- *Boundary:* introspection is a read-only discovery query, not exploitation.

**B3 — Stop discarding source signal already fetched. ✅ BUILT with Track D
(2026-08-23).** `stage7.run_jsluice_urls` used to keep only `url` and throw away
jsluice's `queryParams`, `bodyParams`, and `method` — exactly the
parameter/method context primitive's sink analysis wants. It now returns
`{url, method, queryParams, bodyParams}` per finding, captured into
`parameter`/`endpoint` records (`target_derived=1`). Near-zero cost; the data was
already on disk in the raw archive.

**B4 — Archived JS mining.  ·  ✅ BUILT 2026-08-24 (stage 11).** gau/waybackurls
already pull historical URLs; nothing mines the historical *JS bodies*. Old JS
routinely contains removed endpoints and rotated-but-informative secrets. Fetch
archived `.js` from wayback and run jsluice over them, same as live JS. Shipped as
terminal **stage 11** (`stages/stage_archived_js.py`): Wayback CDX → `id_` raw
body → reused stage-7 jsluice runners → endpoint/parameter/secret records
(`target_derived=1`, `source=wayback`). **Passive toward the target** (contacts only
web.archive.org → no `rate_limits.py` entry, seeds all in-scope subdomains regardless
of liveness); runs after stage 7 so live+archived endpoints dedup and archived-only
(removed-from-live) ones surface fresh. Real-run verified end-to-end on
`demo.owasp-juice.shop`. Full spec: `RECON_B4_ARCHIVED_JS_MINING_DESIGN.md`.

---

## Track C — signal quality & prioritization  ·  ✅ COMPLETE (C1–C5) 2026-08-23

**Highest-signal single tool change is C1.** Mixed passive/active.

**C1 — Broaden nuclei beyond takeover + a recon POI/findings table.** Stage 8
runs `-tags takeover` *only*. Nuclei's `exposures` / `misconfiguration` /
`exposed-tokens` / `panels` sets are **detection, not exploitation** (same
boundary as the existing takeover check) and produce very high-signal leads — an
exposed `.env`, a public actuator, an admin panel's mere presence.
- *Data model:* today only `takeover_findings` exists; add a general
  `recon_findings` / POI table (mirroring primitive's `points_of_interest`,
  with a `status` lifecycle and provenance) so these land as structured,
  promotable leads.
- *Why / who:* primitive gets confirmed-exposure leads to prioritize; report
  gets findings recon can stand behind.
- **Boundary — detection only, and the line is specific.** Enable a curated,
  *non-intrusive* subset. **Exclude `default-logins` and any credential-
  submitting / write / exploit template** — those *submit* creds or change
  state, which is active auth testing, i.e. primitive's guarded, refuse-capable
  territory, not recon's. `exposed-panels` (a login panel *exists*) is fine;
  `default-logins` (trying admin/admin) is not. Inherits the stage-8 "verify
  real output" discipline (the current nuclei parser is still UNVERIFIED against
  a positive finding).

**C2 — Screenshots.** `httpx -screenshot` (already-wired tool) or gowitness.
Visual triage is how the interesting 5% of hosts get found.
- *Why / who:* feeds A2's interest scoring; a vision model can flag login
  panels, admin dashboards, dev/staging, default/error pages. Report gets
  evidence imagery.
- *Note:* screenshots are sensitive-at-rest — they land under the R8 run-dir
  hygiene (chmod 700 / gitignore).

**C3 — WAF/CDN detection** (`wafw00f` / `cdncheck`). Primitive's behavior should
change based on whether a host sits behind a WAF/CDN — this is exactly the
"know your target" signal its rate-backpressure and technique selection depend
on. Recon should label it, not make primitive rediscover it live.

**C4 — Auth-surface classification.** Recon captures status codes but never
labels **public vs auth-gated (401/403)** endpoints or identifies
**login/register/OAuth/SSO** surfaces. Mostly free — the data's already in
httpx/katana output, just unlabeled. (Lands in the `endpoints.auth_status`
column Track D already defined.)
- *Why / who:* primitive's authenticated-testing mode (its R2-14) needs a map
  of what's gated and where auth happens.

**C5 — Tech → CVE candidate flagging.** Stage 9 collects version-level
fingerprints explicitly "for CVE correlation," then stores them and does
nothing. Flag candidate CVEs from version strings as POIs.
- *Boundary:* recon flags *candidates*; primitive confirms. Not a vuln claim —
  a prioritized lead.

---

## Track D — first-class source data model

**✅ BUILT + VERIFIED 2026-08-23 (Phase 1).** Design-lock and build record in
`RECON_TRACK_D_DESIGN.md`; mocked suite `testing/test_track_d.py` green; real
`zonetransfer.me` run populated `services` = 5 (non-standard ports 81/4000/8080,
FK-linked). **Foundational — Track A and most of B/C produce better data because
this now exists.** The units the agents consume are promoted from ad-hoc metadata
keys to queryable **sibling tables** (FK to a parent asset, like
`takeover_findings`):

- **D1 — `parameter`** ✅ (name, host/endpoint, method, location, reflected?) —
  replaces `x8_reflected_params`; x8 (`target_derived=0`) and jsluice
  (`target_derived=1`) both populate it. The direct input to primitive's
  `source_sink_map`.
- **D2 — `endpoint`** ✅ table built (url, host, path, method, auth_status,
  content_type). Lightly populated now (jsluice url+method); heavy population
  waits for B1/B2.
- **D3 — `secret`** ✅ as a first-class finding — **fingerprint +
  `raw_log_ref`, never the raw value in `assets.db`**; `validated` left null,
  **set downstream by primitive** (see E4); carries R9 provenance
  (`target_derived=1`) and R8 at-rest hygiene by construction.
- **D4 — `service`** ✅ (target/host/ip:port:proto) — R12's non-standard open
  ports are now probeable records instead of dead-end metadata; naabu populates
  them (`target_derived=0`).

*Why / who:* makes the recon→primitive "sources come from recon" seam **literal**
rather than aspirational. *Delivered as:* new sibling tables + `add_*`/`load_*`
methods in `state.py`, `main.persist_records` linking `asset_id` and dropping
out-of-scope records, a per-row `target_derived` provenance flag, and a
`secret_fingerprint` helper. **Settles R13** (asset vs finding vs source record:
locations are assets; params/endpoints/secrets/services are records; `js_file`
reserved/unused). *Deferred within the track:* heavy `endpoint` population (Track
B), E4 provider classification of secrets.

---

## Track E — process & tooling (cheaper wins)  ·  ✅ COMPLETE (E1–E5) 2026-08-23

**E1 — Richer httpx.** Already wired; you use a fraction of it. Add `-favicon`
(favicon-hash correlation across hosts), `-body-preview`, `-method`/OPTIONS,
`-asn`/`-cdn`, `-jarm`. Cheap enrichment from a tool already in the pipeline;
feeds C3/C4/A2.

**E2 — Incremental / diff runs.** For ongoing bug-bounty, "what's *new* since
last run" (new subdomain / endpoint / param) is fresh attack surface and the
highest-value continuous-monitoring signal. The externalized-state design makes
this natural; nothing consumes it yet. Emit a per-run diff artifact.

**E3 — Wordlist strategy.** Everything is small/hardcoded (top-5000 subdomains,
burp-params, a hand-curated bundler list — the last already flagged v1). Adopt
AssetNote-quality lists *and* **target-derived wordlists** mined from the crawled
corpus/JS (endpoint and param tokens the target itself uses). Raises B1/stage-3/
stage-5 yield more than any single tool swap.

**E4 — Secret classification (NOT live validation).** jsluice *extracts* raw
strings; a classifier (trufflehog's detectors in *no-verification* mode, or an
equivalent) labels each hit by **kind and provider** (AWS key, Stripe token,
GitHub PAT, JWT, …) — entirely **offline, no network**. This makes D3's `secret`
records useful (typed, deduped) without recon touching anything.
- **Boundary — recon does not validate secrets live.** Live validation means
  *sending the secret to its provider* — which (a) usually targets a **third-
  party service outside the program's scope**, and (b) is exactly the "confirm
  a found credential's validity" action primitive's design reserves for its
  **guard** (read-only, data-capped, refuse-capable). So D3's `validated?` field
  is populated **downstream by primitive**, never by recon. Recon classifies;
  primitive validates under its guard; neither ever *uses* a credential.

**E5 — Throughput within the rate budget.** Per-host whatweb is N sequential
processes; large targets are slow. Bounded parallelism (workers under the
per-host rate ceiling) improves wall-clock without violating the courtesy rate —
but must respect the R3-corrected per-host model, not just an aggregate cap.

---

## Track F — coverage breadth (opportunistic)  ·  F1/F5/F6 ✅ BUILT; F2/F3/F4 credential-gated

Named so they survive as tracked intent; lower priority than A–D.

- **F1 — URL clustering / representative sampling.** A big site yields thousands
  of templated URLs (`/product/1`, `/product/2`, …). Cluster by structure and
  hand primitive a *representative sample per template*, not the raw flood —
  protects primitive's budget from noise. Builds on R6 canonicalization.
- **F2 — Cloud asset discovery.** S3/GCS/Azure blob enumeration (cloud_enum /
  s3scanner) from target keywords + discovered names. Common, high-impact
  surface recon misses entirely.
- **F3 — ASN / IP-range expansion.** Wire the already-deferred `asnmap` (needs a
  CIDR/ASN asset type — a `state.py` question), for programs with IP-range
  scope.
- **F4 — Wire the deferred stage-1 sources.** chaos (API key), github-subdomains
  / gitleaks (org-level secret + subdomain discovery), gauplus. Straight
  coverage from tools already named/installed.
- **F5 — Assorted DNS/host breadth.** Reverse DNS/PTR on in-scope ranges, vhost
  discovery (multiple sites per IP), NSEC walking. Opportunistic.
- **F6 — Target profile summary.** A one-page "know your target" digest (size,
  primary tech stack, WAF/CDN posture, auth model, notable exposures) — a small
  cousin of A1, useful even before the full brief exists.

---

## Recommended sequencing

Enhancements have real dependencies; this order maximizes payoff per phase.

| Phase | Content | Rationale |
|---|---|---|
| **0 (prereq)** | The scope/rate/canonicalization fixes specifically — **R1** (scope covers traffic), **R3** (per-host rate), **R6** (canonicalization) — the true blockers; the rest of R1–R16 should land too but don't gate these | Every active-traffic enhancement (B1, B2, C1) inherits R1/R3; F1 builds on R6. Don't add active tooling onto un-fixed scope/rate discipline. **✅ done 2026-08-23.** |
| **1** | **Track D** (first-class records) + D-settles-R13 + B3 (jsluice fields) rode along | Foundational: A and most of B/C produce better data once the model exists. **✅ BUILT + VERIFIED 2026-08-23.** |
| **2** | **Track B — ✅ COMPLETE** (~~B1 content~~, ~~B2 API/GraphQL~~, ~~B3 jsluice fields~~, ~~B4 archived JS~~) + ~~**E1** richer httpx~~ ✅ | Biggest raw-coverage jump. **All built + verified** (B1/B2/B3/E1 2026-08-23; **B4 stage 11 2026-08-24**, real-run on demo.owasp-juice.shop). |
| **3** | **Track C — ✅ COMPLETE** (~~C1 nuclei+POI~~, ~~C2 screenshots~~, ~~C3 WAF/CDN~~, ~~C4 auth-gating~~, ~~C5 CVE candidates~~) | Turns coverage into prioritized signal. **All built + verified 2026-08-23.** |
| **4** | **Track A** (~~A2 scoring~~ ✅ → **A1 brief** — remaining) | Capstone. A2 built; **A1 = recon's first LLM, needs the LLM env/endpoint**. |
| **5+** | **Track E — ✅ COMPLETE** (~~E2 diff runs~~, ~~E3 wordlists~~, ~~E4 secret classification~~, ~~E5 throughput~~) + **Track F** (~~F1 clustering~~ ✅, ~~F5 reverse DNS~~ ✅, ~~F6 profile~~ ✅; **F2/F3/F4 credential-gated**) | Continuous-monitoring + breadth. Track E complete; F1/F5/F6 built. |

**If only three things get built:** ~~D~~ **done** → ~~B1+B2~~ **done** → **A1 (brief it)**
← the top remaining lever (recon's first LLM). ~~C1~~ **done** (the highest-signal single
tool change). Essentially the whole roadmap is built except **A1** (LLM) and **F2/F3/F4**
(credential-gated) — see the status header + memory for exact blockers. (**B4** built
2026-08-24 as stage 11 — Track B complete.)

---

## Boundary & safety notes (non-negotiable)

- **Active-traffic additions inherit the whole R1–R16 review.** B1 (content
  discovery), B2 (schema probing), C1 (broader nuclei), E4 (secret validation),
  E5 (parallelism) all send target traffic — they are scope-gated (R1),
  rate-bounded under the R3-corrected per-host model, and fault-isolated (R7)
  like every existing active stage. None of them is exempt because it's
  "just discovery."
- **The recon/primitive line holds.** Recon *discovers, enriches, prioritizes,
  and flags candidates*. It never *tests, exploits, uses a credential, or
  confirms a vulnerability* — those are primitive's guarded, refuse-capable
  territory. C1 uses detection templates only; C5 flags CVE *candidates*; E4
  classifies secrets offline and never validates them (primitive sets
  `secret.validated`).
- **New data is untrusted-by-default.** Everything B/C/D ingests is
  target-authored; it carries the R9 provenance markers — now including Track
  D's per-record `target_derived` flag — and (secrets, screenshots) the R8
  at-rest hygiene from the moment it's written. The A1 brief, as recon's first
  LLM over that content, treats it as delimited data, never instructions.
- **Every new tool follows the verify-real-tool discipline.** ffuf,
  feroxbuster, graphw00f, wafw00f, cdncheck, gowitness, trufflehog, cloud_enum,
  s3scanner, asnmap — none is trusted from its docs. Real `--help` + real run
  against a throwaway target before the parser is written, exactly as every
  existing stage was built (`CONTRIBUTING.md`).

---

## Doc cascade (when items are built)

- **`STATE_SCHEMA.md`** — new record types (D1–D4 ✅ done), `recon_findings`/POI
  table (C1), `recon_summary` artifact (A1), diff artifact (E2).
- **`README.md`** — new stages in the pipeline flow, updated architecture
  diagram, the realized "final review pass" LLM point. (Track D pipeline notes ✅
  done.)
- **`pipeline_schematic.mermaid`** — content-discovery / API-discovery /
  brief nodes; the second LLM judgment point moves from implied to built. (Track
  D source-record nodes still to add — low priority.)
- **`RECON_AGENT_DESIGN.md`** — fold each built enhancement into the relevant
  section; move items from this roadmap to the design capture as they ship.
  (Track D fold still pending — larger edit.)
- **`CONTRIBUTING.md`** — the new active-discovery stages reaffirm the
  verify-real-tool + fail-closed + rate-audit checklist. (Track D source-record
  discipline ✅ done.)

---

## See also

- `RECON_AGENT_DESIGN.md` — what recon is today (the baseline these enhance)
- `RECON_TRACK_D_DESIGN.md` — the Phase-1 design-lock + build record for Track D
- `RECON_DESIGN_REVIEW_RESOLUTIONS.md` — the R1–R16 safety fixes these depend on
- `PRIMITIVE_AGENT_DESIGN.md` — the consumer whose needs drive this roadmap
  (`source_sink_map` sources, authenticated-testing surface, budget discipline)
- `CONTRIBUTING.md` — design-locked-before-code discipline each item follows
