# Changelog

Compact, newest-first. Status tags: **DONE** / **DESIGN** (locked, not built) /
**DECISION** / **BLOCKED**. 🐛→✅ = real bug found on a live run and fixed.

---

## 2026-09-10 — stage 6.5 pre-flight WAF-challenge retreat: DONE

Closes the documented blind spot that ffuf's `-sf` breaker only catches 403
floods, so a 200-with-JS-challenge WAF would be hammered for the whole
`-maxtime-job` window (and its challenge pages ingested).

- **`stages/stage_content_discovery.py`** — new `_challenge_signal(meta)` +
  `_JS_CHALLENGE_MARKERS`: before fuzzing, check the host's already-collected
  stage-4 `httpx_title` / `httpx_body_preview` for interstitial-wall markers
  (Cloudflare "Just a moment…", "Checking your browser", DDoS-Guard, Incapsula,
  etc.). A matching host is RETREATED-from — no ffuf, zero extra traffic —
  recorded as `waf_flags[host] = {waf_suspected, waf_signal: "js_challenge"}`.
- Deliberately high-precision: `is_behind_waf` alone does NOT trigger retreat
  (most real targets sit behind a WAF/CDN yet serve content fine), and a
  reCAPTCHA/hCaptcha widget on a legit page is not treated as a challenge wall.
- `_detect_waf` post-hoc path still covers 403 floods + the maxtime backstop for
  hosts that pass pre-flight; its stale "known blind spot" note updated.
- Tests: `testing/test_waf_preflight.py`. Suite 177 passed. ⚠️ mocked only.

## 2026-09-10 — true per-host rate limiting (R3 close-out): DONE

Closes the R3 whole-invocation-`-rl` gap for the two tools it actually bit, and
fixes a latent global-scope over-rate in the already-parallelized per-host stages.

- **`rate_limits.py`** — `katana_rate_args` / `nuclei_rate_args` rewritten to the
  ffuf model: take only `scope`, emit `-rl <per_host>` (a TRUE per-host cap), no
  `host_count` scaling. The old `base_rps x host_count` whole-invocation ceiling
  (which one link-heavy host or a 60+-template scan could absorb) is gone.
- **`stages/parallelism.py`** — new `resolve_host_workers(scope)`: `per_host`
  scope → `resolve_max_workers()`; **`global` scope → 1 (sequential)**, so W
  concurrent hosts × the per-host rate can't exceed a stated global ceiling.
- **`stages/stage6_crawling.py`** (katana) + **`stages/stage8_takeover.py`**
  (nuclei takeover + C1 detection) — now run ONE HOST PER INVOCATION, parallelized
  across distinct hosts via `resolve_host_workers()`, per-host raw archives (R5),
  per-host failure isolated (R7). nuclei stdouts concatenate in stable host order
  so `parse_nuclei_jsonl` is unchanged.
- **`stages/stage_content_discovery.py`** (ffuf), **`stages/stage9_whatweb.py`**
  (whatweb), **`stages/stage5_hidden_params.py`** (x8) — switched from
  `resolve_max_workers` to `resolve_host_workers`, closing the latent
  global-scope over-rate (up to `max_workers`× the ceiling) in these
  already-parallelized per-host stages.
- Residual (documented, minor): the stage-7 bundler httpx probe keeps a
  whole-invocation `-rl` over a small FIXED path list; httpx liveness / naabu /
  screenshots are single batched invocations (~1 req/host or own model) and are
  global-safe as-is.
- Tests: `testing/test_per_host_rate.py` (resolver + per-host invocation + R7
  isolation). Suite 175 passed. ⚠️ mocked only — a real confirming run on a
  multi-host consented target is the natural next step.

## 2026-09-07 — `--target-dir`: runs populate a target folder's `runs/`: DONE

**DONE (verified: run-dir resolution exercised directly — dir created + `chmod
700` + canonical `scope.json` copied + time-sortable name; arg parser rejects
neither/both).** Adds the run-layout `sozin-dashboard` consumes.

- **`main.py`** — new `--target-dir`, mutually exclusive with `--run-dir` (one
  required). Given a target folder holding the canonical `scope.json`, recon
  creates `<target>/runs/run_<UTC-ts>_<shortid>/`, `chmod 700`s it up front (R8),
  copies the canonical `scope.json` in as the run's immutable snapshot, and runs
  there. New helpers `resolve_run_dir()` + `_new_run_name()`. `--run-dir` is
  unchanged; the timestamp-prefixed name sorts chronologically so a consumer can
  pick the latest run from the dir name alone.
- **README** — documents `--run-dir` vs `--target-dir` (local + Docker).
- ✅ (2026-09-08) A full end-to-end pipeline run has since been completed in the
  `--target-dir` layout — the consented ginandjuice run at
  `runs/run_20260908T012659Z_00912a/` shows every `--target-dir` signature
  (`chmod 700` run dir, copied `scope.json` snapshot, time-sortable name) with
  real stage-3→11 timings, confirming the end-to-end path, not just the run-dir
  plumbing.

## 2026-08-24 — B4 / stage 11 archived-JS mining: DESIGN → DONE (Track B complete)

**DONE (built + verified end-to-end; 23 test suites green).** Realizes **B4** of
`RECON_ENHANCEMENTS.md` — the remaining Track-B item — as terminal **stage 11**. IA/CDX
came back up, so the verify-before-parser discipline could finally run.

- **New `stages/stage_archived_js.py`** — mines the Wayback Machine's archived `.js`:
  CDX API (which snapshots exist) → `id_` raw-snapshot fetch (the unmodified body) →
  reused stage-7 jsluice runners → Track-D endpoint/parameter/secret records, all
  `target_derived=1` with `metadata={source:"wayback", snapshot_timestamp, archived_url}`.
  **Passive toward the target** — only `web.archive.org` is contacted, so no
  `rate_limits.py` entry and the seed is **all in-scope subdomains regardless of
  liveness** (the one divergence from B1/B2). Runs after stage 7 so a live+archived
  endpoint dedups to the stage-7 row (`INSERT OR IGNORE`) while an archived-only
  (removed-from-live) endpoint surfaces fresh — B4's reason to exist.
- **`stage7_js_extraction.py`** — `run_jsluice_urls`/`run_jsluice_secrets` gained
  backward-compatible `base_url` / `stage` params so B4 runs jsluice over a **local
  archived body** while resolving relative endpoints onto the **original** target host
  (the central B4 correctness trap), and archives under stage 11 without overwriting
  stage 7. Stage-7 behavior unchanged.
- **Tests:** `testing/test_archived_js.py` (13 mocked tests — CDX header-skip +
  statuscode/digest dedup + degrade, `id_` fetch + R5 archive, provenance/`target_derived`
  records, D3 secret rule, the base_url resolution trap, two-level R7 isolation,
  `INSERT OR IGNORE` dedup vs. a live stage-7 row, persist linkage, not-live-gated seed).
  `testing/run_stage11_only.py` re-runner (imports the shared reporter).
- **Real-run:** interface facts verified 2026-08-24 (CDX list-of-lists w/ header row;
  `collapse=digest` is adjacency-only → client-side digest dedup; `id_` returns the
  unmodified body with no injected toolbar vs. the replay form; jsluice reads local file
  paths and `-u` is `--unique`, not a fetch flag). **End-to-end confirmed on
  `demo.owasp-juice.shop`** (public, consented; B4 sends it zero traffic): 11
  wayback-provenance endpoints resurrected from archived Angular bundles (real routes
  incl. `/rest/admin`, `/application-configuration`), all linked to parent url assets; a
  transient archive fetch failure was R7-isolated and the stage continued.
- ⚠️ Wayback CDX is intermittently slow / returns HTTP 000 → degrades to
  zero-snapshots-this-run (logged, not raised). B4's jsluice-*secrets* path stays
  UNVERIFIED against a real positive (shared with the stage-7 secrets gap).
- **Track B is now complete** (B1/B2/B3/B4). Roadmap remaining: **A1** (LLM capstone) +
  **F2/F3/F4** (credential-gated).

---

## 2026-08-23 — Enhancement roadmap: Tracks C & E complete, + A2/F1/F5/F6

**DONE (built + verified; 22 test suites green; pushed to origin/main).** The bulk of
`RECON_ENHANCEMENTS.md` landed in one push. Each followed design→build→verify; new tools
installed (wafw00f, cdncheck, s3scanner, asnmap; Chrome already present).

- **Track C COMPLETE** — **C1** detection-only nuclei (exposures/misconfig/panels; excludes
  default-logins/intrusive) + a general **`recon_findings`** POI table (🐛→✅ the nuclei
  JSONL parser is now verified against real positive output). **C2** screenshots (httpx
  headless Chrome → run-dir PNGs). **C3** WAF/CDN (stage 4.5: cdncheck offline + wafw00f
  active; ⚠️ wafw00f sends attack-signature probes to fingerprint the filter). **C4**
  auth-surface classification (deterministic; endpoints.auth_status + auth_model). **C5**
  tech→CVE candidates (offline nuclei-template CPE index; nuclei CVE *templates* rejected
  as exploit templates; unconfirmed leads).
- **Track E COMPLETE** — **E1** richer httpx (favicon/cdn/jarm/asn/body-preview on the same
  stage-4 invocation). **E2** diff runs (`run_diff.py`). **E3** target-derived wordlists
  (`run_wordlist_mining.py`). **E4** offline secret classification (regex detector map; zero
  network by construction; never validates). **E5** bounded-parallelism helper (applied to C3).
- **A2** interest scoring (ranks the surface for A1). **F1** URL clustering (representative
  samples). **F5** reverse DNS (dnsx -ptr). **F6** target-profile digest (target_profile.{json,md}).
- **Remaining:** A1 (LLM capstone — needs env/endpoint), B4 (archived-JS — Wayback CDX
  downtime), F2/F3/F4 (credential-gated: AWS keys / PDCP key / GitHub token).

## 2026-08-23 — B2: API-schema discovery (stage 10, Track B)

**DONE (built + real-run verified).** New terminal `stages/stage_api_discovery.py`
turns a machine-readable API description into Track-D `endpoint` + `parameter` records
(`target_derived=1` — the schema is target-authored). `run_stage10_and_report` wired
after stage 9; `_live_hosts_with_origins` helper shared with B1. `testing/test_api_discovery.py`
(14 tests) green. **B2a — OpenAPI/Swagger:** deterministic (urllib fetch + json/yaml
parse, no external tool). Detection is **content-based** (require `openapi`/`swagger`+`paths`),
not status — an SPA catch-all returns `200 text/html` (verified on Juice Shop). Handles
2.0 (`basePath`, `in:body` schema `$ref`→`definitions`) and 3.0 (`servers[].url` relative
base, `requestBody.content.<media>.schema $ref`→`components/schemas`); per-op `security`
→ `auth_status`. **B2b — GraphQL:** POST a read-only introspection query; record the
endpoint + query/mutation→args catalog in endpoint metadata (one endpoint, not one-per-field
— all share `url`+`POST`, `UNIQUE(url,method)`), arg names as body `parameter`s. Same-origin
(R1): spec host / absolute `servers` never followed; introspection is read-only (a discovered
mutation is a lead, never executed). Real runs: local Petstore 3.0 (19 eps/51 params, SPA
skipped) + real 2.0 parse (20/52) + local graphql-core server (2 queries + 2 mutations, 6 args).

## 2026-08-23 — B1: content discovery (stage 6.5, Track B)

**DONE (built + real-run verified vs local OWASP Juice Shop).** New
`stages/stage_content_discovery.py` — ffuf directory/file brute force, **one invocation
per host** so `-rate` is a true per-host cap (closes the R3 gap for ffuf). Placed at
fractional **stage 6.5** (between crawl and JS-extraction) so discovered `.js` is
jsluice-mined same-pass — revises the B1 design doc's terminal-stage-10 decision #2.
Each hit → `url` asset + `endpoint` record; 5xx flagged `server_error`; WAF 403-flood
trips `-sf` → host `waf_suspected` (B1 retreats, never engages). `ffuf_rate_args` in
rate_limits, `RunState.raw_path()`, 16 tests, `run_content_discovery_only.py`.
🐛→✅ verified real ffuf 2.1.0-dev before the parser: `content-type` key HYPHENATED;
`-sf`/`-maxtime-job` both **exit 0** + write a partial file → early-stop detected by
**stderr string + 403-ratio, never exit code**. 🐛→✅ real-run fixes: WORDLIST_PATH
(`/usr/share/seclists`→`~/tools/SecLists`, `SECLISTS_DIR` override); seed scheme derived
from `httpx_final_url` (was hardcoded https, failed on http-only hosts).

## 2026-08-23 — Track D: first-class source records (Phase 1)

**DONE (built + verified).** Promotes the units the hunting agents consume from
ad-hoc `assets.db` metadata into first-class sibling tables. Settles R13. Mocked
suite `testing/test_track_d.py` green; real zonetransfer.me run populated `services`
(incl. non-standard ports 81/4000/8080, all linked).

- Four sibling tables in `assets.db`: `parameters`, `endpoints`, `secrets`,
  `services` — FK to a parent asset, inherit its scope (not re-gated), per-row
  `target_derived` provenance flag.
- Producers rewired (forward-only): naabu → `service` (D4); x8 → `parameter`
  (target_derived 0, reflected); jsluice → `endpoint` + `parameter` (B3:
  query/body/method, previously discarded, target_derived 1) + `secret`.
- `secret` stores a capped `fingerprint` + `raw_log_ref` only — **raw value never
  in assets.db**; `validated` left for a downstream consumer, never set by recon.
- Dropped `x8_reflected_params` / `jsluice_secrets` metadata keys (records supersede).
- Stage-7 jsluice raw archives now per-source (R5-style) so `raw_log_ref` is stable.
- `main.persist_records` links `asset_id` + drops out-of-scope records.
- R13 settled: locations = subdomain/url/ip; params/endpoints/secrets/services are
  records; `js_file` reserved/unused.

## 2026-08-23 — Repo reorg

**DONE.** Docs → `docs/` (README stays at root), tests + `run_stage*_only.py` →
`testing/`. Test/script path setup made location-independent (walk up to state.py).
Doc filenames canonicalized (`git mv`). Four planning docs stay Project-only, not in
the repo.

## 2026-08-23 — Recon review R1–R13 pass coded + verified (Batches 1–3)

**DONE.** First real code from `RECON_DESIGN_REVIEW_RESOLUTIONS.md`, after R8.
Mocked suite green; real zonetransfer.me run `stage_complete`, no regression.

- **R6** canonicalize at `Asset.__post_init__` (host-case/port/fragment; path+query
  untouched). **R9** `TARGET_DERIVED_METADATA_KEYS`. **R13** `js_file`→`classify_url`.
  **R10** review-queue dedup by canonical value.
- **R5** per-target raw filenames. **R7** fault isolation (stages 3/4/6/8/9) +
  `run_state.status="error"`+`failed_at_stage` on crash.
- **R2** absent `rate_limit` block blocks the run. **R4** `rate_limit.scope`
  (per_host|global; global unscaled). **R3** comment-only (nuclei/bundler share
  katana's whole-invocation `-rl` gap).
- **R1** whatweb `--follow-redirect=same-site`, katana `-fs rdn` — **flags VERIFIED**
  vs real CLIs + behaviorally (no digi.ninja fingerprint; katana on-root).
- **R11** certspotter `after=` pagination (+short-page stop, no-new-ids guard, cap).
  ⚠️ live `after=` unconfirmed; guard fails safe.
- Deferred/accepted: R12, R16, R15, R14 (loop unbuilt).

## 2026-08-23 — R8 run-dir hygiene

**DONE.** `RunState.__init__` chmods run dir 0700; `.gitignore` rules already present.
Test `test_run_dir_hygiene.py`; real-run verified. At-rest encryption deferred.

## 2026-08-23 — Recon agent design-captured + reviewed + roadmapped

**DESIGN.** `RECON_AGENT_DESIGN.md` (capture), `RECON_DESIGN_REVIEW_RESOLUTIONS.md`
(16 findings R1–R16; Jared calls R1/R2/R6/R9), `RECON_ENHANCEMENTS.md` (tracks A–F).
R3 generalized katana's `-rl` gap to nuclei + bundler probe.

---

## 2026-08-22 — Proceed past recon on one-pass; loop-until-stable deferred

**DECISION.** One-pass accepted as workable; loop design locked, not wired.

## 2026-08-22 — Stage 1: Cert Spotter added (crt.sh substituted)

**DONE.** crt.sh 502 → Cert Spotter (same CT data). Real API verified before parser.
🐛→✅ single cert lists 26 mostly-unrelated dns_names → filtered via
`_is_subdomain_of_root()`; wildcard SANs stripped/kept/flagged. ~10 req/hr anon
limit. (R11 later: was single-page → now paginated.)

## 2026-08-22 — Amass hang recurs despite fresh config

**BLOCKED (mocked-tested).** Stale-config theory disproven as sole cause. Fix:
`-timeout 8` (⚠️ partial-emit unverified) + `_run_tool` salvages partial stdout on
any timeout (real-tested).

## 2026-08-22 — discovered_by single-attribution fix

**DONE.** Scalar column dropped all but the first tool on merge. Now a JSON list;
both merge paths union; pre-fix strings load without migration. Verified real +
second confirming run.

## 2026-08-22 — Amass hang + empty output + parser + metadata-loss (4 bugs)

**DONE** (item 1 later reopened). 🐛→✅ stale config hang → pre-flight move; 🐛→✅
`-silent` suppresses lines → dropped; 🐛→✅ output is a relationship graph →
`_parse_amass_relationships`; 🐛→✅ same-batch duplicate metadata dropped → in-batch
merge. New `run_stage1_only.py`.

## 2026-08-20/21 — Amass anomaly

**RESOLVED 2026-08-22** (above).

## 2026-08-20/21 — Rate-limiting pass

**DONE** for httpx/naabu/dnsx/katana/nuclei/puredns/x8/whatweb. Per-host rps ceiling,
`CONSERVATIVE_DEFAULT_RPS=5`; `rate_limit` block + LLM-first extraction gate (stub,
fails closed to `pending`). 🐛→✅ puredns+dnsx throttled to target rate despite public
resolvers (~32-min stage-3 step) → `DNS_RESOLVER_RATE_LIMIT=200`. ⚠️ katana `-rl`
whole-invocation, not per-host (R3 later: also nuclei + bundler probe).

## Prior to 2026-08-20 — Recon stages 1–9 built + field-confirmed

- Stages 1–9 wired into main.py, confirmed vs zonetransfer.me; 58+ tests. Tech
  fingerprinting (katana `-td`, whatweb `-a 3` per-host). Tool-interface bugs caught
  by real runs (paramspider no `-o`; x8 needs `-w`/`found_params`; katana JSONL two
  shapes; bundler probe 301-as-found-JS; whatweb batching cross-host attribution;
  SQLite migration dropped duplicate metadata).

---

## Template

```
## <date> — <title>
**STATUS.** One-line context.
- what changed (terse). 🐛→✅ for real-run bugs. ⚠️ for named gaps/unverified.
```
