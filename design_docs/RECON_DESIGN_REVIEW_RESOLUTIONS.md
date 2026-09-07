# Recon agent design review — resolutions

**Status: DESIGN REVIEW COMPLETE. Resolutions locked 2026-08-23. Implementation
of the coded items COMPLETE (R1–R11, R13 shipped 2026-08-23; R3 comment landed;
R8 shipped earlier same day). R12/R15/R16 remain deferred/accepted as designed;
R14's loop guard waits on the unbuilt loop.** The recon agent is already built
and field-confirmed, so these 16 resolutions were *change orders* against running
code. Each followed the design-locked-before-code discipline `CONTRIBUTING.md`
mandates: decision + rationale here first; then code, tests (mocked +
real-run), and doc-cascade.

This is the finding-by-finding record behind the adversarial review of
`RECON_AGENT_DESIGN.md`. It is the recon-side analogue of
`PRIMITIVE_DESIGN_REVIEW_RESOLUTIONS.md`. Read it alongside the design doc,
whose affected sections now carry `(R#)` tags pointing back here.

Four resolutions (R1, R2, R6, R9) were explicit Jared calls during the review,
noted inline. The rest follow the codebase's own precedents (stage 9's per-host
raw-file fix, the `discovered_by` migration, the fail-closed gate discipline).

**Severity legend:** the four **High** findings (R1, R2, R3, R4 plus R5/R6) are
the ones where current behavior actively does something undesirable — off-scope
traffic, over-rate, silent data loss, non-convergence. The rest close
robustness, completeness, and honesty gaps.

**Implementation note (2026-08-23):** the coded items landed together as Batches
1–3 of `RECON_RESOLUTIONS_IMPL_PLAN.md` — mocked suite (`test_recon_resolutions.py`
+ updated `test_certspotter.py`) green, real `zonetransfer.me` run
`stage_complete` with no regression. R1's two ⚠️ tool flags were verified against
the real CLIs (whatweb `--follow-redirect=same-site` is a real WHEN value; katana
`-fs rdn` is real and its default) and behaviorally (no off-domain whatweb
fingerprint, katana on-root only). R11's `after=` pagination is coded with a
fail-safe no-new-ids guard but its live contract stays ⚠️ unconfirmed (anonymous
~10 req/hr). See `CHANGELOG.md`.

---

## Cross-cutting themes

Three themes shape the resolutions, mirroring how the primitive review
crystallized its own:

- **Scope discipline must cover traffic, not just storage.** The gate is
  authoritative for what enters `assets.db`; it was never authoritative for
  what recon's tools actually *touch*. R1 closes the widest leaks.
- **The rate ceiling has to know what it's protecting and how the tool spends
  it.** R2/R3/R4 fix three distinct ways the current per-host model
  mis-serves its own goal: an inert gate (R2), a whole-invocation ceiling
  masquerading as per-host for multi-request tools (R3), and a per-host
  number silently multiplied when it was meant globally (R4).
- **Recon is the ingestion layer, so the properties primitive assumes must
  start here.** Provenance tagging (R9), sensitive-at-rest run dirs (R8), and
  canonical identity (R6) are all things primitive/escalation/report *assume
  hold* about recon's output — they have to be true where the data enters.

---

## Scope & TOS discipline

### R1 (High) — recon sends real traffic to out-of-scope hosts before the gate rejects them

**Where:** `stage4.run_httpx` (`-follow-redirects`), `stage9._scan_one_host`
(`whatweb -a 3` follows redirects — the module comment records the real chain
ending on `digi.ninja`, out of scope), `stage6.run_katana` (`-jc -kf all`, no
crawl-scope flag).

**Resolution (locked — Jared call: "Hybrid").** Distinguish benign single-GET
discovery from aggressive/multi-request off-scope contact:
- **httpx keeps `-follow-redirects`** — a single GET to a redirect target is
  benign and is load-bearing (redirect-discovered hosts are a real discovery
  source). The discovered host is gated before any *later* stage touches it, so
  no compounding. The one residual off-scope GET is named as accepted.
- **whatweb `--follow-redirect=same-site`** — in-scope redirects still
  fingerprinted, off-domain hop (the digi.ninja case) not `-a 3`'d.
- **katana `-fs rdn`** (field-scope = root domain name) — crawl stays within the
  target's own root domain. **Residual, named:** coarser than the scope gate —
  honors the root domain but not `out_of_scope` exclusions or multiple unrelated
  roots; a precise `-crawl-scope` regex from `scope.json` is a tracked follow-up.

**Implemented 2026-08-23.** Both flags VERIFIED against the real CLIs and
behaviorally on zonetransfer.me (see implementation note above) — neither
documented fallback (`--follow-redirect=never`, `-fs fqdn`) was needed.

**Doc cascade:** `README.md` scope-gate section gains a "scope covers stored
assets; traffic-to-destinations is bounded separately" note.

---

## Rate-limiting correctness

### R2 (High) — a forgotten prose rate limit silently degrades to the 5/s default

**Where:** `rate_limit_gate.check_run_not_blocked` only raised on
`resolution == "pending"`, and `pending` is only set via the
`NotImplementedError` LLM stub — so the blocking path was unreachable and a
program stating "1 req/s" the human didn't transcribe ran at the 5/s default.

**Resolution (locked — Jared call).** A run requires an explicit `rate_limit`
resolution. A `scope.json` with **no** `rate_limit` block now **blocks** — to
get the conservative default the human must affirmatively set
`resolution: "not_applicable"`. **Implemented 2026-08-23** (breaking change —
old scopes without a block must add one). **Doc cascade:** `README.md`,
`STATE_SCHEMA.md`, `CONTRIBUTING.md` fail-closed section.

### R3 (High) — the "whole-invocation, not per-host" `-rl` gap is not unique to katana

**Where:** `rate_limits.py` scales `per_host × host_count` as a whole-invocation
`-rl` for httpx/naabu/dnsx/nuclei/katana. False exemption for **nuclei** (60+
templates/host) and the **stage-7 bundler probe** (15 paths/host).

**Resolution (locked).** Generalize katana's accepted limitation to all
multi-request `-rl` tools; correct the "~1 request per target" comment.
**Comment-only fix landed 2026-08-23** — status matches katana: flagged,
per-host-invocation fix deferred to the request-count-instrumentation work.

### R4 (High) — a confirmed *global* rate limit is silently multiplied by host count

**Where:** every native-rl `*_rate_args` called `_multi_host_rate` with no
schema field distinguishing per-host from global, so a stated global "10 req/s"
became `-rl 10 × host_count`.

**Resolution (locked).** Add `rate_limit.scope`: `"per_host"` (default) |
`"global"`; scale only for per_host, pass global through unscaled; an unresolved
per-host-vs-global reading → `pending` (fail closed). **Implemented 2026-08-23**
(`resolve_rate_scope()` + `_effective_total()`). **Doc cascade:**
`STATE_SCHEMA.md`, `rate_limit_gate.py`, `README.md`.

---

## Data integrity / persistence

### R5 (High) — raw archives collide and overwrite on multi-root-domain scopes

**Where:** stage 1 loops per root domain and stage 3 loops bruteforce per domain,
all with a fixed `save_raw` filename — for an N-root scope only the last domain's
raw output survives.

**Resolution (locked).** Suffix raw filenames with a sanitized domain token
(mirrors stage 9's per-host `whatweb_json_{host}`). **Implemented 2026-08-23**
(`_sanitize()` in stage 1 + stage 3). **Doc cascade:** `STATE_SCHEMA.md`.

### R6 (High) — no URL/host canonicalization before `UNIQUE(type, value)` de-dupe

**Where:** `state.add_assets` de-duped on raw `(type, value)` — trailing-slash,
fragment, default-port, host-case variants became distinct assets (bloat, and a
loop-until-stable that can never converge).

**Resolution (locked — Jared call: "Conservative").** Type-aware
`canonicalize(type, value)` at ingestion: lowercase scheme+host, strip default
ports, drop fragments; lowercase `subdomain`. **Path and query never touched**,
so distinct endpoints never merge. Placed in `Asset.__post_init__`; existing DBs
re-normalize lazily on next write/load. **Implemented 2026-08-23.** **Doc
cascade:** `STATE_SCHEMA.md`.

### R10 (Medium) — `needs_review.json` is populated pre-dedup and never deduplicated

**Where:** `main.apply_scope_gate` appended a review item for every ambiguous
asset before `add_assets` de-duped, so rediscoveries appended duplicate entries.

**Resolution (locked).** Dedup incoming review items by (now canonical, R6)
`value` — within batch and against the existing queue — before save. Fail-closed
preserved. **Implemented 2026-08-23.**

---

## Robustness / run state

### R7 (Medium-High) — inconsistent fault isolation; `status="error"` is never set

**Where:** stages 1/5/7 wrapped tool calls; stages 3/4/6/8/9 did not.
`RunStatus` defined `"error"` but `main.py` never wrote it.

**Resolution (locked).** (a) Per-tool try/except-and-continue on stages 3/4/6/8/9
(stage 3's within-leg alterx→puredns→dnsx chains documented as intentionally
all-or-nothing; its independent legs isolated). (b) `main()` wraps the run so an
unhandled exception sets `status="error"` + `failed_at_stage`. **Implemented
2026-08-23.** **Doc cascade:** `STATE_SCHEMA.md`, `CONTRIBUTING.md`.

### R8 (Medium-High) — sensitive data hits an unprotected run dir today

**Where:** `stage7.run_jsluice_secrets` writes extracted secrets into
`assets.db` metadata now; run-dir hygiene was deferred to "once primitive is
built," against a repo with a private GitHub mirror.

**Resolution (locked — bring hygiene forward to now).** Owner-only permissions
(`chmod 700` at `RunState` init) + `.gitignore` rule; at-rest encryption stays
deferred (preserves `sqlite3`/`cat` inspectability).

**Implemented 2026-08-23** (Batch 0). `RunState.__init__` calls
`self.run_dir.chmod(0o700)` on every open (via `Path.chmod`, no new import), so
both fresh and pre-R8 looser-mode run dirs end up owner-only. The `.gitignore`
run-dir rules (`run_*/`, `test1/`, `*.db`, `raw/`, `needs_review.json`,
`run_state.json`, `scope.json`) were already present. Mocked test
`test_run_dir_hygiene.py`; real-run verified. **Doc cascade:** `README.md`,
`STATE_SCHEMA.md`.

---

## Security / data handling

### R9 (Medium) — no provenance tagging of attacker-controlled strings at ingestion

**Where:** whatweb plugin values (a real run captured a literal `<script>`),
katana header values / `katana_error`, jsluice output, `httpx_title`, TLS SANs —
all stored untyped, with no signal about which fields are target-authored.

**Resolution (locked — Jared call: "Cheap tag now").** A documented
`TARGET_DERIVED_METADATA_KEYS` registry naming the attacker-influenceable keys
(`whatweb_tech`, `whatweb_redirect_chain`, `katana_headers`, `katana_error`,
`jsluice_secrets`, `httpx_title`, `httpx_tls_san`). Keyed, so it covers existing
rows with no retrofit. **Explicitly NOT target-derived:** status codes, port
lists, hashes, Wappalyzer/httpx_tech labels, x8 param names. **Implemented
2026-08-23.** **Doc cascade:** `STATE_SCHEMA.md`; recon-side half of the
cross-agent untrusted-data lock. Track D carries this forward per-record: the
`target_derived` flag is `1` on jsluice-sourced records, `0` on x8/naabu.

---

## Discovery completeness

### R11 (Medium) — certspotter reads only the first page

**Where:** `stage1.run_certspotter` issued one query with no `after=` pagination.

**Resolution (locked).** Page with `after=<last id>` until a short/empty page,
archiving each page raw. **Implemented 2026-08-23** — with a short-page stop, a
no-new-ids loop guard (fails safe if `after=` is ignored), a MAX_PAGES cap, and
per-domain+per-page raw archives. ⚠️ The live `after=`/`limit=` contract stays
unconfirmed against a real multi-page domain (anonymous ~10 req/hr); the guard
makes an incorrect assumption stop early rather than loop.

### R12 (Medium) — open non-standard ports are recorded but never probed

**Resolution (locked — tracked completeness item, not fixed now).** Feed
`host:port` for non-standard open ports back into httpx/katana seeding. Deferred
(widens traffic surface, interacts with the rate model); tracked in README
known-gaps. **Note (Track D, 2026-08-23):** those non-standard open ports are now
first-class `service` records (naabu → `add_services`), so the completeness gap
is now "probe the recorded services," not "record them" — a real run captured
ports 81/4000/8080 as services.

### R16 (Low-Med) — TLS SANs / CNAME targets captured but never harvested

**Resolution (locked — tracked completeness item, grouped with R12).** Harvest
on-scope SAN/CNAME hostnames into new gated assets. Deferred; tracked in README.

---

## Spec consistency / design honesty

### R13 (Medium) — `js_file` is a declared AssetType with no producer and a broken gate path

**Where:** `main.apply_scope_gate` would run `classify_domain` on a `js_file`'s
URL value (always → ambiguous) if one were ever created.

**Resolution (locked).** Route `js_file` through `classify_url` (same as `url`);
keep the type reserved. **Implemented 2026-08-23. Settled by Track D
(2026-08-23):** the location AssetTypes are `subdomain`/`url`/`ip`;
parameters/endpoints/secrets/services are first-class *sibling records* (their own
tables), not AssetTypes. `js_file` therefore stays reserved/unused — JS URLs are
captured as `endpoint` records with their source noted in metadata, not as a
distinct asset type. No producer will ever create a `js_file` asset; the gate
route is kept only as defensive coverage.

---

### R14 (Medium) — "deterministic" is code-path-only; the loop's convergence premise is unsound

**Resolution (locked — reframe + guard).** (a) Reframe determinism as
logic-level in `RECON_AGENT_DESIGN.md`. (b) When loop-until-stable is built, its
termination must add R6 canonicalization **plus** a hard pass cap +
diminishing-returns cutoff. **Design constraint recorded; no code today** (loop
unbuilt). **Doc cascade:** `RECON_AGENT_DESIGN.md`, `README.md`.

---

## Accepted asymmetries (named, not fixed)

### R15 (Low-Med) — `verified_by_human` never expires

**Resolution (locked — accept + document).** Recon is lower-stakes, manual-launch,
traffic bounded by the rate model + (post-R1) scope discipline. Asymmetry with
primitive named explicitly in `RECON_AGENT_DESIGN.md`; revisit if recon ever runs
unattended/scheduled.

---

## Already-acknowledged (interacts, not re-opened)

The katana `-rl` per-host gap (generalized by R3), stale metadata keys never
clearing on merge, no runtime request-count enforcement / ratio safety net, and
the stage-8 nuclei parser being UNVERIFIED against a real positive finding. Minor:
`_clear_stale_amass_config` treats `run_state.json`'s `last_updated` as "run
start," but that field advances on every update — works for the current call order.

---

## Resolution status table

| # | Sev | Finding | Resolution | Impl |
|---|---|---|---|---|
| R1 | High | Off-scope redirect/crawl traffic | httpx single-GET kept; whatweb `--follow-redirect=same-site`; katana `-fs rdn` | ✅ done 2026-08-23 (flags verified) |
| R2 | High | Forgotten prose rate limit → silent 5/s | Require affirmative `rate_limit`; absent block → fail closed | ✅ done 2026-08-23 |
| R3 | High | Whole-invocation `-rl` ≠ per-host for multi-request tools | Generalize katana's flagged-limitation to nuclei/bundler | ✅ comment landed 2026-08-23 (code fix deferred) |
| R4 | High | Confirmed global limit multiplied by host count | `rate_limit.scope` (per_host default); global unscaled | ✅ done 2026-08-23 |
| R5 | High | Raw-archive overwrite on multi-root scopes | Per-domain filename suffix | ✅ done 2026-08-23 |
| R6 | High | No canonicalization before de-dupe | Conservative canonicalize at ingestion; lazy migration | ✅ done 2026-08-23 |
| R7 | Med-High | Inconsistent fault isolation; `error` never set | Uniform per-tool try/except; set `status="error"` on crash | ✅ done 2026-08-23 |
| R8 | Med-High | Secrets in unprotected run dir now | chmod 700 + `.gitignore` now; encryption deferred | ✅ done 2026-08-23 |
| R9 | Med | No provenance tagging at ingestion | `TARGET_DERIVED_METADATA_KEYS` registry (+ per-record `target_derived` in Track D) | ✅ done 2026-08-23 |
| R10 | Med | Review queue populated pre-dedup | Dedup review insertion by canonical value | ✅ done 2026-08-23 |
| R11 | Med | certspotter single-page | Paginate with `after=` (+guard/cap) | ✅ done 2026-08-23 (⚠️ live after= unconfirmed) |
| R12 | Med | Open non-standard ports never probed | Tracked completeness item (now recorded as `service` records via Track D) | deferred |
| R13 | Med | `js_file` ghost type, broken gate path | Route through `classify_url`; settled by Track D (sibling records, not AssetTypes) | ✅ done 2026-08-23 |
| R14 | Med | Determinism overclaim; unsound loop convergence | Reframe; loop gets pass-cap + diminishing-returns guard | pending (loop unbuilt) |
| R15 | Low-Med | `verified_by_human` never expires | Accept + document | accepted |
| R16 | Low-Med | SANs/CNAMEs captured but not harvested | Tracked completeness item | deferred |

---

## Doc-upkeep cascade (per CONTRIBUTING.md)

Landed with the implementation: `STATE_SCHEMA.md` (rate_limit affirmative +
`scope`, canonicalized `(type,value)`, reachable `error` status, per-target raw
filenames, target-derived registry, run-dir hygiene), `README.md` (R2 run-setup
change, scope-covers-traffic note, run-dir hygiene, generalized `-rl` gap,
known-gaps reclassified), `CONTRIBUTING.md` (fail-closed gains rate-limit-absence,
fault-isolation expectation), `CHANGELOG.md` (compact entry). `RECON_AGENT_DESIGN.md`
carries the `(R#)` tags and the R14 determinism reframe.

---

## See also

- `RECON_AGENT_DESIGN.md` — the design these resolutions harden (planning doc, not in repo)
- `RECON_RESOLUTIONS_IMPL_PLAN.md` — the execution plan (Batches 0–4) (planning doc, not in repo)
- `RECON_TRACK_D_DESIGN.md` — the source-record model that settles R13 (planning doc, not in repo)
- `PRIMITIVE_DESIGN_REVIEW_RESOLUTIONS.md` — the sibling review this models on (planning doc, not in repo)
- `CONTRIBUTING.md` — the design-locked-before-code / fail-closed discipline (in repo, `docs/`)
