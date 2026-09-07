# Recon agent design

**Status: BUILT, wired, and field-confirmed against `zonetransfer.me` (and,
for the content/API-discovery additions, OWASP Juice Shop + local spec
servers) — then adversarially design-reviewed (16 findings, resolutions
locked 2026-08-23).** Unlike `PRIMITIVE_AGENT_DESIGN.md` (a design-before-code
document for a component that doesn't exist yet), this document is a *design
capture* of a system that already runs. It reverse-documents the locked
decisions, invariants, and rationale the pipeline was actually built on
— pulled from the code itself (`main.py`, `state.py`, `scope_gate.py`,
`rate_limit_gate.py`, `rate_limits.py`, the stage + enrichment-pass modules
under `stages/`, `logging_setup.py`) and cross-checked against `README.md`,
`CONTRIBUTING.md`, `STATE_SCHEMA.md`, `CHANGELOG.md`, and
`pipeline_schematic.mermaid`.

> **Scope of this capture (2026-08-23 fold).** The original document captured
> the scripted core (stages 1–9). It has since been folded to cover the whole
> shipped pipeline: **Track D** first-class source records
> (parameters/endpoints/secrets/services), the new active stages **4.5** (C3
> WAF/CDN), **6.5** (B1 content discovery), **10** (B2 API-schema
> discovery), and **11** (B4 archived-JS mining, passive toward the target),
> the **C1** detection band inside stage 8, and the
> post-discovery **enrichment / finalizer passes** (F5, E4, C2, C5, C4, F1,
> A2, F6, plus the E2/E3/E5 tooling). The organizing roadmap for these is
> `RECON_ENHANCEMENTS.md` (Tracks A–F); each item also has (or is captured by)
> a per-item design doc or its own module docstring. What remains *unbuilt* on
> that roadmap is **A1** (the LLM attack-surface brief), **B4** (archived-JS
> mining), and **F2/F3/F4** (credential-gated breadth) — see § Planned
> enhancements.

The same day this capture was written it was put through an adversarial
design review — every gate, invariant, and stage scrutinized for logic,
scope-discipline, rate-limiting, data-integrity, and specification gaps. **16
findings surfaced (R1–R16); each was worked to a locked resolution.** Because
recon is already built, those resolutions are *change orders* against running
code (design-locked, implementation pending), not pre-build design. The
finding-by-finding record — with rationale, the four explicit Jared calls
(R1 scope posture, R2 rate-limit forcing function, R6 canonicalization,
R9 provenance), and the full doc cascade — lives in
`RECON_DESIGN_REVIEW_RESOLUTIONS.md`. Affected sections below carry `(R#)`
tags pointing there; the four **High** findings whose current behavior
actively does something undesirable are R1 (off-scope traffic), R2 (silent
over-rate), R5 (raw-archive data loss), and R6 (non-convergent de-dupe).

Its purpose: give the recon agent the same single, authoritative design
surface primitive has, so a follow-up session can review and improve it
against one document rather than re-deriving intent from a dozen-plus source files.
Where the code and the prose docs already disagree or leave something
implicit, this document names it (in **§ Known gaps** and inline) rather
than smoothing it over — the same "named, not silently dropped" discipline
the codebase uses everywhere.

Companion to `README.md` (what the pipeline is, how to run it),
`CONTRIBUTING.md` (the design/verification discipline the recon agent was
built under and that this document reflects), `STATE_SCHEMA.md` (the on-disk
contract), and `PRIMITIVE_AGENT_DESIGN.md` (the *opposite pattern* that
consumes recon's output).

---

## What recon is, per the locked architecture

Per `README.md`: recon is the **scripted, deterministic core** of the
pipeline. Same input, same behavior, every time. It discovers and classifies
the target's asset graph — subdomains, URLs, IPs, JS files — *and* the
first-class **source records** about those locations (parameters, endpoints,
secrets, services — Track D, § State model), then **enriches and
prioritizes** that surface (WAF/CDN labels, auth-gating, interest scores, a
target-profile digest) and **flags candidate leads** (detection-only nuclei
POIs, tech→CVE candidates) — never confirming any of them. Every piece of
state is externalized to disk so a human (or Claude Code as the agentic
interface) can inspect, intervene, or resume between any two steps.

This is the deliberate counterpoint to primitive. Primitive is a free
agentic loop that *acts* on a live target with freedom over what it tries
next; recon is a fixed sequence of tool invocations that only ever
*collects and classifies* facts. Per `README.md`, the LLM is reserved for
**two fixed in-run judgment points** by design — the **scope-gate ambiguous
tier** and the **final review pass** — plus a separate LLM-first **rate-limit
extraction gate** that runs once at scope setup. Notably, **none of the three
is built yet** (the scope tier and final review pass are unimplemented; the
rate-limit extractor is a `NotImplementedError` stub), so the running recon
agent today makes **zero** LLM calls and is pure deterministic scripting end to
end. That is a feature, not a gap: recon should behave identically on identical
input, and the fail-closed degraded state (everything ambiguous → human review)
holds with the LLM tiers absent. The unbuilt **final review pass** is the home
of the roadmapped attack-surface brief — see § Planned enhancements (Track A).

**The boundary that defines recon:** recon captures *raw discovered facts
about the target's own assets*, enriches and prioritizes them, and flags
*candidate* leads. It does not test for vulnerabilities, it does not use a
credential, it does not confirm a finding, and it does not chain anything —
that is primitive's guarded territory. The traffic it sends is *discovery
and fingerprinting* traffic, not exploitation: the newer active stages widen
it (ffuf directory brute force at 6.5, wafw00f's WAF-trigger probe at 4.5,
per-host page renders for C2 screenshots), but each stays scope-implied
(same in-scope host only, R1), per-host rate-bounded, and *detect/label
only* — recon labels an obstacle like a WAF, it never engages or bypasses it.
Everything downstream (primitive → escalation → validator → report) builds on
the asset graph + source records recon hands off. This boundary shows up
concretely all over the code — e.g. amass's relationship parser keeps only
FQDNs that are subdomains of the root and discards netblocks/ASNs/RIR-org
relations, because "nothing in this pipeline probes, crawls, or checks a /22
netblock"; C5 flags a version's *candidate* CVEs but never version-probes;
E4 classifies a secret entirely offline and never transmits it to a provider.

---

## Core invariants — the spine every stage hangs on

Six properties are load-bearing across the whole recon agent. A change that
breaks any of them is a design change, not a refactor.

### 1. Fail closed, always

The hard rule from `CONTRIBUTING.md`, enforced in code at every judgment
point:

- **Scope.** Anything the deterministic scope-gate tier can't confidently
  classify goes to `needs_review.json` for a human — never silently
  admitted. `classify_domain`/`classify_url`/`classify_ip` return
  `ambiguous` for anything that isn't a clean match, and `apply_scope_gate`
  in `main.py` routes every `ambiguous` result to the review queue. The
  planned LLM tier (`llm_review.py`) is architecturally forbidden from
  auto-admitting — its return type has no `admitted` outcome, only
  `needs_review`.
- **Rate limits.** If a program's rules mention rate limiting but the
  extraction can't confidently pin a number, the run **blocks**
  (`resolution: "pending"`) rather than guessing. `extract_rate_limit()`
  fails closed even on an LLM response it can't parse — a malformed
  extraction is itself treated as ambiguity.
- **Run-start preconditions fail loud.** `verified_by_human != true` →
  `load_scope()` raises. `rate_limit.resolution == "pending"` →
  `check_run_not_blocked()` raises. Both raise rather than returning a
  bool, so a caller can't forget to check the return value.

Every new judgment point must define its fail-closed behavior *before* its
success path.

### 2. Two-tier persistence (archive first, curate second)

Raw tool output is archived verbatim to `raw/stageN_toolname.json` via
`state.save_raw()` **before any parsing happens**. Everything else — asset
metadata, curated fields — is *derived* from those archives. Consequence: a
parsing bug never loses data (the bytes are already on disk), and a schema
change to the curated layer never requires re-running a tool against the
target — you reprocess the existing raw archive. This is why, for example,
stage 6 puts the full unfiltered katana JSONL (including 20KB+ response
bodies) in the raw archive but only a small curated header allowlist into
`assets.db`.

### 3. Caller filters, stage consumes

Each stage is seeded by the orchestrator from the **full current asset
graph** (`state.load_assets()` filtered as needed) — never from just the
previous stage's fresh return value. Stage 3 pulls *every* known in-scope
subdomain across all prior passes to seed permutations; stage 4 probes the
whole in-scope host set; and so on. This matters for loop-until-stable
(unbuilt): once a stage can run across multiple passes, each run must
benefit from everything confirmed in-scope so far. No stage module does its
own scope-status filtering — the caller (`main.py`) hands it a
pre-filtered list.

### 4. Stages don't touch state directly — they return, the caller applies

Every stage module is decoupled from `assets.db`/scope-gate specifics. A
stage returns either:

- **new `Asset` objects** (for the caller to run through the scope gate and
  `add_assets()`), and/or
- **a `metadata_updates` dict** keyed by existing asset value (for the
  caller to apply via `update_asset_metadata()`).

A stage never classifies its own new assets and never writes the DB. This
is what keeps scope classification in exactly one place and lets the
standalone re-run scripts share the exact orchestration logic.

### 5. Standalone re-run scripts import, never duplicate

`run_stage5_only.py` / `run_stage7_only.py` (and any future
`run_stageN_only.py`) exist so one stage can be re-run against an existing
`assets.db` without repeating everything before it. They import the shared
`run_stageN_and_report()` function directly from `main.py` rather than
reimplementing it — two implementations of the same stage logic drift, and
tests exercising only one entrypoint won't catch it.

### 6. Verify the real tool, never trust its docs

Every tool-interface fact in the codebase was confirmed against the real
CLI's `--help` and real output before the parser was written — because a
single sample invocation, or a careful reading of `--help`, does not
exercise every code path a real multi-target run does. The scars are all in
the code as comments: paramspider has no `-o` flag; x8 needs an explicit
`-w`, emits a text preamble before its JSON, and uses `found_params` not
`found_parameters`; katana's JSONL has two distinct line shapes; the
bundler probe was treating 301 redirects as "found JS"; whatweb's
multi-host batching produced cross-host attribution errors. **The one
explicit, logged exception is stage 8's nuclei parser** — built defensively
from documented schema, never confirmed against a real positive finding
(see §Stage 8).

---

## Pre-run gates — checked once, up front, before any tool fires

Two blocking preconditions in `main.py`, both fail-loud, both checked
before a single subprocess runs:

| Gate | Enforced by | Blocks when | Why |
|---|---|---|---|
| `verified_by_human` | `RunState.load_scope()` raises | not `true` | refuses to run against unverified scope |
| `rate_limit.resolution` | `rate_limit_gate.check_run_not_blocked()` raises | `"pending"` | a program mentioned a rate limit that couldn't be confidently pinned to a number — a human must resolve it first |

A `scope.json` with **no** `rate_limit` block at all, or
`resolution` of `"confirmed"`/`"not_applicable"`, passes through without
blocking and falls back to the conservative default. "No policy stated" is
a normal, common case — not an error.

`scope.json` is **read-only from the recon agent's point of view** — the
pipeline never writes to it. Only a human, or the (unbuilt) LLM rate
extractor via `resolve_pending()`, modifies it.

> **Review — accepted asymmetry (R15).** `verified_by_human` is a bare bool
> with no `authorized_at`/expiry, unlike primitive's authorization freshness.
> The review deliberately did **not** add freshness to recon: it's lower-stakes
> (read-only-ish discovery), manual-launch, and its traffic is bounded by the
> rate model and (post-R1) scope discipline. The asymmetry is named here as a
> conscious choice — revisit if recon ever runs unattended/scheduled or its
> traffic profile grows.

---

## The scope gate — `scope_gate.py`

Two-tier, fail-closed, deterministic-first. **Tier 1 is built; tier 2 is
not.**

**Tier 1 (deterministic, built).** Pattern-matches domains/URLs/IPs against
`scope.json`'s allowlist and auto-admits only clean matches. Three
classifiers, dispatched by asset type in `main.py`'s `apply_scope_gate()`:

- `classify_domain` — used for `subdomain` assets (and, in the type
  dispatch, anything that isn't `url`/`ip` — see the `js_file` gap, **R13**).
  **Exclusions win and propagate downward:** an explicit `out_of_scope`
  match always beats a broader `in_scope` wildcard, and anything nested
  *beneath* a literal out-of-scope entry is also excluded
  (`_is_subdomain_of_or_equal`, so `sub.legacy.example.com` is excluded by
  an `out_of_scope: legacy.example.com` entry even though it doesn't match
  the bare pattern literally). A clean `in_scope` wildcard/exact match →
  `in_scope`. Anything else → `ambiguous`. Notably, this tier does **not**
  resolve CNAMEs or detect third-party hosting — those fall to ambiguous by
  design.
- `classify_url` — extracts the host via `urlparse` and defers to
  `classify_domain`. An unparseable URL fails closed to `ambiguous`.
- `classify_ip` — **deliberately not the same logic.** An IP only ever
  auto-admits via an explicit deterministic match against
  `in_scope.ip_ranges` (CIDR or exact IP). It **never returns
  `out_of_scope`** (there is no out-of-scope IP list in the schema) and,
  crucially, an IP resolving from a known in-scope hostname is **not**
  treated as sufficient signal to admit — shared-hosting/CDN/LB risk means
  the box could host unrelated third-party infrastructure. That
  resolved-from-host link is passed to the reviewer as *context* in the
  `needs_review` reason string, never used as scope signal. This is the
  deterministic seed of the same shared-infra suspicion primitive extends
  to CNAME'd third-party SaaS.

**Tier 2 (LLM ambiguous-tier, `llm_review.py`, NOT built).** Intended to
resolve *some* of what tier 1 flags as ambiguous. **Never auto-admits** —
it can only flag, same as tier 1's ambiguous outcome, enforced by return
type rather than convention. Until it exists, **everything** ambiguous
goes straight to `needs_review.json` for a human. This is a safe degraded
state, not a broken one: fail-closed holds either way; the review queue is
just larger than it will eventually be.

Every deterministically-classified asset carries `scope_decision_by =
"deterministic"`; ambiguous ones carry `None` until a human (or the future
LLM tier) resolves them.

---

## The rate-limiting subsystem — `rate_limit_gate.py` + `rate_limits.py`

Done and real-tested against a live run (Aug 20–21). Two modules, two
distinct concerns.

### Extraction gate (`rate_limit_gate.py`)

A **single-shot, scope-setup-time, LLM-first** extraction of a
program-stated rate limit from pasted program-rules text. This is a
different judgment point from the scope gate: it runs *once per run* against
one short block of text (not per-asset across thousands), so there's no
volume argument for a deterministic pre-pass — a keyword/regex layer would
just be a worse version of what the LLM does directly. LLM-first is
intentional here.

Fail-closed resolution logic:

- Nothing stated → `resolution: "not_applicable"`, conservative default
  applies, run **not** blocked.
- Stated + confidently pinned → `resolution: "confirmed"`, run not blocked.
- Stated but ambiguous ("please be reasonable", conflicting numbers, unclear
  per-host vs global) → `resolution: "pending"`, run **blocked** until a
  human resolves it. A blocking gate, unlike the scope gate's ambiguous
  tier, because a rate limit governs how hard *every* invocation hits the
  target — it can't be quietly deferred while the run proceeds.

> **Review changes (R2, R4).** Two gaps here are now resolved (design-locked,
> implementation pending). **R2:** the `pending` block is only ever set by the
> unbuilt LLM extractor, so today a human who forgets to transcribe a stated
> limit silently runs at the 5/s default — the fix requires an *affirmative*
> `rate_limit` resolution (a `scope.json` with no `rate_limit` block now blocks;
> the conservative default must be chosen via `resolution: "not_applicable"`,
> not defaulted into). **R4:** the confirmed number is treated as per-host and
> multiplied by host count, silently exceeding a stated *global* cap N× — the
> fix adds `rate_limit.scope` (`per_host` default; `global` passed unscaled).

`call_llm_extractor()` is a **contract stub that raises
`NotImplementedError`** until wired to a real API client — and deliberately
raises rather than returning a fake "not found" result, because a stubbed
extractor silently reporting "no limit stated" would be fail-open on a
safety gate. `extract_rate_limit()` itself never raises on a malformed LLM
response — it falls back to blocking `"pending"`. `resolve_pending()` is the
human-resolution helper (validates a positive int, records `resolved_by`,
only ever writes `"confirmed"`); marking something `not_applicable` after
the fact requires an explicit hand-edit, by design.

`CONSERVATIVE_DEFAULT_RPS = 5` req/s **per host** — sourced from real bug
bounty program conventions (observed permitted rates cluster in the 2–10
range; 5 sits centered and clearly on the respectful side), not an
arbitrary pick.

### Per-tool translation (`rate_limits.py`)

Resolves one effective per-host RPS ceiling (`resolve_effective_rps()`:
confirmed program value if present, else the conservative default) and
translates it into each tool's **real, verified** CLI flags. Every flag
name below was confirmed against real `--help`.

Three shapes:

- **Native rate flag, multi-host scaled** (`httpx -rl`, `naabu -rate`,
  `katana -rl`, `nuclei -rl`). These tools take a combined multi-host
  target list in *one* invocation, and their rate flag caps the *whole
  invocation* — so a bare per-host number would silently divide the budget
  across N hosts (a 20-host run throttling to 5/20 = 0.25 req/s/host).
  `_multi_host_rate()` scales `per_host_rps × host_count` so each host gets
  its intended share.
- **DNS-resolver-facing, NOT target-scaled** (`puredns -l`, `dnsx -rl`).
  These query public resolvers (1.1.1.1/8.8.8.8/9.9.9.9), **not the
  target**, so they use a separate `DNS_RESOLVER_RATE_LIMIT = 200` anchored
  below puredns's own 500-qps trusted-leg default — nothing to do with the
  target's tolerance. **This was a real bug** (Aug 20): the first version
  reused the 5-req/s HTTP courtesy rate for puredns, producing a ~32-minute
  wait for one stage-3 sub-step (9,640 candidates / 5 qps) with zero
  protective benefit. Re-auditing every tool against "does this rate
  actually protect the *target*?" caught `dnsx` sharing the same latent
  bug before it hurt.
- **No native rate flag, delay-derived** (`x8 -c 1 -d <ms>`, `whatweb -t 1
  --wait <s>`). Concurrency pinned to 1 and a delay computed from the
  target rate (`1000 / rps`). Pinning concurrency makes the delay math's
  "one in-flight request" assumption hold and visible. whatweb's `--wait`
  has whole-second granularity so it floors at 1s (a disclosed
  conservative trade-off, since `-a 3` can fire a burst of plugin requests
  per host).
- **No change needed** (`paramspider`, `jsluice`). Confirmed via real
  `--help`: both query archive APIs / process files rather than hitting the
  target with a per-invocation request-volume lever — no target-facing
  rate applies. Named explicitly so their absence reads as a decision, not
  an oversight.

**Known open gap (flagged, not fixed) — generalized in review (R3).**
`katana -rl` is a whole-invocation ceiling, not a true per-host guarantee: a
single seed host with many internal links can absorb close to the entire
multi-host budget (17 hosts × 5 = `-rl 85`, but one host could see ~85 req/s
if the crawl concentrates there). This is a *wrong-shape* problem — no scaling
constant fixes uneven distribution — distinct from the puredns/dnsx
*wrong-anchor* bug. **R3 corrected the scope of this gap:** it is **not unique
to katana**. The code comments exempt httpx/naabu/dnsx/nuclei with "≈1 request
per target," but that's false for **nuclei** (60+ takeover templates per host
→ one host can absorb the whole aggregate `-rl`) and the **stage-7 bundler
probe** (15 paths per host in one httpx invocation). The exemption holds only
for httpx liveness and dnsx/naabu's ~1-per-target scans. Status is unchanged —
flagged as an accepted limitation across *all* multi-request `-rl` tools, with
per-host invocation as the deferred fix that rides with the
request-count-instrumentation / ratio-safety-net work. Candidates: per-host
invocations (mirrors whatweb's fix, at the cost of cross-host crawl-queue
sharing), documenting as accepted, or non-linear host-count scaling.

---

## State model — `state.py`

All run state lives on disk in a per-run directory. `RunState` is the sole
interface; stage modules never touch files directly, so the on-disk format
can evolve without touching stage code.

**`assets.db` (SQLite).** The one piece of state that grows unboundedly
with target size (tens of thousands of assets on a real program), so it's
SQLite for indexed de-dupe and partial-graph queries — but still a single
file, no server, `sqlite3`-inspectable. Everything else stays plain
human-editable JSON.

- `assets` table, keyed `UNIQUE(type, value)` — the de-dupe key. Asset
  types: `subdomain` | `url` | `ip` | `js_file`. Scope status: `in_scope` |
  `needs_review` | `out_of_scope`. **Review change (R6):** the raw `value` is
  de-duped with **no canonicalization**, so trailing-slash / fragment /
  default-port / host-case variants become distinct assets (bloat, and a
  loop-until-stable that can't converge). The fix adds *conservative*
  canonicalization at ingestion — lowercase scheme+host, strip default ports,
  drop URL fragments, lowercase subdomains; **path and query untouched** so no
  distinct endpoint is ever merged. Changes the de-dupe key, so existing DBs
  re-normalize lazily (like the `discovered_by` migration).
- **`discovered_by` is a JSON array**, not a scalar (fixed 2026-08-22).
  Originally a single TEXT column that kept only whichever tool inserted
  first, silently dropping every other contributing tool's attribution on a
  merged duplicate. `Asset.__post_init__` normalizes a stage's bare-string
  construction into a one-item list; both merge paths union tool names.
  `_parse_discovered_by()` treats an unparseable pre-fix string as a
  single-item list, so old DBs upgrade on next write with no migration.
- **Merge-on-duplicate, never drop.** `add_assets()` uses `INSERT OR
  IGNORE`, but a duplicate carrying non-empty metadata (e.g. stage 3
  rediscovering a stage-1 host now with dnsx records) has that metadata
  **merged into the existing row**, and `discovered_by` unioned — on both
  the in-batch-collision path and the against-existing-row path, and even
  when the duplicate carries no new metadata (attribution credit still
  accrues). `add_assets()` returns only the genuinely-new assets, which is
  what the (unbuilt) loop-termination check will care about.
- **Downstream consequence, flagged not fixed:** because merges are
  read-modify-write unions, **stale metadata keys never clear** between
  runs — no versioning or explicit key-clearing yet. Needs a future design
  pass.

**`takeover_findings` table.** Separate from asset metadata because a
finding is a fundamentally different record than an asset's descriptive
metadata. **No `UNIQUE` constraint** — every `add_takeover_findings()`
inserts unconditionally, intentionally: the same dangling CNAME should be
re-reported every pass until it's fixed, and that history is wanted.
De-dupe/history-collapsing is deferred until real multi-pass behavior is
observed.

**Track D — first-class source records (four sibling tables).** The single
largest state-model change since the original capture (design-lock +
resolution of R13). Facts *about* a location that the hunting agents consume
as testable surface were previously buried in an asset's `metadata` blob;
Track D promotes them to queryable rows in four sibling tables, each
FK-linked (`asset_id`) to a parent asset and **inheriting the parent's
scope** — `persist_records()` drops any record whose parent is
`out_of_scope`, and never independently auto-admits one. Every row carries a
per-record `target_derived` flag (the provenance split R9 seeded, now
first-class). Stages return records as the third element of their return
tuple (`{"parameters": [...], "endpoints": [...], "secrets": [...],
"services": [...]}`); the caller runs `persist_records()` **after**
`add_assets()`, so each record's parent-value lookup resolves.

| Table | `UNIQUE` key | Produced by | `target_derived` | Notable fields |
|---|---|---|---|---|
| `parameters` | `(host, endpoint, name, method, location)` | x8 (stage 5), jsluice (stage 7), B2 (stage 10), wayback_jsluice (stage 11) | x8=0 (SecLists names), jsluice/B2/wayback=1 | `reflected` (True only when x8 confirms a response change; NULL when merely observed), `location`, `inferred_type` |
| `endpoints` | `(url, method)` | jsluice (stage 7, light), **ffuf/B1 (stage 6.5, heavy)**, B2 (stage 10), wayback_jsluice (stage 11, `source=wayback`) | ffuf=0 (wordlist paths), jsluice/B2/wayback=1 | `auth_status` (filled by C4; B1/B2 pre-seed `gated` on a 401/403), `content_type` |
| `secrets` | `(asset_id, fingerprint)` | jsluice (stage 7), wayback_jsluice (stage 11, `source=wayback`) | always 1 | **raw value NEVER stored** — only a capped `fingerprint` + `raw_log_ref` into the chmod-700 raw archive; `kind`/`provider` set by E4; `validated` set downstream by primitive, never recon |
| `services` | `(target, port, proto)` | naabu (stage 4, promoted in `main.py`) | 0 | `host`/`ip` split out from `target`; makes R12's non-standard open ports probeable records instead of dead-end metadata |

**Hard rule (restated for Track D):** a raw secret value never enters
`assets.db` — fingerprint + `raw_log_ref` only. This is what lets E4 reclassify
a secret offline by re-reading the raw archive and recomputing the fingerprint
to re-link the row, with zero risk of the plaintext leaking into the queryable
graph.

**`recon_findings` table.** A general recon lead / point-of-interest table
(C1), the detection-only cousin of `takeover_findings`. Populated by C1's
detection-only nuclei run (exposures/misconfig/panels — never
credential-submitting templates) at stage 8, and by C5's offline tech→CVE
*candidate* flagging (`source="cve-candidate"`). Carries a `status` lifecycle
(`new` → …), `severity`, `category`, and `target_derived=1`. `UNIQUE(host,
template_id, matched_at)` de-dupes re-detections. **`raw_finding` is trimmed**
of nuclei's request/response/curl-command bodies (they can carry sensitive
content) — the full verbatim output stays only in the R8 chmod-700 raw
archive. A finding here is a *prioritized lead*, never a confirmed vuln; the
report agent must render CVE candidates as unconfirmed.

**`needs_review.json`.** The scope-gate ambiguous queue. Each item carries
`asset_id`, `value`, a `reason` string, and `resolution` (`pending` |
`admitted` | `rejected`). A human resolves each by hand today.

**`run_state.json`.** Single overwritten status object: `run_id`,
`current_stage`, `current_pass`, `status` (`running` |
`paused_needs_review` | `stage_complete` | `stable` | `error`),
`passes_completed`, `last_updated`, plus a `timings` dict. `"stable"` is
reserved for loop-until-stable (a zero-`newly_added` pass) and is not
currently reachable.

**`raw/stageN_toolname.json`.** One verbatim archive per tool invocation
(§ two-tier persistence). **Review change (R5):** the filename has no
per-target suffix, so on a **multi-root-domain scope** stage 1's per-domain
loop (and stage 3's per-domain bruteforce) overwrites all but the last
domain's raw output — silently violating the "never lose data" invariant. The
fix suffixes filenames per domain, exactly as stage 9 already does per host.

> **Review changes (R9, R10) — ingestion is where untrusted data enters.**
> **R9:** attacker-controlled strings (whatweb plugin values with literal
> `<script>`, katana header values, jsluice output, `httpx_title`, TLS SANs)
> are stored in metadata untyped. The fix adds a keyed
> `TARGET_DERIVED_METADATA_KEYS` registry — cheap, retroactive, and the exact
> hook a downstream consumer needs to know what to escape/distrust. This is the
> recon-side seed of primitive's provenance split. **R10:** `needs_review.json`
> is populated *before* `add_assets` de-dupes and is never deduplicated, so a
> rediscovered ambiguous asset appends duplicate review items — the fix gates
> review insertion on genuinely-new assets (reliable now that R6 canonicalizes).

**`timed` context manager.** Records wall-clock duration per stage/sub-step
into `run_state.json`'s `timings` dict using `time.monotonic()` (immune to
mid-run clock adjustments) and does not suppress exceptions (a crashed
sub-step still leaves a timing showing how long it ran before failing).
`record_timing()` is deliberately a read-merge-write of just the one key —
not `update_run_state(**kwargs)`, which would replace the whole `timings`
dict and lose prior entries. Lives in `state.py` (not `main.py`) so stage
modules can import it without a circular import.

---

## The orchestrator — `main.py`

Runs the pipeline **once, in sequence** (stage 2 is a reserved/skipped
number). The full order as wired in `run_pipeline()`:

```
1 → 3 → 4 → [service promotion] → [F5 reverse DNS] → 4.5 (C3 WAF/CDN)
  → 5 → 6 → 6.5 (B1 content discovery) → 7 → [E4 offline secret classification]
  → 8 (+ C1 detection band) → 9 → [C2 screenshots] → [C5 CVE candidates]
  → 10 (B2 API-schema) → 11 (B4 archived-JS, passive) → [C4 auth] → [F1 clustering] → [A2 interest] → [F6 profile]
```

The bracketed passes are *enrichment / finalizer passes* (§ Enrichment &
finalizer passes) — most are offline finalizers over already-collected data;
F5, 4.5, 6.5, C2, and 10 send scope-implied, rate-bounded active traffic (stage
11 is **passive toward the target** — it reads web.archive.org, not the host). The
integer-numbered discovery stages (1/3/4/5/6/7/8/9) and the fractional actives
(4.5/6.5) and terminal (11) all use the same `run_stage_and_report()` tail
where they add assets.

There is **no loop-until-stable** — this is one full pass, not a converged
run. That loop is design-locked (sum `newly_added` across the discovery
stages; loop while sum > 0; the once-after stages run last) but not wired in,
and Jared explicitly chose to treat one-pass recon as workable and move
attention to primitive. **Note the loop design predates the newer stages:**
its original `1/3/4/5/6/7` newly-added sum must be revisited to include **6.5**
(a genuine url-asset discovery stage), **11** (archived-JS url assets), and F5's
reverse-DNS candidates when the loop is finally built; 4.5/C2/9 are metadata-only
and 11 is terminal.

**Track-D persistence and service promotion.** After each stage that produces
source records, `main.py` calls `persist_records()` (§ State model — links each
record to its parent asset by value, drops out-of-scope records). Stage 4 is a
special case: naabu's open ports live in host `metadata_updates` and on IP-only
assets, so `main.py` **promotes** them into first-class `Service` records
inline (D4) before persisting — turning R12's non-standard ports into probeable
records while keeping the `naabu_open_ports` per-host summary in metadata.

**The shared tail — `run_stage_and_report()`.** Every stage that discovers
new assets ends the same way, in one function so no stage reimplements it
slightly differently: scope-gate the raw discoveries → `add_assets()`
de-dupe/merge → log an in-scope/needs-review/out-of-scope breakdown →
`update_run_state()`. It returns the genuinely-new assets so a caller can
seed a later stage.

**Metadata-before-new-assets ordering.** Stages that return *both* a
`metadata_updates` dict and new assets (4, 5, 7) always apply the metadata
to existing rows *first*, then run new assets through the scope-gate tail.
Consistent ordering across every such stage.

**Seeding from the full graph.** Before each stage, `main.py` reloads
`state.load_assets()` and filters (e.g. in-scope subdomains for stage 3's
permutation seed, confirmed-live hosts for stage 9) — never reusing just
the prior stage's return value (§ invariant 3).

**Liveness inference.** A host is "confirmed live" if it carries an
`httpx_status_code` in its own metadata (stage 4 probed it). Stages 5 (x8
target selection) and 9 (whatweb seed set) both infer liveness this way via
the shared `get_live_urls_for_x8()` / equivalent host-match logic, rather
than reading liveness off a separate field — factored out so partial-pipeline
scripts share the exact rule.

> **Review change (R7) — fault isolation is uneven, and crashes look clean.**
> Stages 1/5/7 wrap tool calls per-item and continue on failure; stages
> 3/4/6/8/9 do **not**, so a single tool exception aborts the whole pipeline.
> And `status="error"` is defined in `RunStatus` but **never written**, so a
> mid-stage crash leaves a misleading `stage_complete`. The fix applies stage
> 1's per-tool try/except uniformly (or documents a stage as intentionally
> all-or-nothing, e.g. stage 3's sequential chain) and sets `status="error"`
> with the failing stage on any unhandled exception.

---

## Stage-by-stage design

Every stage follows the § invariant-4 return contract. What varies is the
tool set, the new-asset-vs-metadata split, and the stage-specific scars.

### Stage 1 — Passive discovery

**Tools:** subfinder (JSON), assetfinder (text), amass (relationship
graph), gau (text URLs), waybackurls (text URLs), certspotter (CT-log JSON
API via curl). No live traffic to the target itself — every source queries
a third-party archive/API.

**Locked decisions & scars:**
- **`_run_tool` salvages partial output on timeout.** On
  `TimeoutExpired`, whatever the tool already produced is recovered
  (decoded from raw bytes with `errors="replace"`) rather than discarded —
  so amass having queried 44 of 45 sources before one hangs doesn't lose
  100% of its output. Verified directly, not assumed.
- **amass is the problem child.** Passive mode only (active enum belongs
  conceptually to stage 3). A stale `~/.config/amass` can cause an
  indefinite zero-output hang; a pre-flight check moves a config dir that
  predates the current run to a timestamped backup and lets amass rebuild
  fresh (fails open). `-silent` is deliberately *not* used (it suppresses
  the relationship-graph lines the parser needs in v4.2.0); `-timeout 8`
  (minutes) sits under the 600s external kill. **Still not fully closed:**
  the hang recurred even with a confirmed-fresh config — leading theory is
  transient flakiness in one of ~45 third-party sources, not a structural
  bug. The partial-output salvage is the independently-verified backstop.
- **amass relationship parser.** Only FQDNs that are subdomains of the root
  (including the root itself, added as a synthetic asset) become `subdomain`
  assets; `a_record`/`aaaa_record` targets of in-scope hosts become `ip`
  assets with `resolved_from` metadata; `cname_record` and root-level
  `mx`/`ns` targets fold into metadata (someone else's CDN/mail/DNS
  infra isn't a probeable target asset); netblocks/ASNs/RIR-orgs are
  discarded. `managed_by` RIR lines are explicitly recognized-and-skipped
  so the unparsed-line warning stays meaningful.
- **certspotter, not crt.sh.** The CT slot was originally locked as a
  direct crt.sh query, but crt.sh was hard-down (502) at build time, so
  Cert Spotter was substituted — same data source in spirit, better uptime.
  Real response shape verified via a live query before any parser was
  written. **Critical filter:** a single cert's `dns_names` can list many
  unrelated domains sharing only a SAN bundle (zonetransfer.me's real certs
  list digi.ninja, digininja.org, etc.) — only entries that are actually
  subdomains of the queried root are kept (`_is_subdomain_of_root`, shared
  with amass). Wildcard SANs have `*.` stripped and are flagged in metadata.
  Non-list/non-JSON responses (rate-limit error object, HTML error page)
  degrade to zero-results-this-run, logged not raised. Anonymous rate limit
  ~10 req/hour. crt.sh remains a revisit candidate as a possible second
  source alongside Cert Spotter. **Review change (R11):** the query reads only
  the first page (no `after=` pagination), so large-cert domains are silently
  under-enumerated — the fix pages until a short response, archiving each page
  raw. **(R16):** amass `cname_targets` (like httpx TLS SANs) are captured in
  metadata but never harvested into new subdomain candidates — tracked
  completeness item.

**Deliberately not wired in (deferred, installed or named):** chaos (needs
API key), gitleaks (confirmed as the intended GitHub-secret-scanning tool,
referenced in the highlighter and stage 7's docstring but wired nowhere),
asnmap (likely needs a new CIDR/ASN asset type — a `state.py` schema
question), gauplus (installed, not wired).

**Fault isolation:** one tool failing (or one domain failing within a
tool) logs and continues — a single source never kills the stage.

### Stage 3 — Active DNS resolution + brute force

Unlike stage 1's independent sources, stage 3 has real internal
sequencing: **alterx → puredns → dnsx.**

1. **alterx** generates permutation candidates (`api-staging`, `dev-api`,
   …) seeded **only from already-confirmed in-scope subdomains** — never
   from `needs_review`/`out_of_scope`, since permuting unverified scope
   would defeat the gate.
2. **puredns** does two jobs: resolve alterx's permutations, and
   brute-force the root domain against a SecLists wordlist (the "assets
   nobody else found" source). Both are "give a name list, get back live
   ones." Rate: the DNS-resolver cap, not the target rate.
3. **dnsx** does a final validation/metadata pass over everything puredns
   resolved, capturing A/CNAME records into asset metadata. A host dnsx
   can't re-confirm is logged but not discarded (puredns already validated
   it).

**Locked decision:** every live subdomain found here is a **new asset that
still goes through the scope gate** — a permutation of an in-scope domain is
not auto-admitted just because its seed was in-scope. It should almost
always land `in_scope` again (same base domain), but that's the gate's call.
Wordlist and resolver set are small/hardcoded for now, flagged to grow
deliberately once runtime budget is being tuned.

### Stage 4 — Live host probing

Two independent probes over the same in-scope host set (they don't feed each
other): **httpx** (liveness/status/tech/title/redirect/response-hash/TLS
SAN) and **naabu** (port scan).

> **Review changes (R1, R12, R16).** **R1:** httpx keeps `-follow-redirects`
> (a single benign GET, and the source of redirect-discovered hosts) — that one
> off-scope GET is now *named as accepted* rather than unexamined; the aggressive
> tools (whatweb, katana) are what get constrained. **R12:** naabu's non-standard
> open ports are recorded but never HTTP-probed/crawled (tracked completeness
> item). **R16:** httpx's captured TLS SANs are never harvested into new
> subdomain candidates (tracked completeness item, grouped with R12).

**Locked decisions & scars:**
- **httpx is metadata-enrichment on existing assets, except redirects.**
  When httpx's `final_url` points at a host not already known, that host
  becomes a **new asset** (`discovered_by = httpx_redirect`) re-entering the
  scope gate. Real httpx JSON shape was verified: `hash` is
  `{body_sha256, header_sha256}` (not flat), and there is **no `chain`
  field** — only `chain_status_codes` (ints, no hosts) and `final_url`, so
  redirect discovery keys off `final_url` alone.
- **naabu is fed both hostnames and IPs** (from stage 3's dnsx `a_records`)
  in one de-duplicated invocation — naabu natively accepts mixed input.
  Port findings for a known hostname attach as metadata on that host; a
  bare IP with no matching hostname asset becomes a standalone `ip` asset
  (not dropped), carrying `resolved_from_host` as reviewer context.
  naabu can emit duplicate lines per target+port, so ports are de-duped
  through a set (caught on the real run: `[80,443,80,443]` → `[80,443]`).
- **Service promotion (Track D / D4).** naabu's open ports are promoted from
  metadata to first-class `Service` records in `main.py` right after stage 4
  (§ Orchestrator), so a non-standard open port is a probeable record, not a
  dead-end string (R12's partial close).

### Stage 4.5 — WAF / CDN detection (C3)

A fractional stage right after liveness so the "know your target" label is
available to every later active stage. `stages/stage_waf_cdn.py`. Metadata-only
(no new assets, no scope gate), two complementary tools:

- **cdncheck** (ProjectDiscovery) — **offline** IP-range classification (CDN /
  WAF / cloud name from local range data + DNS resolution; **no target
  traffic**). One batched invocation for all hosts.
- **wafw00f** — **active** WAF-vendor fingerprint, one invocation per host.
  ⚠️ Verified on a real run: wafw00f sends ~2 requests **including an
  attack-signature probe** (XSS/SQLi/traversal in the query string) to trigger
  the WAF. That's *fingerprinting the filter*, not exploiting the app — but it
  is active, attack-looking traffic, so it's scope-implied (R1, same host only)
  and run per-host under the bounded-parallel helper (E5), each host keeping its
  own rate.

Writes agent-authored, **trusted** host metadata (not `target_derived`):
`is_behind_waf`, `waf_vendor`, `is_cdn`, `cdn_name`, `cloud_name`. **Relationship
to B1:** B1's `waf_suspected` is an *in-flight* 403-flood breaker computed during
ffuf; C3's label is a *pre-flight* fingerprint — both kept, orthogonal. Recon
**detects and labels** the obstacle so primitive can choose rate-backpressure /
technique; recon never engages or bypasses it. **Scars:** neither tool's exit
code is a reliable signal — the parsers key on output, not exit status.
Origin-IP discovery (favicon→E1, ASN→F3) is deferred.

### Stage 5 — Hidden parameter discovery

**Placement is locked BEFORE crawling** — neither tool depends on katana's
output (paramspider mines history already available from stage 1; x8 fuzzes
hosts stage 4 confirmed live). Anything katana finds later becomes x8 fair
game on the next loop pass via normal scope re-entry.

Two tools, two different existing patterns:
- **paramspider** — mines historical parameterized URLs per root domain →
  **new `url` assets** through the scope gate (like gau/waybackurls). Real
  CLI has **no `-o` flag**; it writes to a fixed `results/<domain>.txt`
  relative to cwd, so it's run in a dedicated temp dir. Not target-facing,
  so no rate limit.
- **x8** — response-diff-fuzzes a *single live URL* to find params that
  change the response → **Track-D `parameter` records** (`target_derived=0`,
  since the names come from our SecLists wordlist; `reflected=True` only when
  x8 confirms the param changes the response), not new assets and — since
  Track D — no longer metadata (`x8_reflected_params` is gone; the stage's
  `metadata_updates` return is now empty but kept for contract symmetry with
  stages 4/7). x8 discovers a *fact about a location*, which is exactly what a
  Track-D record is. Scars: needs an explicit `-w` wordlist
  (without it, "wordlist len: 0" and always-empty results); emits a
  human-readable preamble before its JSON array (found by locating the
  leading `[`); real field is `found_params`. Targets only httpx-confirmed
  live URLs — a URL with no live host behind it is just request-failure
  noise.

### Stage 6 — Crawling

**katana**, JS-aware.

> **Review change (R1).** katana runs `-jc -kf all` with **no crawl-scope
> flag**, so the crawl can follow links off the seed domain and fetch them
> before those URLs come back to be gated. The fix pins katana to in-scope
> crawl scope with `-fs rdn` (field-scope = root domain). **Residual, named:**
> `-fs rdn` is coarser than the scope gate — it honors the root domain but not
> `out_of_scope` exclusions or multiple unrelated roots; a precise
> `-crawl-scope` regex derived from `scope.json` is a tracked follow-up. Flag
> semantics **UNVERIFIED** against real katana.

Locked decisions:
- **`-jc` (JS-crawl) enabled** as a crawl-*completeness* mechanism (parses
  JS it encounters, feeds discovered endpoints back into its own queue).
  This is distinct from and complementary to stage 7's dedicated JS
  deep-dive.
- **No explicit depth/page caps** (`-d`/`-mdp` at katana's defaults) —
  trusted to loop-until-stable, consistent with not artificially limiting
  depth elsewhere. `-rl` (how fast) is a separate concern from depth (how
  far).
- **Two-tier persistence, strictly.** Full unfiltered JSONL (including
  20KB+ bodies and all headers) → raw archive; only a small curated set
  (status, content-type, a security-relevant header allowlist) →
  `assets.db`. Bodies/full-headers never touch the queryable graph:
  downstream agents test the *live* target, not a stale snapshot, so a body
  copy in the asset graph is bloat with little value.
- **Two JSONL line shapes** verified on a real run: success (`response`)
  and failure (`error`, no `response` key). `_extract_metadata` handles
  both explicitly — a failed crawl surfaces `katana_error` rather than
  being indistinguishable from a success with no interesting headers. (14
  of 15 targets failed on zonetransfer.me — expected given its quirky DNS,
  not a bug.)

Every crawled URL becomes a `url` asset carrying its curated metadata
directly on construction; re-crawled known URLs are handled by
`add_assets()`'s merge, not a special case.

### Stage 6.5 — Content / endpoint discovery (B1)

**ffuf** directory/file brute force — the pipeline's first content-discovery
tool and the single largest source of `endpoint` records for primitive.
`stages/stage_content_discovery.py`. Full build spec:
`RECON_B1_CONTENT_DISCOVERY_DESIGN.md`. Seeded exactly like stage 9
(in-scope subdomains stage 4 confirmed live via `httpx_status_code`, on the
scheme/origin httpx actually confirmed — not a hardcoded `https`). Each hit →
a `url` asset (through the scope gate) **and** a Track-D `endpoint` record
(`target_derived=0` — the path came from *our* wordlist; `auth_status="gated"`
on a 401/403, else left for C4).

**Locked decisions & scars:**
- **Placement at 6.5, not terminal stage 10** (this *revises* the B1 design
  doc's locked decision #2). Running after katana (6) and **before** jsluice (7)
  means a ffuf-discovered `.js` file is jsluice-mined **in the same pass** —
  removing the loop-until-stable dependency for that coverage, since stage 7
  seeds from `.js` url assets already in the graph. **Named residual:** katana
  does *not* re-crawl ffuf-discovered directories this pass (it seeds from
  hosts, not our url assets) — recoverable once loop-until-stable or a stage-6
  seed change exists. 6.5 (over 5.5) also minimizes WAF-ban blast radius (only
  7/8/9 follow). The fractional STAGE is a deliberate float that flows through
  `current_stage` / `discovered_at_stage` / the raw filename — **watch for any
  integer-stage comparison** added later (e.g. R14 loop logic).
- **One ffuf invocation PER HOST** in a Python loop (like whatweb/wafw00f),
  under the E5 bounded-parallel helper. This makes ffuf's native `-rate` a
  **true per-host cap** — closing the R3 whole-invocation gap for the pipeline's
  most traffic-heavy tool, the one place R3 is actually fixed rather than just
  flagged.
- **Verified ffuf 2.1.0-dev interface** (real runs, these bit prior stages too
  so they were confirmed not assumed): `-of json` result key `content-type` is
  **hyphenated**; `redirectlocation` is `""` not null; default `-mc` includes
  500, so app 5xx error-noise gets recorded — kept but **flagged**
  `server_error=True` in metadata (Juice Shop returned 500 for `/api.*`/`/rest.*`
  perms). `-ac` filters the soft-404 catch-all.
- **WAF guard is ffuf-native + post-hoc flag, never adaptive.** `-sf`
  (stop-on-403-flood) and `-maxtime-job` both **exit 0 and still write a partial
  file** — the *only* early-stop signal is a **stderr string**, so WAF detection
  keys on stderr + a computed 403-ratio, **never the exit code**. Produces a
  per-host `waf_suspected` breaker flag (distinct from C3's pre-flight vendor
  label, § Stage 4.5). B1 always *retreats* from a WAF, never engages one.
  ⚠️ Known blind spot (shared with `PRIMITIVE_WAF_HANDLING_DESIGN.md`): `-sf`
  keys on **403**, so a **200-with-JS-challenge** WAF won't trip it. Named, not
  closed.
- **Test target:** OWASP Juice Shop (`zonetransfer.me` is too thin to fuzz) —
  ⚠️ it OOM-crashes under a full wordlist + recursion, so bound test runs.
  SecLists lives at `~/tools/SecLists` (honored via a `SECLISTS_DIR` env
  override), not the `/usr/share/seclists` the doc originally assumed.

### Stage 7 — JS discovery + extraction

Two-part discovery, then extraction:
1. **Reuse** stage 6's already-crawled `.js` URLs (no new call needed).
2. **Bundler-path probe** — actively probe a hand-curated `BUNDLER_PATHS`
   list against every in-scope host via httpx, to catch JS a generic crawl
   missed. **Only status 200 + a `javascript` content-type counts** — a
   real bug caught on zonetransfer.me: every nonexistent path 301-redirected
   to the same fallback page, producing 45 false-positive "found JS"
   candidates. Redirects are *not* signal here (unlike stage 4). The
   wordlist is hand-curated v1 (SecLists had no good fit — the
   promising-named JavaScript-Miners.txt turned out to be a 2017-era
   adblock filter list, verified by reading it), flagged to improve.
   **Rate-limit subtlety:** `host_count` passed to `httpx_rate_args` is
   `len(hosts) × len(BUNDLER_PATHS)` (the real per-invocation target count),
   not `len(hosts)` — this call site was missed on the first rate-limiting
   pass and caught on a second read-through of every `subprocess.run` call.

**Extraction: jsluice** (urls mode + secrets mode), run directly against JS
URLs (jsluice fetches them itself). Relative URLs are resolved against the
source JS file's own URL before becoming assets. Resolved endpoint URLs →
**new `url` assets** through the *existing* scope gate (which already
handles third-party rejection — no stage-7-specific pre-filter, even though
jsluice output is often 100+ mostly-third-party URLs). **Since Track D + B3,
jsluice also emits source records**, not metadata blobs: `endpoint` records
(with the method/query/body context B3 captured, `target_derived=1` — the
paths come from the target's own JS), `parameter` records (`target_derived=1`),
and **`secret` records** (`target_derived=1`) — a secret isn't a location, and
its **raw value is never stored**, only a capped `fingerprint` + a `raw_log_ref`
into the chmod-700 raw archive (§ State model, hard rule). `-u` is
urls-mode-only. Secrets mode hasn't been observed firing on a real file yet (a
plausible zero, built defensively either way) — E4 (§ Enrichment passes)
classifies whatever it does find, offline. gitleaks is explicitly *not* used
here (it's for git history, not deployed JS).

> **Review change (R8).** Because stage 7 extracts secrets from deployed JS
> *right now*, the recon run dir is **already** sensitive-at-rest — but run-dir
> hygiene was deferred to "once primitive is built," and the `.gitignore` rule
> is still an open to-do, against a repo with a private GitHub mirror. The fix
> brings the primitive design's posture forward to recon immediately: `chmod
> 700` on the run dir at `RunState` init + a `.gitignore` rule so run
> directories are never committed. At-rest encryption stays deferred (it would
> break `sqlite3`/`cat` inspectability — same rationale as primitive).

### Stage 8 — High-signal checks (subdomain takeover)

**nuclei**, full `-tags takeover` template set (both the `dns/` category and
the 60+ `http/takeovers/` provider fingerprints) — broad coverage chosen
deliberately over a hand-curated subset. Runs **once, after the loop exits**
(the takeover check doesn't need to run before the asset graph stabilizes),
not every pass. Confirmed-real: empty stdout + exit 0 *is* the zero-findings
signal (no sentinel line).

**⚠️ This is the codebase's one explicit exception to "verify the real tool
before writing the parser."** `parse_nuclei_jsonl()` was built defensively
from nuclei's *documented* schema, **never confirmed against a real positive
finding** — a throwaway GitHub-Pages test was blocked (no owned domain to
point DNS at, not worth buying one for a rare/low-priority finding class).
Known risk areas, all logged: exact field names/casing may differ;
nonzero-exit handling is inferred from CLI convention, not observed; and
`asset_id` FK linkage depends on nuclei's `host` field exact-string-matching
a bare hostname in `assets.db` (silently `None` if nuclei emits a
scheme/port). **This must stay flagged UNVERIFIED until a real positive
finding confirms or corrects it** — it must not quietly pass as "tested" the
way stages 4–7 are. Every real run so far has hit only the zero-findings
path.

Findings are stored in the separate `takeover_findings` table
(`add_takeover_findings()`), not as assets — every host here is already a
known in-scope asset, so there's no new asset to gate.

**C1 detection band (same stage).** After the takeover run, `run_stage8_detection()`
does a **second, broader nuclei pass** — detection-only templates
(exposures / misconfig / panels) → `recon_findings` POIs (`status="new"`,
§ State model). This is Track C's signal-quality lift: broaden nuclei beyond
takeover, but **strictly detection-only**. Credential-submitting templates
(`default-logins` and the like) are **deliberately excluded** — submitting a
credential is primitive's guarded territory, never recon's. The `recon_findings`
row trims nuclei's request/response bodies (they can carry sensitive matched
content); the verbatim output stays in the R8 raw archive.

### Stage 9 — Deep tech fingerprinting

**whatweb `-a 3`**, added as a genuinely *deeper* complement to httpx's and
katana's Wappalyzer-class detection — plugin-based (1800+ plugins) with
version-level precision for downstream CVE correlation. Its own stage
because fingerprinting depth is a distinct concern from liveness/crawling
and needs only a live host. Metadata-only, **no new assets, no scope gate**
(redirect targets are deliberately not modeled as assets — enrichment isn't
discovery, which stages 4/6 own).

**Scars:**
- **One invocation PER HOST, not batched** — a real bug (Aug 19): whatweb's
  JSON output has no field indicating which seed host a result entry came
  from, so a single batched call's flat result list can't be re-partitioned
  by host, and cross-host redirect chains got mis-attributed
  (www's stored chain wrongly included staging's 403). Per-host invocation
  makes each result list unambiguously one host's own chain. Slower (N
  processes), but correct — no way to recover attribution from whatweb's
  own output.
- whatweb writes JSON to a **file** (`--log-json`), not stdout — the only
  tool in the pipeline that does; `_scan_one_host` writes to a tempfile and
  reads it back. Output is a JSON **array** (not JSONL), with valid-but-odd
  bare `,` lines that `json.loads` handles.
- whatweb follows redirects and emits a separate entry per hop, possibly
  landing on a different/out-of-scope domain: the seed host's own entry
  populates `whatweb_tech`; other entries become plain
  `whatweb_redirect_chain` context. **Review change (R1):** this means
  whatweb `-a 3` (aggressive, multi-request fingerprinting) actually *hits*
  those off-scope hops — the module's own comment records the real chain
  ending on `digi.ninja`. The fix constrains whatweb to same-site redirects
  (`--follow-redirect=same-site`, flag **UNVERIFIED** — confirm against real
  `whatweb --help`) so in-scope redirects are still fingerprinted but off-domain
  hops aren't probed.
- **Untrusted content:** whatweb faithfully reports zonetransfer.me's
  intentionally-hostile fake `X-Powered-By` header verbatim, including a
  literal `<script>` tag — plugin string values are attacker-influenceable
  and must never be rendered unescaped downstream. (This is the recon-side
  seed of the untrusted-data discipline primitive/escalation/validator
  carry forward.)

### Stage 10 — API-schema discovery (B2)

A clean-integer stage after stage 9 (terminal until B4 added stage 11).
`stages/stage_api_discovery.py`. Full build spec:
`RECON_B2_API_SCHEMA_DISCOVERY_DESIGN.md`. Turns a machine-readable API
description into first-class `endpoint` + `parameter` records. A **record-only
producer** — no downstream recon stage consumes its output this pass (which is
exactly why it can be terminal, with none of B1's fractional-stage tension).
Seeded like stage 9 (confirmed-live in-scope hosts, on the confirmed origin).
Deterministic, **no external tool** — urllib fetch + json/yaml parse (chosen
over httpx because we need the spec *body*; PyYAML is present, so YAML specs
are handled in v1).

- **B2a — OpenAPI/Swagger.** Probe common spec paths per host; when a response
  is a **real spec by content** (`openapi`/`swagger` + `paths`) — *never* by
  status, because an SPA catch-all returns `200 text/html` (verified on Juice
  Shop, the central trap) — parse every path × method × parameter into records.
  Real 2.0 and 3.0 shapes were verified against the Swagger Petstore specs
  (basePath vs `servers[0].url`; `parameters[]` vs `requestBody...schema.$ref`;
  per-op `security`).
- **B2b — GraphQL introspection.** Probe candidate endpoints; POST a read-only
  introspection query; when a real schema returns (`data.__schema.types`),
  record the endpoint + its operation→args catalog. **Modeling note (resolved
  during build):** all GraphQL fields share `url=/graphql, method=POST`, which
  collides with `endpoints`' `UNIQUE(url, method)` — so B2b records **one**
  endpoint for the GraphQL endpoint, with the full query/mutation→args catalog
  in its metadata, plus the distinct arg names as body `parameter` records
  (not one-endpoint-per-field). Verified against a local `graphql-core` server.
  graphw00f engine-fingerprint is deferred (not installed).

**Provenance & boundary:** unlike B1's wordlist paths, the schema is
**target-authored**, so every record here is `target_derived=1` (untrusted; the
future A1 brief treats it as delimited data, R9). Same-origin (R1): endpoints
are built only on the *seeded* host's origin + the spec's base path — the spec's
own absolute `servers`/host URLs are **never** followed. Recon *reads* the
description; it never executes an operation, submits a body, or authenticates to
reach a protected spec. A described `DELETE /pet/{id}` is a lead for primitive,
never called here.

### Stage 11 — archived-JS mining (B4)

The clean-integer **terminal stage**, after stage 10. `stages/stage_archived_js.py`.
Full build spec: `RECON_B4_ARCHIVED_JS_MINING_DESIGN.md`. Resurrects endpoints,
params, and secrets from the **Wayback Machine's archived `.js` bodies** — old JS
routinely holds endpoints removed from the live app and rotated-but-informative
secrets. Two phases per host: the **CDX API** lists archived `.js` snapshots
(`original`/`timestamp`/`digest`; header-row skipped; `collapse=digest` is
adjacency-only so we also dedup by digest client-side), then each snapshot's raw
body is fetched via the **`id_`** form (the *unmodified* body — the replay form
injects a wayback toolbar that would poison jsluice) to a temp file and run through
the **reused stage-7 jsluice runners** (`base_url` set to the original URL so
relative endpoints resolve onto the target host, not the temp path — the central
correctness trap). Records are `target_derived=1` with
`metadata={source:"wayback", snapshot_timestamp, archived_url}`.

- **Passive toward the target.** Both halves hit `web.archive.org`, never the host
  — exactly the archive-querying bucket gau/waybackurls/paramspider already occupy.
  So there is **no `rate_limits.py` entry** (that module protects the *target*); the
  courtesy is toward the archive (a `MAX_SNAPSHOTS_PER_HOST` cap + sequential fetches).
- **Seeds ALL in-scope subdomains regardless of liveness** — the one divergence from
  B1/B2. A host dead *today* may still hold the archived `.js` that reveals a removed
  endpoint; that is the point.
- **Runs after stage 7** so the `INSERT OR IGNORE`/`UNIQUE(url,method)` constraint
  keeps the live stage-7 endpoint when a route exists in both, while an
  **archived-only** (removed-from-live) endpoint surfaces fresh — B4's whole value.
- **R7 fault isolation at both levels** (per-host CDX call, per-snapshot fetch), so one
  dead snapshot or one host's CDX outage never aborts the stage. ⚠️ CDX is
  intermittently slow / HTTP 000 → degrades to zero-snapshots-this-run (logged).

**Boundary:** recon *reads a public third-party archive and extracts strings.* A
resurrected `/api/internal/debug` or a rotated key fingerprint is a lead handed to
primitive as a Track-D record; recon never fetches the live host, submits input, or
sets `secret.validated`. The recon/primitive line sits exactly where stage 7 draws
it, over older data.

---

## Enrichment & finalizer passes

Beyond the numbered discovery stages, the pipeline runs a band of
**enrichment / finalizer passes** — most deterministic and offline over
already-collected state, a couple sending scope-implied active traffic. They
embody Track C (signal quality) and parts of Tracks A/E/F: recon's job isn't
just to *find* surface but to hand the hunting agents a *labeled, prioritized*
one. All obey the same invariants (return-don't-write where they add assets,
R7 fault isolation, the recon/primitive boundary). Ordered as they run:

- **F5 — reverse DNS** (`reverse_dns.py`, stage-4 band, active-ish). `dnsx -ptr`
  over discovered IPs surfaces other hostnames sharing an IP → new `subdomain`
  candidates through the normal scope gate (most are shared-hosting noise the
  gate drops). It's a **DNS-resolver** query stream, not target traffic — rated
  by the DNS-resolver cap (like stage 3's dnsx/puredns), not the target rate.
  vhost discovery + NSEC walking are named-deferred.
- **C2 — screenshots** (`stage_screenshots.py`, active). Renders each live host
  in headless Chrome via httpx's native `-screenshot`; the per-host PNG path is
  stored as trusted host metadata for the report agent + a future vision model.
  Active (a full page render per host) → scope-implied (R1), rate-bounded
  (httpx `-rl`), R7-isolated. Screenshots are **sensitive-at-rest** (a render
  can show tokens/PII), so they land under the R8 chmod-700 run dir.
- **E4 — offline secret classification** (`secret_classification.py`, offline,
  **zero network**). Labels each Track-D `secret` by `kind`/`provider` from a
  self-contained regex detector map. **The safety linchpin:** E4 must *never*
  contact a provider (that would transmit a live credential and cross the
  recon/primitive boundary), so v1 is offline **by construction** — there's no
  networking code to misconfigure. It reads the chmod-700 jsluice-secrets raw
  archive, recomputes `secret_fingerprint(value)` to re-link each row with no
  drift, classifies, and writes back `kind`/`provider`; `validated` stays NULL
  (primitive's job). A network-verifying tool (trufflehog) is a deferred upgrade,
  gated on a confirmed no-verify flag + egress isolation.
- **C5 — tech→CVE candidate flagging** (`cve_candidates.py`, offline). Turns a
  detected `(product, version)` from stage 9/stage 4 fingerprints into candidate
  CVEs → `recon_findings` (`source="cve-candidate"`). Data source: an **exact-
  version** CPE index harvested from the on-box nuclei-templates
  `classification.cpe` (+ cve-id + cvss-score); product-only CPEs (version `*`)
  are excluded (they'd flood). Running nuclei's CVE *templates* was **rejected**
  — they're exploit templates (LFI/RCE payloads), a boundary violation. A
  candidate is a prioritized lead, **never a vuln claim** (`target_derived=1`;
  the report agent must render it unconfirmed).
- **C4 — auth-surface classification** (`auth_classification.py`, deterministic,
  no traffic). Labels each `endpoint.auth_status` and writes a per-host
  `auth_model` from signals already on disk. Vocabulary extends B1/B2's
  `{NULL, "gated"}`: `gated` (response-confirmed 401/403, **never downgraded**) >
  `auth_surface` (a login/register/oauth/… path heuristic) > `public` (known-2xx,
  no auth signal) > `NULL`. Keyword matching is on **segment boundaries** (so
  `/auth` matches but `/authors` doesn't — the make-or-break trap). C4-set labels
  carry `auth_classified_by="c4"` to mark them heuristic leads vs
  response-confirmed gates.
- **F1 — URL clustering** (`url_clustering.py`, deterministic, no traffic).
  Groups templated url assets (`/product/1`, `/product/2`, …) by structural
  template (id-like segments → `{id}`, sorted query-param names) and marks a
  representative sample per cluster (min cluster size 3), so the hunting agents
  get the *shape* of a templated flood, not the raw flood — protecting
  primitive's bounded budget. Marks metadata, deletes nothing.
- **A2 — interest scoring** (`interest_scoring.py`, deterministic, no traffic).
  Scores every url/host asset from collected data into `interest_score` +
  `interest_signals` (signal→points, for explainability): path keywords
  (`admin`/`graphql`/`actuator`/`env`/… weighted), auth status, presence of
  params, secrets, services on non-standard ports, finding severity. This is the
  deterministic **feeder for A1** (the unbuilt LLM brief) — the LLM becomes an
  *editor of a ranked surface* rather than a from-scratch author. The score is
  agent-authored (trusted), a priority hint, never a vuln claim.
- **F6 — target profile digest** (`target_profile.py`, deterministic, no
  traffic). A one-page "know your target" summary (size, tech stack, WAF/CDN
  posture, auth model, notable exposures, top-interest surface) — a small cousin
  of the A1 brief that's useful *today* without any LLM. Aggregates everything
  above; writes `target_profile.json` + `target_profile.md` to the run dir.

**E5 — bounded parallelism** (`parallelism.py`) is a shared *helper*, not a
pass: `bounded_parallel_map()` runs an independent per-host function across a
bounded thread pool (default 5 workers), used by whatweb, wafw00f (4.5), and
ffuf-per-host (6.5). It is **R3-correct by construction** — each item is a
*distinct host* keeping its own per-host rate, so W concurrent hosts give
`W × per_host` (each host's own budget), never one shared budget split across
hosts. Deliberately *not* used to fan out many requests at one host (that would
break the per-host cap). R7 preserved: a per-item exception is logged and
skipped, not fatal.

**E2 / E3 — offline utility passes (standalone runners, not in `run_pipeline`).**
`diff_runs.py` (E2, `run_diff.py`) computes the set-difference between two run
dirs' `assets.db` + record tables — "what's new since last run", the highest-
value continuous-monitoring signal, made a pure offline set-difference by the
externalized-state design (secrets diffed by fingerprint, raw value never read).
`wordlist_mining.py` (E3, `run_wordlist_mining.py`) mines the target's own path
segments + parameter names into `target_derived_paths.txt` / `_params.txt`
artifacts to raise B1/stage-5 yield on a subsequent run; auto-feeding B1 in the
same pass waits on loop-until-stable.

---

## Cross-cutting themes

Five threads run through the whole recon agent and are worth naming as
themes, the way the primitive review surfaced its own:

- **Deterministic by construction — but only at the code-path level (R14).**
  Two LLM judgment points are *designed in* but both unbuilt; the running
  agent makes zero LLM calls and its logic behaves identically on identical
  input. **The review corrected an overclaim here:** the *results* are not
  reproducible run-to-run, because passive sources, CT logs, DNS, and timing
  all vary. That matters for the unbuilt loop-until-stable: its
  `sum(newly_added) == 0` termination can never fire under non-deterministic
  sources plus un-canonicalized URL variants (R6), so the loop must be built
  with canonicalization *and* a hard pass cap / diminishing-returns cutoff, not
  convergence alone. The fail-closed degraded state (all ambiguity → human)
  remains the intended operating mode until the LLM tiers land.
- **Archive first, curate second.** Raw bytes hit disk before any parser
  runs, everywhere. Re-deriving the curated layer never re-touches the
  target.
- **The stage/orchestrator boundary is rigid.** Stages consume a
  caller-filtered list and return assets-or-metadata; the caller owns scope
  classification, DB writes, and the shared report tail. This is what makes
  standalone re-runs share exact logic and keeps classification in one
  place.
- **Real tool behavior over documentation.** Every parser was written
  against confirmed real output — with one loudly-flagged exception (stage
  8). The comments preserve the scars so nobody re-learns them.
- **Target-courtesy is a first-class, per-host concern — and knows what
  it's actually protecting.** The rate subsystem distinguishes
  target-facing traffic from DNS-resolver/archive traffic and refuses to
  throttle the latter to the former's rate. Untrusted target content is
  already treated as untrusted at the recon edge.

---

## Known gaps & placeholders (authoritative for recon)

Grouped by how blocking they are. This consolidates what's scattered across
`README.md`, the stage docstrings, and `CHANGELOG.md`. **The adversarial
review (R1–R16) resolved or reclassified many of these** — items now carrying
a locked resolution are marked; see `RECON_DESIGN_REVIEW_RESOLUTIONS.md` and
the § Review resolutions summary below.

**Resolved in review — now shipped (2026-08-23):** off-scope redirect/crawl
traffic (R1), silent over-rate on a forgotten limit (R2), global-vs-per-host
rate multiply (R4), raw-archive overwrite on multi-root scopes (R5), no URL
canonicalization (R6), uneven fault isolation + unset `error` status (R7),
unprotected run dir with secrets (R8), untrusted metadata untagged (R9),
review-queue duplication (R10), certspotter single-page (R11), `js_file`
mis-gate (R13, settled first-class by Track D). These are **implemented**, not
just locked; the (R#) tags inline still point to
`RECON_DESIGN_REVIEW_RESOLUTIONS.md` for rationale. R3 is comment-only (per-host
fix landed for ffuf via B1's per-host invocation); R12/R16 deferred; R14 waits
on the loop; R15 accepted. The gaps below are what remains genuinely open.

**Structural / affects real use:**
- **Loop-until-stable not built.** `main.py` runs one pass and stops. The
  design is locked (sum `newly_added` across the discovery stages; loop while
  > 0; the once-after stages run last) but not wired in. `run_state.json`'s
  `"stable"` status is reserved and unreachable until then. ⚠️ **The locked
  `1/3/4/5/6/7` newly-added set predates the newer stages** — it must be
  revisited to include **stage 6.5** (a genuine url-asset discovery stage) and
  F5's PTR candidates before the loop is wired; 4.5/C2/9 are metadata-only and
  10 is terminal/record-only.
- **No runtime request-count enforcement** beyond per-invocation CLI flags.
  The ratio-based safety net (requests-spent : assets-gained over a window;
  a flat ceiling was rejected as wrong for large legit targets) doesn't
  exist, and its prerequisite — per-tool request-count instrumentation — is
  in progress. A pathological target could still run away.
- **Scope gate LLM tier (`llm_review.py`) not built.** Everything ambiguous
  goes to human review. Safe degraded state, larger queue.
- **Rate-limit LLM extractor (`call_llm_extractor()`) is a stub** raising
  `NotImplementedError`. Write the `rate_limit` block by hand. **(R2 changes
  the fallback:** omitting the block will no longer default silently — a run
  requires an affirmative `rate_limit` resolution, so the conservative default
  must be chosen via `resolution: "not_applicable"`.)

**Correctness items tracked:**
- **Stage 8 nuclei parser UNVERIFIED** against a real positive finding
  (see §Stage 8). The single most important thing to close the next time a
  real takeover surfaces.
- **`update_asset_metadata()` is merge-only** — stale metadata keys never
  clear between runs. Needs a versioning/key-clearing design pass.
- **amass hang not root-caused** — mitigated by partial-output salvage +
  `-timeout 8`, but the underlying intermittent hang (likely a flaky
  third-party source) recurs.
- **Whole-invocation `-rl` ≠ per-host guarantee** (R3, was "katana gap") —
  generalized in review to *every* multi-request `-rl` tool (katana, nuclei,
  the stage-7 bundler probe), not just katana. Flagged as an accepted
  limitation; per-host invocation is the deferred fix that rides with the
  request-count-instrumentation work.
- **Non-standard open ports never probed (R12)** and **SANs/CNAMEs never
  harvested (R16)** — tracked completeness items from the review, deferred.

**Tool coverage deferred (named, installed, or partly referenced):** crt.sh
as a possible second CT source; chaos (API key); gitleaks (GitHub secret
scanning, referenced but unwired); asnmap (needs a CIDR/ASN asset type);
gauplus (installed, unwired); the CTBB technique KB (schema locked,
scraper/collector unbuilt).

---

## Handoff to primitive

Recon's terminal output — the `assets.db` asset graph — is what primitive
consumes. Two seams are worth stating explicitly at the boundary, both
already reflected in `PRIMITIVE_AGENT_DESIGN.md`:

- **Sources come from recon, not rediscovery.** Primitive's
  `source_sink_map` treats recon's existing discoveries as its source
  candidates — and since **Track D** those are literal, queryable rows, not
  metadata to re-parse: `parameter` records (x8 @5, jsluice @7, B2 @10),
  `endpoint` records (jsluice @7, **ffuf @6.5**, B2 @10), `secret` records
  (jsluice @7, classified offline by E4), `service` records (naabu @4), plus
  the `recon_findings` POIs (C1/C5) and A2's `interest_score` ranking. Each row
  carries its `target_derived` provenance flag so primitive knows what to
  distrust. This keeps the recon/primitive split intact — recon enumerates,
  enriches, and prioritizes; primitive tests.
- **`scope_gate.py` is reused, not reimplemented.** Primitive's action-time
  scope re-check imports `scope_gate.py`'s classifiers (belt-and-suspenders
  on top of recon's stored classification, confirmed at the moment of
  action) and extends the same shared-infra suspicion — currently applied
  to IPs — to domains that CNAME to third-party SaaS. The IP classifier's
  "resolves-from-in-scope-host is context, not admission" rule is the
  deterministic seed of that whole posture.

The untrusted-content discipline also originates here: stage 9 already
treats attacker-influenceable plugin strings as content to be escaped
downstream, which is the recon-side instance of the "target content is data,
never instructions" rule that becomes a hard cross-agent lock once primitive
and its downstream agents ingest live-response text.

---

## Planned enhancements (roadmap — mostly shipped; three items remain)

A separate capability pass (distinct from the R1–R16 correctness review) asked
*how recon could hand the downstream agents a richer, better-prioritized attack
surface.* The recurring answer: recon finds *hosts and locations* well but
under-produced *testable surface*, and handed it off as a flat `assets.db` dump
rather than a prioritized brief. The full roadmap — six tracks (A–F), phased,
with per-item design, downstream-consumer rationale, and boundary/safety notes
— lives in `RECON_ENHANCEMENTS.md`. **As of 2026-08-23 it is almost fully
built** (Tracks C/D/E complete; most of A/B/F), and the folded stages/passes
above *are* that roadmap landing. Status by track:

- **Track A — the attack-surface brief.** **A2 (deterministic interest scoring)
  BUILT** (§ Enrichment passes) + **F6's profile digest** as a today-useful
  cousin. **A1 (the LLM brief) is the headline UNBUILT item** — it realizes the
  designed-but-unbuilt **"final review pass"** (the second of `README.md`'s two
  fixed LLM judgment points) as a curated handoff artifact. It is recon's
  **first LLM over target-derived content**, so it inherits the "content is
  data, never instructions" discipline (§ Handoff / R9 provenance). **Blocked
  on** the LLM env/endpoint from Jared; it also unblocks the scope-gate Tier-2
  and rate-limit-extractor stubs.
- **Track B — coverage. B1 (ffuf content discovery @6.5), B2a/B2b (OpenAPI +
  GraphQL @10), and B3 (jsluice method/query/body fields, via Track D) all
  BUILT** (§§ Stage 6.5, Stage 10, Stage 7). **B4 (archived-JS mining) is
  DESIGNED, not built** — blocked on Wayback CDX API downtime (verify-before-
  parser can't run); builds cleanly when IA is back.
- **Track C — signal & prioritization. COMPLETE:** C1 (detection-only nuclei +
  `recon_findings` POIs, § Stage 8), C2 (screenshots), C3 (WAF/CDN @4.5), C4
  (auth-surface classification), C5 (tech→CVE candidates). Credential-submitting
  templates stay excluded — primitive's territory.
- **Track D — first-class source records. BUILT** (§ State model) — parameter/
  endpoint/secret/service promoted from metadata blobs to queryable records,
  making the recon→primitive "sources come from recon" seam literal (and
  settling R13 in the same sitting).
- **Track E — process. COMPLETE:** E1 (richer httpx), E2 (diff runs), E3
  (target-derived wordlists), E4 (offline secret classification), E5 (bounded
  parallelism helper). **Track F — breadth:** F1 (URL clustering), F5 (reverse
  DNS), F6 (target profile) **BUILT**; **F2/F3/F4 remain** — credential-gated
  (F2 cloud/s3scanner needs AWS creds; F3 asnmap needs a PDCP key; F4 deferred
  stage-1 sources need GitHub/PDCP tokens).

**Boundary, reaffirmed:** every roadmap item — shipped or pending — stays on the
recon side. Recon *discovers, enriches, prioritizes, and flags candidates*; it
never *tests, uses a credential, or confirms a vulnerability*. Every
active-traffic addition inherited the entire R1–R16 review. **Remaining work:**
**A1** (the capstone LLM brief — needs the LLM env), **B4** (archived-JS — needs
IA uptime), **F2/F3/F4** (credential-gated breadth). Live blockers + exact
inputs needed are tracked in the `sozin-recon-roadmap-status` memory.

---

## Review resolutions summary (adversarial review, 16 findings, 2026-08-23)

Full record in `RECON_DESIGN_REVIEW_RESOLUTIONS.md`. Four were explicit Jared
calls (marked ★). **R1–R11 and R13 shipped 2026-08-23** (R13 settled first-class
by Track D); R3 is comment-only (per-host fix landed for ffuf via B1); R12/R16
deferred; R14 waits on the loop; R15 accepted + documented.

| # | Sev | Finding | Resolution |
|---|---|---|---|
| R1 ★ | High | Off-scope redirect/crawl traffic before the gate | Hybrid: httpx keeps single-GET; whatweb `--follow-redirect=same-site`; katana `-fs rdn` (flags UNVERIFIED) |
| R2 ★ | High | Forgotten prose limit → silent 5/s | Require affirmative `rate_limit` resolution; absent block → fail closed |
| R3 | High | Whole-invocation `-rl` ≠ per-host for multi-request tools | Generalize katana's flagged limitation to nuclei/bundler; per-host invocation deferred |
| R4 | High | Confirmed global limit multiplied by host count | Add `rate_limit.scope` (per_host default); global passed unscaled |
| R5 | High | Raw-archive overwrite on multi-root scopes | Per-domain filename suffix (mirror stage 9) |
| R6 ★ | High | No canonicalization before de-dupe | Conservative canonicalize at ingestion; lazy migration |
| R7 | Med-High | Uneven fault isolation; `error` never set | Uniform per-tool try/except; set `status="error"` on crash |
| R8 | Med-High | Secrets in unprotected run dir now | chmod 700 + `.gitignore` now; encryption deferred |
| R9 ★ | Med | Untrusted metadata untagged at ingestion | `TARGET_DERIVED_METADATA_KEYS` registry |
| R10 | Med | Review queue populated pre-dedup | Dedup insertion on genuinely-new / by value |
| R11 | Med | certspotter single-page | Paginate with `after=` |
| R12 | Med | Non-standard open ports never probed | Tracked completeness item (defer) |
| R13 | Med | `js_file` ghost type, broken gate path | Route through `classify_url`; keep type reserved |
| R14 | Med | Determinism overclaim; unsound loop convergence | Reframe as logic-level; loop gets pass-cap + diminishing-returns guard |
| R15 | Low-Med | `verified_by_human` never expires | Accept + document the asymmetry |
| R16 | Low-Med | SANs/CNAMEs captured but not harvested | Tracked completeness item (defer) |

---

## Decision log

| Decision | Locked as | Status |
|---|---|---|
| Recon pattern | Scripted, deterministic core; LLM only at two fixed judgment points (both currently unbuilt → zero LLM calls today) | Built |
| Pre-run gates | `verified_by_human` (load_scope raises) + `rate_limit.resolution != pending` (check_run_not_blocked raises), both fail-loud | Built |
| Scope gate | Two-tier fail-closed; tier-1 deterministic built; tier-2 LLM never auto-admits, not built | Tier 1 built |
| IP classification | Only explicit CIDR/IP match admits; resolves-from-in-scope-host is reviewer context, never scope signal; no out_of_scope IP outcome | Built |
| Rate limiting | Per-host ceiling; LLM-first extraction gate (fail-closed to blocking pending); per-tool real-flag translation; DNS-resolver traffic on a separate cap; multi-host scaling; delay-derivation for x8/whatweb | Built (extractor stubbed) |
| `CONSERVATIVE_DEFAULT_RPS` | 5 req/s/host, from real program conventions | Built |
| DNS vs target rate | `DNS_RESOLVER_RATE_LIMIT = 200` for puredns/dnsx; never the target courtesy rate | Built (bug-fixed) |
| Multi-request `-rl` per-host gap | Whole-invocation ceiling ≠ per-host guarantee; generalized (R3) beyond katana to nuclei + bundler probe | Flagged, deferred |
| Persistence | Two-tier: raw verbatim archive + curated derived state; `assets.db` SQLite, rest JSON | Built |
| `discovered_by` | JSON array, union-on-merge, backward-compatible load | Built (bug-fixed) |
| Merge-on-duplicate | Metadata + attribution merged into existing row, never dropped; stale keys never clear (flagged) | Built |
| `takeover_findings` | Separate table, no UNIQUE constraint (history wanted) | Built |
| Orchestration | One pass 1→3→4→4.5→5→6→6.5→7→8→9→10 + a finalizer band (F5/E4/C2/C5/C4/F1/A2/F6); shared `run_stage_and_report` tail; metadata-before-new-assets; seed from full graph; `persist_records` after each record-producing stage | Built |
| Loop-until-stable | Design locked (sum newly_added across discovery stages); ⚠️ locked `1/3/4/5/6/7` set predates 6.5/F5 — revisit before wiring | Not built |
| Stage/orchestrator boundary | Stages return assets-or-metadata; caller classifies + writes; standalone scripts import shared logic | Built |
| Stage 1 CT source | Cert Spotter substituted for crt.sh (outage at build); root-subdomain SAN filter | Built |
| Stage 1 amass | Passive only; no `-silent`; stale-config pre-flight; partial-output salvage; hang not root-caused | Built (partial) |
| Stage 3 | alterx→puredns(perms+bruteforce)→dnsx; permutations still re-gated | Built |
| Stage 4 | httpx (metadata + redirect-new-assets) + naabu (hosts+IPs, IP-only findings materialized) | Built |
| Stage 5 | Before crawling; paramspider (new url assets) + x8 (metadata); real-CLI fixes | Built |
| Stage 6 | katana `-jc`, no depth caps, curated-vs-raw split, two JSONL shapes | Built |
| Stage 7 | Bundler probe (200+JS-content-type only) + jsluice urls/secrets | Built |
| Stage 8 | nuclei full takeover set, runs once; **parser UNVERIFIED** | Built, unverified parser |
| Stage 9 | whatweb `-a 3`, per-host invocation (attribution fix), file-output, untrusted strings | Built |
| Track D (source records) | parameters/endpoints/secrets/services sibling tables; per-record `target_derived`; inherit parent scope; `persist_records` links + drops out-of-scope; settles R13 | Built |
| Stage 4.5 (C3) | cdncheck (offline) + wafw00f (active per-host WAF-trigger probe); trusted WAF/CDN host metadata; detect/label never engage | Built |
| Stage 6.5 (B1) | ffuf content discovery, **per-host invocation = true per-host `-rate`** (R3 closed for ffuf); url assets + endpoint records; native `-sf`/`-maxtime-job` WAF retreat + `waf_suspected` flag; ⚠️ 200-JS-challenge blind spot | Built |
| Stage 10 (B2) | OpenAPI/Swagger (B2a) + GraphQL introspection (B2b); content-based spec detection; record-only terminal stage; `target_derived=1`; same-origin, never executes an operation | Built |
| C1 detection band | detection-only nuclei (exposures/misconfig/panels) → `recon_findings` POIs; credential-submitting templates excluded | Built |
| Enrichment/finalizer passes | F5 reverse-DNS, C2 screenshots, E4 offline secret classification (zero-network by construction), C5 tech→CVE candidates (offline), C4 auth-surface, F1 URL clustering, A2 interest scoring, F6 target profile | Built |
| E5 bounded parallelism | shared per-host helper (whatweb/wafw00f/ffuf); R3-correct by construction (distinct hosts, own rate); R7 per-item isolation | Built |
| E2 / E3 (offline utilities) | diff-runs + target-derived wordlist mining; standalone runners, not in `run_pipeline` | Built |
| Roadmap remaining | A1 (LLM brief — needs LLM env), B4 (archived-JS — Wayback down), F2/F3/F4 (credential-gated) | Not built |

---

## See also

- `RECON_DESIGN_REVIEW_RESOLUTIONS.md` — the finding-by-finding record of the
  adversarial review (R1–R16), with rationale, the four Jared calls, and the
  full doc cascade
- `RECON_ENHANCEMENTS.md` — the capability roadmap (tracks A–F, phased): how to
  hand the downstream agents a richer, better-prioritized attack surface
- `RECON_TRACK_D_DESIGN.md` — the first-class source-record model (§ State
  model) design-lock + build record
- `RECON_B1_CONTENT_DISCOVERY_DESIGN.md` / `RECON_B2_API_SCHEMA_DISCOVERY_DESIGN.md`
  — the build specs for stages 6.5 and 10; per-item C/E/F specs sit alongside
  (see `CLAUDE.md` §13), and C2/E5/F5/F6 are captured in their module docstrings
- `README.md` — what the pipeline does, how to run it, the authoritative
  known-gaps list
- `CONTRIBUTING.md` — the design-locked-before-code, fail-closed-always,
  staged-verification discipline this document reflects
- `STATE_SCHEMA.md` — the exact on-disk contract for every state file
- `PRIMITIVE_AGENT_DESIGN.md` — the opposite pattern that consumes recon's
  asset graph
- `pipeline_schematic.mermaid` — full visual architecture, built vs.
  placeholder
- `CHANGELOG.md` — dated history of what shipped, what broke, and every
  real-run bug fix referenced above
- Individual stage module docstrings — each documents its own non-obvious
  decisions in the detail this document summarizes
