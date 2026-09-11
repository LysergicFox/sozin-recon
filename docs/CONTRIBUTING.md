# Contributing to sozin-recon

This document captures how work gets done on this project — the process
and principles behind the code, not the code itself. Read this before
building a new stage or extending an existing one. `../README.md` covers
what the recon engine does and how to run it; this covers how to safely
change it.

> **Repo layout note:** **shipped project docs live in `docs/`** (tracked); the
> single-stage re-run scripts live in `testing/` (`run_*.py`, tracked); `README.md`
> stays at the repo root. The design/planning docs referenced throughout this file
> (`RECON_AGENT_DESIGN.md`, `RECON_ENHANCEMENTS.md`, `RECON_RESOLUTIONS_IMPL_PLAN.md`,
> `RECON_TRACK_D_DESIGN.md`, the `RECON_B1`/`RECON_B2` build specs, the R1–R16 review
> record) live in `design_docs/`, which is **local-only / git-ignored** — dev history
> kept on disk, not shipped in the repo.

---

## Design-locked before code

Architecture decisions get settled in conversation and explicitly written
down *before* implementation starts. This is what makes it possible to pick
work back up across sessions without re-litigating settled questions.

In practice:
- A design is "locked" when it's been discussed, alternatives considered,
  and a specific choice written down with its rationale.
- Deferred items are **named and tracked**, not silently dropped (README's
  known-gaps list or the CHANGELOG - not someone's memory).
- If you're about to write code implementing a design that hasn't been
  locked yet, stop and lock the design first. Recent examples: the recon
  agent's retroactive capture + 16-finding review, and **Track D's
  source-record model** (`RECON_TRACK_D_DESIGN.md`, locked then built
  2026-08-23).

---

## Staged verification discipline

Every stage, every change, follows the same sequence:

1. **Build** the code.
2. **Mocked-subprocess tests** (exercise logic without real tools/targets).
3. **Real run** against a real, consented target (`zonetransfer.me` is the
   standing recon target).
4. **Fix any real bugs found.** There will be real bugs.
5. **Second real run to confirm clean.**

**Why step 3 always finds something:** a single sample invocation, or even a
careful reading of `--help`, does not exercise every real code path. Examples
on record: paramspider has no `-o`; x8 needs an explicit `-w`, emits a text
preamble, uses `found_params`; katana's JSONL has two line shapes; a bundler
probe treated 301s as "found JS"; whatweb's multi-host batching produced
cross-host attribution errors. None were catchable from docs alone.

**Never assume a tool's behavior from its documentation. Run it.** This
applies to every tool in the recon enhancement roadmap. **ffuf (B1) and the OpenAPI/GraphQL formats (B2) were VERIFIED
this way 2026-08-23** — real ffuf 2.1.0-dev (`content-type` key is hyphenated;
`-sf`/`-maxtime-job` exit 0 and only signal early-stop on stderr), real Swagger
Petstore 2.0/3.0 shapes, and a real graphql-core introspection response, each
confirmed before its parser was written. **More tools VERIFIED this way 2026-08-23**
(Track C/E build): real cdncheck (`-jsonl -resp`) + wafw00f (`-a -f json -o`,
example.com→Cloudflare — and wafw00f was found to send attack-signature probes, so it's
run per-host/scoped), dnsx `-ptr -json` (F5), httpx `-screenshot -system-chrome` (C2),
and the nuclei detection JSONL + nuclei-template CPE metadata (C1/C5). The nuclei
**detection** JSONL parser (C1) — long flagged UNVERIFIED — is **now confirmed** against
real positive output. (The separate **takeover**-finding parser in `stage8_takeover.py`
stays UNVERIFIED until a real positive takeover finding — see README known-gaps.)
**The Wayback archive surface (B4 / stage 11) was VERIFIED this way 2026-08-24** — real
CDX (`output=json` is a list-of-lists whose **first row is a header**; `collapse=digest`
is **adjacency-only**, so identical non-adjacent captures survive and we dedup by digest
client-side; CDX is intermittently slow / HTTP 000 → degrade to zero-snapshots-this-run),
the raw-snapshot **`id_`** form (returns the *unmodified* body vs. the replay form's
injected wayback toolbar — mandatory), and **jsluice over a local file** (reads a file
path as its positional arg; `-u` is `--unique`, **not** a fetch flag — stage 7's old
docstring wrongly implied a fetch). End-to-end confirmed on `demo.owasp-juice.shop`.
Remaining tools stay UNVERIFIED until confirmed against the real CLIs: feroxbuster,
graphw00f, gowitness, trufflehog (E4 uses an offline regex map instead), and the
credential-gated F2/F3/F4 tools (s3scanner needs AWS creds, asnmap needs a PDCP key). **The R1 resolution's flags
(`whatweb --follow-redirect=same-site`, `katana -fs rdn`) were VERIFIED this
way on 2026-08-23** — confirmed against the real CLIs (`same-site` is a real
whatweb WHEN value; `-fs rdn` is real and katana's default) and behaviorally
on zonetransfer.me. Certspotter's live `after=` pagination (R11) remains
⚠️ UNVERIFIED (anon rate limit); its no-new-ids guard fails safe.

---

## Fail closed, always

Hard rules, not preferences:

- **Scope decisions.** Anything the deterministic tier can't confidently
  classify goes to `needs_review.json`. The planned LLM tier can only flag,
  never auto-admit. An asset never becomes `in_scope` without a deterministic
  rule or a human. Track-D source records inherit their parent asset's scope;
  they are dropped when the parent is out_of_scope, never independently
  auto-admitted.
- **Rate limits.** A low-confidence extraction blocks (`resolution:"pending"`)
  rather than guessing. **(R2) an *absent* `rate_limit` block now blocks the
  run too** — the conservative default (`resolution:"not_applicable"`) must be
  chosen, never fallen into by omission.

If you add a new judgment point, define the fail-closed behavior *before* the
success path.

---

## Fault isolation — one tool failing shouldn't kill the run (R7)

Stage 1 wraps each tool runner in try/except and continues; stages 5/7 wrap
their per-item loops; **the R7 resolution brought stages 3/4/6/8/9 up to this
bar** (stage 3's within-leg alterx→puredns→dnsx chains stay intentionally
all-or-nothing; its independent legs are isolated), and made `run_state`'s
`error` status actually get written on an unhandled failure (with
`failed_at_stage`). New stages must isolate a single tool's failure or
explicitly document themselves all-or-nothing.

---

## Two-tier persistence

Raw tool output is archived verbatim (`raw/stageN_toolname.json`); everything
else is derived from those archives. A curated-layer schema change never
requires re-running a tool. **(R5) suffix the raw filename per target** if a
stage loops a tool over multiple targets (stage 1/3/9 do; stage 7's jsluice
now does too, so `secret.raw_log_ref` points at a stable per-source file).

**Source records vs metadata (Track D):** the units the hunting agents consume
— parameters, endpoints, secrets, services — are first-class rows in their own
tables, not metadata blobs. A stage that produces them returns them as records
(the 3rd element of its return tuple, `{"parameters":[...], ...}`) for
`main.persist_records()` to link + persist. **Never store a raw secret value in
`assets.db`** — store a capped fingerprint + a `raw_log_ref` pointer (the full
value stays only in the chmod-700 raw archive). `validated` on a secret is left
for a downstream consumer to set — recon never confirms a secret.

---

## Caller filters, stage consumes

Each stage is seeded by the orchestrator from the **full current asset graph**
(`state.load_assets()` filtered as needed), not just the previous stage's
fresh finds — this matters once loop-until-stable runs a stage across passes.

---

## Standalone re-run scripts import, never duplicate

`testing/run_stage*_only.py` re-run one stage against an existing `assets.db`
by importing the shared `run_stageN_and_report()` from `main.py` — they never
reimplement it. Two implementations drift.

---

## Before you build a new stage

1. Is the design locked? If not, lock it first.
2. Have you run the real CLI(s) with real flags against a real target — not
   just `--help`?
3. Does the stage seed itself from the full current asset graph?
4. Does new-asset output go through `run_stage_and_report()` (scope-gate →
   dedupe/merge → log → update run_state)? Don't reimplement it.
5. Does it archive raw output before deriving curated data — with a per-target
   filename suffix if it loops (R5)?
6. If it produces **source records** (param/endpoint/secret/service), does it
   return them for `persist_records()` — and, for secrets, store only a
   fingerprint + `raw_log_ref`, never the raw value?
7. If it makes target requests, is there a rate translation in `rate_limits.py`,
   and does it protect the *target* (not a resolver/archive API)? Does the tool
   send multiple requests per host (R3)?
8. Does it isolate a single tool's failure (R7), or is it deliberately
   all-or-nothing?
9. If it sends active traffic, does it stay on the recon side (discover/enrich/
   prioritize, never test/exploit/use-a-credential) and respect scope-covers-
   traffic (R1)?
10. Mocked tests → real run → fix → second real run.
11. Anything deferred named explicitly in README known-gaps or the CHANGELOG.

---

## Documentation upkeep

Doc changes are staged in `docs/DOCUMENTATION_UPDATES.md` and flushed into the
target docs on demand ("apply the doc updates"), to keep large-doc churn down.
When a change lands, log it there; when you flush, update the affected doc:

| Change | Update |
|---|---|
| `state.py` schema change | `docs/STATE_SCHEMA.md` + `../README.md`'s state-file table |
| A stage moves placeholder ↔ built | `../README.md`'s pipeline table |
| A real-run bug or fix | `docs/CHANGELOG.md` |
| A new/closed known gap | `../README.md` known-gaps |
| A locked design decision / review | the relevant design doc + `docs/CHANGELOG.md` |

---

## Committed future items — do not let these drop

- **Recon enhancement roadmap** (`RECON_ENHANCEMENTS.md`) — Track D shipped
  2026-08-23; Track B (content/API discovery) is next and fills the `endpoint`
  table. Every item stays on the recon side (discover/enrich/prioritize/flag
  candidates), never test/exploit/confirm. Active-traffic items inherit R1–R16.
- **Untrusted-data handling** — target-derived text is untrusted data
  everywhere. Recon's hook: the R9 registry + Track-D records' `target_derived`
  flag; if a review-pass LLM is ever added, it must treat target content as
  delimited data, never instructions.

---

## See also

- `../README.md` — what the recon engine does, how to run it
- `STATE_SCHEMA.md` — exact on-disk file formats
- `CHANGELOG.md` — dated history
- Design/planning docs in `../design_docs/`: `RECON_DESIGN_REVIEW_RESOLUTIONS.md`
  (R1–R16), `RECON_AGENT_DESIGN.md`, `RECON_ENHANCEMENTS.md`,
  `RECON_RESOLUTIONS_IMPL_PLAN.md`, `RECON_TRACK_D_DESIGN.md`,
  `RECON_B1_CONTENT_DISCOVERY_DESIGN.md`, `RECON_B2_API_SCHEMA_DISCOVERY_DESIGN.md`
