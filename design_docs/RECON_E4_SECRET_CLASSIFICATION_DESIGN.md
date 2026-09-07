# E4 — secret classification, OFFLINE (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN-LOCKED, NOT BUILT.** Realizes **E4** of `RECON_ENHANCEMENTS.md`
(Track E — "process & tooling"). Turns D3's `secret` records from raw,
opaque hits into **typed** findings: each secret is labelled by **`kind`**
(aws_access_key, stripe_secret_key, github_pat, jwt, …) and **`provider`** (AWS,
Stripe, GitHub, …) so primitive receives a deduped, prioritized credential
surface instead of a pile of unclassified strings. Nothing here is coded yet.

This doc follows the same discipline every existing stage was built to —
**verify the real tool before writing the parser**, fail-closed, fault-isolated
(R7), R8 at-rest hygiene — with one property elevated above all others because
it is the whole point of E4:

> **E4 makes ZERO network calls. Classification is entirely OFFLINE. A
> misconfiguration here does not merely produce bad data — it crosses the
> recon/primitive boundary by transmitting a live credential to its provider.
> That is the single safety-critical property of this item, and it is
> fail-closed: if offline operation cannot be *guaranteed*, E4 does not run.**

---

## Why E4, and the one thing it must never do

Stage 7's jsluice `secrets` mode *extracts* candidate secret strings and stores
each as a D3 `secret` record — a capped `fingerprint` + a `raw_log_ref` pointer,
with `kind` set to whatever jsluice reported (often `"unknown"`) and `provider`
left `NULL` (the E4-reserved column). Today that record tells primitive "there
is *a* secret in this JS file" but not *what kind* — so primitive can't
prioritize (an exposed AWS root key vs a public reCAPTCHA site-key are worlds
apart) and can't dedup by provider.

E4 closes that: an **offline classifier** reads each secret's raw value, labels
it by kind + provider, and writes those two columns back. That is the entire
scope. **The line E4 must never cross:**

- **Recon classifies. Primitive validates.** *Validating* a secret means
  **sending it to its provider** to see if it's live — which (a) usually targets
  a **third-party service outside the program's scope**, and (b) is precisely the
  guarded, data-capped, refuse-capable action primitive's design reserves for
  itself. `secret.validated` stays **`NULL`** after E4; it is populated
  **downstream by primitive**, never by recon.
- E4 never *uses* a credential, never authenticates, never touches a network
  socket. It reads a local file and pattern-matches. That's it.

---

## The linchpin — how "offline" is *guaranteed*, not hoped for

A classifier that has network verification built in (trufflehog does, and it is
**on by default**) is one missing flag away from POSTing a customer's live AWS
key to `sts.amazonaws.com`. A flag is not a guarantee — a typo, a version bump
that renames the flag, a default that flips, and the boundary is silently
crossed with a real credential in the payload. So E4's offline property is
established by **construction and defense-in-depth**, in this priority order:

1. **Prefer a classifier that has no network capability at all** (see Tool
   evaluation — the recommended v1 is a self-contained regex/detector map, which
   *cannot* make a network call because it contains no networking code).
2. **If an external tool is used, the no-verify flag is necessary but NOT
   sufficient** — it runs additionally under **network-egress isolation** (a
   sandbox with no network namespace, e.g. `unshare -n` / a firewalled subprocess
   so a stray connect() *fails* rather than *succeeds*). The flag prevents the
   intent; the isolation prevents the capability.
3. **Fail-closed:** if E4 cannot affirmatively confirm the offline mode is in
   effect (flag present AND — for an external tool — egress blocked), it **does
   not classify**. It leaves `kind`/`provider` as-is and logs a skip. It never
   "tries and sees." An unclassified secret is a tolerable gap; a transmitted
   secret is a boundary breach.

This mirrors `CONTRIBUTING.md`'s "define the fail-closed behavior *before* the
success path" and the scope-gate's "an absent rate_limit block blocks the run":
the safe default is chosen, never fallen into by omission.

---

## The central mechanic — E4 reads the RAW ARCHIVE, not the fingerprint

This is the design's most important structural constraint, forced by D3's data
model, and it must be understood before anything else:

- **The raw secret value is NEVER in `assets.db`.** The `secrets` table stores
  only `fingerprint` (`first4…last4|len=N|sha256=<16hex>` — capped, irreversible)
  and `raw_log_ref` (a pointer). E4 **cannot classify from the fingerprint** —
  it is lossy by design (you cannot regex `AKIA…MPLE|len=20|sha256=…` back into
  an AWS key).
- **The raw value lives only in the chmod-700 raw archive** that `raw_log_ref`
  points at: `raw/stage7_jsluice_secrets_{sanitized_source}.json` (R8-protected,
  inside the run dir). Reading that archive is **fine** — it is local, offline,
  and already owner-only. Classifying its contents is offline work.
- So E4's read path is: **`secret.raw_log_ref` → open the raw archive under
  `state.run_dir` → recover the raw value → classify OFFLINE → write back
  `kind`/`provider`.** The raw value is held in memory only long enough to label
  it; it is **never written back** into `assets.db` (only the two labels are).

### Mapping a classified hit back to the exact Secret row

The raw archive is jsluice `secrets`-mode JSONL — one finding per line, the same
lines stage 7 archived. E4 maps each finding back to its `secrets` row **by
recomputing the fingerprint**, reusing the *exact same helpers stage 7 used to
build the row* (import them, never reimplement — `CONTRIBUTING.md`):

1. For each secret row, resolve `raw_log_ref` to a file under `state.run_dir`.
2. Read that file's JSONL findings.
3. For each finding, extract the candidate value with
   **`stage7_js_extraction._jsluice_secret_value(finding)`** (the same
   `_SECRET_VALUE_KEYS` heuristic stage 7 fingerprinted with).
4. Compute **`state.secret_fingerprint(value)`** and match it against the row's
   stored `fingerprint`. A match identifies the value that produced this row.
   (`secrets` is `UNIQUE(asset_id, fingerprint)`, and `raw_log_ref` already
   scopes to one source file, so `(raw_log_ref, fingerprint)` is an unambiguous
   key.)
5. Classify `value` offline → `(kind, provider)` → write back to that
   `secret_id`.

Because E4 extracts the value with stage 7's own helper and fingerprints with
the same function, the recomputed fingerprint is guaranteed to match the row
stage 7 wrote — no drift. If jsluice's secret-dict shape (still **UNVERIFIED** —
never observed firing on a real file; see stage 7's docstring) turns out to
differ, that heuristic is the *single* place to fix, and both stage 7 and E4
inherit the fix.

---

## Locked decisions (recommended; Jared's calls flagged)

1. **Classifier: a self-contained, in-process regex/detector map for v1 —
   offline by construction.** ← **recommended.** Rationale below (Tool
   evaluation). A parser we control is testable, has *no* networking code to
   misconfigure, needs no new tool install, and mirrors B2a's locked choice ("no
   external tool; a parser we control is testable"). **trufflehog (no-verify +
   egress isolation) is the deferred breadth upgrade**, not v1. ← *Jared call: v1
   regex map vs adopt trufflehog now under isolation.*
2. **Placement: a standalone post-stage-7 enrichment pass** (re-runnable, reads
   the `secrets` table + raw archives), **not** inline in stage 7. ← *Jared call;
   recommended standalone.* Rationale under Placement.
3. **Writes back exactly two columns — `kind` and `provider`.** Never a raw
   value, never `validated` (primitive's). New `RunState` method
   `update_secret_classification(secret_id, kind, provider)` (state.py change).
4. **Reuse stage 7's value-extraction + `secret_fingerprint`** to map hits to
   rows (decision above) — import, never duplicate.
5. **Fail-closed on any offline-uncertainty, per-secret fault isolation (R7).**
   Can't confirm offline → classify nothing. Can't extract a value / archive
   missing / no detector matches → leave that row's `kind`/`provider` unchanged,
   log, continue to the next row.
6. **No new assets, no new records, no scope gate.** E4 only *updates* existing
   `secret` rows. Records inherit their parent's scope already (D3); E4 changes
   no scope.

---

## Tool evaluation — trufflehog no-verify vs a self-contained detector map

Both are named as acceptable in the roadmap ("trufflehog's detectors in
no-verification mode, or an equivalent"). Weighed against E4's linchpin:

### Option A — trufflehog in no-verification mode

- **Install status (verified 2026-08-23): NOT installed** (`command -v
  trufflehog` → empty). **Prerequisite** if chosen.
- **The offline flag is SAFETY-CRITICAL and currently UNVERIFIED.** trufflehog v3
  **verifies by default** (makes live provider calls). The flag that *disables*
  network verification is believed to be **`--no-verification`** on the scan
  subcommand (e.g. `trufflehog filesystem <path> --no-verification --json`), with
  `--only-verified` being the *opposite* (keep only network-confirmed hits — must
  NOT be used). **⚠️ This flag name and its exact semantics MUST be confirmed
  against the real installed CLI (`trufflehog --help` + `trufflehog filesystem
  --help`) before any code is written** — this is the exact verify-real-tool
  discipline every prior stage was bitten by, elevated here to safety-critical.
  Do not trust the flag from this doc or from memory.
- **The flag alone is insufficient** (see Linchpin): even with
  `--no-verification`, run it under egress isolation as defense-in-depth, and
  fail-closed if isolation can't be established.
- **Upside:** ~800 curated, maintained detectors — far broader kind/provider
  coverage than we'd hand-write; native `--json` output with a `DetectorName`
  field that maps cleanly to `kind`/`provider`. Run over the raw-archive dir
  (`trufflehog filesystem raw/ --no-verification --json`), parse each result's
  `DetectorName` + `Redacted`/`Raw`, then map its value back to a row by
  fingerprint (same mechanic).

### Option B — self-contained regex/detector map (RECOMMENDED for v1)

- **Offline by construction — the strongest possible fail-closed.** A Python dict
  of `{provider, kind, compiled_regex}` entries has *no networking code*; it
  *cannot* transmit a secret even if misconfigured. The linchpin is satisfied by
  the absence of the capability, not by a flag.
- **No new tool, no install, no version-drift risk on a safety-critical flag.**
- **Testable and controllable** — exactly B2a's reasoning for parsing OpenAPI
  ourselves rather than shelling to a tool.
- **Cost:** narrower coverage than trufflehog's detector corpus, and a
  maintenance burden as providers add formats. Acceptable for v1: a curated set
  covers the high-value, unambiguous, high-confidence patterns primitive most
  wants triaged — e.g.:

  | provider | kind | pattern (illustrative — confirm before coding) |
  |---|---|---|
  | AWS | aws_access_key | `AKIA[0-9A-Z]{16}` (also ASIA/AGPA/AIDA prefixes) |
  | AWS | aws_secret_key | 40-char base64 in an AWS context |
  | Stripe | stripe_secret_key | `sk_live_[0-9A-Za-z]{24,}` / `rk_live_…` |
  | Stripe | stripe_test_key | `sk_test_[0-9A-Za-z]{24,}` |
  | GitHub | github_pat | `ghp_[0-9A-Za-z]{36}` (also `gho_`/`ghs_`/`ghr_`) |
  | Google | google_api_key | `AIza[0-9A-Za-z_\-]{35}` |
  | Slack | slack_token | `xox[baprs]-[0-9A-Za-z-]+` |
  | generic | jwt | `eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+` |
  | Twilio | twilio_key | `SK[0-9a-f]{32}` |

  Kept as a **module constant** so E3-style curation (and a later trufflehog
  swap) can extend it without a rewrite.

**Recommendation: ship Option B (regex map) as E4 v1** — its offline guarantee is
structural, it adds no tool and no safety-critical flag to get wrong, and it
matches the project's established "parse it ourselves when the format is simple
and the parser is testable" posture. **Defer Option A (trufflehog) as a breadth
upgrade**, and *only* behind (i) a real-CLI-confirmed `--no-verification` and
(ii) network-egress isolation. The classifier is a pluggable function either way,
so the swap is localized.

---

## Placement — a standalone post-stage-7 enrichment pass

E4 reads stage 7's secret raw archives, so it **runs after stage 7**. Two shapes
were considered:

- **Inline in stage 7** (classify each finding as the `Secret` is built — the raw
  value is already in hand for fingerprinting). *Rejected as primary:* couples the
  classifier to stage 7, re-runs classification on every stage-7 run, and can't be
  re-run independently when the detector map improves.
- **Standalone enrichment pass** (RECOMMENDED) — a small step that loads the
  `secrets` table, reads each row's `raw_log_ref` archive, classifies, and writes
  back. **Re-runnable** against an existing `assets.db` (like the
  `run_stage*_only.py` scripts) whenever the detector map is extended or
  trufflehog is later adopted, with **no re-crawl and no re-run of jsluice** — the
  exact benefit two-tier persistence exists to provide (`CONTRIBUTING.md`: "a
  curated-layer schema change never requires re-running a tool"). It also keeps
  stage 7 unchanged and E4's offline classifier cleanly isolated.

### Where it slots in `main.py`

A terminal enrichment step after the last content/API-discovery stage, e.g.:

```python
run_stage9_and_report(state, scope)
run_content_discovery_and_report(...)      # B1 (6.5, already earlier)
run_api_discovery_and_report(...)          # B2 (stage 10)
enrich_secrets_and_report(state)           # NEW — E4, OFFLINE, no traffic
state.update_run_state(status="stage_complete", passes_completed=1)
```

`enrich_secrets_and_report(state)` loads secrets, invokes the classifier, and
calls `state.update_secret_classification(...)` per matched row. It sends **no
target traffic**, so it takes **no `scope`/`patterns` and no rate args** — a
notable and deliberate contrast with every active stage (see R-inheritance).
Provide a `testing/run_enrich_secrets_only.py` re-runner that imports
`enrich_secrets_and_report` (never reimplements it).

### The module — `stages/stage_secret_classification.py`

```python
def classify_secret(value: str) -> tuple[str | None, str | None]:
    """OFFLINE. (kind, provider) for a raw secret value, or (None, None) if no
    detector matches. Pure function — NO I/O, NO network, deterministic."""

def enrich_secrets(state: RunState) -> int:
    """Load secrets; for each, read raw_log_ref archive under state.run_dir,
    recover the value via stage7._jsluice_secret_value, match by
    state.secret_fingerprint, classify_secret(value) OFFLINE, and
    state.update_secret_classification(secret_id, kind, provider). Per-secret
    try/except (R7). Returns count classified. Never writes a raw value; never
    sets `validated`."""
```

`RunState.update_secret_classification(secret_id, kind, provider)` (new): a
targeted `UPDATE secrets SET kind=?, provider=? WHERE secret_id=?` — the only new
state.py surface. Dedup is a non-issue: E4 creates no rows. The same physical
secret found in two JS files is two rows (different `asset_id`, same
`fingerprint`) and stays two rows — legitimately distinct *locations*; classifying
both simply makes the "group by provider" view primitive wants possible at query
time.

---

## Fail-closed behavior (define before the success path)

- **Offline not guaranteed** → classify nothing, log, exit clean. (For Option A:
  `--no-verification` not confirmed on the real CLI, or egress isolation couldn't
  be established. For Option B: n/a — offline by construction.)
- **Raw archive missing / unreadable** for a row → skip that row, log, continue.
- **Value not extractable** from a finding → leave `kind`/`provider` unchanged.
- **No detector matches** → leave `provider` `NULL`; leave `kind` as jsluice set
  it (or `"unknown"`). A non-match is "we couldn't type it," not an error.
- **Per-secret fault isolation (R7):** one row raising never aborts the pass; wrap
  the whole pass so a catastrophic failure marks nothing and moves on.
- **`validated` is never touched** — it is and stays `NULL` (primitive's field).

---

## Boundary — classify offline, NEVER validate

- E4 **labels**; it does not **confirm**. `kind`/`provider` are E4's;
  `validated` is primitive's and stays `NULL`.
- E4 makes **zero network calls** and never *uses* a credential. Live validation
  (sending the secret to its provider) is primitive's guarded, refuse-capable,
  usually-out-of-scope action — E4 does not go near it.
- Everything E4 reads is target-authored (jsluice output, `target_derived=1`);
  the derived `kind`/`provider` labels are **our determination** about that
  content (agent-authored, trusted metadata), the same way B1's `waf_suspected`
  is our determination, not target text. The raw value itself is never surfaced
  into `assets.db` — only the labels.

---

## Rate / R-inheritance

E4 is the rare enrichment that **sends no target traffic at all**, so its
R-profile is deliberately unlike every active stage:

- **No rate translation, no scope gate, no `-rate` args** — there is no target
  request to bound. (This *is* the point: any request to bound would be a
  boundary violation.)
- **R5 (per-target raw)** — n/a; E4 produces no new raw tool output. It *reads*
  stage 7's existing per-source raw files.
- **R7 (fault isolation)** — per-secret try/except + whole-pass guard.
- **R8 (at-rest hygiene)** — E4 reads the chmod-700 raw archive and writes only
  labels back to `assets.db` (itself in the R8 run dir). The raw value never
  leaves memory and is never re-persisted.
- **R9 / untrusted-by-default** — labels are agent-authored (trusted); the source
  content stays `target_derived=1`; the A1 brief treats the underlying secret
  content as delimited data.

---

## Tests

**Mocked / offline tier — `testing/test_secret_classification.py`:**

- **`classify_secret` truth table with FAKE, well-formed test values** (never a
  real credential): the canonical AWS docs example `AKIAIOSFODNN7EXAMPLE` →
  `(aws_access_key, AWS)`; `sk_test_4eC39HqLyjWDarjtT1zdp7dc` →
  `(stripe_test_key, Stripe)`; `ghp_` + 36 chars → `(github_pat, GitHub)`; a
  synthetic `eyJ…​.eyJ…​.sig` → `(jwt, generic)`; a non-secret string →
  `(None, None)`.
- **Round-trip mapping:** build a mock raw jsluice-secrets archive holding a
  finding, construct the matching `Secret` row with
  `secret_fingerprint(_jsluice_secret_value(finding))` (exactly as stage 7 does),
  run `enrich_secrets`, assert the row's `kind`/`provider` are set and the
  **fingerprint is unchanged** and **`validated` is still `NULL`** and **no raw
  value appears anywhere in `assets.db`**.
- **Fail-closed:** missing raw archive → row untouched, no raise; unmatchable
  value → `provider` stays `NULL`; per-secret exception isolated (one bad row
  doesn't stop the rest).
- **Zero-network assertion (the safety test):** patch `socket.socket` (and, for
  Option A, assert the subprocess argv contains the confirmed no-verify flag) and
  assert `enrich_secrets` completes having opened **no** network connection. For
  Option B this is trivially true by construction; keep the test anyway as a
  regression guard against a future trufflehog swap.

**Real-tool verification (BEFORE the parser, per `CONTRIBUTING.md`) — only if
Option A/trufflehog is chosen:**

- `trufflehog --help` + `trufflehog filesystem --help` → **confirm the exact flag
  that disables network verification** (candidate `--no-verification`; confirm it,
  and confirm `--only-verified` is not silently defaulted on), the `--json` output
  shape, and the `DetectorName` field values → the kind/provider map.
- One real run over a directory containing **fake** test secrets, **with egress
  blocked**, confirming (via a packet/connection check) that **no outbound
  connection is attempted** even against a detector whose provider is reachable.
- Only then write `_parse_trufflehog_json` + the DetectorName→(kind,provider) map.

For Option B (recommended v1) there is no external CLI to verify; the "real"
step is validating each regex against real-world example formats from provider
docs (fake values only).

---

## Doc cascade (flush when built)

- **`STATE_SCHEMA.md`** — `secrets.kind`/`secrets.provider` now populated by E4
  (offline classification); note `validated` stays primitive's; new
  `update_secret_classification` method; the labels are agent-authored/trusted.
- **`README.md`** — the E4 enrichment step in the pipeline flow; note it sends no
  traffic.
- **`pipeline_schematic.mermaid`** — a secret-classification node reading stage 7
  raw archives → `secrets` table (offline).
- **`CONTRIBUTING.md`** — reaffirm verify-real-tool + fail-closed; add the
  offline-only + egress-isolation note if trufflehog is adopted.
- **`CHANGELOG.md`** — DESIGN → BUILT entry.
- **`RECON_ENHANCEMENTS.md`** — flip **E4** from roadmap to BUILT; note validated
  stays primitive's.
- **`RECON_AGENT_DESIGN.md`** — fold E4 into the stage inventory (with the
  Track-D / stage-10 fold already owed).

---

## Explicitly OUT of scope for E4

- **Live validation of any secret** — sending it to its provider (primitive's
  guarded action; `secret.validated` stays `NULL`).
- **Any network call whatsoever.**
- **Using / authenticating with a credential.**
- **Creating new secret rows or re-running jsluice** — E4 only enriches existing
  rows from the existing raw archives.
- **Surfacing the raw value into `assets.db`** — only `kind`/`provider` labels.
- **trufflehog adoption without a real-CLI-confirmed no-verify flag AND egress
  isolation** — deferred, gated on both.
- **Mining archived JS bodies (B4) or spec example values (B2 §7) for secrets** —
  those *produce* new secret records; E4 only *classifies* what stage 7 produced.
  When those land, they route their secrets through the same D3 model and E4
  classifies them for free.

---

## Open questions for Jared

1. **v1 classifier: regex map (recommended, offline-by-construction) or adopt
   trufflehog now** (broader detectors, but a safety-critical flag to confirm +
   an install + egress isolation to build)?
2. **Egress isolation mechanism** if trufflehog is ever used — `unshare -n`, a
   firewall rule, or a container? (Needed to make "flag alone is insufficient"
   real.)
3. **Detector coverage for v1** — which providers/kinds are must-haves for
   primitive's prioritization? (The table above is a starting set.)
4. **jsluice secret-dict shape is still UNVERIFIED** (never observed firing).
   E4's value-extraction depends on it. Do we stand up a JS file with a planted
   **fake** secret to finally capture the real shape, or ship E4 against the
   heuristic and refine when a real hit appears?
5. **Placement confirmation** — standalone re-runnable pass (recommended) vs
   inline in stage 7?

---

## See also

- `RECON_TRACK_D_DESIGN.md` — the D3 `secret` model (fingerprint + raw_log_ref)
  E4 enriches; `secret_fingerprint` + the `validated`-is-primitive's rule.
- `stages/stage7_js_extraction.py` — E4's INPUT: `run_jsluice_secrets`,
  `_jsluice_secret_value`, the per-source `raw_log_ref` archive naming.
- `RECON_B2_API_SCHEMA_DISCOVERY_DESIGN.md` — the "no external tool; a parser we
  control is testable" precedent this reuses; its §7 flags spec-embedded secrets
  as future E4 input.
- `RECON_ENHANCEMENTS.md` — E4 sketch + boundary note; the cross-agent
  untrusted-data lock.
- `PRIMITIVE_AGENT_DESIGN.md` — the consumer; owns live validation +
  `secret.validated` under its guard.
- `CONTRIBUTING.md` — verify-real-tool, fail-closed, R8 at-rest hygiene, the
  import-never-duplicate rule (E4 reuses stage 7's helpers), the 11-point
  pre-build checklist.
</content>
</invoke>
