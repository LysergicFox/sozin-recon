# A2 — deterministic interest scoring (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN (locked). Realizes A2** of `RECON_ENHANCEMENTS.md` (Track A). A
deterministic pre-score over the full asset graph + Track-D records + recon
findings, producing a per-asset `interest_score` (int) + an `interest_signals`
breakdown. **Feeds A1** (the attack-surface brief): makes the LLM an *editor* of a
ranked surface, not a from-scratch author — cheaper, explainable, and it survives
even if A1 is never built (a `sqlite3 ... ORDER BY interest_score` is useful today).

Deterministic post-processing, **zero traffic** — every signal is already on disk.
Boundary: A2 *prioritizes*; it never tests. Runs as a finalizer after C4.

## Locked decisions

1. **A finalizer pass, not a stage** (mirrors C4): `run_interest_scoring(state)`,
   called after C4 in `run_pipeline`. No new assets, no traffic, no scope gate.
2. **Score url assets AND host (subdomain) assets**, each with the signals that
   apply, writing `interest_score` (int) + `interest_signals` (dict signal→points,
   for explainability + A1) onto the asset metadata. Agent-authored/trusted (NOT
   target_derived — the SCORE is our computation, though it summarizes target data).
3. **Signals + weights (v1, a module constant so they're tunable):**
   - **url path keywords** (segment-boundary, reusing the /auth≠/authors care):
     admin·api·graphql·swagger·actuator·upload·debug·internal·staging·dev·backup·
     config·console·redirect·token·oauth·sso·git·env·well-known — weighted.
   - **auth** (from C4's endpoints.auth_status): `gated` +3, `auth_surface` +2.
   - **params present** on the url's endpoint: +1.
   - **host: recon_findings** (C1) by severity: critical 10 / high 7 / medium 4 /
     low 2 / info·unknown 1.
   - **host: secrets** (D3) attributable to it: +5 each (high-value lead).
   - **host: services** on non-standard ports (D4): +2 each.
   - **host: waf_suspected** (B1): +1 (mild — a filtered host often guards something).
4. **No score decay / normalization in v1** — raw additive points, documented as
   tunable. A1/A2-v2 can normalize; keeping it additive keeps it explainable.

## Boundary / provenance
- A2 reads only already-collected data; sends nothing. The `interest_score` and
  `interest_signals` are agent-authored (trusted). A high score is a *priority
  hint*, never a vuln claim — primitive confirms.

## Tests (mocked, over a synthetic assets.db)
- url with `/admin` + gated endpoint + params scores > a bare `/products` url.
- host with a high-severity recon_finding + a secret + a non-standard-port service
  scores accordingly; `interest_signals` records the contributing pieces.
- segment-boundary keyword care (`/authors` doesn't score the `auth`… wait, `auth`
  isn't a scoring keyword — but `/gitlab` must not score the `git` keyword: assert).
- idempotent (re-run identical).
- empty graph → no crash.

## Verification
- Run over an existing assets.db (e.g. a Juice Shop content-discovery run) and eyeball
  that `/administration`, `/api`, `/ftp` rank above noise; a pure-function mocked list.

## Doc cascade (flush when built)
- `STATE_SCHEMA.md` — new `interest_score`/`interest_signals` asset-metadata keys (trusted).
- `README.md` — an A2 interest-scoring finalizer after C4; note it feeds A1.
- `pipeline_schematic.mermaid` — A2 node feeding the (still-placeholder) A1 brief.
- `RECON_ENHANCEMENTS.md` — flip A2 → BUILT; note A1 is now the top remaining lever.

## Out of scope for A2 v1
- The A1 brief itself (LLM) — A2 only produces the ranked input.
- CVE-derived interest (waits on C5) and screenshot/vision signals (C2) — additive
  later via new signal weights, no rescoring-engine change.
- Cross-host correlation / clustering (F1).
