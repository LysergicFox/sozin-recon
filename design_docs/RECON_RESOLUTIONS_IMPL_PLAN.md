# Recon resolutions — implementation plan

**Status: Batches 0–3 COMPLETE (2026-08-23).** R8 (Batch 0) plus R1–R7, R9–R11,
R13 (Batches 1–3) are coded, mocked-tested, and confirmed on a real
`zonetransfer.me` run (`stage_complete`, no regression); R1's two tool flags were
verified against the real CLIs. R3 is comment-only (landed). Batch 4 is no-code
by design (R12/R15/R16 deferred/accepted). R14's loop guard waits on the unbuilt
loop-until-stable. **Next: `RECON_ENHANCEMENTS.md` Phase 0 gate (R1/R3/R6) is now
satisfied → Track D can begin.**

This turned `RECON_DESIGN_REVIEW_RESOLUTIONS.md` into an ordered, testable work
list. Kept for the record of how the pass was sequenced.

## How it was done

Every fix followed `CONTRIBUTING.md`'s staged discipline. **Definition of done
per fix:** (1) code, (2) mocked-subprocess tests green, (3) real run, (4) fix real
bugs, (5) second confirming run, (6) doc-upkeep (flip status in RESOLUTIONS +
README/STATE_SCHEMA, CHANGELOG entry). Two fixes needed real *tool-behavior*
verification (flagged ⚠️): R1 (whatweb/katana flags — VERIFIED) and R11
(certspotter pagination — coded, live `after=` still ⚠️ unconfirmed under the
~10 req/hr anon limit; guard fails safe).

## Test-target notes

- **`zonetransfer.me` (single root)** — standing target; redirects off to
  `digi.ninja`, so it directly exercises R1.
- **Synthetic multi-root scope** — exercises R5 (mocked integration test used).
- **`scope: "global"` scope.json** — exercises R4 (unit-tested).
- **certspotter** real API rate-limited (~10 req/hr) — R11 covered by mocked
  multi-page tests + no-new-ids guard.

Mocked suite: `test_recon_resolutions.py` (R1/R2/R4/R5/R6/R7/R9/R10/R11/R13) +
updated `test_certspotter.py` (R5/R11).

---

## Batch 0 — immediate — ✅ DONE 2026-08-23

### R8 — run-dir hygiene
- `state.py` `RunState.__init__` → `self.run_dir.chmod(0o700)` (via `Path.chmod`).
- `.gitignore` run-dir rules already present.
- Test `test_run_dir_hygiene.py`; real-run verified (700 + git-ignored).

---

## Batch 1 — foundational state/orchestrator fixes — ✅ DONE 2026-08-23

- **R6** — `state.canonicalize(type,value)` in `Asset.__post_init__`
  (host-case/default-port/fragment; path+query untouched); lazy re-normalize.
- **R10** — `main.apply_scope_gate` dedups review items by canonical value.
- **R5** — `_sanitize(domain)` suffix on stage 1 runners + stage 3 bruteforce.
- **R7** — stages 3/4/6/8/9 tool-call isolation; `main()` sets `status="error"`
  + `failed_at_stage`. Stage 3 within-leg chains documented all-or-nothing.
- **R13** — `apply_scope_gate` routes `js_file` → `classify_url`.
- **R9** — `state.TARGET_DERIVED_METADATA_KEYS` registry.

---

## Batch 2 — rate-limit gate — ✅ DONE 2026-08-23

- **R2** — `check_run_not_blocked` raises on an absent block (affirmative
  decision required). Breaking change — fixtures/example scopes updated.
- **R4** — `rate_limit.scope` (`per_host`|`global`); `resolve_rate_scope()` +
  `_effective_total()`; `_multi_host_rate` only for per_host.
- **R3** — docstring corrections only (nuclei + bundler probe share katana's
  whole-invocation `-rl` gap).

---

## Batch 3 — active-traffic tool-flag fixes — ✅ DONE 2026-08-23

- **R1** — whatweb `--follow-redirect=same-site` (stage 9), katana `-fs rdn`
  (stage 6). **Flags VERIFIED** against real CLIs + behaviorally on
  zonetransfer.me (no off-domain whatweb fingerprint; katana on-root only).
  Residual: `-fs rdn` honors root domain, not `out_of_scope`/multi-root — a
  precise `-crawl-scope` regex is a tracked follow-up.
- **R11** — certspotter `after=` pagination (short-page stop, no-new-ids guard,
  MAX_PAGES cap, per-domain+page raw archives). ⚠️ live `after=` contract
  unconfirmed; guard fails safe.

---

## Batch 4 — no code (deferred/accepted as designed)

- **R12** (non-standard ports never probed) — enhancement Track F; README gap.
- **R16** (SANs/CNAMEs not harvested) — Track F; README gap.
- **R15** (`verified_by_human` never expires) — accepted asymmetry, documented.
- **R14** (loop convergence guard) — design constraint recorded; no code until
  loop-until-stable is built.

---

## ⚠️ Tool-flag / API verifications — RESULTS

| Item | Check | Result |
|---|---|---|
| R1 whatweb | `whatweb --help`: is `--follow-redirect=same-site` real? | ✅ real WHEN value (never/http-only/meta-only/same-site/always) |
| R1 katana | `katana -h`: `-fs rdn` semantics | ✅ `-fs` = dn/rdn/fqdn; `rdn` = root-domain-name (katana's default) |
| R11 certspotter | live `after=` pagination + end signal | ⚠️ unconfirmed (anon rate limit); coded with fail-safe guard |

---

## Definition of done — status

- R1, R2, R4, R5, R6, R7, R8, R9, R10, R11, R13 coded + mocked-tested + real-run
  clean. ✅
- R3 comment correction landed. ✅
- R12, R15, R16 confirmed tracked/accepted (no code). ✅
- Docs updated: RESOLUTIONS status table, README known-gaps, STATE_SCHEMA,
  CHANGELOG (compact), this plan. ✅
- **Remaining (optional/next):** a second confirming real run; then open
  `RECON_ENHANCEMENTS.md` Phase 1 (Track D — first-class source records), whose
  Phase 0 gate (R1/R3/R6) is now satisfied.

## See also

- `RECON_DESIGN_REVIEW_RESOLUTIONS.md` — finding-by-finding rationale + status
- `RECON_AGENT_DESIGN.md` — the design these fixes modify
- `RECON_ENHANCEMENTS.md` — what comes after this pass
- `CONTRIBUTING.md` — the staged-verification discipline
