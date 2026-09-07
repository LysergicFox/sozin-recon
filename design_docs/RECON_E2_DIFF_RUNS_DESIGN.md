# E2 — incremental / diff runs (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN (locked). Realizes E2** of `RECON_ENHANCEMENTS.md` (Track E). For
ongoing bug-bounty, **"what's NEW since the last run"** (a new subdomain / endpoint /
param / secret / finding) is the highest-value continuous-monitoring signal and fresh
attack surface. The externalized-state design makes this natural; nothing consumes it
yet. E2 computes the delta between two run directories and emits a **diff artifact**.

Offline, zero traffic — pure comparison of two `assets.db` files.

## Locked decisions

1. **Standalone cross-run comparison, NOT a pipeline stage.** A diff needs two runs
   (a baseline + the current), which the per-run `main.py --run-dir` flow doesn't have.
   Ship `stages/diff_runs.py` (the compute) + `testing/run_diff.py` (a CLI:
   `--baseline <dir> --current <dir>`), mirroring the `run_stage*_only.py` re-runner
   pattern. Auto-diffing against a stored "last run" is a future wiring, named not built.
2. **Compare every layer by its natural identity key:**
   - assets: `(type, value)` (value already R6-canonical)
   - endpoints: `(url, method)` · parameters: `(host, endpoint, name, method, location)`
   - secrets: `fingerprint` · services: `(target, port, proto)`
   - recon_findings: `(host, template_id, matched_at)`
3. **Emit `new` and `removed` per layer** (removed = disappeared since baseline — a host
   that went down, a rotated secret). Write the artifact to `current/diff.json` +
   return a summary dict. The artifact carries the actual new items (values) so it's
   directly actionable (feeds a future alert/report), not just counts.
4. **Provenance is preserved, not recomputed** — E2 reads what each run already
   classified; it makes no scope/interest judgments of its own.

## Boundary
- Pure offline set-difference over two on-disk states. No traffic, no scope gate, no
  new records. The diff artifact lives in the R8 run dir (it can name secrets by
  fingerprint — never the raw value, which E2 never reads).

## Tests (mocked, two synthetic run dirs)
- an added subdomain/url/endpoint/param/service/finding appears under `new`; a removed
  one under `removed`; an unchanged one in neither.
- secrets diffed by fingerprint (never raw value).
- identical runs → empty diff. `summary` counts match the lists.

## Doc cascade (flush when built)
- `README.md` — a `run_diff.py --baseline --current` re-runner emitting `diff.json`.
- `STATE_SCHEMA.md` — the `diff.json` artifact shape.
- `RECON_ENHANCEMENTS.md` — flip E2 → BUILT.

## Out of scope for E2 v1
- Auto-selecting the baseline (a "last run" pointer) — CLI-supplied for now.
- Alerting / notification on the diff (a consumer, not E2).
- Semantic diffing of metadata changes (e.g. a host's status flipping) — v1 is
  presence-diff of assets + records by identity key.
