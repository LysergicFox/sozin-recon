# CLAUDE.md — sozin-recon

Standalone reconnaissance engine.
Scripted and deterministic: same input → same behavior. **No LLM calls, no
exploitation.** It discovers, enriches, prioritizes, and flags candidates — it
never tests, exploits, uses a credential, or confirms a vulnerability.

## What it is
`python3 main.py --run-dir <dir>` runs one pass of stages 1→3→4→(4.5)→5→6→
(6.5)→7→8→9→(C2)→(C5)→10→11 plus deterministic finalizers (C4/F1/A2/F6).
Stage 2 is intentionally skipped. See `README.md` for the full stage/tool map
and `docs/STATE_SCHEMA.md` for the on-disk format.

## Layout
- `main.py` — the stage-sequencer entrypoint (`run_pipeline`).
- `state.py` — `RunState`: all disk I/O (asset graph + Track-D source records).
- `scope_gate.py` — deterministic scope classification (fail-closed).
- `rate_limit_gate.py` — fail-closed rate-limit gate (the LLM extractor is a
  contract stub here; recon ships without an LLM).
- `rate_limits.py` — per-tool RPS translation.
- `stages/` — one module per stage + enrichment pass.
- `testing/` — `test_*.py` mocked suites + `run_stage*_only.py` re-runners
  (which **import** the shared `run_stageN_and_report()` from `main.py`, never
  reimplement it).
- `docs/` — shipped docs (CONTRIBUTING, STATE_SCHEMA, CHANGELOG).
- `design_docs/` — design specs + the R1–R16 adversarial review record.
- `Dockerfile` / `docker-compose.yml` — the self-contained image (all external
  CLIs + SecLists at `~/tools/SecLists` + nuclei templates baked in).

## Working agreements (from `docs/CONTRIBUTING.md`)
1. **Design-locked before code**; deferred items named, never silently dropped.
2. **Staged verification:** build → mocked tests → real run on a consented
   target → fix → confirming run. Commit only after the confirming run.
3. **Never trust a tool's docs — run it.** Confirm real output shapes.
4. **Fail closed.** Unclassifiable scope → `needs_review.json`; absent/low-
   confidence rate limit → blocks.
5. **Fault isolation:** one tool failing must not kill the run.
6. Raw tool output archived verbatim; curated data derived from it. Never store
   a raw secret — fingerprint + `raw_log_ref` only.

Standing consented recon test target: `zonetransfer.me`.

## Git
Manual and explicit — do not stage/commit/branch/push unless asked. Never commit
run dirs, `*.db`, `raw/`, or a real `scope.json` (all `.gitignore`d).
