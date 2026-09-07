# E3 — target-derived wordlists (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN (locked). Realizes E3** of `RECON_ENHANCEMENTS.md` (Track E). Recon's
wordlists are all small/hardcoded (B1's SecLists set, stage-5 burp-params). E3 mines
**the tokens the target itself uses** — path segments + parameter names from the crawled
corpus / JS / discovered endpoints — into wordlists that raise B1/stage-5 yield more than
any single tool swap (a target that uses `/api/v3/pet` teaches you to try `/api/v3/order`).

Offline, zero traffic — pure extraction from the current run's `assets.db`.

## Locked decisions

1. **Standalone miner + artifact, NOT wired into the live pass (v1).** E3 mines from
   crawled/extracted data (stages 6/7) that only fully exists *after* B1 runs at stage
   6.5, so feeding B1 in the SAME pass is a loop-until-stable concern (unbuilt). v1
   ships `stages/wordlist_mining.py` + `testing/run_wordlist_mining.py` (CLI) that write
   the wordlist artifacts to the run dir, for use on a **subsequent run / loop pass**
   (repoint B1's `WORDLIST_PATH` / stage-5's list at them). Auto-wiring into a live pass
   is named, deferred to loop-until-stable.
2. **Two artifacts:** `target_derived_paths.txt` (unique path segments from `url` assets
   + `endpoints`) and `target_derived_params.txt` (parameter names from the `parameters`
   table + query strings on url assets).
3. **Cleaning rules (module constants, tunable):** lowercase; drop pure-numeric segments
   (templated ids like `/product/42`), single-char, and empty; keep dotted files
   (`config.json`) whole AND their stem; de-dup; cap total size. Never emit a token that
   is itself a full URL or contains a scheme.
4. **Provenance note:** these tokens are TARGET-AUTHORED. As a B1 wordlist they become
   the *value* ffuf fuzzes → the resulting endpoints are still `target_derived=0` (the
   path we tried came from our wordlist, even if that wordlist was target-seeded) — the
   same rule B1 already documents. The wordlist FILE is target-derived data at rest.

## Tests (mocked, over a synthetic assets.db)
- path segments extracted from url assets + endpoints; `/product/42` yields `product`
  (not `42`); `config.json` yields `config.json` (and optionally `config`).
- param names extracted from the parameters table + a `?q=1&id=2` query string.
- de-dup + cleaning (lowercase, no single-char, no pure-numeric); empty db → empty files.

## Doc cascade (flush when built)
- `README.md` — a `run_wordlist_mining.py` re-runner emitting the two wordlist artifacts;
  note B1/stage-5 can be repointed at them on a later run.
- `RECON_ENHANCEMENTS.md` — flip E3 → BUILT; note auto-feed waits on loop-until-stable.

## Out of scope for E3 v1
- Auto-feeding B1/stage-5 in the same pass (loop-until-stable).
- Archived-JS token mining (that corpus comes from B4).
- Frequency ranking / smart ordering of the wordlist (v1 is a de-duped set).
