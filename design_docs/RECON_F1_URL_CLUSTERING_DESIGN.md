# F1 — URL clustering / representative sampling (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN (locked). Realizes F1** of `RECON_ENHANCEMENTS.md` (Track F). A big
site yields thousands of templated URLs (`/product/1`, `/product/2`, …). F1 clusters
them by structure and marks a **representative sample per template**, so the hunting
agents get the shape of the surface, not the raw flood — protecting primitive's bounded
budget from noise. Builds on R6 canonicalization. Deterministic, offline, zero traffic.

## Locked decisions
1. **A finalizer pass** (like C4/A2), `run_url_clustering(state)`, over `url` assets.
   No traffic, no new assets/records — only metadata on the existing url assets.
2. **Template key = path with id-like segments collapsed** to `{id}` + sorted query
   param NAMES (values dropped). "Id-like" (module constant, tunable): pure-numeric,
   hex ≥8, uuid, or long (≥20) alnum. `/product/42?ref=x` and `/product/99?ref=y` both
   → `/product/{id}?ref`. Clustering is per `(host, template)`.
3. **Mark, don't delete.** Every clustered url asset gets metadata `url_cluster`
   (the template), `cluster_size`; the first `REPRESENTATIVES_PER_CLUSTER` (default 2,
   deterministic order) get `cluster_representative=True`. A cluster below
   `CLUSTER_MIN_SIZE` (default 3) is left unmarked (not a flood). Nothing is dropped —
   the consumer chooses to sample by `cluster_representative` or take all.
4. **Trusted, agent-authored metadata** (the clustering is our computation) — not
   target_derived, though the URLs it summarizes are.

## Boundary
- Pure offline structural grouping of already-collected url assets. F1 prioritizes/
  samples; it never tests. A cluster is a hint, not a judgment about the URLs.

## Tests (mocked)
- `/product/1..5` (+ mixed query) cluster to one template `/product/{id}`; size=5;
  exactly 2 marked representative; a lone `/about` (size 1) left unmarked.
- id detection: numeric/hex/uuid collapsed; `/api/v3` NOT collapsed (v3 is not id-like).
- idempotent; empty graph → no crash.

## Doc cascade (flush when built)
- `STATE_SCHEMA.md` — url-asset metadata `url_cluster`/`cluster_size`/`cluster_representative`.
- `README.md` — an F1 clustering finalizer; consumers sample by representative flag.
- `RECON_ENHANCEMENTS.md` — flip F1 → BUILT.

## Out of scope for F1 v1
- Cross-host clustering (same template on many hosts) — per-host in v1.
- Semantic/response-similarity clustering (v1 is structural on the URL only).
- Auto-pruning the wordlist/crawl seed from clusters (a consumer concern).
