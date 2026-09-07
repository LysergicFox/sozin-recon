# C1 — broaden nuclei (detection-only) + recon findings/POI table (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN (locked). Realizes C1** of `RECON_ENHANCEMENTS.md` (Track C). Two parts:

1. **A general `recon_findings` (POI) table** — the structured home for promotable
   recon *leads* (mirrors primitive's `points_of_interest`): a `status` lifecycle +
   provenance. Today only `takeover_findings` exists (takeover-specific). `recon_findings`
   is general: C1's nuclei detections populate it now; **C5 (tech→CVE candidates) will
   write to it later** without a new table.
2. **Broaden nuclei beyond takeover** — a second, **detection-only** nuclei run
   (exposures / misconfiguration / exposed-panels) producing `recon_findings`. Stage 8
   currently runs `-tags takeover` only.

> **This finally gives the nuclei parser a REAL positive sample.** Stage 8's
> `parse_nuclei_jsonl` is flagged UNVERIFIED (no real takeover finding was ever
> produced). C1's detection run WILL trip templates on a live target (Juice Shop),
> so the shared nuclei JSONL parsing gets confirmed against real positive output.

---

## The boundary is specific and non-negotiable (detection only)

Recon detects that something is *exposed / present*; it never *submits a credential,
writes, or exploits*. So:

- **Include tags:** `exposures`, `misconfiguration`, `exposed-panels`. These fingerprint
  presence (an exposed `.git`/`.env`, a public actuator, a login panel's mere existence).
- **EXCLUDE, hard:** `default-logins` (tries admin/admin — active auth testing = primitive's
  guarded territory) and any `intrusive` / credential-submitting / write / exploit template.
  Belt-and-suspenders: pass nuclei `-etags default-logins,intrusive,fuzzing,dos` in addition
  to the include set, and (Jared-call) consider `-exclude-severity unknown` off — keep all
  severities as leads.
- **`exposed-tokens` is DEFERRED to E4/D3 (out of scope v1).** Those templates *extract a
  credential value*, which collides with the project's hard rule "never store a raw secret
  value." Handling extracted secrets = the D3 fingerprint+raw_log_ref path, which belongs
  with E4 secret classification. Named, not silently dropped.

---

## Locked decisions

1. **Extend stage 8, don't add a stage.** Same tool (nuclei), same host seed (in-scope
   live hosts), same `nuclei_rate_args`. Add `run_nuclei_detection()` alongside
   `run_nuclei_takeover()`; wire both in `run_stage8_and_report`. Each nuclei invocation
   is independently R7-isolated (one failing ≠ the other lost). Stage 8's name
   ("high-signal checks") already fits. Alternative (a new stage 11) rejected: needless
   stage proliferation for the same tool.
2. **New `recon_findings` table + `ReconFinding` dataclass + `add_/load_recon_findings`**
   in `state.py`, mirroring `takeover_findings`. Columns: `finding_id` (PK), `asset_id`
   (FK, nullable), `host`, `source` (`"nuclei"` now, `"cve-candidate"` for C5),
   `template_id`, `template_name`, `category` (nuclei tag bucket), `severity`, `matched_at`,
   `status` (lifecycle: `new`|`triaged`|`promoted`|`dismissed`, default `new`),
   `target_derived` (1 — `matched_at`/extracted content is target-authored), `raw_finding`
   (JSON, same precedent as `takeover_findings`), `discovered_at_stage`,
   `discovered_in_pass`, `discovered_at`. **`UNIQUE(host, template_id, matched_at)`** dedup.
3. **asset_id linkage** by exact host-string match against in-scope host assets (same
   `asset_lookup` pattern stage 8 already uses; unmatched → `asset_id=None`, finding kept).
4. **target_derived=1 + R8 at-rest.** `matched_at` and any extracted snippet are
   target-authored → untrusted (the A1 brief treats them as delimited data). `raw_finding`
   JSON lives in the R8 chmod-700 run dir like `takeover_findings` already does. ⚠️ Named
   residual: an `exposures` template could surface a sensitive snippet inside `raw_finding`;
   acceptable in v1 under R8, revisit with E4.

---

## ⚠️ Tool-interface facts to confirm on REAL nuclei output before trusting the parser
(C1 CAN produce a real positive, unlike takeover — so actually confirm these):

- Real JSONL field names on a POSITIVE detection: `template-id`, `info.name`,
  `info.severity`, `info.tags` (the category bucket — confirm it's `info.tags` and its
  shape: list vs csv string), `matched-at` (vs `matched_at`), `type`, `extracted-results`.
  The existing `parse_nuclei_jsonl` guesses these — CONFIRM and correct against real output.
- That `-tags exposures,misconfiguration,exposed-panels` + `-etags default-logins,intrusive`
  actually selects a detection-only set (spot-check `nuclei -tl -tags ... -etags ...`), and
  that none of the selected templates are credential-submitting.
- nuclei's real exit code + stderr on a run WITH findings (stage 8 only ever saw the
  zero-findings exit-0 path).
- Rate flag `-rl` (already used) still applies; the detection set is much larger than
  takeover (hundreds of templates) → the R3 whole-invocation gap is *worse* here — note it,
  and cap with `-timeout`/the existing DEFAULT_TIMEOUT; consider `-severity` scoping if runs
  are too heavy (Jared-call).

---

## Where it slots in `main.py`

`run_stage8_and_report` gains a second block: after takeover findings, call
`run_nuclei_detection(hosts, ...)` → `state.add_recon_findings(...)`. Same host seed +
`asset_lookup`. `state.py` grows the table + dataclass + add/load.

## Tests (mocked)
- `parse_nuclei_jsonl` (or a detection-specific parser) on a real-shaped POSITIVE
  detection line → `ReconFinding` with template/category/severity/matched_at, `status="new"`,
  `target_derived=1`.
- `recon_findings` add/load/dedup on `(host, template_id, matched_at)`.
- detection tag/exclude args include exposures/misconfiguration/exposed-panels and EXCLUDE
  default-logins/intrusive (assert the exact argv).
- asset_id linkage (host match → asset_id; no match → None, kept).
- R7: a detection-run failure doesn't lose takeover findings (and vice versa).
- empty output → zero findings (the confirmed zero signal).

## Real-run verification
- Run the detection set against a live target that trips templates (Juice Shop, or
  zonetransfer.me for a lighter set) → capture a REAL positive JSONL line, confirm the
  field names, fix the parser, second confirming run. **This closes the long-standing
  UNVERIFIED-parser gap for the shared nuclei plumbing.**

## Doc cascade
- `STATE_SCHEMA.md` — new `recon_findings` table (columns, UNIQUE, status lifecycle,
  target_derived, the general source field for C5).
- `README.md` — stage 8 now also runs detection-only exposures/misconfig/panels →
  `recon_findings`; state-file table gains the table.
- `pipeline_schematic.mermaid` — stage 8 node: takeover + detection; a recon_findings state node.
- `CHANGELOG.md` — C1 entry; 🐛→✅ the nuclei parser confirmed against a real positive.
- `RECON_ENHANCEMENTS.md` — flip C1 to BUILT.

## Explicitly out of scope for C1 v1
- `exposed-tokens` / any credential-*extracting* template (→ E4/D3 secret handling).
- `default-logins` / intrusive / write / exploit templates (primitive's territory).
- A promotion workflow that changes `status` beyond the default `new` (the lifecycle
  column exists; consumers/primitive drive transitions later).
- C5 tech→CVE candidates (separate item; will reuse this table via `source="cve-candidate"`).
