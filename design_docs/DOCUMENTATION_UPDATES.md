# Documentation Updates — staging file

**Purpose.** A low-churn buffer for documentation changes. Instead of rewriting a
large doc every time something changes, pending edits are logged here as compact
bullets under the target doc's section. When you say "apply the doc updates" (all,
or a named file), Claude flushes that section into the real doc(s) and resets the
section to **_No pending changes._**

**How Claude uses it**
- When a code/design change affects a doc, append a bullet under that doc's section
  here — precise enough to apply later. Do **not** rewrite the target doc then.
- On "apply": edit the target doc(s), then reset those sections to _No pending changes._
- Terse bullets. `🐛→✅` for real-run bug fixes, `⚠️` for named gaps.

**Last full flush:** 2026-08-24 — the **B4 / stage 11 archived-JS mining** doc-cascade was
flushed into README, CHANGELOG, STATE_SCHEMA, CONTRIBUTING, pipeline_schematic, CLAUDE.md,
RECON_ENHANCEMENTS, RECON_AGENT_DESIGN, and the B4 design doc (status → BUILT). Track B is now
complete. Only the unbuilt items (A1/F2/F3/F4) remain pending below. (Prior flush 2026-08-23:
the entire enhancement-roadmap cascade + the RECON_AGENT_DESIGN whole-pipeline fold.)

---

## Repo layout & doc locations — reference

Two tracked doc folders: **`docs/`** = shipped project docs (README at root, CHANGELOG,
CONTRIBUTING, STATE_SCHEMA, pipeline_schematic); **`design_docs/`** = design/planning
reference (DOCUMENTATION_UPDATES, RECON_* design docs incl. per-item build specs, PRIMITIVE_*).

---

## README.md
_No pending changes._ (B4/stage-11 cascade flushed 2026-08-24.)

## docs/CHANGELOG.md
_No pending changes._ (B4/stage-11 DESIGN→DONE entry flushed 2026-08-24.)

## docs/STATE_SCHEMA.md
_No pending changes._ (wayback_jsluice producer + stage11 raw files flushed 2026-08-24.)

## docs/CONTRIBUTING.md
_No pending changes._ (Wayback CDX/`id_`/jsluice-local-file verified-tool ledger flushed 2026-08-24.)

## docs/pipeline_schematic.mermaid
_No pending changes._ (stage 11 archived-JS node off web.archive.org flushed 2026-08-24.)

## CLAUDE.md
_No pending changes._ (§2 board/summary, stage-numbering, §8 tracks, §12/§13 flushed 2026-08-24.)

## design_docs/RECON_ENHANCEMENTS.md
_No pending changes._ (B4→BUILT, Track B complete, Phase-2 row flushed 2026-08-24.)

## Per-item design docs (RECON_C1…/C3…/C4…/C5…/E1…/E2…/E3…/E4…/A2…/F1…)
_No pending changes._ (RECON_B4 status → BUILT flushed 2026-08-24. C2/E5/F5/F6 have no
separate spec — module docstrings.)

## design_docs/RECON_AGENT_DESIGN.md
_No pending changes._ (The deferred whole-pipeline fold was applied 2026-08-23: Track-D
records + `recon_findings` into the state model; stages 4.5 (C3), 6.5 (B1), 10 (B2), and
the C1 detection band into the stage inventory; a new "Enrichment & finalizer passes"
section (F5/C2/E4/C5/C4/F1/A2/F6 + the E5 helper + E2/E3 offline utilities); orchestrator
order + persist_records + service promotion; header, boundary, known-gaps, roadmap,
decision-log, handoff, and review-summary sections reframed from "stages 1–9 / roadmap
not built" to the current mostly-built state with A1/B4/F2–F4 remaining. **2026-08-24:**
stage 11 (B4 archived-JS) folded into the inventory + intro + Track-D producer tables +
orchestrator-order/loop notes; A1/F2/F3/F4 now the remaining items.)

## Remaining unbuilt items (no doc action until built)
- **A1** — attack-surface brief (needs the LLM env/endpoint). **F2/F3/F4** — credential-gated
  (AWS / PDCP / GitHub). When any lands, add its doc-cascade bullets here, then flush.
  (**B4** built 2026-08-24 — see the staged sections above, pending flush.)

---

_Add a new `## <path>` section here whenever a doc not listed above needs a staged change._
