# sozin-recon — Performance & Coverage Findings (engineering hand-off)

**Date:** 2026-09-07
**Author:** operator + Claude (Opus) during the first real large-scope run
**Run that surfaced this:** `runs/eternal` (HackerOne "Eternal" = Zomato/Blinkit/
Hyperpure/District), 19 root domains, rate limit **2 req/s per host** (program states
no number; conservative default), `X-Hackerone: LysergicFox` header injected.
**Status:** findings recorded live while the run was still in Stage 1. Numbers for
"live-host count" are not yet known (Stage 4 had not run) — they are the dominant
unknown in every wall-clock estimate below.

---

## TL;DR

Two independent problems, both structural, both fixable without touching the
per-host request rate (i.e. **without** widening what the RoE authorizes):

1. **Wall-clock explosion — serial execution.** Active per-host stages loop hosts
   *serially*. Content discovery's wall-clock is literally `~20 min × live-host count`.
   For a large program that is tens of hours to days.
2. **Coverage truncation — time caps vs. rate.** The ffuf `-maxtime-job` cap (20 min)
   combined with 2 req/s means content discovery tests only **~2,400 of 29,999**
   wordlist entries per host = **~8% coverage**. Most of the wordlist never runs. The
   amass `-timeout 8` cap has a similar but far less costly effect on passive.

The frustrating part: the fix for #1 is **already written** (`parallelism.py`,
`bounded_parallel_map`, documented as RoE-correct by construction) and is wired into
exactly one stage (WAF/CDN). The fix for #2 is a wordlist right-size that *also* speeds
things up and *reduces* total traffic.

---

## Problem 1 — Serial per-host execution

### Evidence (file:line)

| Stage | Location | Loop |
|---|---|---|
| 1 passive discovery | `stages/stage1_passive.py:707` | `for domain in root_domains:` — roots run serially |
| 6.5 content discovery | `stages/stage_content_discovery.py:212` | `for host in live_hosts:` — **serial ffuf per host** |
| 7 JS extraction | `stages/stage7_js_extraction.py:137` | `for host in hosts:` |
| 9 whatweb | `stages/stage9_whatweb.py:237` | `for host in hosts:` |
| 5 hidden params | `stages/stage5_hidden_params.py:236` | `for url in live_urls:` |
| 4.5 WAF/CDN | `stages/stage_waf_cdn.py:143` | **uses `bounded_parallel_map(workers=5)`** ← the only stage that does |

### The helper that already solves this

`stages/parallelism.py` — `bounded_parallel_map(fn, items, workers=5)`. Its own
docstring:

> "The rate model is R3-correct BY CONSTRUCTION: each item is a DISTINCT host, and each
> host keeps its own per-host rate ... running W hosts concurrently makes the aggregate
> W * per_host, which is exactly the intended 'each host gets its own budget' model —
> NOT one shared budget split across hosts. Only use this for genuinely independent
> per-host work (whatweb, wafw00f, ffuf-per-host); never to fan out many requests at
> ONE host."

It explicitly names **whatweb and ffuf-per-host** as intended callers. They don't call
it. Only `stage_waf_cdn.py` imports it (`grep -rln parallelism stages/` → one hit).

### Wall-clock impact

- Stage 1: amass runs to its full 8-min ceiling on big roots (observed:
  `zomato.com` amass 13:42:30→13:51:42 = **9 min wall**, returned 60 assets vs
  subfinder's 158 in 7 s and assetfinder's 94 in 16 s). ~9–10 min/root × 19 roots ≈
  **~3 h for passive alone**, all serial.
- Content discovery: `20 min × live_host_count`, serial. 30 live hosts → 10 h; 100 →
  33 h; 200 → 66 h. This term dominates the entire run.

### RoE note

Parallelizing across **distinct hosts** does **not** raise the per-host rate — each host
still gets its own 2 req/s. Aggregate traffic to the org's shared infra rises to
`workers × 2` req/s (10 req/s at 5 workers), spread across 5 different hostnames. The
RoE concern the program stated is per-host hammering / service degradation / "significant
volume" — 2 req/s per individual host is unchanged. This is a defensible "responsible"
speedup, but the aggregate increase is a judgment call worth stating to the program.

---

## Problem 2 — Coverage truncation (time caps × rate)

### The math

- `stages/stage_content_discovery.py:56` → `MAXTIME_JOB_SECONDS = 1200` (ffuf
  `-maxtime-job`, a 20-min per-host wall cap, intended as a WAF/abuse backstop).
- Rate = 2 req/s (per-host, from `scope.json`, via `rate_limits.ffuf_rate_args` →
  ffuf `-rate 2`, a true per-host cap).
- Request budget per host = `1200 s × 2 req/s = 2,400 requests`.
- Wordlist = `raft-medium-directories.txt` = **29,999** entries
  (`stages/stage_content_discovery.py:72`).
- **Coverage = 2,400 / 29,999 = ~8.0%.** The other ~92% of the wordlist is never sent.

To cover the full raft-medium at 2 req/s you'd need 29,999 / 2 = **~4.2 h per host** —
and raising `-maxtime-job` to allow that multiplies total traffic and turns each host
into 4 h of sustained scanning (arguably *less* responsible, not more).

The amass `-timeout 8` (`stage1_passive.py:418`, external kill 600 s at :417) has the
same shape but is cheap: it truncates the long tail of third-party passive sources.
Observed loss is small (amass added 60 where subfinder/assetfinder already had 250+).

### Implication — what we actually miss

- **Directory/content brute-force is running at 8% and is the weakest leg.** Most
  hidden directories/files the wordlist would find are never requested.
- **Partial mitigation already in the pipeline:** content discovery is *not* the only
  endpoint source. Katana crawl (stage 6), JS extraction (stage 7, jsluice), archived-JS
  mining (stage 11, Wayback CDX), API-schema discovery (B2), and paramspider/x8 (stage 5)
  all contribute endpoints/params. So the attack surface isn't built from ffuf alone —
  but an 8% dirbrute is still a real blind spot for unlinked/unreferenced paths
  (admin panels, backups, config, old endpoints) that only brute-force finds.
- amass truncation: minor. Acceptable.

---

## Proposed fixes (sorted by RoE-safety; all keep per-host rate at 2 req/s unless noted)

### A. Right-size the ffuf wordlist to the request budget — *fixes coverage AND speed, reduces traffic* ✅ safest
- **What:** swap `raft-medium-directories.txt` (30k) for a curated list that fits the
  2,400-request budget, so coverage → ~100% of a high-signal list instead of 8% of a
  big one. Candidates on this box (`~/tools/SecLists/Discovery/Web-Content/`):
  `quickhits.txt` (2,570 — near-exact budget fit), `common.txt` (4,751).
- **Where:** `stages/stage_content_discovery.py:72` `WORDLIST_PATH`. Note E3
  (target-derived wordlists) is already a named hook near line 60 — this dovetails.
- **Impact:** same wall-time, same/less traffic, dramatically better *effective*
  coverage. This is the highest-value, lowest-risk change.
- **RoE:** strictly *fewer* requests. No downside.
- **Residual:** loses the deep long-tail of raft-medium. Best paired with a later
  full-depth pass on only the highest-interest hosts (see D).

### B. Parallelize per-host stages via the existing helper — *fixes wall-clock* ✅ safe (aggregate caveat)
- **What:** route content discovery (`:212`), whatweb (`:237`), JS (`:137`), hidden
  params (`:236`) through `bounded_parallel_map(..., workers=N)` exactly as
  `stage_waf_cdn.py:143` already does.
- **Where:** the four loops in the table above.
- **Impact:** ~`N×` wall-clock reduction on the dominant stages (N=5 → content
  discovery 66 h → ~13 h at 200 hosts).
- **RoE:** per-host rate unchanged; aggregate = `N × 2` req/s across distinct hosts.
  Make `N` a config knob (default conservative, e.g. 5) so it's an explicit dial.
- **Risk:** verify each per-host fn is truly independent (the helper's contract) and
  that R7 per-item isolation holds (it does inside the helper). Screenshots (Chromium)
  may need a lower worker count for memory.

### C. Trim / de-risk amass in passive — *cheap wall-clock win* ✅ safe
- **What:** lower `AMASS_INTERNAL_TIMEOUT_MINUTES` (`stage1_passive.py:418`) from 8 to
  ~2–3, and/or parallelize the passive roots loop (`:707`) — passive sources are
  third-party APIs, **zero target traffic**, so fanning out roots is RoE-free (watch
  third-party API limits; tools already degrade gracefully per R7).
- **Impact:** saves ~1.5–2 h off Stage 1 with negligible coverage loss.
- **RoE:** none (no target traffic).

### D. Two-phase depth strategy — *coverage without more aggression* ✅ safe
- **What:** phase 1 = fast curated wordlist (A) across all hosts; phase 2 = full
  raft-medium (or E3 target-derived list) against **only** the top-interest hosts
  (interest scoring already exists: `stages/interest_scoring.py`). Note interest scoring
  currently runs *after* content discovery in pipeline order — this would require
  either a cheap pre-score or moving a lightweight scoring pass earlier.
- **Impact:** recovers deep coverage where it matters, bounded host count.
- **RoE:** concentrates traffic on fewer hosts; defensible.

### E. Raise the per-host rate — *the one RoE-sensitive lever* ⚠️ needs program/human ownership
- **What:** raise `requests_per_second` in `scope.json`. Speeds active stages *and*
  improves ffuf coverage linearly (5 req/s → 6,000 budget → 20% of raft-medium).
- **RoE:** the Eternal ToS states **no number** and says *"please do not use vulnerability
  testing tools that generate a significant volume of traffic"* + no service degradation.
  Raising this is a re-verification of `scope.json` and a program-risk judgment the
  operator must own; safe-harbor covers *good-faith compliance* only.
- **Most responsible unlock:** email `bugbounty@zomato.com` (the ToS invites scope/
  clarification questions) and ask what scan rate they're comfortable with, then encode
  the answer with `stated_by_program: true`, `resolution: "confirmed"`. That converts a
  guess into an authorized number and removes the tension entirely.
- **DECISION 2026-09-07: E declined for now — staying at 2 req/s per host.** Operator is
  on a new HackerOne account with a 4-report cap before block; not spending a report slot
  on a rate question. NOTE: emailing `bugbounty@zomato.com` directly does *not* cost a
  report slot and remains a no-cost option if we later want an authorized higher number.
  Because fixes A and B deliver the coverage and wall-clock wins **at 2 req/s**, this
  decision has little downside.

### F. Scope prioritization / triage the root set — *strategic* ✅ safe
- **What:** run Tier 1 roots first (`*.zomato.com`, `*.zomans.com`, `*.runnr.in`,
  `blinkit.com`) for fast high-value signal; defer Tier 3 (`*.edition.in`,
  `*.ticketnew.com`, etc.). Fewer hosts → shorter wall-clock, effort aligned to bounty
  bands (see the target's `roe.md`).
- **RoE:** less total traffic.

---

## Recommended sequencing

1. **A + C now** (wordlist right-size + amass trim): pure wins, no RoE cost, big impact.
2. **B** (parallelize the 4 loops, `workers` as a conservative config knob): the
   wall-clock fix, RoE-neutral on per-host rate.
3. **F** (Tier-1-first) as the operating default for large programs.
4. **D** (two-phase depth) as the coverage-recovery follow-up.
5. **E** only after an explicit operator decision or, better, a rate confirmed by the
   program over email.

Expected combined effect (illustrative, 200 live hosts): content discovery
66 h → ~13 h (B, N=5) with coverage 8% → ~100% of a curated list (A); passive ~3 h →
~1 h (C). Rate to any single host stays at the authorized 2 req/s throughout.

---

## Open decisions requiring a human (not for the engineer to assume)

- [ ] Accept aggregate `N × 2` req/s from parallelism? Pick `N` (default 5?).
- [ ] Right-size wordlist choice: `quickhits.txt` vs `common.txt` vs E3 target-derived.
- [x] Raise per-host rate at all? **NO — staying at 2 req/s** (2026-09-07, new-account report cap). Email route left open as a no-cost option.
- [ ] Adopt Tier-1-first as default, or always run the full root set?
- [ ] Restart the current `runs/eternal` run to apply fixes, or let it finish and apply
      to the next engagement? (Current run is serial/8%-coverage as-is.)

---

## Known follow-ups (surfaced by the ginandjuice.shop run, not yet fixed)

- [ ] **Malformed / crawl-noise URLs enter `assets.db`.** gau/waybackurls (and
  katana) yield junk "URLs" — HTML fragments like `/%3C/a%3E` (`</a>`),
  `/)%3C/a%3E`, stray `/)`, backslash paths — which get scope-gated and stored as
  `url` assets, bloating the graph and every downstream consumer. Stage 5 now
  *skips* them for x8 (via `x8_candidate_urls`), but the real fix is to filter/
  reject them at **ingestion / canonicalization** so they never enter the DB at
  all. Needs its own small design (where to draw the "is this a plausible URL
  path" line without dropping legitimate odd paths). **To fix soon.**
- [ ] **Stage 7 JS extraction not yet parallelized** (excluded from the perf pass:
  its jsluice fetches aren't distinct hosts and jsluice has no rate flag). Confirm
  on a JS-heavy target whether it's the next serial bottleneck and design a
  host-safe fix if so (host-grouped like stage 5, or a jsluice-level rate cap).

---

## Appendix — key constants & their homes

- `stages/stage_content_discovery.py:56` `MAXTIME_JOB_SECONDS = 1200`
- `stages/stage_content_discovery.py:72` `WORDLIST_PATH` (raft-medium-directories, 29,999)
- `stages/stage1_passive.py:417-418` amass timeouts (external 600 s / internal 8 min)
- `stages/parallelism.py` `bounded_parallel_map`, `DEFAULT_MAX_WORKERS = 5`
- `rate_limits.py` `ffuf_rate_args` → ffuf `-rate` (per-host, true cap)
- `scope.json` `rate_limit.requests_per_second` = 2, `scope = per_host`
