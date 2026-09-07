# B1 — content / endpoint discovery (design-lock)

**Status: BUILT + REAL-RUN VERIFIED 2026-08-23** (local OWASP Juice Shop;
`stages/stage_content_discovery.py`, `testing/test_content_discovery.py`). **⚠️ Locked
decision #2 was REVISED at build time: shipped as fractional _stage 6.5_ (between crawl
and JS-extraction), NOT terminal stage 10** — so a ffuf-discovered `.js` is jsluice-mined
in the same pass (stage 7 seeds from `.js` url assets), removing the loop-until-stable
dependency for that coverage; katana (seeds from hosts) still won't re-crawl ffuf dirs
without a separate stage-6 change (named residual); 6.5 also minimises WAF-ban blast
radius. Costs accepted: the float `STAGE` is a latent footgun for integer-stage
comparisons; the `%d`→`%s` log format was fixed. Verified ffuf interface facts folded into
the module docstring. Below is the original design; read it with decision #2's revision in
mind. Realizes **B1** of
`RECON_ENHANCEMENTS.md` (Phase 2, Track B — "coverage: the testable surface
*on* the hosts"). Adds directory/file brute-forcing with **ffuf**, the single
largest new source of endpoints for primitive's `source_sink_map`. Populates the
Track-D `endpoints` table (built but only lightly populated until now) and emits
`url` assets through the existing scope gate.

This doc is the detailed design a building agent follows. It is written to the
same discipline every existing stage was: **verify the real tool interface
before writing the parser**, fail-closed, rate-bounded per-host, fault-isolated
(R7), scope-safe (R1). Nothing here is coded yet.

---

## Why B1, and the one non-negotiable prerequisite

There is no directory/file brute-forcing anywhere in the pipeline today — nothing
hunts `/admin`, `/.git/`, `/.env`, backups, `/api/v*`, `/actuator`,
`/swagger.json`. B1 is the highest raw-coverage jump on the roadmap **and** its
highest-traffic addition (thousands of requests per host — the item most likely
to trip a WAF or a program abuse threshold).

Its Phase-0 gate (**R1** scope-covers-traffic, **R3** per-host rate) is already
satisfied (Batches 0–3 done 2026-08-23), which is why B1 is unblocked. **Its
designed companion, C3 (WAF/CDN detection → back-off), is NOT yet built (Phase
3).** B1 therefore ships without a *pre-flight* WAF label this pass. It is NOT,
however, shipping without any WAF guard: a minimal *in-flight* breaker is folded
in below (§Minimal in-loop WAF guard). Do not build the full adaptive/pre-flight
back-off here; that is C3's job and lands with it.

---

## Locked decisions (recommended; Jared's calls flagged)

1. **Tool: ffuf, single tool this pass.** Chosen over feroxbuster: ffuf is
   already in `logging_setup.py`'s highlighter list (anticipated), has native
   JSON output (`-of json`) and a native rate flag (`-rate`), a native
   stop-on-403-flood flag (`-sf`), and its single-URL-with-`FUZZ`-keyword model
   gives same-origin safety by construction (see §R1). feroxbuster stays an
   unwired alternative.
2. **New stage number: 10, terminal** (runs after stage 9). ← **Jared call;
   recommended 10.** Rationale: avoids renumbering stages 5–9 (which would ripple
   through tests, `run_stage*_only.py`, and docs — against the project's
   forward-only/low-blast-radius ethos). B1 is framed as a *record producer for
   primitive*, not a crawl feeder, so running it terminal and populating
   `endpoint` records is the natural fit. **Tradeoff, named:** discovered
   directories/`.js` files are NOT re-crawled by stage 6 (katana) or re-mined by
   stage 7 (jsluice) this pass. That is acceptable and recoverable once
   loop-until-stable exists (a second pass picks them up). *Alternative Jared may
   pick:* insert after stage 4 so the crawl sees discovered dirs — costs a
   renumber of 5–9 or an out-of-order `current_stage`. Recommendation stands at
   terminal stage 10.
3. **One ffuf invocation PER HOST, in a Python loop** (like whatweb/x8), NOT one
   combined multi-host run. This makes ffuf's `-rate` a **true per-host cap** and
   sidesteps the R3 whole-invocation-ceiling gap entirely — for the single
   most-traffic-heavy tool in the pipeline, where that gap matters most. See
   §Rate.
4. **Seed set: confirmed-live, in-scope hosts only** — `subdomain` assets with
   `scope_status == "in_scope"` AND `httpx_status_code` in metadata (the exact
   stage-9 filter). Brute-forcing a host not serving HTTP is wasted traffic.
5. **Records: each hit → a `url` asset (through the scope gate) + an `endpoint`
   record.** Mirrors stage 6/7's "return new assets + records; caller classifies
   and persists" contract.
6. **Wordlist: a curated SecLists set this pass; target-derived wordlists (E3)
   deferred.** Kept as a module constant so E3 can extend it later.
7. **In-flight WAF guard is ffuf-native + post-hoc flag, not adaptive back-off.**
   Use ffuf's `-sf` (stop on 403 flood) + `-maxtime-job`; on an early stop,
   flag the host `waf_suspected` as intel for primitive. Adaptive/pre-flight
   back-off is C3, not B1. See §Minimal in-loop WAF guard.

---

## Where it slots in `main.py`

Add `run_stage10_and_report(patterns, state, scope)` and call it as the last
stage in `run_pipeline()`, after `run_stage9_and_report(...)`:

```python
run_stage9_and_report(state, scope)
run_stage10_and_report(patterns, state, scope)   # NEW — B1 content discovery
state.update_run_state(status="stage_complete", passes_completed=1)
```

`run_stage10_and_report` mirrors `run_stage7_and_report` exactly:

```python
def run_stage10_and_report(patterns, state, scope):
    all_assets = state.load_assets()
    live_hosts = [
        a.value for a in all_assets
        if a.type == "subdomain" and a.scope_status == "in_scope"
        and "httpx_status_code" in a.metadata           # decision 4: live only
    ]
    logger.info("Seeding stage 10 with %d confirmed-live in-scope host(s)", len(live_hosts))

    logger.info("--- Stage 10: content / endpoint discovery (ffuf) ---")
    new_assets, records, waf_flags = run_stage10(live_hosts, state, current_pass=1, scope=scope)

    run_stage_and_report(10, "content discovery", new_assets, patterns, state)
    persist_records(state, records)                      # links endpoint.url → url asset
    _apply_waf_flags(state, waf_flags)                   # host metadata: waf_suspected (see below)
```

`persist_records` already links `endpoint` records by `e.url` matching a parent
asset value and drops out-of-scope parents — no change needed there. Because each
hit is emitted as BOTH a `url` asset (added first, in `run_stage_and_report`) and
an `endpoint` record (persisted second), the endpoint's `url` resolves to the
just-added parent asset, exactly like stage 7. `_apply_waf_flags` writes the
per-host `waf_suspected` metadata onto the existing host asset via
`update_asset_metadata` (same path stage 4/9 use for host metadata).

---

## The stage module — `stages/stage10_content_discovery.py`

### Return contract

```python
def run_stage10(live_hosts: list[str], state: RunState, current_pass: int,
                scope: dict) -> tuple[list[Asset], dict[str, list], dict[str, dict]]:
    """
    Returns (new_assets, records, waf_flags):
      - new_assets: list[Asset] — every discovered URL as type="url", carrying
        curated metadata (ffuf_status, ffuf_length, ffuf_content_type) on
        construction, for the caller to scope-gate before add_assets().
      - records: {"endpoints": [Endpoint, ...]} — one endpoint record per hit.
        (No parameters/secrets/services from this stage.)
      - waf_flags: {host: {"waf_suspected": bool, "waf_signal": "...",
        "waf_block_ratio": float|None}} — per-host WAF intel for the caller to
        attach as host metadata (see §Minimal in-loop WAF guard).
    Empty live_hosts → ([], {"endpoints": []}, {}).
    """
```

### Per-host loop (decision 3 + R7)

```python
for host in live_hosts:
    try:
        hits, waf = run_ffuf(host, state, scope)     # one invocation, one host
    except Exception:
        logger.exception("stage 10 ffuf failed for %s — skipping this host (R7)", host)
        continue                                     # one host failing ≠ kill the stage
    waf_flags[host] = waf
    for h in hits:
        ... build Asset + Endpoint ...
```

Fault isolation sits at the **per-host** call site (finer-grained than stage
6/8's single-invocation guard, because B1 genuinely loops). A timeout or crash on
one host yields no results for that host, never aborts the stage. Additionally
wrap the whole stage body in `run_stage10_and_report` the way other stages are,
so a catastrophic failure marks nothing and moves on.

### The ffuf invocation (VERIFY every flag against real `ffuf -h` first)

```python
seed = f"https://{host}/FUZZ"                        # FUZZ keyword = same-origin by construction
out_path = state.raw_path(STAGE, f"ffuf_{_sanitize(host)}")   # R5 per-target raw file

cmd = [
    "ffuf",
    "-u", seed,
    "-w", WORDLIST_PATH,
    "-e", ",".join(EXTENSIONS),                      # extension permutations
    "-recursion", "-recursion-depth", str(RECURSION_DEPTH),   # capped
    "-ac",                                           # auto-calibrate soft-404 / catch-all
    "-sf",                                           # stop when >95% of responses are 403 (WAF flood) — §WAF guard
    "-maxtime-job", str(MAXTIME_JOB_SECONDS),        # per-host wall cap (also a WAF/abuse backstop)
    "-of", "json", "-o", out_path,                   # machine-readable output to file
    "-noninteractive",
    "-t", str(THREADS),
    *ffuf_rate_args(scope).extra_args,               # -rate <n> (see Rate)
    # NO -r : do NOT follow redirects (see §R1 — a 30x is a finding, not a chase)
]
```

**⚠️ Tool-interface facts to confirm on a real ffuf before writing the parser**
(exactly as stage 4/5/6 each did — real bugs were caught this way every time):

- `-of json -o <file>` output **shape** — top-level `results[]`, and per-result
  keys (`input.FUZZ`, `url`, `status`, `length`, `words`, `lines`,
  `content-type`, `redirectlocation`). Do not trust these key names from memory.
- `-rate` semantics — confirm it is **requests/second for the whole ffuf
  process** (so per-host-invocation makes it a true per-host cap).
- `-sf` semantics — confirm it is "stop when > 95% of responses return **403**"
  and how that early stop is signalled (exit code? a marker in the JSON? stderr?)
  so the post-hoc `waf_suspected` detection has something real to key on. Also
  check `-se` (stop on spurious errors) / `-sa` (stop on all error conditions)
  and decide whether to add them.
- `-ac` auto-calibration behavior against a **wildcard / catch-all host** — the
  200-vs-301 soft-404 lesson stage 7's bundler probe already learned. Confirm
  `-ac` actually suppresses the catch-all before trusting it; keep `-mc all` +
  manual size/word filters as the fallback if `-ac` under-performs.
- `-maxtime-job` vs `-maxtime` — confirm which is per-host vs whole-run and that
  it terminates cleanly (writes partial JSON, or none — see timeout note).
- `-recursion` interaction with `-e`, `-rate`, and `-sf` (does the rate cap and
  the 403-stop hold across recursion? they should, same process).
- On **timeout / early stop**: ffuf writes the `-o` file at completion, so a
  killed ffuf may leave no file → no results for that host (accept, R7). Keep the
  wordlist + recursion bounded so timeouts are rare rather than salvaging partial
  output.

### Building records from hits

```python
new_assets.append(Asset(
    value=hit_url, type="url",
    discovered_by="ffuf", discovered_at_stage=STAGE, discovered_in_pass=current_pass,
    metadata={"ffuf_status": status, "ffuf_length": length,
              "ffuf_content_type": content_type},     # curated only — NO body
))

records["endpoints"].append(Endpoint(
    url=hit_url, host=host, path=urlparse(hit_url).path, method="GET",
    content_type=content_type,
    auth_status=("gated" if status in (401, 403) else None),   # see below
    discovered_by="ffuf", target_derived=False,       # path came from OUR wordlist
    discovered_at_stage=STAGE, discovered_in_pass=current_pass,
    metadata={"ffuf_status": status, "ffuf_length": length},
))
```

- **`target_derived=False`** — the endpoint's *value* (which wordlist word
  matched) is agent-authored, exactly like x8 params (target_derived 0). The
  response `content_type`/title IS target-authored, but it lives in metadata, not
  in a keyed value column. Consistent with Track D's rule ("is the *value*
  target-authored?").
- **`auth_status`** — B1 opportunistically sets `"gated"` on a 401/403 (cheap,
  unambiguous, and it's the exact signal primitive's authenticated-testing mode
  wants). It does **not** attempt the fuller public-vs-gated + login/OAuth/SSO
  classification — that is **C4**, which owns `auth_status` formally. Leave
  everything else `None` for C4. (Note: a WAF flooding 403s (see §WAF guard) can
  make `auth_status="gated"` noisy — the `waf_suspected` host flag is the signal
  downstream uses to discount a host's 403s.)
- **Two-tier persistence (R5):** the FULL ffuf JSON per host lives in
  `raw/stage10_ffuf_{host}.json` (per-target suffix, so nothing is overwritten
  across hosts). `assets.db`/`endpoints` get only the curated status/length/
  content_type. Bodies never touch `assets.db` — same rule as stage 6.

### Module constants (kept configurable for E3 later)

```python
STAGE = 10
DEFAULT_TIMEOUT_SECONDS = 1800        # content discovery is long; bounded wordlist keeps it rare
MAXTIME_JOB_SECONDS = 1200            # ffuf -maxtime-job per-host wall cap (WAF/abuse backstop)
RECURSION_DEPTH = 2                   # capped — do not run unbounded
THREADS = 40                          # ffuf default; -rate is the real ceiling regardless

# Curated v1 wordlist — SecLists. E3 (target-derived wordlists) extends this.
WORDLIST_PATH = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
# consider also raft-medium-files.txt + an API list (api/objects.txt); keep small this pass

EXTENSIONS = [".bak", ".old", ".zip", ".tar.gz", ".env", ".git/config",
              ".json", ".txt", ".config", ".swp"]   # curated; confirm ffuf -e syntax
```

The roadmap's named high-value targets (`/admin`, `/.git/`, `/.env`, backups,
`/api/v*`, `/actuator`, `/swagger.json`) should be present in the chosen list(s);
`/swagger.json` / `/openapi.json` / GraphQL probing proper is **B2**, not B1 —
don't build API-schema discovery here.

---

## Rate — `ffuf_rate_args(scope)` in `rate_limits.py`

Add a new helper. Because B1 runs **one host per invocation, sequentially**
(decision 3), it belongs with the "sequential per-host → the per-host number
applies directly, and a GLOBAL scope needs no special handling" reasoning already
documented for x8/whatweb (Shape 2), even though ffuf *has* a native rate flag:

```python
def ffuf_rate_args(scope: dict) -> ToolInvocationExtras:
    """
    ffuf: confirmed real flag `-rate <n>` (requests/sec, whole ffuf process).
    Stage 10 runs ffuf ONE HOST PER INVOCATION in a Python loop, so `-rate`
    is a TRUE per-host cap — this deliberately sidesteps the R3 whole-
    invocation-ceiling gap that bites katana/nuclei (the highest-traffic tool
    in the pipeline is exactly where a real per-host guarantee matters most).

    Uses resolve_effective_rps() directly (program-confirmed or the
    conservative default), NOT scaled by host_count: only one host is being
    fuzzed at any instant, so the per-host number applies as-is. A GLOBAL
    rate scope (R4) needs no special handling for the same reason x8/whatweb
    don't — sequential single-host invocations keep the instantaneous
    pipeline rate at or below the stated number.
    """
    per_host = resolve_effective_rps(scope)
    return ToolInvocationExtras(
        extra_args=["-rate", str(per_host)],
        note=f"ffuf -rate {per_host} (per-host cap; one host per invocation, "
             f"so a TRUE per-host guarantee — not the R3 whole-invocation gap)",
    )
```

This is the design's strongest safety property: the roadmap's "most
rate-sensitive item" gets the pipeline's *only* genuinely-per-host rate
enforcement, by construction, at the cost of losing ffuf's cross-host
parallelism (an acceptable trade for the highest-traffic tool).

---

## Minimal in-loop WAF guard (folded in 2026-08-23)

B1 is the stage where a WAF flipping into block mode mid-run does the most
damage, in three distinct ways: (a) **result poisoning** — a WAF that starts
returning 403-to-everything, or 200-with-a-block-page, makes *every* path look
"found" and defeats even `-ac` calibration (calibration baselined against the
pre-block behavior), so the `endpoints` table fills with garbage primitive then
wastes budget chasing; (b) **bans** — a triggered block can get the source IP
banned, poisoning every *subsequent* host in the loop and the rest of the
pipeline; (c) **the program's abuse threshold** — a ToS/scope concern, the exact
thing the rate gate exists to respect.

**This is a deterministic circuit breaker, borrowing the shape of primitive's
flattened breaker — NOT adaptive back-off (that's C3).** It is deliberately
minimal and mostly ffuf-native:

- **Primary mechanism — ffuf `-sf`.** ffuf's native "stop when >95% of responses
  return 403" flag aborts a host's scan the moment it's being 403-flooded. Cheap,
  in-tool, no Python-side subprocess interruption needed. Paired with
  `-maxtime-job` as a hard per-host wall cap so a slow/challenging host can't run
  unbounded.
- **Post-hoc flag.** If ffuf stopped early for a `-sf`/`-maxtime-job` reason (see
  the ⚠️ verify note — determine the real early-stop signal), set the host's
  `waf_flags[host] = {"waf_suspected": True, "waf_signal": "403_flood"|"maxtime",
  "waf_block_ratio": <observed if available>}`. `_apply_waf_flags` writes this as
  host metadata (`waf_suspected`, listed in `state.TARGET_DERIVED_METADATA_KEYS`?
  — no: this is *our* determination about the host, agent-authored, so it is
  trusted metadata, not target-derived).
- **The flag IS the handoff.** `waf_suspected` (+ signal + observed ratio, and
  later C3's vendor label) is the intel primitive consumes when it needs to
  decide whether to attempt WAF-bypass techniques against this host. See
  `PRIMITIVE_WAF_HANDLING_DESIGN.md` — B1 detects and retreats; primitive is the
  agent that (under its guard + budget) may engage.

**B1 always retreats — it has no bypass license, and that's correct.** Unlike
primitive, B1 is bulk untargeted discovery with no authorization to engage a
filter and nothing to gain by fighting one (a tripped WAF is pure downside:
bans + poisoned data). So B1's posture is unconditional back-off; the *offensive*
side (finding and using bypasses) is primitive's, and the boundary is clean.

**⚠️ Known blind spot, shared with the primitive side.** `-sf` keys on **403**.
A challenge-based WAF that answers **`200` with a JS challenge / CAPTCHA /
interstitial** (Cloudflare, Akamai Bot Manager, DataDome) will NOT trip `-sf`,
and `-ac` may not suppress a uniform 200-challenge either — so a
challenge-flooded host can still poison results. Detecting the 200-challenge case
needs a richer signal than status code (challenge-page fingerprints, body-size
collapse, vendor headers). **This is deferred, and it is the same open question
flagged in `PRIMITIVE_WAF_HANDLING_DESIGN.md` (Open Q1) — needs more info before
either side commits a solution.** For B1 v1, `-sf` + `-maxtime-job` is the
minimal guard; the 200-challenge gap is named, not closed.

---

## R-inheritance (every active stage carries these)

- **R1 (scope covers traffic) — satisfied by construction.** ffuf fuzzes a single
  seeded host's own path space (`https://host/FUZZ`); it never leaves that host.
  Redirects are **not followed** (`-r` off) — a 30x is recorded as a finding
  (the bundler-probe 301-as-JS lesson), never chased off-origin. No katana-style
  `-fs` regex needed; same-origin is inherent to the tool's model.
- **R3 (per-host rate) — actively resolved, not merely inherited.** The per-host
  invocation loop makes `-rate` a true per-host cap (see §Rate). B1 is the first
  multi-request-per-host tool in the pipeline that closes the R3 gap rather than
  accepting it.
- **R5 (per-target raw files)** — `raw/stage10_ffuf_{sanitized_host}.json`.
- **R7 (fault isolation)** — per-host try/except in the loop; nothing aborts the
  run.
- **R8 (at-rest hygiene)** — raw ffuf output lands in the chmod-700 run dir by
  construction (RunState owns it).
- **R9 / untrusted-by-default** — target-authored response fields
  (`content_type`, any title) are metadata only; the A1 brief (future) treats
  them as delimited data. Endpoint *values* are agent-authored
  (`target_derived=0`). The `waf_suspected` flag is *agent-authored* (our
  determination), so it is trusted, not target-derived.

---

## Boundary — recon discovers, it does not test

B1 sends active discovery traffic (GET requests against wordlist paths). It
**enumerates** what exists; it does not exploit, submit input, use credentials,
or confirm a vulnerability. A discovered `/admin` panel or `/.git/config` is a
*lead* handed to primitive as an `endpoint` record — primitive tests it under its
guard. The line is the same one C1 (detection-only nuclei) and C5 (CVE
*candidates*) hold.

**WAF handling sits on the same line.** B1 *detects* a WAF (the `waf_suspected`
flag) and *retreats* from it. It never *engages* the filter — no bypass, no
evasion, no probing what the filter blocks. Engaging a WAF (finding and using a
bypass to prove a specific bug) is primitive's guarded, budgeted, authorized
territory (`PRIMITIVE_WAF_HANDLING_DESIGN.md`). Recon characterizes the obstacle;
primitive defeats it. The single highest-value recon contribution to primitive's
bypass work is not in B1 at all — it's **origin-IP discovery** (C3 `cdncheck`,
F2 cloud assets, F3 ASN expansion, E1 favicon correlation): finding the origin
behind the CDN hands primitive a path that avoids the WAF entirely. B1 does not
do origin discovery; it's noted here as the related, boundary-clean capability
that makes primitive's job easier.

---

## Tests

**Mocked tier — `testing/test_stage10_content_discovery.py`** (mirror
`test_track_d.py` / `test_recon_resolutions.py`):

- Mock ffuf JSON output (a multi-hit `results[]` shape AND an empty result) →
  assert `new_assets` (type=url, ffuf_* metadata) and `endpoint` records
  (url/host/path/method=GET/content_type, `target_derived=0`) are produced.
- `auth_status == "gated"` on a mocked 401/403 hit; `None` otherwise.
- Per-host raw filename suffix `stage10_ffuf_{host}.json` (R5).
- `ffuf_rate_args` emits `-rate <resolve_effective_rps>` and is NOT scaled by
  host count; global-scope scope.json produces the same number.
- Per-host fault isolation: one host raising does not stop the others (R7).
- **WAF guard:** a mocked ffuf early-stop signal (`-sf`/`-maxtime-job`) →
  `waf_flags[host]["waf_suspected"] is True` with the right `waf_signal`; a
  normal completion → `waf_suspected is False`. `_apply_waf_flags` writes the
  flag to host metadata via `update_asset_metadata`.
- Via `main.persist_records`: an endpoint whose parent url asset is
  `out_of_scope` is dropped; in-scope parent gets `asset_id` linked.
- `_sanitize(host)` suffix matches the stage-7 sanitizer behavior.

**Real-tool verification (BEFORE the parser, per CONTRIBUTING):**

- `ffuf -h` → confirm `-rate`, `-ac`, `-sf`/`-se`/`-sa`, `-maxtime-job`,
  `-recursion`/`-recursion-depth`, `-e`, `-of json -o`, `-noninteractive` flag
  names + semantics, AND the real early-stop signal `-sf` emits (exit code /
  JSON marker / stderr).
- One real ffuf run against a **deliberately fuzzable throwaway** (zonetransfer.me
  is too thin for content discovery — use a target you control or a local test
  server) → capture the real JSON shape, confirm `-ac` suppresses a catch-all,
  confirm `-rate` throttles as expected, and (if you can point it at anything
  behind a WAF) confirm what `-sf` early-stop actually looks like. Only then
  write `_parse_ffuf_json`.
- A confirming second run (the project's definition-of-done step 5).

**`testing/run_stage10_only.py`** — a standalone re-runner mirroring the other
`run_stage*_only.py` scripts (calls `run_stage10_and_report`), for iterating on a
run dir that already has live hosts in `assets.db`.

---

## Doc cascade (flush when built)

- **`STATE_SCHEMA.md`** — `endpoints` table note: now *heavily* populated (ffuf,
  stage 10), producer + `target_derived=0` + curated-metadata rule; new
  `raw/stage10_ffuf_{host}.json` line; the `waf_suspected` host-metadata key
  (agent-authored, trusted — NOT in `TARGET_DERIVED_METADATA_KEYS`).
- **`README.md`** — stage 10 in the pipeline flow + state-file table; note the
  live-host seed, the per-host-loop rate property, and the minimal WAF breaker.
- **`pipeline_schematic.mermaid`** — a content-discovery node feeding the
  `endpoints` table.
- **`CONTRIBUTING.md`** — reaffirm verify-real-tool + fail-closed + rate-audit for
  the new active stage (ffuf).
- **`CHANGELOG.md`** — compact entry (DESIGN → DONE).
- **`RECON_ENHANCEMENTS.md`** — flip **B1** from roadmap to BUILT; update the
  Phase-2 row and the "if only three things get built" line.
- **`RECON_AGENT_DESIGN.md`** — fold stage 10 into the stage inventory (larger
  edit; may defer with the Track-D fold).

---

## Explicitly OUT of scope for B1 (so the building agent doesn't over-reach)

- **API-schema / GraphQL discovery** — that's **B2** (Swagger/OpenAPI probing,
  graphw00f + introspection). B1 may *hit* `/swagger.json` if it's in the
  wordlist, but parsing a schema into typed endpoints/params is B2's job.
- **Screenshots (C2), WAF/CDN *detection/labeling* (C3), auth-surface
  classification beyond the free 401/403 signal (C4), CVE candidates (C5)** —
  later phases. B1's `waf_suspected` flag is a minimal in-flight breaker
  by-product, NOT C3's pre-flight `wafw00f`/`cdncheck` vendor labeling.
- **Origin-IP discovery** — the recon-side "WAF bypass" (find the origin behind
  the CDN) lives in C3/F2/F3/E1, not B1.
- **Adaptive/pre-flight WAF back-off** — belongs to C3; B1 ships with only the
  minimal ffuf-native breaker (disclosed, incl. the 200-challenge blind spot).
- **Offensive WAF bypass** — primitive's territory, not recon's
  (`PRIMITIVE_WAF_HANDLING_DESIGN.md`).
- **Target-derived wordlists (E3)** — v1 uses a curated static SecLists set;
  keep `WORDLIST_PATH`/`EXTENSIONS` as constants so E3 can extend without a
  rewrite.

---

## See also

- `RECON_ENHANCEMENTS.md` — B1 sketch + Track B sequencing (this realizes it)
- `RECON_TRACK_D_DESIGN.md` — the `endpoints` table + record/persist pattern B1 fills
- `STATE_SCHEMA.md` — `endpoints` schema + `target_derived` provenance
- `PRIMITIVE_WAF_HANDLING_DESIGN.md` — the offensive-bypass side of WAF handling;
  consumes B1's `waf_suspected` intel; shares the 200-challenge blind spot
- `stage6_crawling.py` — the closest existing active-stage pattern (two-tier raw,
  return-assets-caller-classifies, R1/R7)
- `rate_limits.py` — where `ffuf_rate_args` lands; x8/whatweb are the per-host-loop precedent
- `PRIMITIVE_AGENT_DESIGN.md` §10 — `source_sink_map`, the consumer of these endpoint records
- `CONTRIBUTING.md` — verify-real-tool-before-parser discipline B1 follows
