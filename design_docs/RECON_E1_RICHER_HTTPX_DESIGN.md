# E1 — richer httpx (design-lock)

> **✅ BUILT + REAL-DATA VERIFIED 2026-08-23** (pushed to origin/main). The original design-lock status below is superseded; see `CHANGELOG.md` + the module for the shipped form.

**Status: DESIGN-LOCKED, NOT BUILT.** Realizes **E1** of `RECON_ENHANCEMENTS.md`
(Track E, "process & tooling — cheaper wins"; scheduled with Phase 2). httpx is
**already invoked in stage 4** (`stages/stage4_live_probing.py`, `run_httpx`) and
the pipeline consumes only a fraction of its output. E1 **extends that existing
invocation in place** with five near-free enrichments — favicon hash, body
preview, ASN, CDN/WAF label, JARM TLS fingerprint, and HTTP-method surface — that
feed **C3** (WAF/CDN + origin-IP correlation), **C4** (auth-surface / method
classification) and **A2** (interest scoring). No new tool, no new stage, no new
request pass for most of it.

This doc is written to the same discipline every stage was: **the real tool
interface was verified before the design was locked** (`httpx -h` + `httpx -ldv`
run 2026-08-23 against the installed ProjectDiscovery httpx — see §Confirmed
interface facts). It is fail-closed, rate-audited, R7-isolated (inherited from
stage 4's existing httpx guard), and scope-safe (R1). Nothing here is coded yet.

---

## Why E1 — cheapest enrichment on the roadmap

Stage 4 already sends one httpx probe per in-scope live host and already parses a
JSON line per host. Today it keeps `status_code`, `title`, `tech`, the body/header
`sha256` hashes, `final_url`, `chain_status_codes`, and the TLS SAN list — and
throws the rest of the line away. Five of httpx's own already-computed fields are
exactly the "know your target" signals the later tracks were going to rediscover:

- **favicon hash** → the recon-side path *around* a WAF: correlate a CDN-fronted
  host to its **origin IP** (C3). B1's boundary doc names "E1 favicon correlation"
  as one of the origin-discovery capabilities that make primitive's bypass work
  possible.
- **ASN + CDN/WAF label** → C3's pre-flight "is this host behind a WAF/CDN"
  signal, so primitive doesn't rediscover it live and B1's future adaptive
  back-off has something to key on.
- **HTTP-method surface** → C4's auth-/method-surface map.
- **body preview** + all of the above → cheap, explainable inputs to A2's interest
  score.

The point of E1 is that this is **data already on the wire** — we pay for the
probe in stage 4 regardless; E1 just stops discarding what httpx already returns
(favicon and JARM are the two exceptions that add traffic — see §Cost classes).

---

## Confirmed interface facts (verified 2026-08-23 — `httpx -h` + `httpx -ldv`)

Per CONTRIBUTING's "never trust flag spellings from a roadmap," every flag below
was confirmed against the **installed** httpx, and every **JSON output key** was
confirmed via `httpx -ldv` (which lists the real json field-key names locally,
with no target traffic). **The roadmap's shorthand was wrong in two places** —
`-jarm`'s key is `jarm_hash` not `jarm`, and `-method`/`OPTIONS` are two different
mechanisms (see facts 6–7). These are confirmed **flag + key** facts; the **nested
object shapes** of `asn`/`cdn` (flagged ⚠️) still need one real probe to pin down
before the parser is written, exactly as stage 4's original hash-shape assumptions
had to be corrected on a real run.

| # | Roadmap asked for | Real flag | Real JSON key(s) (from `-ldv`) | Notes |
|---|---|---|---|---|
| 1 | favicon-hash | `-favicon` | `favicon` (mmh3 hash), `favicon_url`, `favicon_path`, `favicon_md5` | `-h`: "display mmh3 hash for `/favicon.ico`". The **mmh3** value in `favicon` is the Shodan-style correlation hash. **Adds one request** (`GET /favicon.ico`, same-origin). |
| 2 | body-preview | `-bp` / `-body-preview` | `body_preview` | `-h`: "display first N characters of response body (default 100)". Rides the existing root request — **no extra request**. Target-authored text. |
| 3 | asn | `-asn` | `asn` | `-h`: "display host asn information". ⚠️ **object shape unconfirmed** — expected sub-fields `as_number`/`as_name`/`as_country`/`as_range`; confirm on a real probe before parsing. Computed from the host IP, not target-authored. Rides the existing request. |
| 4 | cdn | `-cdn` | `cdn` (bool), `cdn_name`, `cdn_type` | `-h`: "display cdn/waf in use **(default true)**". **httpx already runs cdncheck by default** — stage 4 simply never reads `cdn*`. So the cdn/WAF label is *literally free* today (no flag even needed; add `-cdn` for explicitness). `cdn_type` distinguishes cdn vs waf vs cloud. Rides the existing request. |
| 5 | jarm | `-jarm` | **`jarm_hash`** (NOT `jarm`) | `-h`: "display jarm fingerprint hash". JARM sends ~**10 crafted TLS ClientHellos** per host — **adds handshakes**, distinct cost class (see §Cost classes). Computed fingerprint. |
| 6 | method | `-method` | `method` | `-h`: "display http request method". **This only echoes OUR request method (GET)** — near-useless for C4 on its own. Free (rides existing request), trusted (it's our value). |
| 7 | OPTIONS | `-x string` | (probed method reflected in `method`) | `-h`: "`-x` request methods to probe, use 'all' to probe all HTTP methods". This is the real "OPTIONS" lever — but `-x OPTIONS` **adds an OPTIONS request per host**, and `-x all` multiplies requests per host. The *useful* allowed-methods signal is the server's `Allow` response header, which needs `-irh` (include response headers) to capture. See decision 4 + Open Q1. |

Supporting facts also confirmed and reused:
- Output stays **`-json -silent`** (unchanged); every new field appears as an
  added key on the **same** per-host JSON line stage 4 already iterates — so the
  parser change is purely "read more keys off `obj`," no new invocation to parse.
- `-favicon`/`-asn`/`-jarm`/`-method`/`-cdn` are all **display/probe** flags that
  populate their key only when present (except `cdn`, already on by default).
- Body/header hash keys are `body_sha256`/`header_sha256` under the `hash` object
  (already handled by stage 4 — unchanged).

---

## Locked decisions (recommended; Jared's calls flagged)

1. **Extend stage 4's existing `run_httpx` invocation in place — do NOT add a
   separate pass or a new stage.** This is the whole point of E1: the enrichment
   fields ride the probe stage 4 already sends. A second httpx pass would double
   the target traffic to collect data the first pass could have returned for free.
   The four zero-added-request fields (body-preview, asn, cdn, method) are pure
   additive flags on the existing command; favicon and jarm add traffic but still
   belong on the same invocation (same rate envelope, same R7 guard, same raw
   archive). *Alternative rejected:* a dedicated "stage 4b enrichment" module —
   more code, more traffic, no benefit; the data is a superset of what stage 4
   already fetches.

2. **Ship body-preview, asn, cdn, method now (all zero added request).** These
   ride the existing root GET (or, for asn/cdn, are computed from its IP/result).
   Near-zero cost, immediate feed to C3/C4/A2. `-cdn` is already defaulting on, so
   this is mostly "start reading keys we already pay for."

3. **Ship favicon now (accept +1 same-origin request/host).** Favicon
   correlation is the single highest-value E1 field (origin-IP discovery, C3), and
   `GET /favicon.ico` on the same host is as benign as the root probe (R1 clean).
   One extra request per host is a bounded constant, not a crawl. **Recommended
   in.**

4. **JARM: ⚠️ Jared call — recommended IN, but named as the one meaningful-cost
   field.** JARM adds ~10 TLS ClientHello handshakes per host (no HTTP body, no
   exploitation — pure TLS fingerprinting, R1-benign). It is genuinely useful
   (server-stack fingerprint → clustering + C3), but it is *not* the "free
   enrichment" the other fields are. Recommend enabling it because the handshake
   cost is a small bounded per-host constant and it only runs once per host in
   stage 4; **flag it so Jared can drop it if the added handshake volume against a
   large host set is unwelcome.** *Alternative:* gate JARM behind a config flag,
   default on.

5. **HTTP-method surface: ⚠️ Jared call.** Add **`-method`** now (free, trivially
   trusted) so the probed method is captured, but recognize it only echoes GET.
   The real C4 signal — *which* methods a host allows — needs either `-x OPTIONS`
   (+1 request/host) plus `-irh` to capture the `Allow` header, or `-x all`
   (multiplies requests/host — **rejected**, breaks the single-request envelope).
   **Recommended:** defer server-stated allowed-methods to **C4** (which formally
   owns `endpoints.auth_status` and the auth/method surface) and ship only the
   free `-method` echo in E1, so E1 stays honestly "cheap enrichment." *Alternative
   Jared may pick:* include `-x OPTIONS -irh` in E1 now to populate an
   `httpx_allow_methods` key from the OPTIONS `Allow` header (+1 request/host,
   still benign). See Open Q1.

6. **Provenance: `body_preview` is target_derived (untrusted); favicon hash, asn,
   cdn label, jarm hash, method are computed/observed (trusted).** See §Provenance
   — this drives one `TARGET_DERIVED_METADATA_KEYS` change and nothing else.

7. **Curated metadata only in `assets.db`; full JSON stays in the raw archive.**
   As today, the verbatim httpx JSONL is `save_raw`'d; E1 adds only the curated
   keys to host metadata. `body_preview` is capped by httpx itself (default 100
   chars) so it is safe to store as-is; do **not** widen it with `-body-preview`'s
   length option (keep the 100-char default — a preview, not a body dump).

---

## Where it slots — `stages/stage4_live_probing.py` `run_httpx`

E1 touches exactly two spots in `run_httpx`, plus one provenance line in
`state.py`. **No `main.py` change** — stage 4's metadata-update plumbing
(`main.py` lines ~534–543, `update_asset_metadata` per host) carries any new
metadata keys through unchanged, because it applies the whole returned dict
generically.

**(a) The invocation** (current flags → E1 flags):

```python
stdout, stderr, code = _run_tool([
    "httpx", "-l", hosts_path,
    "-json", "-silent",
    "-status-code", "-title", "-tech-detect",
    "-follow-redirects", "-location",
    "-hash", "sha256",
    "-tls-grab",
    # --- E1 additions (same invocation) ---
    "-favicon",          # -> favicon (mmh3), favicon_url  [decision 3, +1 req/host]
    "-body-preview",     # -> body_preview                 [decision 2, free]
    "-asn",              # -> asn (object)                 [decision 2, free]
    "-cdn",              # -> cdn, cdn_name, cdn_type       [decision 2, free/default-on]
    "-jarm",             # -> jarm_hash                    [decision 4, +~10 handshakes/host]
    "-method",           # -> method (echoes GET)          [decision 5, free]
    *rate.extra_args,
])
```

**(b) The parse** (add keys to the existing `metadata_by_host[input_host]` dict —
same block that today builds `httpx_status_code` etc.):

```python
asn_obj = obj.get("asn") if isinstance(obj.get("asn"), dict) else {}
metadata_by_host[input_host] = {
    # ... existing keys unchanged ...
    "httpx_favicon_hash": obj.get("favicon"),          # mmh3, correlation key (C3)
    "httpx_body_preview": obj.get("body_preview"),     # TARGET-AUTHORED (untrusted)
    "httpx_asn": asn_obj or None,                      # ⚠️ confirm shape on real probe
    "httpx_cdn": obj.get("cdn"),                        # bool: behind a CDN/WAF?
    "httpx_cdn_name": obj.get("cdn_name"),             # e.g. "cloudflare"
    "httpx_cdn_type": obj.get("cdn_type"),             # cdn|waf|cloud
    "httpx_jarm": obj.get("jarm_hash"),                # NOTE key is jarm_hash
    "httpx_method": obj.get("method"),                 # echoes our GET (trusted)
}
```

`asn`'s nested shape is the one ⚠️ **verify-on-real-probe** item before this
parser is trusted (stage 4's docstring already records that httpx's hash shape had
to be corrected this way — the same lesson applies to `asn`).

---

## Records / metadata produced

E1 produces **no new Track-D records** — it is pure **host-metadata** enrichment on
existing `subdomain` assets, applied through the same `update_asset_metadata` path
stage 4/9 already use. New keys:

| Metadata key | Source field | Meaning | Feeds |
|---|---|---|---|
| `httpx_favicon_hash` | `favicon` | mmh3 favicon hash (origin correlation) | C3, A2 |
| `httpx_body_preview` | `body_preview` | first 100 chars of body (**untrusted**) | A2 |
| `httpx_asn` | `asn` (obj) | ASN number/name/country/range | C3, A2 |
| `httpx_cdn` | `cdn` | bool: behind CDN/WAF | C3 |
| `httpx_cdn_name` | `cdn_name` | CDN/WAF vendor label | C3, A2 |
| `httpx_cdn_type` | `cdn_type` | `cdn`\|`waf`\|`cloud` | C3 |
| `httpx_jarm` | `jarm_hash` | JARM TLS-stack fingerprint | C3, A2 |
| `httpx_method` | `method` | probed method (echoes GET) | C4 (thin) |

*(If decision 5's alternative is chosen: `httpx_allow_methods` from the OPTIONS
`Allow` header → C4.)*

---

## Provenance — one `TARGET_DERIVED_METADATA_KEYS` change

R9 asks a single question per key: **is the stored value target-authored text?**

- **`httpx_body_preview` → TARGET_DERIVED (untrusted).** It is literally the first
  100 characters of the target's response body — attacker-controllable free text,
  exactly the class the review flagged (the real run captured a literal
  `<script>`). It **must** join `state.TARGET_DERIVED_METADATA_KEYS` alongside
  `httpx_title` (its exact sibling), so recon's first LLM (the A1 brief) treats it
  as delimited data, never instructions.
- **`httpx_favicon_hash`, `httpx_asn`, `httpx_cdn`, `httpx_cdn_name`,
  `httpx_cdn_type`, `httpx_jarm`, `httpx_method` → trusted (computed/observed).**
  None is free target text: favicon/jarm are **computed hashes** (a hash can't
  carry a prompt-injection payload, same reasoning that keeps `httpx_body_hash`
  out of the set); asn/cdn are **httpx's own lookups/classification** against IP
  ranges and cdncheck data, not the target's words; `method` is **our** request
  verb. These stay out of `TARGET_DERIVED_METADATA_KEYS`. (This mirrors B1's
  `waf_suspected`-is-agent-authored / target-response-is-metadata split.)

The **only** state.py edit E1 requires:

```python
TARGET_DERIVED_METADATA_KEYS = frozenset({
    # ... existing ...
    "httpx_title",
    "httpx_tls_san",
    "httpx_body_preview",   # E1 — first 100 chars of target body, attacker-controllable
})
```

---

## Rate model — unchanged invocation, but the R3 per-host caveat now applies

**The rate translation (`rate_limits.httpx_rate_args`) is unchanged.** E1 adds
flags to the *same* httpx invocation; the same whole-invocation `-rl` ceiling
(base_rps × host_count, or an unscaled global cap per R4) still applies to the
whole run. No new `rate_limits.py` helper, no new call site.

**But E1 changes stage-4 httpx from "~1 request/host" to a small bounded
constant/host** (root GET + `/favicon.ico` GET + ~10 JARM handshakes, and +1
OPTIONS if decision 5's alternative is taken). That nudges stage-4 httpx out of
the "~1 request/host, so host_count scaling distributes correctly" camp (R3) and
into the **same whole-invocation-not-strictly-per-host caveat already documented
for the stage-7 bundler probe and nuclei**: the `-rl` ceiling caps the aggregate,
so a single host can, in principle, see more than `base_rps` if httpx concentrates
its handshakes. This is **disclosed, not fixed here** — it is small (a bounded
per-host constant, not an unbounded crawl) and identical in kind to the existing
flagged tools; the real fix (per-host invocation / request-count instrumentation)
rides with that same tracked work, exactly as `katana_rate_args`/`nuclei_rate_args`
say. The honest note belongs in `run_httpx`'s docstring: stage 4 is no longer a
clean ~1-req/host tool once favicon + jarm are on.

---

## Downstream consumers (why E1 exists)

- **C3 — WAF/CDN + origin-IP correlation (its biggest single win).**
  - `httpx_cdn`/`httpx_cdn_name`/`httpx_cdn_type` are literally C3's pre-flight
    WAF/CDN label — recon labels it once, primitive stops rediscovering it live,
    and B1's future adaptive back-off keys on it.
  - `httpx_favicon_hash` is the **origin-discovery** feed: a CDN-fronted host and
    its true origin server usually serve the **same favicon**, so the mmh3 hash
    pivots (via a Shodan/Censys `http.favicon.hash` lookup) from the fronted host
    to **candidate origin IPs** — the recon-side "path around the WAF" that B1's
    boundary section explicitly credits to "E1 favicon correlation."
  - `httpx_asn` clusters hosts by owning network and helps separate
    target-owned infrastructure from shared CDN/cloud ranges.
- **C4 — auth/method surface.** `httpx_method` (and, if adopted, the OPTIONS
  `Allow` capture) is the method-surface half of C4's public-vs-gated map that
  lands in `endpoints.auth_status`.
- **A2 — interest scoring.** Every E1 key is a cheap, explainable A2 signal:
  non-CDN origin (more likely directly attackable), unusual JARM/tech cluster,
  a `body_preview` matching A2's keyword list (`admin`, `login`, `debug`, …), a
  shared favicon hash grouping sibling hosts.

E1 only **produces** these signals; C3/C4/A2 **consume** them when they are built.

---

## R-inheritance

- **R1 (scope covers traffic).** Every E1 field is benign, read-only, single-host:
  `/favicon.ico` is same-origin; JARM is TLS handshakes to the same host; asn/cdn
  are computed, not fetched from elsewhere. No new off-scope traffic — stage 4's
  one accepted residual (the redirect GET) is unchanged.
- **R5 (per-target raw).** Unchanged — stage 4 saves one combined httpx JSONL via
  `save_raw(STAGE, "httpx", ...)`; E1 adds keys to lines already archived.
- **R7 (fault isolation).** Inherited unchanged — the existing stage-4 httpx
  try/except already isolates an httpx failure from naabu and from the run. A
  malformed `asn`/`favicon` field degrades to `None` for that host (the parse uses
  `.get`), never aborts.
- **R8 (at-rest hygiene).** Raw JSONL (now including `body_preview`) lands in the
  chmod-700 run dir by construction.
- **R9 / untrusted-by-default.** `httpx_body_preview` joins
  `TARGET_DERIVED_METADATA_KEYS`; the computed/observed fields stay trusted (see
  §Provenance).

---

## Boundary — recon enriches, it does not test

E1 is pure enrichment on a probe recon already sends. It **observes** (a favicon
hash, a CDN label, a TLS fingerprint, a method echo); it never tests, exploits,
submits input, uses a credential, or engages a WAF. Discovering a CDN or an origin
candidate is a **lead** handed downstream — primitive is the agent that (under its
guard) may act on an origin IP or attempt a bypass. This is the same line B1/B2
hold; E1 sits comfortably on the recon side of it. Target-authored fields
(`body_preview`) are untrusted-by-default from the moment they are written.

---

## Verification target (before the parser is trusted — CONTRIBUTING step 3)

- **`zonetransfer.me`** (the standing recon target) exercises the free fields:
  `asn`, `favicon`, `jarm_hash`, `method`, `body_preview` all populate on a normal
  host. Confirm the **`asn` object shape** here (the one ⚠️ unconfirmed key) and
  confirm `favicon`/`jarm_hash` are non-null.
- **A CDN-fronted host** (e.g. any Cloudflare/Fastly-fronted consented target)
  is required to exercise `cdn`/`cdn_name`/`cdn_type` — zonetransfer.me is not
  reliably CDN-fronted, so a second host that *is* behind a CDN is the only way to
  confirm the `cdn*` keys populate with a real vendor label. Capture one real JSON
  line from each before writing the parser; then mocked tests → real stage-4 run →
  fix → confirming run (steps 2–5).

---

## Tests (mocked — extend `testing/` stage-4 coverage)

- A mocked httpx JSON line carrying `favicon`, `body_preview`, `asn` (object),
  `cdn`/`cdn_name`/`cdn_type`, `jarm_hash`, `method` → assert every new
  `httpx_*` metadata key is populated on the host's metadata dict with the right
  value.
- A line **missing** the new keys (older httpx / field absent) → each new key
  degrades to `None`, no `KeyError` (the `.get` contract).
- `asn` present but **not a dict** → `httpx_asn` is `None`, no crash (mirrors the
  existing `hash`/`tls` isinstance guards).
- **Provenance:** assert `"httpx_body_preview" in TARGET_DERIVED_METADATA_KEYS`
  and the computed keys (`httpx_favicon_hash`, `httpx_asn`, `httpx_cdn*`,
  `httpx_jarm`, `httpx_method`) are **not** in it.
- Rate: `httpx_rate_args` output is unchanged by E1 (same `-rl` args) — a guard
  test that the invocation still carries exactly one `-rl`.
- (If decision 5 alt adopted) an OPTIONS `Allow` header → `httpx_allow_methods`.

---

## Doc cascade (flush when built)

- **`STATE_SCHEMA.md`** — new `httpx_*` host-metadata keys on `subdomain` assets;
  note `httpx_body_preview` is in `TARGET_DERIVED_METADATA_KEYS` (untrusted) while
  favicon/asn/cdn/jarm/method are trusted/computed.
- **`README.md`** — stage 4 description gains the enrichment fields (favicon/CDN/
  ASN/JARM/method); note the CDN label now lands in recon, feeding C3.
- **`CONTRIBUTING.md`** — httpx moves from ⚠️-partially-consumed to E1-enriched;
  reaffirm the verify-real-tool discipline that caught `jarm_hash` ≠ `jarm`.
- **`CHANGELOG.md`** — DESIGN → BUILT entry; record the confirmed flag/key facts.
- **`RECON_ENHANCEMENTS.md`** — flip **E1** from roadmap to BUILT; update the
  Phase-2 row (E1 no longer "remains").
- **`RECON_AGENT_DESIGN.md`** — fold the enriched stage-4 httpx into the stage
  inventory (with the Track-D fold already owed).

---

## Explicitly OUT of scope for E1

- **Consuming** the new signals — C3 (WAF/CDN back-off + origin correlation), C4
  (auth/method map), A2 (interest score), A1 (brief) own consumption. E1 only
  produces the metadata.
- **A separate enrichment stage or a second httpx pass** — E1 is strictly an
  extension of the stage-4 invocation.
- **Shodan/Censys favicon-hash lookups** to resolve origin IPs from the hash —
  that network pivot is C3/F-track origin discovery, not E1. E1 records the hash;
  something else queries the index.
- **`-x all` method fuzzing** — rejected (multiplies requests/host, breaks the
  single-request envelope). Only the free `-method` echo (and optionally one
  `-x OPTIONS`) is on the table.
- **Screenshots (`-screenshot`)** — that's **C2**, a heavier, sensitive-at-rest
  addition, not E1.
- **Widening `-body-preview`** beyond httpx's 100-char default — a preview, not a
  body dump; the full body stays only in the raw archive.
- **New Track-D records** — E1 produces none; it is host metadata only.

---

## Open questions for Jared

1. **OPTIONS / allowed-methods (decision 5).** Ship only the free `-method` echo
   now and let **C4** own real allowed-method discovery, or include `-x OPTIONS
   -irh` in E1 now (+1 request/host) to populate `httpx_allow_methods` from the
   `Allow` header? *Recommendation: defer to C4; ship `-method` echo only.*
2. **JARM (decision 4).** Enable `-jarm` (adds ~10 TLS handshakes/host,
   R1-benign) as recommended, gate it behind a default-on config flag, or drop it?
   *Recommendation: enable, it's a bounded per-host constant and a genuinely
   useful fingerprint.*
3. **`asn` object shape** is the one interface fact still ⚠️ unconfirmed (couldn't
   be read from `-ldv`, which lists only the top-level key). Confirm the nested
   sub-fields on the first real probe before locking the `httpx_asn` parse — no
   blocker, just the standard "verify on real data" gate.

---

## See also

- `RECON_ENHANCEMENTS.md` — the E1 sketch + Track E; C3/C4/A2 (the consumers)
- `stages/stage4_live_probing.py` — `run_httpx`, the invocation E1 extends
- `rate_limits.py` — `httpx_rate_args` (unchanged; the R3 whole-invocation caveat
  E1 now inherits is documented in `katana_rate_args`/`nuclei_rate_args`)
- `state.py` — `TARGET_DERIVED_METADATA_KEYS` (the one edit E1 needs)
- `RECON_B1_CONTENT_DISCOVERY_DESIGN.md` — boundary section credits "E1 favicon
  correlation" as recon-side origin discovery; `waf_suspected`-is-agent-authored
  precedent for the trusted/target-derived split
- `RECON_TRACK_D_DESIGN.md` — the record/metadata + `target_derived` provenance model
- `CONTRIBUTING.md` — verify-real-tool-before-parser discipline (caught
  `jarm_hash` ≠ `jarm`, `-method` ≠ OPTIONS-probing)
