# sozin-recon

A **scripted, deterministic reconnaissance engine** for authorized web-application
security testing and bug-bounty work. It discovers assets, fingerprints them, and
hands back a prioritized, first-class **attack surface** — subdomains, live hosts,
URLs, parameters, endpoints, secrets, and services — with **every stage's state
externalized to disk** so a human can inspect, intervene, or resume between any two
steps.

It is a self-contained, Dockerized product. It runs stages 1–11 plus enrichment
passes, scripted end to end — same input, same behavior — **looping the discovery
stages until the asset graph stabilizes** (loop-until-stable), then running the
finalizers once. It makes **no LLM calls** and does **no exploitation**: it
discovers, enriches, prioritizes, and flags candidates, and never tests, exploits,
uses a credential, or confirms a vulnerability.

> **Authorized use only.** Every active-traffic stage runs behind a deterministic
> scope gate and per-host rate limits. You must supply a `scope.json` with an
> explicit in-scope allowlist, `verified_by_human: true`, and an affirmative
> `rate_limit` block before the pipeline will run. An absent rate-limit block
> **blocks** the run rather than guessing (fail-closed). At runtime a request-count
> **rate-guard** observes how fast tools actually send requests and gracefully halts
> the run if a tool grossly exceeds the rate it was authorized for — so an unattended
> run can't quietly overshoot even if a tool ignores its own rate flag.

**New here? Start with [QUICKSTART.md](QUICKSTART.md)** — build → scope → run →
read results, end to end.

---

## What it does (pipeline order)

```
1   passive discovery            (subfinder, assetfinder, amass, gau, waybackurls, certspotter)
3   active DNS + brute force     (alterx, puredns, dnsx)
4   live host probing            (httpx, naabu)   → +F5 reverse DNS
4.5 WAF / CDN detection (C3)      (wafw00f)
5   hidden parameter discovery   (x8, paramspider)
6   crawling                     (katana)
6.5 content discovery (B1)        (ffuf + SecLists)
7   JS discovery + extraction    (jsluice)        → +E4 offline secret classification
8   subdomain takeover + detection (nuclei)
9   technology fingerprinting    (whatweb)
    C2 screenshots               (httpx -system-chrome)
    C5 tech→CVE candidate flagging (offline)
10  API-schema discovery (B2a)    (OpenAPI/Swagger + GraphQL introspection)
11  archived-JS mining (B4)       (Wayback CDX → jsluice; passive toward target)
    C4 auth-surface classification (deterministic, no traffic)
    F1 URL clustering            (deterministic, no traffic)
    A2 interest scoring          (deterministic, no traffic)
    F6 target-profile digest     (deterministic, no traffic)
```

Stage 2 is intentionally reserved/skipped. Stages 6.5 and 4.5 are fractional
by design (they slot between integer stages). Every active-traffic stage is
scope-gated, per-host rate-bounded, and fault-isolated (one tool failing does
not kill the run).

The list above is a **stage → tools** catalog. Actual execution is
**loop-until-stable**: PRE-LOOP {1} → LOOP {3, 4, F5, 5, 6, 6.5, 7} repeated
until the asset graph converges → FINALIZE once {4.5, 8, 9, C2, C5, 10, 11 + the
offline C4/F1/A2/F6 finalizers}. See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**
for the visual topology, the loop/convergence flow, and the data model.

## Output

All state lands in the run directory you point it at:

| File | Contents |
|---|---|
| `assets.db` | SQLite: the asset graph (`subdomains`/`urls`/`ips`) + `takeover_findings` + first-class source records (`parameters`, `endpoints`, `secrets`, `services`) |
| `needs_review.json` | Assets the scope gate could not classify — pending human resolution |
| `run_state.json` | Current stage/pass/status + `passes_completed` + `pass_deltas` (loop trail) |
| `raw/stageN_toolname.json` | Verbatim tool output (per-target suffix on multi-target loops; `__pN` suffix on loop passes ≥ 2) |
| `scope.json` | Your input allowlist (read-only from recon's POV) |

Inspect it at any point: `sqlite3 run/assets.db`. The full on-disk schema is
`docs/STATE_SCHEMA.md` (authoritative).

**Never commit a run directory** — stage 7 extracts real secrets. Run dirs and
`*.db` are `.gitignore`d; keep them out of version control.

---

## Quick start (Docker — recommended)

The image bakes in every external CLI tool plus SecLists and the nuclei
templates, so you don't have to install ~20 Go/Rust/Ruby/Python tools yourself.

```bash
docker build -t sozin-recon .
```

Prepare a run directory on the host with your `scope.json` (see
`scope.example.json`):

```bash
mkdir -p runs/example
cp scope.example.json runs/example/scope.json
$EDITOR runs/example/scope.json   # set your real in-scope allowlist + rate_limit
```

Run the pipeline (the run dir is a mounted volume, so state stays on the host):

```bash
docker run --rm -v "$PWD/runs:/runs" \
  -e SOZIN_RUNDIR_UID=$(id -u) -e SOZIN_RUNDIR_GID=$(id -g) \
  sozin-recon --run-dir /runs/example
```

Or via compose:

```bash
SOZIN_RUNDIR_UID=$(id -u) SOZIN_RUNDIR_GID=$(id -g) \
  docker compose run --rm recon --run-dir /runs/example
```

> The container runs as **root** (so the baked CLIs + SecLists under `/root`
> resolve), which would leave the `chmod 700` run dir root-owned and unreadable
> from the host. `SOZIN_RUNDIR_UID`/`GID` hand the finished run dir back to your
> host user — same 700 mode, host-readable (`sqlite3 assets.db` etc.). Omit them
> to leave it root-owned. A local (no-Docker) run already owns its files, so it
> ignores these.

## Quick start (local / no Docker)

Requires Python 3.11+ and **all** the external CLIs on your `PATH` (see the
pipeline table above) plus SecLists at `/usr/share/seclists`.

```bash
pip install -r requirements.txt
python3 main.py --run-dir /path/to/run_directory
```

### Where runs go — `--run-dir` vs `--target-dir`

Exactly one is required:

- **`--run-dir <dir>`** — run into an existing directory that already contains a
  verified `scope.json`. The manual/legacy path.
- **`--target-dir <dir>`** — point at a **target folder** that holds the
  canonical `scope.json` (e.g. `bugbounty/targets/<platform>/<target>/`, as
  produced by the `scope-tos-parser` skill). Recon creates a fresh, time-sortable
  run dir at `<target>/runs/run_<UTC-ts>_<shortid>/`, `chmod 700`s it, copies the
  canonical `scope.json` in as the run's immutable snapshot, and runs there.

The `--target-dir` layout (one target folder, many runs under `runs/`) is what
**`sozin-dashboard`** consumes. Docker note: bind-mount the target folder, pass
its in-container path, and set the hand-back UID/GID so the new run dir is
host-readable, e.g.
`-e SOZIN_RUNDIR_UID=$(id -u) -e SOZIN_RUNDIR_GID=$(id -g) -v "$PWD/targets:/targets" … --target-dir /targets/hackerone/acme`.

```bash
python3 main.py --target-dir /path/to/bugbounty/targets/hackerone/acme
```

### Re-run a single stage

`testing/run_stage1_only.py` / `run_stage7_only.py` / `run_stage8_only.py` /
`run_stage9_only.py` / `run_stage11_only.py` / `run_content_discovery_only.py`
iterate one stage against an existing `assets.db` by importing the shared
`run_stageN_and_report()` from `main.py` (never reimplementing it).

---

## `scope.json`

Minimal shape (full example in `scope.example.json`):

```json
{
  "verified_by_human": true,
  "in_scope": { "domains": ["*.example.com"], "ip_ranges": ["203.0.113.0/24"] },
  "rate_limit": {
    "stated_by_program": true, "requests_per_second": 5, "scope": "per_host",
    "source_text": "please limit automated scanning to 5 req/s",
    "extracted_by": "human", "resolution": "confirmed"
  }
}
```

- `rate_limit.scope` is `per_host` (default, scaled by host count) or `global`
  (passed through unscaled).
- If a program states no rate limit, use `"resolution": "not_applicable"` for
  the conservative default — but the block must be **present**, or the run is
  blocked.

### Runtime rate-guard & optional `request_budget`

The `rate_limit` block tells each tool how fast it *may* go; the **runtime rate-guard**
(always on) checks how fast it *actually* went and halts the run — status
`rate_exceeded` — if a tool's observed rate grossly exceeds what it was authorized for.
The rate is the safety-relevant dimension, so it is always enforced.

**Total volume is not.** Programs almost never state a request cap, and inventing one
would truncate legitimate deep recon, so there is **no volume cap by default**. Add an
optional `request_budget` block *only* when a program states such a limit:

```json
"request_budget": {
  "max_requests_per_host": 50000,
  "max_requests_total": 200000,
  "max_runtime_seconds": 21600
}
```

All fields are optional (omit the block entirely for the default: rate-guarded,
uncapped). A cap that is hit halts the run with status `budget_exhausted`
(`runtime_exceeded` for the wall-clock cap). On any halt the offline finalizers still
run, so you get a labeled, scored surface over whatever was gathered. Per-run request
telemetry lands in `run_state.json`'s `request_ledger` block.

---

## Design & discipline

This engine was built to a strict staged-verification discipline — every stage:
build → mocked tests → **real run against a consented target** → fix → confirming
run. Tool interfaces are never trusted from `--help`; they're confirmed against
real output. See `docs/CONTRIBUTING.md` for the working agreements.

Standing consented test targets for recon verification: `zonetransfer.me` (a
deliberately open, consented DNS-testing domain — the quick convergence/clean-exit
smoke test) and `ginandjuice.shop` (PortSwigger's deliberately-scannable demo shop
— the rich-surface target for the URL/param/JS/loop machinery).

## Known limitations & post-v1 roadmap

**Intentional scope boundary (by design):** **no LLM calls, no exploitation.**
Recon discovers, enriches, prioritizes, and flags candidates; it never tests,
exploits, uses a credential, or confirms a vulnerability. That is the contract,
not a gap.

**Small residuals in shipped features:**
- **Per-pass timings** — `run_state.json`'s `timings` keeps only the last loop
  pass's value per stage (fixed keys). Cosmetic; telemetry only.
- **WAF/JS-challenge detection is marker-based** — content discovery retreats
  from a 403 flood (ffuf `-sf`), a near-total **403-wall** (block-ratio backstop),
  and a **200-with-JS-challenge** interstitial (Cloudflare "Just a moment",
  DDoS-Guard, …); a challenge whose title/body carries no recognizable marker
  could still be fuzzed.
- **Subdomain-takeover findings are unconfirmed candidates** — the nuclei
  takeover parser is verified against real nuclei v3.11.1 output, but in-the-wild
  *detection* of a dangling resource is nuclei's job; recon flags, never confirms.
- **Screenshots (C2)** depend on a system Chromium and may need per-environment
  tuning inside the container.

**Named-deferred, post-v1 roadmap** (tracked, never silently dropped):
- LLM scope-gate + review tiers (today everything ambiguous → human review, the
  safe degraded state) and the curated A1 attack-surface brief.
- Network secret verification (trufflehog) and additional passive/discovery
  breadth (chaos/asnmap sources, origin-IP discovery, GraphQL introspection,
  NSEC walking).
- A **measuring/throttling egress proxy** (Phase B of the runtime rate-guard): the
  detective rate-guard shipped today observes and halts *post-invocation* (a tool that
  ignores its flag is caught after that host, before the next); routing all HTTP tools
  through a local measuring proxy would enforce the rate in real time regardless of
  tool behavior. The ledger is built to accept proxy-fed counts without stage changes.

## Licensing / authorization

**License:** proprietary — © 2026 LysergicFox, all rights reserved. See
[LICENSE](LICENSE). No use, copying, modification, or distribution without the
copyright holder's prior written permission.

**Authorized use:** run this only against systems you are explicitly authorized
to test; you are responsible for staying within the scope and rate limits you
declare.
