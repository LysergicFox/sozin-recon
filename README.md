# sozin-recon

A **scripted, deterministic reconnaissance engine** for authorized web-application
security testing and bug-bounty work. It discovers assets, fingerprints them, and
hands back a prioritized, first-class **attack surface** — subdomains, live hosts,
URLs, parameters, endpoints, secrets, and services — with **every stage's state
externalized to disk** so a human can inspect, intervene, or resume between any two
steps.

It is a self-contained, Dockerized product. It runs **one pass** of stages 1–11
plus enrichment passes, scripted end to end — same input, same behavior. It makes
**no LLM calls** and does **no exploitation**: it discovers, enriches, prioritizes,
and flags candidates, and never tests, exploits, uses a credential, or confirms a
vulnerability.

> **Authorized use only.** Every active-traffic stage runs behind a deterministic
> scope gate and per-host rate limits. You must supply a `scope.json` with an
> explicit in-scope allowlist, `verified_by_human: true`, and an affirmative
> `rate_limit` block before the pipeline will run. An absent rate-limit block
> **blocks** the run rather than guessing (fail-closed).

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

## Output

All state lands in the run directory you point it at:

| File | Contents |
|---|---|
| `assets.db` | SQLite: the asset graph (`subdomains`/`urls`/`ips`) + `takeover_findings` + first-class source records (`parameters`, `endpoints`, `secrets`, `services`) |
| `needs_review.json` | Assets the scope gate could not classify — pending human resolution |
| `run_state.json` | Current stage/pass/status |
| `raw/stageN_toolname.json` | Verbatim tool output (per-target suffix on multi-target loops) |
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
docker run --rm -v "$PWD/runs:/runs" sozin-recon --run-dir /runs/example
```

Or via compose:

```bash
docker compose run --rm recon --run-dir /runs/example
```

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
**`sozin-dashboard`** consumes. Docker note: bind-mount the target folder and
pass its in-container path, e.g.
`-v "$PWD/targets:/targets" … --target-dir /targets/hackerone/acme`.

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

---

## Design & discipline

This engine was built to a strict staged-verification discipline — every stage:
build → mocked tests → **real run against a consented target** → fix → confirming
run. Tool interfaces are never trusted from `--help`; they're confirmed against
real output. See `docs/CONTRIBUTING.md` for the working agreements.

Standing consented test target for recon verification: `zonetransfer.me` (a
deliberately open, consented DNS-testing domain).

## Known gaps

- Runs **one pass** — loop-until-stable is not built here.
- Content discovery's WAF handling covers both a 403 flood (ffuf `-sf`) and a
  **200-with-JS-challenge** wall (a pre-flight retreat when the host's stage-4
  fingerprint matches a known interstitial — Cloudflare "Just a moment", DDoS-Guard,
  etc.). Residual: detection is marker-based, so a challenge whose title/body preview
  carries no recognizable marker could still be fuzzed.
- `nuclei` takeover-finding parse path is unverified against a real positive.
- Screenshots (C2) depend on a system Chromium and may need per-environment
  tuning inside the container.

## Licensing / authorization

Use this only against systems you are explicitly authorized to test. You are
responsible for staying within the scope and rate limits you declare.
