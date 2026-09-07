# Quickstart

End-to-end: from a fresh clone to a structured attack surface on disk.

> **Authorized use only.** Only run this against systems you are explicitly
> authorized to test. The scope gate is fail-closed and will refuse to run
> without an affirmative, human-verified scope (see step 2).

## 1. Build the image (once)

```bash
docker build -t sozin-recon .
```

This is the heavy step — it bakes in every external CLI (the ProjectDiscovery
suite, amass, ffuf, jsluice, x8, whatweb, …), massdns, SecLists, the nuclei
templates, and Chromium. After it completes, everyday use is just `docker run`.

## 2. Set up a run directory + scope

Each engagement gets its own directory on the host. The engine reads
`scope.json` from it and writes all output back into it.

```bash
mkdir -p runs/acme
cp scope.example.json runs/acme/scope.json
$EDITOR runs/acme/scope.json
```

The gate requires **all** of the following, or the run is blocked:

- `verified_by_human: true` — your assertion that you are authorized.
- an `in_scope` allowlist — domains (wildcards allowed) and/or IP ranges.
- a `rate_limit` block that is **present**. An absent block blocks the run
  rather than guessing. If the program states no limit, set
  `"resolution": "not_applicable"` for the conservative default.

```json
{
  "verified_by_human": true,
  "in_scope": { "domains": ["*.acme.com", "acme.com"], "ip_ranges": [] },
  "rate_limit": {
    "stated_by_program": true,
    "requests_per_second": 5,
    "scope": "per_host",
    "source_text": "limit automated scanning to 5 req/s",
    "extracted_by": "human",
    "resolution": "confirmed"
  }
}
```

`rate_limit.scope` is `per_host` (default; scaled by host count) or `global`
(passed through unscaled).

## 3. Run the pipeline

Mount the run directory into the container and point the engine at it. Because
it's a mounted volume, all state stays on the host and nothing sensitive is
baked into the image.

```bash
docker run --rm -v "$PWD/runs:/runs" sozin-recon --run-dir /runs/acme
```

Or with compose:

```bash
docker compose run --rm recon --run-dir /runs/acme
```

It runs **one deterministic pass**:

```
passive discovery → DNS brute/resolve → live probing → WAF/CDN → hidden params
→ crawl → content discovery → JS extraction → takeover/detection
→ fingerprinting → screenshots → CVE flagging → API-schema → archived-JS
→ auth classification → URL clustering → interest scoring → target profile
```

## 4. Read the results

Everything lands in `runs/acme/`:

```bash
sqlite3 runs/acme/assets.db
```

| File | What's in it |
|---|---|
| `assets.db` | The asset graph (`subdomains`/`urls`/`ips`) **plus** the first-class source records that are the real product: `parameters`, `endpoints`, `secrets` (fingerprints only — never raw values), `services`, `takeover_findings`, and the interest-scored / clustered / auth-classified surface. |
| `run_state.json` | Current stage/pass/status. |
| `raw/stageN_toolname.json` | Verbatim output from every tool, per target/page — audit exactly what a tool returned. |
| `needs_review.json` | Anything the scope gate couldn't confidently classify — waiting on a human call. |

`docs/STATE_SCHEMA.md` is the authoritative field-by-field map of that database.

**Never commit a run directory** — stage 7 extracts real secrets. Run dirs and
`*.db` are `.gitignore`d.

## Mental model

A one-shot, deterministic recon sweep: authorized scope in → a structured,
prioritized attack surface on disk. It never exploits or confirms anything — it
hands you the map (with the interesting parts ranked) and you decide what to
probe next.

## Local (no Docker)

Requires Python 3.11+ and every external CLI on your `PATH` (see the pipeline
table in `README.md`) plus SecLists at `~/tools/SecLists`.

```bash
pip install -r requirements.txt
python3 main.py --run-dir /path/to/run_dir
```

### Re-run a single stage

The `testing/run_*_only.py` scripts iterate one stage against an existing
`assets.db` (e.g. `run_stage7_only.py`, `run_content_discovery_only.py`). They
import the shared `run_stageN_and_report()` from `main.py` — they never
reimplement it.
