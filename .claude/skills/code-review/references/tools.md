# Tool reference

## What runs, and why each one is there

| tool | covers | severity mapping | auto-fix |
|---|---|---|---|
| ruff | Python lint: pyflakes, pycodestyle, bugbear (B), flake8-bandit (S), pyupgrade, isort, pylint subset, mccabe complexity, and ~20 more plugin families | S-rules high/medium; F8*/B0*/PLE medium; other F low; E/W/I/D info | safe fixes only (`--fix` without `--unsafe-fixes`) |
| ruff-format | Black-compatible formatting | info | yes |
| mypy | static types; kit config is gradual (`check_untyped_defs`, no `strict`) | errors medium; import-not-found/untyped low; notes info | no |
| bandit | Python security AST checks, the full set (ruff's S rules are a subset) | HIGH+HIGH-confidence → critical; else HIGH/MEDIUM/LOW → high/medium/low | no |
| semgrep | pattern + light dataflow rules; kit rules in `configs/semgrep/` always run, registry packs (`p/python`, `p/flask`, `p/django`, `p/bash`, `p/dockerfile`, `p/javascript`, `p/secrets`, `p/owasp-top-ten`) when reachable; `.semgrep/` in the repo is picked up too | ERROR→high (HIGH confidence→critical), WARNING→medium, INFO→low | no |
| pip-audit | known CVEs in `requirements*.txt` (or the active venv when only pyproject exists) | high | no (reports fix version) |
| shellcheck | bash/sh correctness | error→high, warning→medium, info→low, style→info | no |
| shfmt | shell formatting | info | only with `--fix-shell` |
| hadolint | Dockerfile best practice + embedded shellcheck | same as shellcheck | no |
| gitleaks | secrets in the working tree (`dir` mode) or full history (`--history`) | critical | no |
| eslint | JS/TS, only if the repo has it in `node_modules` | fatal→high, error→medium, warn→low | `--fix` |
| sonar | SonarQube Community: bugs, vulnerabilities, hotspots, smells, duplication, cognitive complexity, tech debt | BLOCKER→critical, CRITICAL/HIGH→high, MAJOR/MEDIUM→medium, MINOR/LOW→low, INFO→info; hotspots by vulnerabilityProbability | no |

Deliberately not included: pylint (ruff covers the useful subset far faster), flake8/black/isort
(replaced by ruff), vulture (dead-code reports are mostly false positives without a whitelist —
add it per-repo if wanted), pytest/coverage (a review tool shouldn't run the test suite by
surprise; feed coverage XML to Sonar instead — see `sonar-project.properties.example`).

## Config precedence

For ruff, mypy, bandit, hadolint and gitleaks: if the repo has its own config
(`pyproject.toml [tool.x]`, `ruff.toml`, `mypy.ini`, `.bandit`, `.hadolint.yaml`,
`.gitleaks.toml`), that is used untouched. Otherwise the kit defaults in `configs/` apply.
To adopt the kit defaults permanently, copy the relevant file into the repo — then tune it there.

The kit ruff config enables a broad rule set but ignores the highest-churn ones (`E501`,
`PLR2004`, `TRY003`, `T201`, `ERA001`). Tests get `S`, `ARG`, `PLR` waived.

## Environment knobs

| variable | effect |
|---|---|
| `REVIEW_SEMGREP_OFFLINE=1` | skip registry packs, run only kit + repo rules |
| `SONAR_HOST_URL`, `SONAR_TOKEN` | override `~/.config/code-review/sonar.env` |
| `SONAR_PROJECT_KEY` | override the auto key (repo dir name); `sonar-project.properties` also wins |
| `SONAR_SCANNER_HOST_URL` | URL the *scanner container* uses to reach the server, if different (auto-rewrites localhost → host.docker.internal) |
| `REVIEW_HOOK_MYPY=0` | hook only: skip mypy on edit |
| `REVIEW_HOOK_QUIET=1` | hook only: disable entirely (bulk refactors) |
| `REVIEW_HOOK_RUFF_IGNORE` | hook only: comma list of rule prefixes the hook stays quiet about |

## CLI

```
review.py [--root DIR] [--changed] [--base REF] [--fix] [--fix-shell] [--sonar] [--sonar-wait S]
          [--history] [--only a,b] [--skip a,b] [--out DIR] [--max-md N] [--fail-on SEV] [--json] [-v]
```

`--fail-on high` makes it usable as a CI gate or pre-commit check (exit 1 if any finding ≥ high).
`--json` prints a one-line summary object (used by the optional Stop hook).

## Adding a repo-local semgrep rule

Create `.semgrep/<name>.yaml` in the repo; it's picked up automatically. Example — flag
any HTTP call in the recon pipeline that doesn't go through the rate-limited client:

```yaml
rules:
  - id: recon-direct-requests
    languages: [python]
    severity: ERROR
    message: "Use recon.http.client (rate-limited, scope-checked) instead of requests directly."
    paths: { include: ["recon/**"] }
    pattern-either:
      - pattern: requests.$M(...)
      - pattern: httpx.$M(...)
```

## SonarQube notes

* First-time: `docker compose -f sonar/docker-compose.yml up -d && bash sonar/setup.sh`.
  Linux/WSL2 needs `vm.max_map_count=262144`.
* The scanner runs as a container (`sonarsource/sonar-scanner-cli`) unless `sonar-scanner`
  is on PATH. On Docker Desktop (Windows/macOS) the container reaches the server via
  `host.docker.internal`; on Linux the kit adds `--add-host=host.docker.internal:host-gateway`.
* Projects are created on first scan with the token from setup (admin token has Create Projects).
* Community Build analyses the main branch only; `--changed` scoping does not apply to Sonar —
  it always scans the whole tree, and the report pulls all *unresolved* issues.
* Coverage: run `pytest --cov --cov-report=xml:.review/coverage.xml` first and set
  `sonar.python.coverage.reportPaths` in `sonar-project.properties`.
