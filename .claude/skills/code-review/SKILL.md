---
name: code-review
description: Run a full multi-tool code review of the current repo (or just the changed files) — ruff lint + format, mypy, bandit, semgrep, pip-audit, shellcheck, shfmt, hadolint, gitleaks, eslint, and SonarQube — auto-apply the safe fixes, then triage the rest into a ranked report and fix what matters. Use this whenever the user asks to review, audit, lint, type-check, security-scan, "check", "clean up", or "make sure it's solid" for a repo, branch, PR, or set of files, or before committing/merging/releasing. Also use it when the user mentions SonarQube, mypy, ruff, bandit, or code quality in the context of their own code.
allowed-tools: Bash(python3 *) Bash(git *) Read Edit Grep Glob
---

# /code-review

One command runs every analyzer that applies to this repo and writes a single normalized
report. Your job is the part the tools can't do: decide what's real, fix it well, and
explain what you left alone.

## 1. Run it

```bash
python3 .claude/skills/code-review/scripts/review.py --fix            # whole repo, safe fixes applied
python3 .claude/skills/code-review/scripts/review.py --fix --changed  # only files changed vs main + working tree
python3 .claude/skills/code-review/scripts/review.py --fix --sonar    # add SonarQube (needs sonar/setup.sh done once)
```

If the skill is installed globally instead of in the repo, the script lives at
`~/.claude/skills/code-review/scripts/review.py`. Use `--changed` when the user is
reviewing a branch or PR; whole-repo when they say "review the repo" or it's the first run.
Add `--sonar` when the user asks for it or the Sonar server is known to be running
(`~/.config/code-review/sonar.env` exists) — it's the slowest step (30 s – few min).
Add `--history` if secrets in git history matter (pre-open-source, post-incident).

Semgrep pulls rule packs from the registry the first time; the kit's own rules always run
even offline. Tools that aren't installed are reported as `skipped`, not errors — tell the
user which ones and the one-line install (it's in the `note` column).

`--fix` applies only changes that cannot alter behaviour: ruff's *safe* fixes (unused
imports, import order, trivial rewrites), `ruff format`, and `eslint --fix`. Shell
formatting (`shfmt`) is report-only unless `--fix-shell`. Nothing else is touched
automatically — every other change is yours to make deliberately.

## 2. Read the report

`.review/report.md` is ranked critical → info and is what you read. `.review/report.json`
has the same findings with `tool`, `rule`, `severity`, `category`, `file`, `line`,
`fixable`, `extra` (e.g. `also` = other tools that flagged the same line, `cwe`, `hint`)
for when you need to slice it:

```bash
jq -r '.findings[] | select(.severity=="high") | "\(.file):\(.line) \(.tool)/\(.rule) \(.message)"' .review/report.json
jq -r '.findings[] | select(.category=="type")' .review/report.json
```

Categories: `secret`, `security`, `dependency`, `bug`, `type`, `shell`, `docker`,
`complexity`, `smell`, `lint`, `style`. Same-line security findings from several tools are
already merged into one record (see `also`), so counts are real, not triple-counted.

## 3. Triage — this is the actual review

Work top-down by severity. For every finding decide one of: **fix**, **suppress with a
reason**, or **report as-is**. Reasoning that helps:

**Secrets (gitleaks / semgrep secret rules).** Treat as real until proven otherwise. If it's
a live credential: don't just delete the line — tell the user it needs rotating, and that
removing it from the working tree doesn't remove it from history (`--history` finds those;
`git filter-repo` removes them). Test fixtures and obvious placeholders can be suppressed
with a `.gitleaks.toml` allowlist or a `# gitleaks:allow` comment, and say why.

**Security (bandit / semgrep / ruff S / sonar hotspots).** The tool sees a pattern, not
the data flow. Read the surrounding code and answer: *can attacker-controlled input reach
this?* `subprocess(shell=True)` on a constant is noise; on a request parameter is a
finding. For this user's repos remember the context: bug-bounty tooling deliberately makes
"unsafe" requests (`verify=False`, raw sockets, odd headers) at targets — that's the tool
working as intended, and the right response is to gate it behind an explicit flag, not to
"fix" it away. Compliance-adjacent code (anything a regulator or auditor might read) is
the opposite: parameterised SQL, no pickle on external data, and no hard-coded credentials
are non-negotiable there.

**Dependencies (pip-audit).** Report the vulnerable package, the CVE, whether the
vulnerable code path is even used, and the fix version. Bump the pin only if the user
asked for fixes beyond "safe" ones or the upgrade is a patch release — a major bump is a
decision for them. Group by package; don't list eight urllib3 CVEs as eight action items.

**Types (mypy).** `Unsupported operand`, `has no attribute`, `incompatible return` are
usually real bugs on some path — fix the logic, not the annotation. `import-untyped` /
`import-not-found` are environment noise unless the module is the project's own.
Prefer a correct annotation over `# type: ignore`; when you do ignore, use the specific
code: `# type: ignore[arg-type]`.

**Bugs (ruff B*, PLE*, F8*, mypy).** Mutable default args, unused variables that hint at a
logic slip, bare `except`, `== None`. Fix these — they're cheap and the tool is nearly
always right.

**Shell (shellcheck).** Unquoted variables, `cd` without `|| exit`, iterating `ls`. In a
shell-heavy repo these are the findings most likely to bite in production; fix
warnings and errors, judge the info-level ones.

**Docker (hadolint).** Running as root and missing `--no-install-recommends` / apt cache
cleanup are worth fixing; version pinning rules are disabled by default in the kit config
because they mostly generate churn.

**Style / smell (ruff style rules, sonar code smells, complexity).** Only act on these when
the user asked for cleanup, or the smell hides a bug (a 60-branch function usually does).
Otherwise summarise the counts and move on — the report is not a to-do list.

## 4. Fix well

* Re-read a file before editing it after `--fix` ran — the formatter changed it.
* Make the minimal correct change. Don't restructure a function to satisfy a complexity
  rule unless asked.
* Every suppression carries a reason on the same line:
  `# noqa: S603  # args are a fixed list, no shell`, `# nosec B608  # table name from enum`.
* After fixing, re-run with `--changed` to confirm the count dropped and nothing new
  appeared (formatters occasionally expose a new lint).
* Don't touch generated code, vendored files, or migrations.

## 5. Report back

Keep it short and concrete — the user is technical and reads the report themselves if
they want the long version. Use this shape:

```
Review: <repo or branch> — <N> findings (<c> critical / <h> high / <m> medium), <k> files auto-fixed

Fixed
- app/core.py:26 SQL built with % — parameterised (bandit B608 + sonar S3649)
- scripts/deploy.sh:3 cd without guard → `cd "$DIR" || exit 1`

Needs you
- app/core.py:6 AWS key in source (gitleaks). Removed from tree; rotate it and run --history.
- requirements.txt requests 2.25 → 2.32.4 fixes 4 CVEs; pinned version bump is your call.

Suppressed (with reasons in-line)
- 3× S603 subprocess on fixed arg lists

Skipped tools: hadolint (not installed: brew install hadolint)
Full report: .review/report.md · Sonar dashboard: <url if run>
```

Lead with what you changed and what needs a human decision. Counts of style findings go
in one line at the end, not as a list.

## Reference

`references/tools.md` — what each tool covers, severity mapping, config precedence
(repo config wins over kit defaults), env knobs, and how to add a repo-local semgrep rule.
Read it when a tool misbehaves or the user asks "why did X flag this".
