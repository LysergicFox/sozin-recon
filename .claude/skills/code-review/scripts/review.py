#!/usr/bin/env python3
"""
review.py — one-shot multi-tool code review with normalized output.

Runs every applicable analyzer for the repo (ruff, mypy, bandit, semgrep,
pip-audit, shellcheck, shfmt, hadolint, gitleaks, eslint, SonarQube),
applies *safe* auto-fixes when asked, and writes:

    .review/report.json   machine-readable, one record per finding
    .review/report.md     human/agent-readable ranked report

Exit code is 0 unless --fail-on is given. Every tool is optional: a tool that
is not installed is reported as "skipped" rather than crashing the run.

Usage (from repo root, or pass --root):
    review.py                    # report only, whole repo
    review.py --fix              # apply safe fixes first (ruff --fix, ruff format)
    review.py --changed          # only files changed vs --base (default: origin/main or main)
    review.py --sonar            # also run the SonarQube scanner + pull issues
    review.py --only ruff,mypy   # subset
    review.py --skip semgrep     # everything but
    review.py --fail-on high     # non-zero exit if any finding >= high
"""

# ruff: noqa: C901, PLR0912, PLR0915, RET502, RET503, S310, S603, PLW2901
# (big linear orchestrator by design; subprocess args are constructed from known tool names)
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

KIT_DIR = Path(__file__).resolve().parent.parent  # .../skills/code-review
CONFIG_DIR = KIT_DIR / "configs"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ALL_TOOLS = [
    "ruff",
    "ruff-format",
    "mypy",
    "bandit",
    "semgrep",
    "pip-audit",
    "shellcheck",
    "shfmt",
    "hadolint",
    "gitleaks",
    "eslint",
    "sonar",
]

DEFAULT_EXCLUDES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".review",
    ".scannerwork",
    "dist",
    "build",
    ".tox",
    ".eggs",
    "site-packages",
    ".idea",
    ".vscode",
}


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str  # critical | high | medium | low | info
    category: str  # lint | style | type | security | secret | dependency | shell | docker | complexity | bug | smell
    file: str
    line: int
    message: str
    col: int = 0
    fixable: bool = False
    url: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolRun:
    name: str
    status: str  # ok | skipped | error
    findings: int = 0
    note: str = ""
    seconds: float = 0.0


# --------------------------------------------------------------------------- utils


def log(msg: str) -> None:
    print(f"[review] {msg}", file=sys.stderr, flush=True)


def which(name: str) -> str | None:
    return shutil.which(name)


def run(
    cmd: list[str], cwd: Path, timeout: int = 900, env: dict | None = None
) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=full_env
    )


def rel(path: str | Path, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def is_excluded(p: Path, root: Path) -> bool:
    try:
        parts = p.resolve().relative_to(root.resolve()).parts
    except ValueError:
        return True
    return any(part in DEFAULT_EXCLUDES for part in parts)


def git(root: Path, *args: str) -> str:
    try:
        cp = run(["git", *args], root)
        return cp.stdout.strip() if cp.returncode == 0 else ""
    except FileNotFoundError:
        return ""


def changed_files(root: Path, base: str | None) -> list[Path]:
    """Files changed vs base (merge-base), plus uncommitted + untracked."""
    if not git(root, "rev-parse", "--is-inside-work-tree"):
        return []
    if not base:
        for cand in ("origin/main", "origin/master", "main", "master"):
            if git(root, "rev-parse", "--verify", "--quiet", cand):
                base = cand
                break
    out: set[str] = set()
    if base:
        mb = git(root, "merge-base", base, "HEAD")
        if mb:
            out.update(git(root, "diff", "--name-only", mb, "HEAD").splitlines())
    out.update(git(root, "diff", "--name-only").splitlines())
    out.update(git(root, "diff", "--name-only", "--cached").splitlines())
    out.update(git(root, "ls-files", "--others", "--exclude-standard").splitlines())
    return [root / f for f in sorted(out) if (root / f).is_file()]


# --------------------------------------------------------------------------- discovery


@dataclass
class Repo:
    root: Path
    py: list[Path]
    sh: list[Path]
    docker: list[Path]
    js: list[Path]
    req_files: list[Path]
    has_pyproject: bool
    has_package_json: bool


def _is_shell(p: Path) -> bool:
    if p.suffix in {".sh", ".bash"}:
        return True
    if p.suffix == "" and p.is_file():
        try:
            with p.open("rb") as fh:
                head = fh.read(80)
            return head.startswith(b"#!") and (b"bash" in head or b"/sh" in head)
        except OSError:
            return False
    return False


def discover(root: Path, subset: list[Path] | None) -> Repo:
    if subset is None:
        files = [p for p in root.rglob("*") if p.is_file() and not is_excluded(p, root)]
    else:
        files = [p for p in subset if not is_excluded(p, root)]
    py = [p for p in files if p.suffix in {".py", ".pyi"}]
    sh = [p for p in files if _is_shell(p)]
    docker = [
        p
        for p in files
        if p.name == "Dockerfile" or p.name.startswith("Dockerfile.") or p.suffix == ".dockerfile"
    ]
    js = [p for p in files if p.suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}]
    req_files = sorted(root.glob("requirements*.txt")) + sorted(root.glob("requirements/*.txt"))
    return Repo(
        root=root,
        py=py,
        sh=sh,
        docker=docker,
        js=js,
        req_files=req_files,
        has_pyproject=(root / "pyproject.toml").exists(),
        has_package_json=(root / "package.json").exists(),
    )


def repo_has_config(root: Path, tool: str) -> bool:
    """Does the repo already configure this tool? If not we pass the kit defaults."""
    pyproject = root / "pyproject.toml"
    text = pyproject.read_text(errors="ignore") if pyproject.exists() else ""
    if tool == "ruff":
        return (
            (root / "ruff.toml").exists() or (root / ".ruff.toml").exists() or "[tool.ruff" in text
        )
    if tool == "mypy":
        return (
            (root / "mypy.ini").exists()
            or (root / ".mypy.ini").exists()
            or (
                (root / "setup.cfg").exists()
                and "[mypy" in (root / "setup.cfg").read_text(errors="ignore")
            )
            or "[tool.mypy" in text
        )
    if tool == "bandit":
        return (
            (root / ".bandit").exists() or (root / "bandit.yaml").exists() or "[tool.bandit" in text
        )
    if tool == "hadolint":
        return (root / ".hadolint.yaml").exists() or (root / ".hadolint.yml").exists()
    if tool == "gitleaks":
        return (root / ".gitleaks.toml").exists()
    return False


# --------------------------------------------------------------------------- tools


class Ctx:
    def __init__(self, repo: Repo, fix: bool, fix_shell: bool, verbose: bool):
        self.repo = repo
        self.root = repo.root
        self.fix = fix
        self.fix_shell = fix_shell
        self.verbose = verbose
        self.findings: list[Finding] = []
        self.runs: list[ToolRun] = []
        self.fixed_files: set[str] = set()
        self.sonar_measures: dict[str, Any] = {}

    def add(self, f: Finding) -> None:
        f.file = (
            rel(self.root / f.file, self.root)
            if not os.path.isabs(f.file)
            else rel(f.file, self.root)
        )
        self.findings.append(f)

    def record(
        self, name: str, status: str, findings: int = 0, note: str = "", t0: float = 0.0
    ) -> None:
        self.runs.append(
            ToolRun(name, status, findings, note, round(time.time() - t0, 1) if t0 else 0.0)
        )
        if self.verbose or status != "ok":
            log(f"{name}: {status} ({findings} findings){' — ' + note if note else ''}")


def _paths(files: Iterable[Path], root: Path) -> list[str]:
    return [rel(p, root) for p in files]


def snapshot_mtimes(files: Iterable[Path]) -> dict[Path, float]:
    return {p: p.stat().st_mtime for p in files if p.exists()}


def diff_mtimes(before: dict[Path, float], ctx: Ctx) -> None:
    for p, m in before.items():
        if p.exists() and p.stat().st_mtime != m:
            ctx.fixed_files.add(rel(p, ctx.root))


# ---- ruff -----------------------------------------------------------------

RUFF_SECURITY_PREFIX = ("S",)  # flake8-bandit rules
RUFF_COMPLEXITY = ("C901", "PLR091")


def _ruff_category(code: str) -> str:
    if code.startswith(RUFF_SECURITY_PREFIX) and code[1:2].isdigit():
        return "security"
    if code.startswith(RUFF_COMPLEXITY):
        return "complexity"
    if code[:1] in {"E", "W", "I", "D", "Q", "COM"} or code.startswith(("N", "UP", "ISC")):
        return "style"
    if code.startswith(
        ("B", "PLE", "F8", "F6", "F7", "ARG", "RET", "SIM", "PIE", "T20", "ERA", "PERF", "RUF")
    ):
        return "bug" if code.startswith(("B", "PLE", "F8", "F6", "F7")) else "lint"
    return "lint"


def _ruff_severity(code: str) -> str:
    if code.startswith("S") and code[1:2].isdigit():
        hi = {
            "S102",
            "S105",
            "S106",
            "S107",
            "S301",
            "S302",
            "S307",
            "S324",
            "S501",
            "S502",
            "S506",
            "S602",
            "S605",
            "S608",
        }
        return "high" if code in hi else "medium"
    if code.startswith(("F8", "F6", "F7", "PLE", "B0")):
        return "medium"
    if code.startswith("F"):
        return "low"
    return "low" if not code.startswith(("E", "W", "I", "D")) else "info"


def tool_ruff(ctx: Ctx) -> None:
    t0 = time.time()
    if not ctx.repo.py:
        return ctx.record("ruff", "skipped", note="no python files", t0=t0)
    if not which("ruff"):
        return ctx.record("ruff", "skipped", note="ruff not installed (pip install ruff)", t0=t0)
    cfg = [] if repo_has_config(ctx.root, "ruff") else ["--config", str(CONFIG_DIR / "ruff.toml")]
    paths = _paths(ctx.repo.py, ctx.root)
    if ctx.fix:
        # fix, then format, *then* report — so every tool downstream (and this report) sees the same line numbers
        before = snapshot_mtimes(ctx.repo.py)
        run(["ruff", "check", "--fix", "--exit-zero", "--quiet", *cfg, *paths], ctx.root)
        run(["ruff", "format", "--quiet", *cfg, *paths], ctx.root)
        diff_mtimes(before, ctx)
    cp = run(["ruff", "check", "--output-format", "json", "--exit-zero", *cfg, *paths], ctx.root)
    try:
        items = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        return ctx.record("ruff", "error", note=cp.stderr[-400:], t0=t0)
    n = 0
    for it in items:
        code = it.get("code") or "RUF"
        fixable = bool(it.get("fix")) and (it["fix"].get("applicability") == "safe")
        ctx.add(
            Finding(
                tool="ruff",
                rule=code,
                severity=_ruff_severity(code),
                category=_ruff_category(code),
                file=it["filename"],
                line=it["location"]["row"],
                col=it["location"]["column"],
                message=it["message"],
                fixable=fixable,
                url=it.get("url") or "",
            )
        )
        n += 1
    ctx.record("ruff", "ok", n, t0=t0)


def tool_ruff_format(ctx: Ctx) -> None:
    t0 = time.time()
    if not ctx.repo.py or not which("ruff"):
        return ctx.record("ruff-format", "skipped", note="no python files or ruff missing", t0=t0)
    cfg = [] if repo_has_config(ctx.root, "ruff") else ["--config", str(CONFIG_DIR / "ruff.toml")]
    paths = _paths(ctx.repo.py, ctx.root)
    if ctx.fix:
        # already applied inside tool_ruff (before its reporting pass)
        return ctx.record("ruff-format", "ok", 0, note="applied", t0=t0)
    cp = run(["ruff", "format", "--check", *cfg, *paths], ctx.root)
    n = 0
    for line in cp.stdout.splitlines():
        m = re.match(r"Would reformat: (.+)", line)
        if m:
            ctx.add(
                Finding(
                    "ruff-format",
                    "format",
                    "info",
                    "style",
                    m.group(1),
                    1,
                    "File is not ruff-formatted",
                    fixable=True,
                )
            )
            n += 1
    ctx.record("ruff-format", "ok", n, t0=t0)


# ---- mypy -----------------------------------------------------------------


def tool_mypy(ctx: Ctx) -> None:
    t0 = time.time()
    if not ctx.repo.py:
        return ctx.record("mypy", "skipped", note="no python files", t0=t0)
    if not which("mypy"):
        return ctx.record("mypy", "skipped", note="mypy not installed (pip install mypy)", t0=t0)
    cfg = (
        [] if repo_has_config(ctx.root, "mypy") else ["--config-file", str(CONFIG_DIR / "mypy.ini")]
    )
    cache = ctx.root / ".review" / ".mypy_cache"
    paths = _paths(ctx.repo.py, ctx.root)
    cp = run(
        ["mypy", "--output", "json", "--cache-dir", str(cache), "--no-error-summary", *cfg, *paths],
        ctx.root,
        timeout=1800,
    )
    n = 0
    for line in cp.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            it = json.loads(line)
        except json.JSONDecodeError:
            continue
        sev = it.get("severity", "error")
        code = it.get("code") or "mypy"
        severity = "medium" if sev == "error" else "info"
        if code in {"import-not-found", "import-untyped"}:
            severity = "low"
        ctx.add(
            Finding(
                "mypy",
                code,
                severity,
                "type",
                it["file"],
                it.get("line", 0),
                it["message"],
                col=it.get("column", 0),
                extra={"hint": it.get("hint")} if it.get("hint") else {},
            )
        )
        n += 1
    if cp.returncode not in (0, 1):
        return ctx.record("mypy", "error", n, note=(cp.stderr or cp.stdout)[-400:], t0=t0)
    ctx.record("mypy", "ok", n, t0=t0)


# ---- bandit ---------------------------------------------------------------


def tool_bandit(ctx: Ctx) -> None:
    t0 = time.time()
    if not ctx.repo.py:
        return ctx.record("bandit", "skipped", note="no python files", t0=t0)
    if not which("bandit"):
        return ctx.record(
            "bandit", "skipped", note="bandit not installed (pip install bandit)", t0=t0
        )
    cfg = (
        ["-c", "pyproject.toml"]
        if "[tool.bandit"
        in (
            (ctx.root / "pyproject.toml").read_text(errors="ignore")
            if ctx.repo.has_pyproject
            else ""
        )
        else ["-c", str(CONFIG_DIR / "bandit.yaml")]
    )
    if (ctx.root / ".bandit").exists() or (ctx.root / "bandit.yaml").exists():
        cfg = []
    paths = _paths(ctx.repo.py, ctx.root)
    cp = run(["bandit", "-q", "-f", "json", *cfg, *paths], ctx.root)
    try:
        data = json.loads(cp.stdout or "{}")
    except json.JSONDecodeError:
        return ctx.record("bandit", "error", note=cp.stderr[-400:], t0=t0)
    sevmap = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    n = 0
    for it in data.get("results", []):
        sev = sevmap.get(it.get("issue_severity", "LOW"), "low")
        conf = it.get("issue_confidence", "LOW")
        if sev == "high" and conf == "HIGH":
            sev = "critical"
        ctx.add(
            Finding(
                "bandit",
                it.get("test_id", "B000"),
                sev,
                "security",
                it["filename"],
                it.get("line_number", 0),
                f"{it.get('issue_text', '')} (confidence: {conf.lower()})",
                url=it.get("more_info", ""),
                extra={"cwe": (it.get("issue_cwe") or {}).get("id")},
            )
        )
        n += 1
    ctx.record("bandit", "ok", n, t0=t0)


# ---- semgrep --------------------------------------------------------------


def tool_semgrep(ctx: Ctx) -> None:
    t0 = time.time()
    if not which("semgrep"):
        return ctx.record(
            "semgrep", "skipped", note="semgrep not installed (pip install semgrep)", t0=t0
        )
    # Kit rules ship with the skill (no network needed); registry packs are layered on when reachable.
    local: list[str] = []
    registry: list[str] = []
    if ctx.repo.py:
        local.append(str(CONFIG_DIR / "semgrep" / "kit-python.yaml"))
        registry += ["p/python", "p/flask", "p/django"]
    if ctx.repo.sh or ctx.repo.docker:
        local.append(str(CONFIG_DIR / "semgrep" / "kit-shell.yaml"))
        registry += (["p/bash"] if ctx.repo.sh else []) + (
            ["p/dockerfile"] if ctx.repo.docker else []
        )
    if ctx.repo.js:
        registry += ["p/javascript"]
    if not local and not registry:
        return ctx.record("semgrep", "skipped", note="nothing to scan", t0=t0)
    registry += ["p/secrets", "p/owasp-top-ten"]
    repo_rules = ctx.root / ".semgrep"
    if repo_rules.exists():
        local.append(str(repo_rules))
    if os.environ.get("REVIEW_SEMGREP_OFFLINE") == "1":
        registry = []

    def _scan(configs: list[str]) -> subprocess.CompletedProcess:
        cmd = ["semgrep", "scan", "--json", "--metrics=off", "--quiet", "--timeout", "30"]
        for c in configs:
            cmd += ["--config", c]
        for ex in DEFAULT_EXCLUDES:
            cmd += ["--exclude", ex]
        cmd.append(".")
        return run(cmd, ctx.root, timeout=1800)

    note = ""
    try:
        cp = _scan(local + registry)
        if cp.returncode not in (0, 1) and registry:
            log("semgrep: registry packs unreachable, falling back to kit rules only")
            note = "registry unreachable — kit rules only"
            cp = _scan(local)
    except subprocess.TimeoutExpired:
        return ctx.record("semgrep", "error", note="timed out", t0=t0)
    if cp.returncode not in (0, 1) or not cp.stdout.strip():
        return ctx.record("semgrep", "error", note=(cp.stderr or cp.stdout)[-400:].strip(), t0=t0)
    try:
        data = json.loads(cp.stdout)
    except json.JSONDecodeError:
        return ctx.record("semgrep", "error", note=(cp.stderr or cp.stdout)[-400:], t0=t0)
    sevmap = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    n = 0
    for it in data.get("results", []):
        ex = it.get("extra", {})
        meta = ex.get("metadata", {})
        sev = sevmap.get(ex.get("severity", "WARNING"), "medium")
        if str(meta.get("confidence", "")).upper() == "HIGH" and sev == "high":
            sev = "critical"
        check_id = it.get("check_id", "")
        rule = (
            check_id[check_id.rindex("kit.") :] if "kit." in check_id else check_id.split(".")[-1]
        )
        cat = (
            str(meta.get("category", ""))
            if meta.get("category") in {"secret", "bug", "security"}
            else ("secret" if "secrets" in check_id else "security")
        )
        ctx.add(
            Finding(
                "semgrep",
                rule,
                sev,
                cat,
                it["path"],
                it["start"]["line"],
                ex.get("message", "").strip().split("\n")[0][:300],
                col=it["start"].get("col", 0),
                url=(
                    meta.get("source") or meta.get("references", [""])[0]
                    if meta.get("references")
                    else meta.get("source", "")
                )
                or "",
                extra={"check_id": it["check_id"], "cwe": meta.get("cwe")},
            )
        )
        n += 1
    errs = [e for e in data.get("errors", []) if e.get("level") == "error"]
    note = f"{len(errs)} rule/parse errors" if errs else ""
    ctx.record("semgrep", "ok", n, note=note, t0=t0)


# ---- pip-audit ------------------------------------------------------------


def tool_pip_audit(ctx: Ctx) -> None:
    t0 = time.time()
    if not which("pip-audit"):
        return ctx.record(
            "pip-audit", "skipped", note="pip-audit not installed (pip install pip-audit)", t0=t0
        )
    targets: list[list[str]] = []
    for rf in ctx.repo.req_files:
        targets.append(["-r", rel(rf, ctx.root)])
    if not targets and ctx.repo.has_pyproject:
        # Audits the *current* environment; only meaningful inside the project venv.
        if os.environ.get("VIRTUAL_ENV") or (ctx.root / ".venv").exists():
            targets.append([])
    if not targets:
        return ctx.record(
            "pip-audit", "skipped", note="no requirements*.txt and no venv; nothing to audit", t0=t0
        )
    n = 0
    for tgt in targets:
        cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off", *tgt]
        if not tgt and (ctx.root / ".venv").exists() and not os.environ.get("VIRTUAL_ENV"):
            py = ctx.root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            cmd = [
                "pip-audit",
                "--format",
                "json",
                "--progress-spinner",
                "off",
                "--python",
                str(py),
            ]
        try:
            cp = run(cmd, ctx.root, timeout=900)
        except subprocess.TimeoutExpired:
            ctx.record("pip-audit", "error", note="timed out", t0=t0)
            return
        try:
            data = json.loads(cp.stdout or "{}")
        except json.JSONDecodeError:
            ctx.record("pip-audit", "error", note=(cp.stderr or cp.stdout)[-400:], t0=t0)
            return
        src = " ".join(tgt) or "environment"
        seen: set[tuple[str, str]] = set()
        for dep in data.get("dependencies", []):
            for v in dep.get("vulns", []):
                vid = v.get("id", "VULN")
                if (dep["name"], vid) in seen:
                    continue
                seen.add((dep["name"], vid))
                fix = ", ".join(v.get("fix_versions", []) or [])
                desc = re.sub(r"[#*`_>]+", " ", v.get("description", "") or "")
                desc = re.sub(r"\s+", " ", desc).strip()
                desc = re.split(r"(?<=[.!?])\s", desc, maxsplit=1)[0][:180]
                aliases = ", ".join(a for a in (v.get("aliases") or []) if a.startswith("CVE"))
                ctx.add(
                    Finding(
                        "pip-audit",
                        vid,
                        "high",
                        "dependency",
                        (tgt[1] if tgt else "pyproject.toml"),
                        0,
                        f"{dep['name']} {dep['version']}"
                        + (f" ({aliases})" if aliases else "")
                        + f": {desc}"
                        + (f" — fix: upgrade to {fix}" if fix else " — no fix released"),
                        url=f"https://osv.dev/vulnerability/{vid}",
                        extra={
                            "package": dep["name"],
                            "installed": dep["version"],
                            "fix_versions": v.get("fix_versions"),
                            "aliases": v.get("aliases"),
                            "source": src,
                        },
                    )
                )
                n += 1
    ctx.record("pip-audit", "ok", n, t0=t0)


# ---- shellcheck / shfmt ---------------------------------------------------


def tool_shellcheck(ctx: Ctx) -> None:
    t0 = time.time()
    if not ctx.repo.sh:
        return ctx.record("shellcheck", "skipped", note="no shell scripts", t0=t0)
    if not which("shellcheck"):
        return ctx.record(
            "shellcheck",
            "skipped",
            note="shellcheck not installed (apt/brew install shellcheck)",
            t0=t0,
        )
    cp = run(
        ["shellcheck", "-f", "json", "-x", "-S", "style", *_paths(ctx.repo.sh, ctx.root)], ctx.root
    )
    try:
        items = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        return ctx.record("shellcheck", "error", note=cp.stderr[-400:], t0=t0)
    sevmap = {"error": "high", "warning": "medium", "info": "low", "style": "info"}
    n = 0
    for it in items:
        code = f"SC{it['code']}"
        ctx.add(
            Finding(
                "shellcheck",
                code,
                sevmap.get(it["level"], "low"),
                "shell",
                it["file"],
                it["line"],
                it["message"],
                col=it.get("column", 0),
                fixable=bool(it.get("fix")),
                url=f"https://www.shellcheck.net/wiki/{code}",
            )
        )
        n += 1
    ctx.record("shellcheck", "ok", n, t0=t0)


def tool_shfmt(ctx: Ctx) -> None:
    t0 = time.time()
    if not ctx.repo.sh:
        return ctx.record("shfmt", "skipped", note="no shell scripts", t0=t0)
    if not which("shfmt"):
        return ctx.record("shfmt", "skipped", note="shfmt not installed", t0=t0)
    paths = _paths(ctx.repo.sh, ctx.root)
    if ctx.fix and ctx.fix_shell:
        before = snapshot_mtimes(ctx.repo.sh)
        run(["shfmt", "-w", *paths], ctx.root)
        diff_mtimes(before, ctx)
        return ctx.record("shfmt", "ok", 0, note="applied", t0=t0)
    cp = run(["shfmt", "-l", *paths], ctx.root)
    n = 0
    for f in cp.stdout.splitlines():
        if f.strip():
            ctx.add(
                Finding(
                    "shfmt",
                    "format",
                    "info",
                    "style",
                    f.strip(),
                    1,
                    "Shell script is not shfmt-formatted (report-only unless --fix-shell)",
                    fixable=True,
                )
            )
            n += 1
    ctx.record("shfmt", "ok", n, t0=t0)


# ---- hadolint -------------------------------------------------------------


def tool_hadolint(ctx: Ctx) -> None:
    t0 = time.time()
    if not ctx.repo.docker:
        return ctx.record("hadolint", "skipped", note="no Dockerfiles", t0=t0)
    if not which("hadolint"):
        return ctx.record("hadolint", "skipped", note="hadolint not installed", t0=t0)
    cfg = (
        []
        if repo_has_config(ctx.root, "hadolint")
        else ["--config", str(CONFIG_DIR / "hadolint.yaml")]
    )
    cp = run(
        ["hadolint", "-f", "json", "--no-fail", *cfg, *_paths(ctx.repo.docker, ctx.root)], ctx.root
    )
    try:
        items = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        return ctx.record("hadolint", "error", note=cp.stderr[-400:], t0=t0)
    sevmap = {"error": "high", "warning": "medium", "info": "low", "style": "info"}
    n = 0
    for it in items:
        ctx.add(
            Finding(
                "hadolint",
                it["code"],
                sevmap.get(it["level"], "low"),
                "docker",
                it["file"],
                it["line"],
                it["message"],
                col=it.get("column", 0),
                url=f"https://github.com/hadolint/hadolint/wiki/{it['code']}"
                if it["code"].startswith("DL")
                else "",
            )
        )
        n += 1
    ctx.record("hadolint", "ok", n, t0=t0)


# ---- gitleaks -------------------------------------------------------------


def tool_gitleaks(ctx: Ctx, history: bool) -> None:
    t0 = time.time()
    if not which("gitleaks"):
        return ctx.record("gitleaks", "skipped", note="gitleaks not installed", t0=t0)
    report = ctx.root / ".review" / "gitleaks.json"
    cfg = ["-c", str(ctx.root / ".gitleaks.toml")] if repo_has_config(ctx.root, "gitleaks") else []
    mode = (
        ["git"] if history and git(ctx.root, "rev-parse", "--is-inside-work-tree") else ["dir", "."]
    )
    cp = run(
        [
            "gitleaks",
            *mode,
            "--no-banner",
            "--exit-code",
            "0",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            *cfg,
        ],
        ctx.root,
        timeout=1200,
    )
    if cp.returncode != 0:
        return ctx.record("gitleaks", "error", note=(cp.stderr or cp.stdout)[-400:], t0=t0)
    try:
        items = json.loads(report.read_text() or "[]") if report.exists() else []
    except json.JSONDecodeError:
        items = []
    n = 0
    seen: set[tuple] = set()
    for it in items:
        key = (it.get("File"), it.get("StartLine"), it.get("RuleID"))
        if key in seen:
            continue
        seen.add(key)
        where = it.get("File", "")
        if is_excluded(ctx.root / where, ctx.root):
            continue
        commit = it.get("Commit", "")
        msg = f"Possible secret ({it.get('Description', it.get('RuleID'))})"
        if commit:
            msg += f" in commit {commit[:8]}"
        ctx.add(
            Finding(
                "gitleaks",
                it.get("RuleID", "secret"),
                "critical",
                "secret",
                where,
                it.get("StartLine", 0),
                msg,
                extra={
                    "fingerprint": it.get("Fingerprint"),
                    "commit": commit,
                    "entropy": it.get("Entropy"),
                },
            )
        )
        n += 1
    ctx.record("gitleaks", "ok", n, note="history" if history else "working tree", t0=t0)


# ---- eslint ---------------------------------------------------------------


def tool_eslint(ctx: Ctx) -> None:
    t0 = time.time()
    if not ctx.repo.js:
        return ctx.record("eslint", "skipped", note="no JS/TS files", t0=t0)
    local = ctx.root / "node_modules" / ".bin" / ("eslint.cmd" if os.name == "nt" else "eslint")
    exe = str(local) if local.exists() else which("eslint")
    if not exe or not ctx.repo.has_package_json:
        return ctx.record(
            "eslint",
            "skipped",
            note="eslint not installed in this repo (npm i -D eslint @eslint/js)",
            t0=t0,
        )
    cmd = [exe, "-f", "json"]
    if ctx.fix:
        cmd.append("--fix")
    before = snapshot_mtimes(ctx.repo.js)
    cp = run([*cmd, *_paths(ctx.repo.js, ctx.root)], ctx.root)
    if ctx.fix:
        diff_mtimes(before, ctx)
    try:
        data = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        return ctx.record("eslint", "error", note=(cp.stderr or cp.stdout)[-400:], t0=t0)
    n = 0
    for f in data:
        for m in f.get("messages", []):
            if m.get("fatal"):
                sev = "high"
            else:
                sev = "medium" if m.get("severity") == 2 else "low"
            ctx.add(
                Finding(
                    "eslint",
                    m.get("ruleId") or "parse",
                    sev,
                    "lint",
                    f["filePath"],
                    m.get("line", 0),
                    m.get("message", ""),
                    col=m.get("column", 0),
                    fixable=bool(m.get("fix")),
                )
            )
            n += 1
    ctx.record("eslint", "ok", n, t0=t0)


# ---- SonarQube ------------------------------------------------------------


def _sonar_env(root: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    candidates = [
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "code-review"
        / "sonar.env",
        root / ".sonar.env",
    ]
    for c in candidates:
        if c.exists():
            for line in c.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    for k in ("SONAR_HOST_URL", "SONAR_TOKEN", "SONAR_PROJECT_KEY", "SONAR_SCANNER_HOST_URL"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def _sonar_api(
    host: str, token: str, path: str, params: dict | None = None, method: str = "GET"
) -> Any:
    url = host.rstrip("/") + path
    data = None
    if params and method == "GET":
        url += "?" + urllib.parse.urlencode(params, doseq=True)
    elif params:
        data = urllib.parse.urlencode(params, doseq=True).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read().decode()
        return json.loads(body) if body else {}


def tool_sonar(ctx: Ctx, wait: int) -> None:
    t0 = time.time()
    env = _sonar_env(ctx.root)
    host, token = env.get("SONAR_HOST_URL"), env.get("SONAR_TOKEN")
    if not host or not token:
        return ctx.record(
            "sonar", "skipped", note="no SONAR_HOST_URL/SONAR_TOKEN (run sonar/setup.sh)", t0=t0
        )
    key = env.get("SONAR_PROJECT_KEY") or re.sub(r"[^A-Za-z0-9_.:-]", "-", ctx.root.name)
    props = ctx.root / "sonar-project.properties"
    if props.exists():
        m = re.search(r"^sonar\.projectKey\s*=\s*(.+)$", props.read_text(), re.M)
        if m:
            key = m.group(1).strip()
    # make sure the project exists (needs a token with "Create Projects")
    try:
        _sonar_api(host, token, "/api/system/status")
    except (urllib.error.URLError, OSError) as e:
        return ctx.record("sonar", "skipped", note=f"SonarQube not reachable at {host}: {e}", t0=t0)
    try:
        found = _sonar_api(host, token, "/api/projects/search", {"projects": key})
        if not found.get("components"):
            _sonar_api(
                host,
                token,
                "/api/projects/create",
                {"project": key, "name": ctx.root.name},
                method="POST",
            )
            log(f"sonar: created project {key}")
    except urllib.error.HTTPError as e:
        return ctx.record("sonar", "error", note=f"project check failed: {e}", t0=t0)

    # scanner: local binary if present, else docker image
    scanner_host = env.get("SONAR_SCANNER_HOST_URL") or host
    exclusions = ",".join(f"**/{d}/**" for d in sorted(DEFAULT_EXCLUDES))
    base_props = [
        f"-Dsonar.projectKey={key}",
        "-Dsonar.sources=.",
        f"-Dsonar.exclusions={exclusions},**/*.min.js",
        "-Dsonar.python.version=3.10,3.11,3.12,3.13",
        "-Dsonar.scm.disabled=false",
    ]
    if which("sonar-scanner"):
        cmd = [
            "sonar-scanner",
            *base_props,
            f"-Dsonar.host.url={scanner_host}",
            f"-Dsonar.token={token}",
        ]
    elif which("docker"):
        if "localhost" in scanner_host or "127.0.0.1" in scanner_host:
            scanner_host = re.sub(r"(localhost|127\.0\.0\.1)", "host.docker.internal", scanner_host)
        cmd = [
            "docker",
            "run",
            "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "-e",
            f"SONAR_HOST_URL={scanner_host}",
            "-e",
            f"SONAR_TOKEN={token}",
            "-v",
            f"{ctx.root.resolve()}:/usr/src",
            "sonarsource/sonar-scanner-cli",
            *base_props,
        ]
    else:
        return ctx.record(
            "sonar", "skipped", note="neither sonar-scanner nor docker available", t0=t0
        )
    try:
        cp = run(cmd, ctx.root, timeout=1800)
    except subprocess.TimeoutExpired:
        return ctx.record("sonar", "error", note="scanner timed out", t0=t0)
    if cp.returncode != 0:
        return ctx.record(
            "sonar", "error", note="scanner failed: " + (cp.stderr or cp.stdout)[-600:], t0=t0
        )

    # wait for the compute-engine task so the issues we fetch are fresh
    task_file = ctx.root / ".scannerwork" / "report-task.txt"
    task_id = ""
    if task_file.exists():
        m = re.search(r"^ceTaskId=(.+)$", task_file.read_text(), re.M)
        task_id = m.group(1).strip() if m else ""
    deadline = time.time() + wait
    status = "UNKNOWN"
    while task_id and time.time() < deadline:
        try:
            status = (
                _sonar_api(host, token, "/api/ce/task", {"id": task_id})
                .get("task", {})
                .get("status", "PENDING")
            )
        except urllib.error.HTTPError:
            status = "UNKNOWN"
        if status in {"SUCCESS", "FAILED", "CANCELED"}:
            break
        time.sleep(3)
    if status not in {"SUCCESS", "UNKNOWN"}:
        return ctx.record("sonar", "error", note=f"compute-engine task {status}", t0=t0)

    sevmap = {
        "BLOCKER": "critical",
        "CRITICAL": "high",
        "MAJOR": "medium",
        "MINOR": "low",
        "INFO": "info",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }
    typemap = {
        "BUG": "bug",
        "VULNERABILITY": "security",
        "CODE_SMELL": "smell",
        "SECURITY_HOTSPOT": "security",
    }
    n = 0
    page = 1
    while True:
        data = _sonar_api(
            host,
            token,
            "/api/issues/search",
            {"componentKeys": key, "resolved": "false", "ps": 500, "p": page},
        )
        for it in data.get("issues", []):
            comp = it.get("component", "")
            path = comp.split(":", 1)[1] if ":" in comp else comp
            impacts = it.get("impacts") or []
            sev = sevmap.get(
                (impacts[0].get("severity") if impacts else it.get("severity", "MAJOR")), "medium"
            )
            ctx.add(
                Finding(
                    "sonar",
                    it.get("rule", ""),
                    sev,
                    typemap.get(it.get("type", ""), "smell"),
                    path,
                    it.get("line", 0),
                    it.get("message", ""),
                    url=f"{host.rstrip('/')}/project/issues?id={urllib.parse.quote(key)}&open={it.get('key')}",
                    extra={
                        "effort": it.get("effort"),
                        "type": it.get("type"),
                        "tags": it.get("tags"),
                    },
                )
            )
            n += 1
        total = data.get("paging", {}).get("total", 0)
        if page * 500 >= total:
            break
        page += 1
    try:
        hs = _sonar_api(
            host,
            token,
            "/api/hotspots/search",
            {"projectKey": key, "status": "TO_REVIEW", "ps": 500},
        )
        for it in hs.get("hotspots", []):
            comp = it.get("component", "")
            path = comp.split(":", 1)[1] if ":" in comp else comp
            prob = it.get("vulnerabilityProbability", "MEDIUM")
            ctx.add(
                Finding(
                    "sonar",
                    it.get("ruleKey", "hotspot"),
                    sevmap.get(prob, "medium"),
                    "security",
                    path,
                    it.get("line", 0),
                    f"Security hotspot to review: {it.get('message', '')}",
                    url=f"{host.rstrip('/')}/security_hotspots?id={urllib.parse.quote(key)}&hotspots={it.get('key')}",
                    extra={"hotspot": True, "category": it.get("securityCategory")},
                )
            )
            n += 1
    except urllib.error.HTTPError:
        pass
    try:
        metrics = "bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density,cognitive_complexity,ncloc,sqale_index,reliability_rating,security_rating,sqale_rating"
        ms = _sonar_api(
            host, token, "/api/measures/component", {"component": key, "metricKeys": metrics}
        )
        ctx.sonar_measures = {
            m["metric"]: m.get("value") for m in ms.get("component", {}).get("measures", [])
        }
        ctx.sonar_measures["dashboard"] = (
            f"{host.rstrip('/')}/dashboard?id={urllib.parse.quote(key)}"
        )
    except urllib.error.HTTPError:
        pass
    ctx.record("sonar", "ok", n, note=f"project {key}", t0=t0)


# --------------------------------------------------------------------------- dedupe

TOOL_PRIORITY = {
    "gitleaks": 0,
    "bandit": 1,
    "semgrep": 2,
    "sonar": 3,
    "ruff": 4,
    "mypy": 5,
    "shellcheck": 6,
    "hadolint": 7,
    "eslint": 8,
}


def dedupe(ctx: Ctx) -> None:
    """Several tools flag the same line for the same reason (ruff S-rules ⊂ bandit, kit semgrep ≈ bandit).
    Collapse security/secret findings that share file+line into one record, keeping the highest severity
    and listing the other tools under extra["also"] so nothing is lost, just de-noised."""
    groups: dict[tuple[str, int, str], list[Finding]] = {}
    keep: list[Finding] = []
    for f in ctx.findings:
        if f.category in {"security", "secret"} and f.line:
            groups.setdefault((f.file, f.line, f.category), []).append(f)
        else:
            keep.append(f)
    for items in groups.values():
        items.sort(key=lambda f: (TOOL_PRIORITY.get(f.tool, 99), SEVERITY_ORDER[f.severity]))
        head = items[0]
        if len(items) > 1:
            head.severity = min((f.severity for f in items), key=lambda s: SEVERITY_ORDER[s])
            head.extra["also"] = [f"{f.tool}/{f.rule}" for f in items[1:]]
            head.fixable = any(f.fixable for f in items)
        keep.append(head)
    ctx.findings = keep


# --------------------------------------------------------------------------- report


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    c = dict.fromkeys(SEVERITY_ORDER, 0)
    for f in findings:
        c[f.severity] += 1
    return c


def write_report(ctx: Ctx, out: Path, scope_note: str, max_md: int) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    findings = sorted(ctx.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
    counts = severity_counts(findings)
    by_tool: dict[str, int] = {}
    for f in findings:
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
    payload = {
        "root": str(ctx.root),
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "scope": scope_note,
        "fix_mode": ctx.fix,
        "fixed_files": sorted(ctx.fixed_files),
        "summary": {"total": len(findings), "by_severity": counts, "by_tool": by_tool},
        "tools": [asdict(r) for r in ctx.runs],
        "sonar_measures": ctx.sonar_measures,
        "findings": [asdict(f) for f in findings],
    }
    jpath = out / "report.json"
    jpath.write_text(json.dumps(payload, indent=2))

    md: list[str] = []
    md.append(f"# Code review report — `{ctx.root.name}`\n")
    md.append(
        f"_Generated {payload['generated']} · scope: {scope_note} · fix mode: {'on' if ctx.fix else 'off'}_\n"
    )
    md.append("## Summary\n")
    md.append("| critical | high | medium | low | info | total |\n|---|---|---|---|---|---|")
    md.append(
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} | {len(findings)} |\n"
    )
    if ctx.fixed_files:
        md.append(
            f"**Auto-fixed {len(ctx.fixed_files)} file(s):** "
            + ", ".join(f"`{p}`" for p in sorted(ctx.fixed_files))
            + "\n"
        )
    md.append("### Tools\n")
    md.append("| tool | status | findings | time | note |\n|---|---|---|---|---|")
    for r in ctx.runs:
        md.append(
            f"| {r.name} | {r.status} | {r.findings} | {r.seconds}s | {r.note.replace('|', '/')} |"
        )
    md.append("")
    if ctx.sonar_measures:
        m = ctx.sonar_measures
        md.append("### SonarQube measures\n")
        md.append(
            f"bugs {m.get('bugs', '?')} · vulnerabilities {m.get('vulnerabilities', '?')} · hotspots {m.get('security_hotspots', '?')} · "
            f"code smells {m.get('code_smells', '?')} · duplication {m.get('duplicated_lines_density', '?')}% · "
            f"cognitive complexity {m.get('cognitive_complexity', '?')} · tech debt {m.get('sqale_index', '?')}min · "
            f"coverage {m.get('coverage', 'n/a')}%  \nDashboard: {m.get('dashboard', '')}\n"
        )

    md.append("## Findings (ranked)\n")
    if not findings:
        md.append("No findings. Nice.\n")
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)
    shown = 0
    for sev in SEVERITY_ORDER:
        items = grouped.get(sev, [])
        if not items:
            continue
        md.append(f"### {sev.upper()} ({len(items)})\n")
        for f in items:
            if shown >= max_md:
                break
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            fx = " _(auto-fixable)_" if f.fixable else ""
            link = f" [ref]({f.url})" if f.url else ""
            also = f" _(also: {', '.join(f.extra['also'])})_" if f.extra.get("also") else ""
            md.append(f"- **{f.tool}/{f.rule}** {loc} — {f.message}{fx}{also}{link}")
            shown += 1
        md.append("")
        if shown >= max_md:
            md.append(
                f"_… truncated at {max_md}; see report.json for the rest ({len(findings)} total)._\n"
            )
            break
    # hot files
    per_file: dict[str, int] = {}
    for f in findings:
        if f.severity in {"critical", "high", "medium"}:
            per_file[f.file] = per_file.get(f.file, 0) + 1
    if per_file:
        md.append("## Files with most medium+ findings\n")
        for fpath, c in sorted(per_file.items(), key=lambda kv: -kv[1])[:10]:
            md.append(f"- `{fpath}` — {c}")
        md.append("")
    mpath = out / "report.md"
    mpath.write_text("\n".join(md))
    return jpath, mpath


# --------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--root", default=".", help="repo root (default: cwd)")
    ap.add_argument(
        "--changed", action="store_true", help="only files changed vs --base + working tree"
    )
    ap.add_argument(
        "--base", default=None, help="git ref for --changed (default: origin/main|main)"
    )
    ap.add_argument(
        "--fix",
        action="store_true",
        help="apply safe fixes (ruff --fix safe rules, ruff format, eslint --fix)",
    )
    ap.add_argument("--fix-shell", action="store_true", help="with --fix, also run shfmt -w")
    ap.add_argument(
        "--sonar",
        action="store_true",
        help="run SonarQube scanner and pull issues (needs sonar/setup.sh)",
    )
    ap.add_argument(
        "--sonar-wait", type=int, default=300, help="seconds to wait for Sonar analysis"
    )
    ap.add_argument(
        "--history",
        action="store_true",
        help="gitleaks: scan full git history instead of working tree",
    )
    ap.add_argument("--only", default="", help="comma list of tools to run")
    ap.add_argument("--skip", default="", help="comma list of tools to skip")
    ap.add_argument("--out", default=None, help="output dir (default: <root>/.review)")
    ap.add_argument("--max-md", type=int, default=200, help="max findings listed in report.md")
    ap.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER),
        default=None,
        help="exit 1 if any finding at/above this severity",
    )
    ap.add_argument(
        "--json", action="store_true", help="print summary JSON to stdout instead of text"
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        log(f"not a directory: {root}")
        return 2
    out = Path(args.out).resolve() if args.out else root / ".review"
    out.mkdir(parents=True, exist_ok=True)
    gi = out / ".gitignore"
    if not gi.exists():
        gi.write_text("*\n")

    subset = changed_files(root, args.base) if args.changed else None
    if args.changed and not subset:
        log("--changed: no changed files found; nothing to do")
        subset = []
    repo = discover(root, subset)
    scope = f"{len(subset or [])} changed files" if args.changed else "whole repo"
    log(
        f"root={root} scope={scope} py={len(repo.py)} sh={len(repo.sh)} docker={len(repo.docker)} js={len(repo.js)}"
    )

    selected = set(ALL_TOOLS)
    if args.only:
        selected = {t.strip() for t in args.only.split(",") if t.strip()}
    if args.skip:
        selected -= {t.strip() for t in args.skip.split(",") if t.strip()}
    if not args.sonar and not args.only:
        selected.discard("sonar")
    unknown = selected - set(ALL_TOOLS)
    if unknown:
        log(f"unknown tools: {', '.join(sorted(unknown))}; valid: {', '.join(ALL_TOOLS)}")
        return 2

    ctx = Ctx(repo, fix=args.fix, fix_shell=args.fix_shell, verbose=args.verbose)
    # order matters a little: fixers first so later analyzers see fixed code
    steps = [
        ("ruff", lambda: tool_ruff(ctx)),
        ("ruff-format", lambda: tool_ruff_format(ctx)),
        ("shfmt", lambda: tool_shfmt(ctx)),
        ("eslint", lambda: tool_eslint(ctx)),
        ("mypy", lambda: tool_mypy(ctx)),
        ("bandit", lambda: tool_bandit(ctx)),
        ("shellcheck", lambda: tool_shellcheck(ctx)),
        ("hadolint", lambda: tool_hadolint(ctx)),
        ("gitleaks", lambda: tool_gitleaks(ctx, args.history)),
        ("pip-audit", lambda: tool_pip_audit(ctx)),
        ("semgrep", lambda: tool_semgrep(ctx)),
        ("sonar", lambda: tool_sonar(ctx, args.sonar_wait)),
    ]
    for name, fn in steps:
        if name not in selected:
            continue
        try:
            fn()
        except Exception as e:  # never let one tool kill the run
            ctx.record(name, "error", note=f"{type(e).__name__}: {e}")

    dedupe(ctx)
    jpath, mpath = write_report(ctx, out, scope, args.max_md)
    counts = severity_counts(ctx.findings)
    summary = {
        "total": len(ctx.findings),
        **counts,
        "fixed_files": sorted(ctx.fixed_files),
        "report_md": str(mpath),
        "report_json": str(jpath),
        "tools": {r.name: r.status for r in ctx.runs},
    }
    if args.json:
        print(json.dumps(summary))
    else:
        print(
            f"\n{len(ctx.findings)} findings — critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, "
            f"low {counts['low']}, info {counts['info']}"
        )
        if ctx.fixed_files:
            print(f"auto-fixed {len(ctx.fixed_files)} file(s)")
        skipped = [r for r in ctx.runs if r.status != "ok"]
        for r in skipped:
            print(f"  {r.name}: {r.status} — {r.note}")
        print(f"report: {mpath}")
    if args.fail_on:
        thr = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= thr for f in ctx.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
