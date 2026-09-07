"""
Shared state management for the recon agent.

All pipeline state lives on disk in a per-run directory, per the locked
architecture: this is what lets the orchestrator (and Claude Code as the
agentic interface) inspect/intervene between stages without reaching into a
running process's memory.

Files (see /areas/hackbot.md state file schema for the full contract):
  scope.json         - input allowlist (read-only from recon agent's POV)
  assets.db           - living asset graph + source-record tables, SQLite
  needs_review.json   - LLM scope-gate ambiguous-match queue
  run_state.json       - current stage/pass/status
  raw/stageN_tool.json - archived raw tool output, one file per tool invocation

assets.db holds the scope-gated *location* graph (the `assets` table:
subdomain/url/ip) plus the Track-D first-class *source-record* tables
(parameters/endpoints/secrets/services) and takeover_findings. Source records
are facts ABOUT a location (a param on a url, a secret in a JS file, an open
service on an ip), FK-linked to their parent asset - they are not themselves
scope-gated locations (they inherit their parent asset's scope). See
STATE_SCHEMA.md and RECON_TRACK_D_DESIGN.md.

Stage modules never touch assets.db directly - they only ever go through
RunState (load_assets/add_assets, add_parameters/add_endpoints/add_secrets/
add_services, etc.). This abstraction boundary is why the on-disk format can
evolve without stage modules knowing the details.
"""

import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlsplit, urlunsplit


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def timed(state: "RunState", key: str):
    """
    Wraps a block of code, records its wall-clock duration into
    run_state.json's timings dict (via RunState.record_timing()), and
    logs it at INFO level. Lives here (not main.py) so both main.py AND
    individual stage modules can import it without a circular import.

    Uses time.monotonic() (immune to clock adjustments mid-run). Does NOT
    suppress exceptions - the timing is recorded in the finally block before
    the exception propagates, so a failed stage still leaves a timing entry.
    """
    import logging
    logger = logging.getLogger(__name__)

    start = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        state.record_timing(key, elapsed)
        logger.info("%s completed in %.1fs", key, elapsed)


# ---------------------------------------------------------------------------
# R6: conservative URL/host canonicalization at ingestion
# ---------------------------------------------------------------------------

def canonicalize(asset_type: str, value: str) -> str:
    """
    (R6) Conservative, type-aware canonicalization applied ONCE at Asset
    construction (see Asset.__post_init__), so the stored value, the
    scope-gate input, the review-item value, and the UNIQUE(type, value)
    de-dupe key are all the same canonical string.

    Conservative rules ONLY (Jared call), zero false-merge risk:
      - url / js_file: lowercase scheme + host, strip the default port
        (:80 on http, :443 on https), drop the URL fragment. PATH AND
        QUERY LEFT EXACTLY AS-IS.
      - subdomain: lowercase, strip a trailing dot.
      - ip / anything else: returned unchanged.

    Never raises; idempotent.
    """
    if not isinstance(value, str):
        return value

    if asset_type == "subdomain":
        return value.strip().lower().rstrip(".")

    if asset_type in ("url", "js_file"):
        raw = value.strip()
        try:
            parts = urlsplit(raw)
        except (ValueError, AttributeError):
            return value
        if not parts.netloc:
            return value

        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()

        userinfo = ""
        if parts.username is not None:
            userinfo = parts.username
            if parts.password is not None:
                userinfo += ":" + parts.password
            userinfo += "@"

        port = None
        try:
            port = parts.port
        except ValueError:
            return value
        if port is not None and not (
            (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        ):
            netloc = f"{userinfo}{host}:{port}"
        else:
            netloc = f"{userinfo}{host}"

        return urlunsplit((scheme, netloc, parts.path, parts.query, ""))

    return value


# ---------------------------------------------------------------------------
# R9: provenance registry for attacker-influenceable metadata (assets.db
# metadata keys). Track-D source records carry their own per-row
# `target_derived` flag instead - see the record dataclasses below.
# ---------------------------------------------------------------------------

TARGET_DERIVED_METADATA_KEYS = frozenset({
    "whatweb_tech",
    "whatweb_redirect_chain",
    "katana_headers",
    "katana_error",
    "jsluice_secrets",  # legacy metadata key (pre-Track-D); secrets are now a table
    "httpx_title",
    "httpx_tls_san",
    "httpx_body_preview",  # (E1) target-authored response body snippet, untrusted
})


# ---------------------------------------------------------------------------
# Track D: secret fingerprinting (never store a raw secret in assets.db)
# ---------------------------------------------------------------------------

def secret_fingerprint(value: str) -> str:
    """
    (Track D / D3) Produce a capped, irreversible fingerprint of a secret
    value for the `secrets` table - the raw value NEVER enters assets.db
    (it lives only in the chmod-700 raw archive, pointed at by raw_log_ref).
    Mirrors primitive's found-credential handling. Format:
    `first4…last4|len=N|sha256=<16hex>`. Short values (<=8 chars) show only
    a single leading char so the fingerprint can't reveal most of a short
    secret. Stable for the same value (so it doubles as a dedup key).
    """
    if not isinstance(value, str):
        value = str(value)
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
    n = len(value)
    if n <= 8:
        head = value[:1] if value else ""
        return f"{head}…|len={n}|sha256={digest}"
    return f"{value[:4]}…{value[-4:]}|len={n}|sha256={digest}"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

AssetType = Literal["subdomain", "url", "ip", "js_file"]
ScopeStatus = Literal["in_scope", "needs_review", "out_of_scope"]
ScopeDecisionBy = Literal["deterministic", "llm_flag", "human"]
RunStatus = Literal["running", "paused_needs_review", "stage_complete", "stable", "error"]
ReviewResolution = Literal["pending", "admitted", "rejected"]
TakeoverType = Literal["dns", "http"]
ParamLocation = Literal["query", "body", "path", "header"]


@dataclass
class Asset:
    value: str
    type: AssetType
    discovered_by: str | list[str]
    discovered_at_stage: int
    discovered_in_pass: int
    scope_status: ScopeStatus = "needs_review"
    scope_decision_by: Optional[ScopeDecisionBy] = None
    asset_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_asset_id: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        # discovered_by is always a list internally (2026-08-22 fix); stage
        # modules still construct with a bare string.
        if isinstance(self.discovered_by, str):
            self.discovered_by = [self.discovered_by]
        # (R6) canonicalize the stored value at construction, after the
        # discovered_by normalization. Runs for stage-built Assets and for
        # Assets rebuilt from a DB row (_row_to_asset), so a pre-R6 raw row
        # lazily re-normalizes on load - no hard migration.
        self.value = canonicalize(self.type, self.value)


@dataclass
class ReviewItem:
    asset_id: str
    value: str
    reason: str
    flagged_at: str = field(default_factory=now_iso)
    resolution: ReviewResolution = "pending"
    resolved_at: Optional[str] = None


@dataclass
class TakeoverFinding:
    host: str
    template_id: str
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: Optional[str] = None
    template_name: str = ""
    severity: str = "unknown"
    matched_at: str = ""
    type: TakeoverType = "http"
    raw_finding: dict = field(default_factory=dict)
    discovered_at_stage: int = 8
    discovered_in_pass: int = 1
    discovered_at: str = field(default_factory=now_iso)


ReconFindingStatus = Literal["new", "triaged", "promoted", "dismissed"]


@dataclass
class ReconFinding:
    """(C1) A general recon lead / point-of-interest — detection-only nuclei
    exposures/misconfig/panels now, tech->CVE candidates (C5) later — with a
    `status` lifecycle and provenance. General cousin of TakeoverFinding.
    `target_derived` is 1: `matched_at` and any extracted content are
    target-authored (untrusted; the A1 brief treats them as delimited data).
    `raw_finding` is TRIMMED of nuclei's request/response/curl-command bodies
    (they can carry sensitive content); the full verbatim output stays only in
    the R8 chmod-700 raw archive."""
    host: str
    template_id: str
    source: str = "nuclei"
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: Optional[str] = None
    template_name: str = ""
    category: str = ""            # nuclei info.tags joined (e.g. "exposures,config")
    severity: str = "unknown"
    matched_at: str = ""
    status: ReconFindingStatus = "new"
    target_derived: bool = True
    raw_finding: dict = field(default_factory=dict)
    discovered_at_stage: int = 8
    discovered_in_pass: int = 1
    discovered_at: str = field(default_factory=now_iso)


# --- Track D source records (facts about a location, not locations) --------

@dataclass
class Parameter:
    """(D1) A request parameter observed on an endpoint. `target_derived`
    is False for x8 (names come from our SecLists wordlist), True for jsluice
    (names come from the target's own JS). `reflected` True only when x8
    confirmed it changes the response; None when merely observed."""
    name: str
    host: str
    endpoint: str
    method: str = "GET"
    location: ParamLocation = "query"
    reflected: Optional[bool] = None
    inferred_type: Optional[str] = None
    discovered_by: str = ""
    target_derived: bool = False
    parameter_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: Optional[str] = None
    discovered_at_stage: int = 0
    discovered_in_pass: int = 1
    metadata: dict = field(default_factory=dict)


@dataclass
class Endpoint:
    """(D2) A testable endpoint. Lightly populated in Phase 1 (jsluice, with
    method context); heavy population is Track B (content/API discovery).
    `auth_status` filled later by C4."""
    url: str
    host: str
    path: str
    method: str = "GET"
    auth_status: Optional[str] = None
    content_type: Optional[str] = None
    discovered_by: str = ""
    target_derived: bool = False
    endpoint_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: Optional[str] = None
    discovered_at_stage: int = 0
    discovered_in_pass: int = 1
    metadata: dict = field(default_factory=dict)


@dataclass
class Secret:
    """(D3) A secret finding. The raw value is NEVER stored here - only a
    capped `fingerprint` (see secret_fingerprint) plus `raw_log_ref` pointing
    at the per-source raw archive that holds the full finding. `validated` is
    set DOWNSTREAM by primitive, never by recon. Always target_derived."""
    kind: str
    fingerprint: str
    raw_log_ref: str
    provider: Optional[str] = None
    severity: Optional[str] = None
    validated: Optional[bool] = None
    discovered_by: str = ""
    target_derived: bool = True
    secret_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: Optional[str] = None
    discovered_at_stage: int = 0
    discovered_in_pass: int = 1
    metadata: dict = field(default_factory=dict)


@dataclass
class Service:
    """(D4) An open service (ip:port:proto), so R12's non-standard ports are
    probeable records instead of dead-end metadata. `target` is the ip-or-host
    string naabu reported; host/ip split out when known. Tool-derived, so
    target_derived is False."""
    target: str
    port: int
    proto: str = "tcp"
    host: Optional[str] = None
    ip: Optional[str] = None
    discovered_by: str = ""
    target_derived: bool = False
    service_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: Optional[str] = None
    discovered_at_stage: int = 0
    discovered_in_pass: int = 1
    metadata: dict = field(default_factory=dict)


ASSETS_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    discovered_by TEXT NOT NULL,
    discovered_at_stage INTEGER NOT NULL,
    discovered_in_pass INTEGER NOT NULL,
    scope_status TEXT NOT NULL,
    scope_decision_by TEXT,
    parent_asset_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(type, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_type_value ON assets(type, value);
CREATE INDEX IF NOT EXISTS idx_assets_scope_status ON assets(scope_status);
"""

TAKEOVER_FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS takeover_findings (
    finding_id TEXT PRIMARY KEY,
    asset_id TEXT,
    host TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_name TEXT,
    severity TEXT,
    matched_at TEXT,
    type TEXT,
    raw_finding TEXT NOT NULL,
    discovered_at_stage INTEGER NOT NULL DEFAULT 8,
    discovered_in_pass INTEGER NOT NULL,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_takeover_host ON takeover_findings(host);

CREATE TABLE IF NOT EXISTS recon_findings (
    finding_id TEXT PRIMARY KEY,
    asset_id TEXT,
    host TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'nuclei',
    template_id TEXT NOT NULL,
    template_name TEXT,
    category TEXT,
    severity TEXT,
    matched_at TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    target_derived INTEGER NOT NULL DEFAULT 1,
    raw_finding TEXT NOT NULL,
    discovered_at_stage INTEGER NOT NULL DEFAULT 8,
    discovered_in_pass INTEGER NOT NULL,
    discovered_at TEXT NOT NULL,
    UNIQUE(host, template_id, matched_at),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_recon_findings_host ON recon_findings(host);
"""

# --- Track D source-record tables ------------------------------------------

PARAMETERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS parameters (
    parameter_id TEXT PRIMARY KEY,
    asset_id TEXT,
    name TEXT NOT NULL,
    host TEXT,
    endpoint TEXT,
    method TEXT,
    location TEXT,
    reflected INTEGER,
    inferred_type TEXT,
    discovered_by TEXT,
    target_derived INTEGER NOT NULL DEFAULT 0,
    discovered_at_stage INTEGER,
    discovered_in_pass INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(host, endpoint, name, method, location),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_parameters_host ON parameters(host);
"""

ENDPOINTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id TEXT PRIMARY KEY,
    asset_id TEXT,
    url TEXT NOT NULL,
    host TEXT,
    path TEXT,
    method TEXT,
    auth_status TEXT,
    content_type TEXT,
    discovered_by TEXT,
    target_derived INTEGER NOT NULL DEFAULT 0,
    discovered_at_stage INTEGER,
    discovered_in_pass INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(url, method),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host);
"""

SECRETS_SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    secret_id TEXT PRIMARY KEY,
    asset_id TEXT,
    kind TEXT,
    provider TEXT,
    fingerprint TEXT NOT NULL,
    raw_log_ref TEXT,
    severity TEXT,
    validated INTEGER,
    discovered_by TEXT,
    target_derived INTEGER NOT NULL DEFAULT 1,
    discovered_at_stage INTEGER,
    discovered_in_pass INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(asset_id, fingerprint),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_secrets_asset ON secrets(asset_id);
"""

SERVICES_SCHEMA = """
CREATE TABLE IF NOT EXISTS services (
    service_id TEXT PRIMARY KEY,
    asset_id TEXT,
    target TEXT NOT NULL,
    host TEXT,
    ip TEXT,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    discovered_by TEXT,
    target_derived INTEGER NOT NULL DEFAULT 0,
    discovered_at_stage INTEGER,
    discovered_in_pass INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(target, port, proto),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_services_target ON services(target);
"""


# ---------------------------------------------------------------------------
# RunState: the main interface stages interact with
# ---------------------------------------------------------------------------

class RunState:
    """
    Wraps a run directory and provides load/save for each piece of state.
    Stages should go through this rather than touching files directly.
    """

    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        self.raw_dir = self.run_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        # R8: the run dir is sensitive-at-rest TODAY (stage 7 extracts real
        # secrets). Owner-only at init, whether freshly created or re-opened.
        self.run_dir.chmod(0o700)

        self.scope_path = self.run_dir / "scope.json"
        self.assets_db_path = self.run_dir / "assets.db"
        self.review_path = self.run_dir / "needs_review.json"
        self.run_state_path = self.run_dir / "run_state.json"

        with self._connect() as conn:
            conn.executescript(ASSETS_SCHEMA)
            conn.executescript(TAKEOVER_FINDINGS_SCHEMA)
            conn.executescript(PARAMETERS_SCHEMA)
            conn.executescript(ENDPOINTS_SCHEMA)
            conn.executescript(SECRETS_SCHEMA)
            conn.executescript(SERVICES_SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.assets_db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- scope ---------------------------------------------------------
    def load_scope(self) -> dict:
        if not self.scope_path.exists():
            raise FileNotFoundError(
                f"scope.json not found at {self.scope_path} - a verified scope "
                "must exist before the recon agent can run"
            )
        with open(self.scope_path) as f:
            scope = json.load(f)
        if not scope.get("verified_by_human"):
            raise ValueError(
                "scope.json exists but verified_by_human is not true - "
                "refusing to run against unverified scope"
            )
        return scope

    # -- assets ----------------------------------------------------------
    @staticmethod
    def _parse_discovered_by(raw: str) -> list[str]:
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return [raw]
        if isinstance(parsed, list):
            return parsed
        return [str(parsed)]

    @staticmethod
    def _row_to_asset(row: tuple) -> Asset:
        (asset_id, value, type_, discovered_by, discovered_at_stage,
         discovered_in_pass, scope_status, scope_decision_by,
         parent_asset_id, metadata_json) = row
        return Asset(
            asset_id=asset_id,
            value=value,
            type=type_,
            discovered_by=RunState._parse_discovered_by(discovered_by),
            discovered_at_stage=discovered_at_stage,
            discovered_in_pass=discovered_in_pass,
            scope_status=scope_status,
            scope_decision_by=scope_decision_by,
            parent_asset_id=parent_asset_id,
            metadata=json.loads(metadata_json),
        )

    def load_assets(self, scope_status: Optional[ScopeStatus] = None) -> list[Asset]:
        query = "SELECT asset_id, value, type, discovered_by, discovered_at_stage, discovered_in_pass, scope_status, scope_decision_by, parent_asset_id, metadata FROM assets"
        params = ()
        if scope_status is not None:
            query += " WHERE scope_status = ?"
            params = (scope_status,)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def add_assets(self, new_assets: list[Asset]) -> list[Asset]:
        """
        Merge new_assets into assets.db, de-duplicating on canonical (R6)
        (type, value) via INSERT OR IGNORE. Returns only genuinely-new
        assets. Duplicate rows have their metadata AND discovered_by merged
        into the existing row (2026-08-22 fixes).
        """
        deduped_by_key: dict[tuple, Asset] = {}
        for a in new_assets:
            key = (a.type, a.value)
            if key not in deduped_by_key:
                deduped_by_key[key] = a
            else:
                existing = deduped_by_key[key]
                if a.metadata:
                    existing.metadata.update(a.metadata)
                for tool in a.discovered_by:
                    if tool not in existing.discovered_by:
                        existing.discovered_by.append(tool)
        deduped_new = list(deduped_by_key.values())

        genuinely_new = []
        with self._connect() as conn:
            for a in deduped_new:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO assets "
                    "(asset_id, value, type, discovered_by, discovered_at_stage, "
                    "discovered_in_pass, scope_status, scope_decision_by, "
                    "parent_asset_id, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (a.asset_id, a.value, a.type, json.dumps(a.discovered_by),
                     a.discovered_at_stage, a.discovered_in_pass, a.scope_status,
                     a.scope_decision_by, a.parent_asset_id, json.dumps(a.metadata)),
                )
                if cur.rowcount > 0:
                    genuinely_new.append(a)
                else:
                    row = conn.execute(
                        "SELECT metadata, discovered_by FROM assets WHERE type = ? AND value = ?",
                        (a.type, a.value),
                    ).fetchone()
                    if row is not None:
                        existing_metadata = json.loads(row[0])
                        existing_discovered_by = self._parse_discovered_by(row[1])

                        merged_metadata = dict(existing_metadata)
                        merged_metadata.update(a.metadata)

                        merged_discovered_by = list(existing_discovered_by)
                        for tool in a.discovered_by:
                            if tool not in merged_discovered_by:
                                merged_discovered_by.append(tool)

                        if (merged_metadata != existing_metadata
                                or merged_discovered_by != existing_discovered_by):
                            conn.execute(
                                "UPDATE assets SET metadata = ?, discovered_by = ? "
                                "WHERE type = ? AND value = ?",
                                (json.dumps(merged_metadata), json.dumps(merged_discovered_by),
                                 a.type, a.value),
                            )

        return genuinely_new

    def update_asset_metadata(self, asset_id: str, metadata_update: dict) -> None:
        with self._connect() as conn:
            row = conn.execute("SELECT metadata FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
            if row is None:
                return
            current = json.loads(row[0])
            current.update(metadata_update)
            conn.execute("UPDATE assets SET metadata = ? WHERE asset_id = ?",
                         (json.dumps(current), asset_id))

    # -- Track D source records ------------------------------------------
    #
    # Each add_*() does INSERT OR IGNORE on the table's UNIQUE key and
    # returns the genuinely-new rows. Source records are NOT counted toward
    # the (future) loop-until-stable stability sum - they're enrichment, not
    # new locations. discovered_by is kept as a plain string (keep-first on
    # a dedup collision) rather than unioned like assets.discovered_by;
    # attribution unioning can be added if a real need appears.

    def add_parameters(self, parameters: list["Parameter"]) -> list["Parameter"]:
        new = []
        with self._connect() as conn:
            for p in parameters:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO parameters "
                    "(parameter_id, asset_id, name, host, endpoint, method, location, "
                    "reflected, inferred_type, discovered_by, target_derived, "
                    "discovered_at_stage, discovered_in_pass, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (p.parameter_id, p.asset_id, p.name, p.host, p.endpoint, p.method,
                     p.location, None if p.reflected is None else int(p.reflected),
                     p.inferred_type, p.discovered_by, int(p.target_derived),
                     p.discovered_at_stage, p.discovered_in_pass, json.dumps(p.metadata)),
                )
                if cur.rowcount > 0:
                    new.append(p)
        return new

    def load_parameters(self) -> list["Parameter"]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT parameter_id, asset_id, name, host, endpoint, method, location, "
                "reflected, inferred_type, discovered_by, target_derived, "
                "discovered_at_stage, discovered_in_pass, metadata FROM parameters"
            ).fetchall()
        return [
            Parameter(
                parameter_id=r[0], asset_id=r[1], name=r[2], host=r[3], endpoint=r[4],
                method=r[5], location=r[6],
                reflected=None if r[7] is None else bool(r[7]),
                inferred_type=r[8], discovered_by=r[9], target_derived=bool(r[10]),
                discovered_at_stage=r[11], discovered_in_pass=r[12],
                metadata=json.loads(r[13]),
            )
            for r in rows
        ]

    def add_endpoints(self, endpoints: list["Endpoint"]) -> list["Endpoint"]:
        new = []
        with self._connect() as conn:
            for e in endpoints:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO endpoints "
                    "(endpoint_id, asset_id, url, host, path, method, auth_status, "
                    "content_type, discovered_by, target_derived, discovered_at_stage, "
                    "discovered_in_pass, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (e.endpoint_id, e.asset_id, e.url, e.host, e.path, e.method,
                     e.auth_status, e.content_type, e.discovered_by, int(e.target_derived),
                     e.discovered_at_stage, e.discovered_in_pass, json.dumps(e.metadata)),
                )
                if cur.rowcount > 0:
                    new.append(e)
        return new

    def load_endpoints(self) -> list["Endpoint"]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT endpoint_id, asset_id, url, host, path, method, auth_status, "
                "content_type, discovered_by, target_derived, discovered_at_stage, "
                "discovered_in_pass, metadata FROM endpoints"
            ).fetchall()
        return [
            Endpoint(
                endpoint_id=r[0], asset_id=r[1], url=r[2], host=r[3], path=r[4],
                method=r[5], auth_status=r[6], content_type=r[7], discovered_by=r[8],
                target_derived=bool(r[9]), discovered_at_stage=r[10],
                discovered_in_pass=r[11], metadata=json.loads(r[12]),
            )
            for r in rows
        ]

    def update_secret_classification(self, secret_id: str, kind: str,
                                     provider: Optional[str]) -> None:
        """(E4) Set a secret's kind + provider from OFFLINE classification. Never
        touches `validated` (primitive's field, set only on live validation). No-op
        if the secret_id doesn't exist."""
        with self._connect() as conn:
            conn.execute("UPDATE secrets SET kind = ?, provider = ? WHERE secret_id = ?",
                        (kind, provider, secret_id))

    def update_endpoint_auth_status(self, endpoint_id: str, auth_status: str,
                                    classified_by: str = "c4") -> None:
        """(C4) Set an endpoint's auth_status and record who classified it
        (merged into metadata as auth_classified_by, marking a heuristic lead vs a
        response-confirmed gate). No-op if the endpoint_id doesn't exist."""
        with self._connect() as conn:
            row = conn.execute("SELECT metadata FROM endpoints WHERE endpoint_id = ?",
                               (endpoint_id,)).fetchone()
            if row is None:
                return
            md = json.loads(row[0]) if row[0] else {}
            md["auth_classified_by"] = classified_by
            conn.execute("UPDATE endpoints SET auth_status = ?, metadata = ? WHERE endpoint_id = ?",
                        (auth_status, json.dumps(md), endpoint_id))

    def add_secrets(self, secrets: list["Secret"]) -> list["Secret"]:
        new = []
        with self._connect() as conn:
            for s in secrets:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO secrets "
                    "(secret_id, asset_id, kind, provider, fingerprint, raw_log_ref, "
                    "severity, validated, discovered_by, target_derived, "
                    "discovered_at_stage, discovered_in_pass, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (s.secret_id, s.asset_id, s.kind, s.provider, s.fingerprint,
                     s.raw_log_ref, s.severity,
                     None if s.validated is None else int(s.validated),
                     s.discovered_by, int(s.target_derived),
                     s.discovered_at_stage, s.discovered_in_pass, json.dumps(s.metadata)),
                )
                if cur.rowcount > 0:
                    new.append(s)
        return new

    def load_secrets(self) -> list["Secret"]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT secret_id, asset_id, kind, provider, fingerprint, raw_log_ref, "
                "severity, validated, discovered_by, target_derived, discovered_at_stage, "
                "discovered_in_pass, metadata FROM secrets"
            ).fetchall()
        return [
            Secret(
                secret_id=r[0], asset_id=r[1], kind=r[2], provider=r[3], fingerprint=r[4],
                raw_log_ref=r[5], severity=r[6],
                validated=None if r[7] is None else bool(r[7]),
                discovered_by=r[8], target_derived=bool(r[9]), discovered_at_stage=r[10],
                discovered_in_pass=r[11], metadata=json.loads(r[12]),
            )
            for r in rows
        ]

    def add_services(self, services: list["Service"]) -> list["Service"]:
        new = []
        with self._connect() as conn:
            for sv in services:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO services "
                    "(service_id, asset_id, target, host, ip, port, proto, discovered_by, "
                    "target_derived, discovered_at_stage, discovered_in_pass, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (sv.service_id, sv.asset_id, sv.target, sv.host, sv.ip, sv.port,
                     sv.proto, sv.discovered_by, int(sv.target_derived),
                     sv.discovered_at_stage, sv.discovered_in_pass, json.dumps(sv.metadata)),
                )
                if cur.rowcount > 0:
                    new.append(sv)
        return new

    def load_services(self) -> list["Service"]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT service_id, asset_id, target, host, ip, port, proto, discovered_by, "
                "target_derived, discovered_at_stage, discovered_in_pass, metadata FROM services"
            ).fetchall()
        return [
            Service(
                service_id=r[0], asset_id=r[1], target=r[2], host=r[3], ip=r[4], port=r[5],
                proto=r[6], discovered_by=r[7], target_derived=bool(r[8]),
                discovered_at_stage=r[9], discovered_in_pass=r[10], metadata=json.loads(r[11]),
            )
            for r in rows
        ]

    # -- takeover findings -------------------------------------------------
    def add_takeover_findings(self, findings: list[TakeoverFinding]) -> list[TakeoverFinding]:
        with self._connect() as conn:
            for f in findings:
                conn.execute(
                    "INSERT INTO takeover_findings "
                    "(finding_id, asset_id, host, template_id, template_name, "
                    "severity, matched_at, type, raw_finding, discovered_at_stage, "
                    "discovered_in_pass, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (f.finding_id, f.asset_id, f.host, f.template_id, f.template_name,
                     f.severity, f.matched_at, f.type, json.dumps(f.raw_finding),
                     f.discovered_at_stage, f.discovered_in_pass, f.discovered_at),
                )
        return findings

    def load_takeover_findings(self) -> list[TakeoverFinding]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT finding_id, asset_id, host, template_id, template_name, "
                "severity, matched_at, type, raw_finding, discovered_at_stage, "
                "discovered_in_pass, discovered_at FROM takeover_findings"
            ).fetchall()
        return [
            TakeoverFinding(
                finding_id=r[0], asset_id=r[1], host=r[2], template_id=r[3],
                template_name=r[4], severity=r[5], matched_at=r[6], type=r[7],
                raw_finding=json.loads(r[8]), discovered_at_stage=r[9],
                discovered_in_pass=r[10], discovered_at=r[11],
            )
            for r in rows
        ]

    def add_recon_findings(self, findings: list["ReconFinding"]) -> list["ReconFinding"]:
        """(C1) Insert recon findings/POIs; INSERT OR IGNORE dedup on
        UNIQUE(host, template_id, matched_at). Returns the input list."""
        with self._connect() as conn:
            for f in findings:
                conn.execute(
                    "INSERT OR IGNORE INTO recon_findings "
                    "(finding_id, asset_id, host, source, template_id, template_name, "
                    "category, severity, matched_at, status, target_derived, raw_finding, "
                    "discovered_at_stage, discovered_in_pass, discovered_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (f.finding_id, f.asset_id, f.host, f.source, f.template_id,
                     f.template_name, f.category, f.severity, f.matched_at, f.status,
                     int(f.target_derived), json.dumps(f.raw_finding),
                     f.discovered_at_stage, f.discovered_in_pass, f.discovered_at),
                )
        return findings

    def load_recon_findings(self) -> list["ReconFinding"]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT finding_id, asset_id, host, source, template_id, template_name, "
                "category, severity, matched_at, status, target_derived, raw_finding, "
                "discovered_at_stage, discovered_in_pass, discovered_at FROM recon_findings"
            ).fetchall()
        return [
            ReconFinding(
                finding_id=r[0], asset_id=r[1], host=r[2], source=r[3], template_id=r[4],
                template_name=r[5], category=r[6], severity=r[7], matched_at=r[8],
                status=r[9], target_derived=bool(r[10]), raw_finding=json.loads(r[11]),
                discovered_at_stage=r[12], discovered_in_pass=r[13], discovered_at=r[14],
            )
            for r in rows
        ]

    # -- needs_review ------------------------------------------------------
    def load_review_queue(self) -> list[ReviewItem]:
        if not self.review_path.exists():
            return []
        with open(self.review_path) as f:
            raw = json.load(f)
        return [ReviewItem(**i) for i in raw.get("items", [])]

    def save_review_queue(self, items: list[ReviewItem]) -> None:
        payload = {"items": [asdict(i) for i in items]}
        with open(self.review_path, "w") as f:
            json.dump(payload, f, indent=2)

    def add_review_item(self, item: ReviewItem) -> None:
        items = self.load_review_queue()
        items.append(item)
        self.save_review_queue(items)

    # -- run_state -----------------------------------------------------
    def load_run_state(self) -> dict:
        if not self.run_state_path.exists():
            return {
                "run_id": str(uuid.uuid4()),
                "current_stage": 0,
                "current_pass": 0,
                "status": "running",
                "passes_completed": 0,
                "last_updated": now_iso(),
            }
        with open(self.run_state_path) as f:
            return json.load(f)

    def update_run_state(self, **kwargs) -> dict:
        state = self.load_run_state()
        state.update(kwargs)
        state["last_updated"] = now_iso()
        with open(self.run_state_path, "w") as f:
            json.dump(state, f, indent=2)
        return state

    def record_timing(self, key: str, duration_seconds: float) -> None:
        state = self.load_run_state()
        timings = state.get("timings", {})
        timings[key] = round(duration_seconds, 2)
        state["timings"] = timings
        state["last_updated"] = now_iso()
        with open(self.run_state_path, "w") as f:
            json.dump(state, f, indent=2)

    # -- raw archive -----------------------------------------------------
    def raw_path(self, stage, tool: str) -> Path:
        """Return the raw-archive path for a stage/tool WITHOUT writing it, for
        tools that write their own output file (e.g. ffuf's `-o`). Same naming
        as save_raw so the two are interchangeable. `stage` may be a float for
        fractional stages (e.g. 6.5 content discovery) - the filename becomes
        raw/stage6.5_ffuf_<host>.json, which is a valid, sortable name."""
        return self.raw_dir / f"stage{stage}_{tool}.json"

    def save_raw(self, stage, tool: str, data) -> Path:
        """Archive a tool's raw output, e.g. raw/stage1_subfinder.json"""
        path = self.raw_dir / f"stage{stage}_{tool}.json"
        with open(path, "w") as f:
            if isinstance(data, (dict, list)):
                json.dump(data, f, indent=2)
            else:
                f.write(str(data))
        return path
