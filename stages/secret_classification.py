"""
E4: Secret classification — label each D3 `secret` record by KIND + PROVIDER,
entirely OFFLINE (zero network). The safety linchpin: E4 must NEVER contact a
provider — that would transmit a live credential and cross the recon/primitive
boundary. This v1 is a self-contained regex/detector map: offline BY CONSTRUCTION
(no networking code to misconfigure), so the boundary can't be crossed by accident.
A network-verifying tool (trufflehog) is a deferred breadth upgrade, gated on a
confirmed no-verify flag + egress isolation.

Mechanism (the D3 model constrains this): the `secrets` table stores only a
capped, irreversible `fingerprint` + a `raw_log_ref` pointer — the raw value is
NEVER in assets.db, it lives only in the R8 chmod-700 jsluice-secrets raw archive.
So E4 reads that archive, recovers each value via stage 7's own extractor, maps it
back to its row by recomputing secret_fingerprint(value) (guaranteed match, no
drift), classifies OFFLINE, and writes back kind/provider. `validated` stays NULL.
"""

import json
import logging
import re

from state import secret_fingerprint

logger = logging.getLogger(__name__)

# High-confidence detectors, ordered. Each: (kind, provider, compiled regex).
# Deliberately specific (low false-positive) — an unmatched value is left
# unclassified rather than guessed. Values are matched, never transmitted.
_DETECTORS = [
    ("aws_access_key_id", "aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_access_key_id", "aws", re.compile(r"\b(?:ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b")),
    ("github_pat", "github", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("github_fine_grained_pat", "github", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("slack_token", "slack", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", "google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_key", "stripe", re.compile(r"\b[rsp]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("twilio_api_key", "twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid_key", "sendgrid", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b")),
    ("npm_token", "npm", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("jwt", "generic", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}\b")),
    ("private_key", "generic", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

# jsluice secret-value candidate keys (kept in sync with stage 7's _SECRET_VALUE_KEYS).
_SECRET_VALUE_KEYS = ("secret", "value", "match", "token", "key", "data", "raw")


def classify_secret(value: str) -> tuple[str | None, str | None]:
    """Return (kind, provider) for a raw secret value from the offline detector
    map, or (None, None) if nothing high-confidence matches. Pure/offline."""
    if not isinstance(value, str) or not value:
        return None, None
    for kind, provider, pattern in _DETECTORS:
        if pattern.search(value):
            return kind, provider
    return None, None


def _value_from_finding(finding: dict) -> str:
    """Best-effort raw value from a jsluice secrets finding (mirrors stage 7's
    _jsluice_secret_value: try known keys, else the serialized finding)."""
    for k in _SECRET_VALUE_KEYS:
        v = finding.get(k)
        if isinstance(v, str) and v:
            return v
    return json.dumps(finding, sort_keys=True)


def _recover_value(state, secret) -> str | None:
    """Read the secret's R8 raw archive (raw_log_ref) and return the raw value
    whose fingerprint matches this row (no drift). None if the file is missing or
    no finding matches. Never raises."""
    if not secret.raw_log_ref:
        return None
    path = state.run_dir / secret.raw_log_ref
    try:
        if not path.exists():
            return None
        text = path.read_text()
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(finding, dict):
            continue
        value = _value_from_finding(finding)
        if secret_fingerprint(value) == secret.fingerprint:
            return value
    return None


def run_secret_classification(state) -> dict:
    """Classify every secret's kind/provider OFFLINE. Reads each row's raw archive,
    recovers the value, classifies, writes back kind/provider (never `validated`).
    Fail-safe: an unreadable archive or unmatched value is skipped. Idempotent."""
    secrets = state.load_secrets()
    classified = 0
    for s in secrets:
        value = _recover_value(state, s)
        if value is None:
            continue
        kind, provider = classify_secret(value)
        if kind:
            state.update_secret_classification(s.secret_id, kind, provider)
            classified += 1
    if secrets:
        logger.info("E4 secret classification: classified %d/%d secret(s) OFFLINE (no network)",
                    classified, len(secrets))
    return {"classified": classified, "total": len(secrets)}
