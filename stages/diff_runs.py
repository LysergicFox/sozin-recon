"""
E2: incremental / diff runs — compute the delta between two run directories'
assets.db (a baseline + the current) and emit a diff artifact of what is NEW (and
what disappeared) since the baseline. "What's new since last run" is the highest-
value continuous-monitoring signal; the externalized-state design makes this a pure
offline set-difference. Zero traffic; makes no scope/interest judgments of its own.
"""

import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _asset_key(a):
    return (a.type, a.value)


def _diff_keyed(baseline_items, current_items, key_fn, render_fn):
    """Return (new, removed) lists (rendered) comparing two item lists by key_fn."""
    base = {key_fn(i): i for i in baseline_items}
    cur = {key_fn(i): i for i in current_items}
    new = [render_fn(cur[k]) for k in cur.keys() - base.keys()]
    removed = [render_fn(base[k]) for k in base.keys() - cur.keys()]
    return new, removed


def compute_run_diff(baseline, current) -> dict:
    """Compare a baseline RunState against the current RunState across every layer.
    Returns {new: {layer:[...]}, removed: {layer:[...]}, summary: {layer:{new,removed}}}.
    Secrets are diffed by fingerprint (the raw value is never read)."""
    layers = {
        "assets": (
            baseline.load_assets(), current.load_assets(),
            _asset_key, lambda a: {"type": a.type, "value": a.value, "scope_status": a.scope_status},
        ),
        "endpoints": (
            baseline.load_endpoints(), current.load_endpoints(),
            lambda e: (e.url, e.method), lambda e: {"url": e.url, "method": e.method, "auth_status": e.auth_status},
        ),
        "parameters": (
            baseline.load_parameters(), current.load_parameters(),
            lambda p: (p.host, p.endpoint, p.name, p.method, p.location),
            lambda p: {"name": p.name, "endpoint": p.endpoint, "method": p.method, "location": p.location},
        ),
        "secrets": (
            baseline.load_secrets(), current.load_secrets(),
            lambda s: s.fingerprint, lambda s: {"kind": s.kind, "fingerprint": s.fingerprint, "provider": s.provider},
        ),
        "services": (
            baseline.load_services(), current.load_services(),
            lambda sv: (sv.target, sv.port, sv.proto), lambda sv: {"target": sv.target, "port": sv.port, "proto": sv.proto},
        ),
        "recon_findings": (
            baseline.load_recon_findings(), current.load_recon_findings(),
            lambda f: (f.host, f.template_id, f.matched_at),
            lambda f: {"host": f.host, "template_id": f.template_id, "severity": f.severity, "matched_at": f.matched_at},
        ),
    }
    new: dict = {}
    removed: dict = {}
    summary: dict = {}
    for layer, (base_items, cur_items, key_fn, render_fn) in layers.items():
        n, r = _diff_keyed(base_items, cur_items, key_fn, render_fn)
        new[layer] = n
        removed[layer] = r
        summary[layer] = {"new": len(n), "removed": len(r)}
    total_new = sum(v["new"] for v in summary.values())
    total_removed = sum(v["removed"] for v in summary.values())
    logger.info("E2 diff: %d new, %d removed across %d layer(s)", total_new, total_removed, len(layers))
    return {"new": new, "removed": removed, "summary": summary,
            "totals": {"new": total_new, "removed": total_removed}}


def write_diff_artifact(current, diff: dict):
    """Write the diff to <current run dir>/diff.json (R8-protected run dir)."""
    path = current.run_dir / "diff.json"
    with open(path, "w") as f:
        json.dump(diff, f, indent=2)
    return path
