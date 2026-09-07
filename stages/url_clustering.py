"""
F1: URL clustering / representative sampling — a finalizer (no traffic) that groups
templated url assets (/product/1, /product/2, …) by structure and marks a
representative sample per template, so the hunting agents get the shape of the
surface, not the raw flood (protecting primitive's bounded budget). Deterministic;
marks metadata, deletes nothing. Trusted (agent-authored) — the clustering is our
computation, though the URLs it summarizes are target-authored.
"""

import logging
import re
from urllib.parse import urlparse, parse_qsl

logger = logging.getLogger(__name__)

CLUSTER_MIN_SIZE = 3            # below this, not a flood — left unmarked
REPRESENTATIVES_PER_CLUSTER = 2

_NUMERIC = re.compile(r"^\d+$")
_HEX = re.compile(r"^[0-9a-f]{8,}$", re.I)
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_LONG_ALNUM = re.compile(r"^[a-z0-9]{20,}$", re.I)


def _is_id_like(seg: str) -> bool:
    return bool(_NUMERIC.match(seg) or _UUID.match(seg) or _HEX.match(seg) or _LONG_ALNUM.match(seg))


def url_template(value: str) -> str:
    """Structural template: path with id-like segments → {id}, plus sorted query
    param names (values dropped). Same-shape URLs collapse to the same template."""
    parsed = urlparse(value)
    segs = [("{id}" if _is_id_like(s) else s) for s in parsed.path.split("/")]
    path = "/".join(segs)
    params = sorted({k for k, _v in parse_qsl(parsed.query)})
    return f"{path}?{','.join(params)}" if params else path


def run_url_clustering(state) -> dict:
    """Cluster url assets per (host, template); mark cluster metadata + a
    representative sample on the assets. Returns {clusters, clustered_assets}."""
    url_assets = [a for a in state.load_assets() if a.type == "url"]
    groups: dict[tuple, list] = {}
    for a in url_assets:
        host = urlparse(a.value).hostname or ""
        groups.setdefault((host, url_template(a.value)), []).append(a)

    clusters = 0
    clustered = 0
    for (host, template), members in groups.items():
        if len(members) < CLUSTER_MIN_SIZE:
            continue
        clusters += 1
        members_sorted = sorted(members, key=lambda a: a.value)  # deterministic representatives
        for i, a in enumerate(members_sorted):
            update = {"url_cluster": template, "cluster_size": len(members)}
            if i < REPRESENTATIVES_PER_CLUSTER:
                update["cluster_representative"] = True
            state.update_asset_metadata(a.asset_id, update)
            clustered += 1

    logger.info("F1 URL clustering: %d cluster(s) over %d url asset(s); %d asset(s) marked",
                clusters, len(url_assets), clustered)
    return {"clusters": clusters, "clustered_assets": clustered}
