"""
Stage 10: API-schema discovery (B2) — turn a machine-readable API description
into first-class Track-D endpoint + parameter records.

B2a (THIS module, built): OpenAPI/Swagger discovery. Probe common spec paths on
each live in-scope host; when a response is a REAL spec (content-based check, not
status — an SPA catch-all returns 200 text/html, verified on Juice Shop), parse
every path × method × parameter into records. Deterministic, no external tool
(urllib fetch + json/yaml parse).

B2b (THIS module, built): GraphQL discovery. Probe candidate endpoints; POST a
read-only introspection query; when a real schema comes back (data.__schema.types),
record the GraphQL endpoint + its operation→args catalog. graphw00f engine
fingerprint is deferred (not installed; introspection is a plain POST).

GraphQL modeling note (resolved during build): all fields share url=/graphql,
method=POST, so "one endpoint per field" collides with Track D's UNIQUE(url,method).
Instead B2b records ONE endpoint for the GraphQL endpoint, with the full
query/mutation→args catalog in its metadata, plus the distinct arg names as body
`parameter` records. The raw introspection archive holds the complete schema.

Provenance: unlike B1 (wordlist paths, target_derived=0), the SCHEMA is
TARGET-AUTHORED, so every record here is **target_derived=1** (untrusted; the
future A1 brief treats it as delimited data, R9).

Boundary: recon reads the description; it never executes an operation, submits a
body, or authenticates to reach a protected spec. A described `DELETE /pet/{id}`
is a lead for primitive, never called here.

Verified real OpenAPI shapes (Swagger Petstore 2.0 + 3.0, 2026-08-23):
  2.0: swagger:"2.0", basePath, paths[p][method].parameters[] {name,in,type,required};
       in:"body" param has schema.$ref → #/definitions/X; per-op security.
  3.0: openapi:"3.0.x", servers[0].url (relative base path), paths[p][method]:
       parameters[] (path/query/header) + requestBody.content.<media>.schema.$ref
       → #/components/schemas/X; per-op security.
Same-origin (R1): endpoints are built on the SEEDED host's origin + the spec's
base path only; the spec's own host/servers absolute URLs are NEVER followed.
"""

import json
import logging
import re
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse

from state import Asset, RunState, Endpoint, Parameter, timed
from rate_limits import resolve_effective_rps

logger = logging.getLogger(__name__)

STAGE = 10
FETCH_TIMEOUT_SECONDS = 15

# OpenAPI/Swagger spec candidate paths (v1 constant; E3 can extend).
OPENAPI_CANDIDATES = [
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
    "/swagger/v1/swagger.json", "/api-docs/swagger.json", "/api/swagger.json",
    "/openapi.yaml", "/swagger.yaml", "/.well-known/openapi.json",
]

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}

# GraphQL (B2b) endpoint candidates + a compact read-only introspection query
# (verified sufficient against a real graphql-core server 2026-08-23).
GRAPHQL_CANDIDATES = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/query"]
INTROSPECTION_QUERY = (
    "query{__schema{queryType{name} mutationType{name} "
    "types{name kind fields{name args{name}}}}}"
)


def _sanitize(s: str) -> str:
    """Filesystem-safe token of a host for per-target raw filenames (R5)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def _fetch(url: str, timeout: int = FETCH_TIMEOUT_SECONDS) -> tuple[int | None, str, str]:
    """GET a URL, returning (status, content_type, body_text). A transport error
    (DNS/refused/timeout/TLS) returns (None, "", ""); an HTTP error status still
    returns its status + body (an SPA may 200 an index page we then reject)."""
    req = urllib.request.Request(url, headers={"User-Agent": "sozin-recon/0 (api-discovery)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4_000_000).decode("utf-8", "replace")  # cap: specs are small
            return resp.status, (resp.headers.get("Content-Type") or "").lower(), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1_000_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, (e.headers.get("Content-Type") or "").lower() if e.headers else "", body
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        logger.debug("api-discovery fetch failed for %s: %r", url, e)
        return None, "", ""


def _looks_like_spec(body: str, content_type: str):
    """Content-based spec check (the central trap: Juice Shop's /swagger.json is a
    200 text/html SPA page, not a spec). Parse JSON or YAML and require a real
    OpenAPI/Swagger marker (`openapi` or `swagger`) AND a `paths` object. Returns
    the parsed dict or None. Never raises."""
    if not body:
        return None
    doc = None
    # try JSON first (fast, strict), then YAML (a superset — only if PyYAML present)
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        try:
            import yaml
            doc = yaml.safe_load(body)
        except Exception:
            return None
    if not isinstance(doc, dict):
        return None
    if not (("openapi" in doc) or ("swagger" in doc)):
        return None
    if not isinstance(doc.get("paths"), dict):
        return None
    return doc


def _resolve_ref(spec: dict, ref):
    """Resolve a local JSON ref (#/components/schemas/X, #/definitions/X). Returns
    the pointed-to node or None (remote/file refs unsupported in v1)."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")  # JSON-pointer unescape
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _schema_property_names(spec: dict, schema) -> list[str]:
    """Top-level property names of a (possibly $ref'd) request-body schema — these
    become body parameters. Does not recurse into nested objects (param names are
    the top-level properties)."""
    if not isinstance(schema, dict):
        return []
    if "$ref" in schema:
        schema = _resolve_ref(spec, schema["$ref"]) or {}
    props = schema.get("properties")
    return list(props.keys()) if isinstance(props, dict) else []


def _base_path(spec: dict) -> str:
    """The spec's base path prefix, kept RELATIVE (same-origin, R1): OpenAPI 2.0
    `basePath`; 3.0 `servers[0].url` only when it's a relative path. An absolute
    server URL (another origin) is ignored — never followed."""
    if "swagger" in spec:  # 2.0
        bp = spec.get("basePath") or ""
    else:  # 3.x
        servers = spec.get("servers") or []
        url = servers[0].get("url", "") if servers and isinstance(servers[0], dict) else ""
        bp = url if url.startswith("/") else ""  # relative only
    return bp.rstrip("/")


def _op_content_type(spec: dict, op: dict):
    """Best-effort request media type for the endpoint (informational)."""
    rb = op.get("requestBody")
    if isinstance(rb, dict) and isinstance(rb.get("content"), dict) and rb["content"]:
        return next(iter(rb["content"]))
    consumes = op.get("consumes") or spec.get("consumes")
    if isinstance(consumes, list) and consumes:
        return consumes[0]
    return None


def parse_openapi(spec: dict, origin: str) -> list[dict]:
    """Parse a validated OpenAPI/Swagger dict into a list of endpoint entries:
       {url, path, method, content_type, auth_status, params:[{name,location}]}.
    Same-origin: url = origin + base_path + op_path (spec host/servers ignored)."""
    base = _base_path(spec)
    global_security = spec.get("security")
    out = []
    for op_path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters") or []   # path-level params (shared across methods)
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            full_path = f"{base}{op_path}"
            url = f"{origin}{full_path}"
            sec = op.get("security")
            if sec is None:
                sec = global_security
            auth_status = "gated" if sec else None      # [] means explicitly public
            params: list[dict] = []
            for p in list(shared_params) + list(op.get("parameters") or []):
                if not isinstance(p, dict):
                    continue
                where = p.get("in")
                if where == "body":                     # 2.0 body param → property names
                    for name in _schema_property_names(spec, p.get("schema")):
                        params.append({"name": name, "location": "body"})
                elif p.get("name"):
                    loc = where if where in ("query", "path", "header") else "query"
                    params.append({"name": p["name"], "location": loc})
            rb = op.get("requestBody")                  # 3.0 request body → property names
            if isinstance(rb, dict):
                for media in (rb.get("content") or {}).values():
                    if isinstance(media, dict):
                        for name in _schema_property_names(spec, media.get("schema")):
                            params.append({"name": name, "location": "body"})
            # de-dup param (name,location) within this operation
            seen = set(); uniq = []
            for pr in params:
                k = (pr["name"], pr["location"])
                if k not in seen:
                    seen.add(k); uniq.append(pr)
            out.append({"url": url, "path": full_path, "method": method.upper(),
                        "content_type": _op_content_type(spec, op),
                        "auth_status": auth_status, "params": uniq})
    return out


def discover_openapi_for_host(host: str, base: str, state: RunState, scope: dict
                              ) -> tuple[list[Asset], list[Endpoint], list[Parameter]]:
    """Probe OpenAPI candidate paths on one host; on the FIRST real spec, archive it
    (R5) and build url assets + endpoint/parameter records. Returns ([],[],[]) if no
    spec is served. Paced to the per-host effective rps (sequential, few requests)."""
    rps = max(1, resolve_effective_rps(scope))
    delay = 1.0 / rps
    for cand in OPENAPI_CANDIDATES:
        url = f"{base}{cand}"
        status, ctype, body = _fetch(url)
        time.sleep(delay)                               # per-host courtesy pacing
        if status != 200:
            continue
        spec = _looks_like_spec(body, ctype)
        if spec is None:
            continue
        # a REAL spec — archive verbatim (R5) and stop probing this host
        state.save_raw(STAGE, f"openapi_{_sanitize(host)}", body)
        logger.info("OpenAPI spec found on %s at %s (%s)", host, cand,
                    "swagger 2.0" if "swagger" in spec else f"openapi {spec.get('openapi')}")
        new_assets: list[Asset] = []
        endpoints: list[Endpoint] = []
        parameters: list[Parameter] = []
        # the spec URL itself becomes a url asset
        new_assets.append(Asset(value=url, type="url", discovered_by="openapi",
                                discovered_at_stage=STAGE, discovered_in_pass=1,
                                metadata={"openapi_spec": True}))
        for ep in parse_openapi(spec, base):
            asset = Asset(value=ep["url"], type="url", discovered_by="openapi",
                          discovered_at_stage=STAGE, discovered_in_pass=1,
                          metadata={"openapi_method": ep["method"]})
            new_assets.append(asset)
            canon = asset.value                         # canonical value → persist_records linkage
            parsed = urlparse(canon)
            endpoints.append(Endpoint(
                url=canon, host=parsed.hostname or host, path=ep["path"] or "/",
                method=ep["method"], content_type=ep["content_type"],
                auth_status=ep["auth_status"], discovered_by="openapi",
                target_derived=True, discovered_at_stage=STAGE, discovered_in_pass=1,
            ))
            for pr in ep["params"]:
                parameters.append(Parameter(
                    name=pr["name"], host=parsed.hostname or host, endpoint=canon,
                    method=ep["method"], location=pr["location"], reflected=None,
                    discovered_by="openapi", target_derived=True,
                    discovered_at_stage=STAGE, discovered_in_pass=1,
                ))
        logger.info("  parsed %d endpoint(s), %d parameter(s) from the spec",
                    len(endpoints), len(parameters))
        return new_assets, endpoints, parameters
    return [], [], []


# ---------------------------------------------------------------------------
# B2b — GraphQL introspection
# ---------------------------------------------------------------------------

def _post_json(url: str, obj: dict, timeout: int = FETCH_TIMEOUT_SECONDS
               ) -> tuple[int | None, str, str]:
    """POST a JSON body, returning (status, content_type, body). Transport error →
    (None,"",""); an HTTP error status still returns its body."""
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "sozin-recon/0 (api-discovery)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, (resp.headers.get("Content-Type") or "").lower(), \
                resp.read(4_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1_000_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, (e.headers.get("Content-Type") or "").lower() if e.headers else "", body
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        logger.debug("graphql POST failed for %s: %r", url, e)
        return None, "", ""


def _looks_like_introspection(body: str):
    """Content-based GraphQL check: parse JSON and require data.__schema.types (a
    non-empty list). Rejects HTML, a 404 page, or an introspection-disabled error
    body. Returns the __schema dict or None. Never raises."""
    if not body:
        return None
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), dict):
        return None
    schema = doc["data"].get("__schema")
    if isinstance(schema, dict) and isinstance(schema.get("types"), list) and schema["types"]:
        return schema
    return None


def parse_graphql(schema: dict, endpoint_url: str) -> tuple[dict, list[str]]:
    """Parse an introspection __schema into (endpoint_entry, distinct_arg_names).
    endpoint_entry carries the query/mutation→args catalog in metadata (all fields
    share url+method, so one endpoint, not one-per-field — see module docstring)."""
    types = {t.get("name"): t for t in (schema.get("types") or []) if isinstance(t, dict)}
    arg_names: set[str] = set()

    def _catalog(root_name):
        out = {}
        t = types.get(root_name) if root_name else None
        for f in (t.get("fields") if isinstance(t, dict) else None) or []:
            if not isinstance(f, dict) or not f.get("name"):
                continue
            args = [a["name"] for a in (f.get("args") or []) if isinstance(a, dict) and a.get("name")]
            out[f["name"]] = args
            arg_names.update(args)
        return out

    queries = _catalog((schema.get("queryType") or {}).get("name"))
    mutations = _catalog((schema.get("mutationType") or {}).get("name"))
    entry = {
        "url": endpoint_url, "path": urlparse(endpoint_url).path or "/", "method": "POST",
        "content_type": "application/json", "auth_status": None,
        "metadata": {"graphql": True, "introspection": "enabled",
                     "graphql_queries": queries, "graphql_mutations": mutations,
                     "graphql_operation_count": len(queries) + len(mutations)},
    }
    return entry, sorted(arg_names)


def discover_graphql_for_host(host: str, base: str, state: RunState, scope: dict
                              ) -> tuple[list[Asset], list[Endpoint], list[Parameter]]:
    """POST an introspection query to each GraphQL candidate; on the FIRST real
    introspection response, archive it (R5) and build the endpoint + arg-parameter
    records. Read-only: introspection only, no operation is ever executed."""
    rps = max(1, resolve_effective_rps(scope))
    delay = 1.0 / rps
    for cand in GRAPHQL_CANDIDATES:
        url = f"{base}{cand}"
        status, _ctype, body = _post_json(url, {"query": INTROSPECTION_QUERY})
        time.sleep(delay)
        if status != 200:
            continue
        schema = _looks_like_introspection(body)
        if schema is None:
            continue
        state.save_raw(STAGE, f"graphql_{_sanitize(host)}", body)
        entry, arg_names = parse_graphql(schema, url)
        n_q = len(entry["metadata"]["graphql_queries"])
        n_m = len(entry["metadata"]["graphql_mutations"])
        logger.info("GraphQL introspection enabled on %s at %s: %d quer(y/ies) + %d mutation(s), %d arg(s)",
                    host, cand, n_q, n_m, len(arg_names))
        asset = Asset(value=url, type="url", discovered_by="graphql",
                      discovered_at_stage=STAGE, discovered_in_pass=1,
                      metadata={"graphql": True, "introspection": "enabled"})
        canon = asset.value
        parsed = urlparse(canon)
        endpoint = Endpoint(
            url=canon, host=parsed.hostname or host, path=entry["path"], method="POST",
            content_type="application/json", auth_status=None, discovered_by="graphql",
            target_derived=True, discovered_at_stage=STAGE, discovered_in_pass=1,
            metadata=entry["metadata"])
        params = [Parameter(
            name=n, host=parsed.hostname or host, endpoint=canon, method="POST",
            location="body", reflected=None, discovered_by="graphql", target_derived=True,
            discovered_at_stage=STAGE, discovered_in_pass=1) for n in arg_names]
        return [asset], [endpoint], params
    return [], [], []


def run_api_discovery(live_hosts: list[str], state: RunState, current_pass: int,
                      scope: dict, host_base: dict[str, str] | None = None
                      ) -> tuple[list[Asset], dict[str, list]]:
    """
    B2a API-schema discovery over confirmed-live in-scope hosts. Returns
    (new_assets, {"endpoints":[...], "parameters":[...]}). `host_base` maps host →
    confirmed-live origin (scheme+authority from httpx_final_url), same as B1;
    defaults to https://{host} when unknown. Empty hosts → ([], {empty}).
    """
    if not live_hosts:
        return [], {"endpoints": [], "parameters": []}

    logger.info("Seeding stage 10 (API discovery) with %d confirmed-live in-scope host(s)",
                len(live_hosts))
    new_assets: list[Asset] = []
    endpoints: list[Endpoint] = []
    parameters: list[Parameter] = []

    n_graphql = 0
    with timed(state, "stage10.api_discovery_total"):
        for host in live_hosts:
            base = (host_base or {}).get(host) or f"https://{host}"
            # OpenAPI and GraphQL are independent capabilities — isolate each (R7)
            # so one failing (or absent) doesn't block the other on the same host.
            try:
                a, e, p = discover_openapi_for_host(host, base, state, scope)
            except Exception:
                logger.exception("stage 10 OpenAPI discovery failed for %s - skipping (R7)", host)
                a, e, p = [], [], []
            try:
                ga, ge, gp = discover_graphql_for_host(host, base, state, scope)
            except Exception:
                logger.exception("stage 10 GraphQL discovery failed for %s - skipping (R7)", host)
                ga, ge, gp = [], [], []
            n_graphql += len(ge)
            new_assets.extend(a + ga); endpoints.extend(e + ge); parameters.extend(p + gp)

    logger.info("Stage 10 API discovery: %d endpoint(s) + %d parameter(s) from %d host(s) "
                "(%d GraphQL endpoint(s))", len(endpoints), len(parameters), len(live_hosts), n_graphql)
    return new_assets, {"endpoints": endpoints, "parameters": parameters}
