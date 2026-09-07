"""
E3: target-derived wordlists — mine the tokens the target itself uses (path
segments + parameter names) from the current run's assets.db into wordlist
artifacts that raise B1/stage-5 yield on a subsequent run / loop pass. Offline,
zero traffic. v1 writes the artifacts; auto-feeding B1 in the same pass waits on
loop-until-stable.
"""

import logging
import re
from urllib.parse import urlparse, parse_qsl

logger = logging.getLogger(__name__)

_PATHS_FILE = "target_derived_paths.txt"
_PARAMS_FILE = "target_derived_params.txt"
_MAX_TOKENS = 20000  # cap each wordlist


def _clean_segment(seg: str, min_len: int = 2) -> str | None:
    """Normalize a token, or None to drop it. Paths use min_len=2 (single-char path
    segments are rarely useful); param names use min_len=1 (`q`, `a` are real params)."""
    seg = seg.strip().lower()
    if len(seg) < min_len:
        return None
    if seg.isdigit():           # templated id like /product/42
        return None
    if "://" in seg or "%" in seg:
        return None
    if not re.match(r"^[a-z0-9][a-z0-9._\-]*$", seg):
        return None
    return seg


def mine_path_tokens(assets, endpoints) -> set[str]:
    """Unique path segments from url assets + endpoint paths. A dotted file like
    `config.json` yields both `config.json` and its stem `config`."""
    tokens: set[str] = set()
    paths = [urlparse(a.value).path for a in assets if a.type == "url"]
    paths += [e.path for e in endpoints if e.path]
    for path in paths:
        for raw in (path or "").split("/"):
            tok = _clean_segment(raw)
            if not tok:
                continue
            tokens.add(tok)
            if "." in tok and not tok.startswith("."):
                stem = _clean_segment(tok.rsplit(".", 1)[0])
                if stem:
                    tokens.add(stem)
    return tokens


def mine_param_names(parameters, assets) -> set[str]:
    """Parameter names from the parameters table + query strings on url assets."""
    names: set[str] = set()
    for p in parameters:
        n = _clean_segment(p.name, min_len=1) if p.name else None
        if n:
            names.add(n)
    for a in assets:
        if a.type != "url":
            continue
        q = urlparse(a.value).query
        for name, _val in parse_qsl(q):
            n = _clean_segment(name, min_len=1)
            if n:
                names.add(n)
    return names


def _write(run_dir, filename, tokens):
    path = run_dir / filename
    with open(path, "w") as f:
        f.write("\n".join(sorted(tokens)[:_MAX_TOKENS]))
        if tokens:
            f.write("\n")
    return path


def run_wordlist_mining(state) -> dict:
    """Mine path + param wordlists from the run's assets.db and write the two
    artifacts to the run dir. Returns {paths, params, paths_file, params_file}."""
    assets = state.load_assets()
    endpoints = state.load_endpoints()
    parameters = state.load_parameters()
    path_tokens = mine_path_tokens(assets, endpoints)
    param_tokens = mine_param_names(parameters, assets)
    paths_file = _write(state.run_dir, _PATHS_FILE, path_tokens)
    params_file = _write(state.run_dir, _PARAMS_FILE, param_tokens)
    logger.info("E3 wordlist mining: %d path token(s) → %s, %d param name(s) → %s",
                len(path_tokens), paths_file.name, len(param_tokens), params_file.name)
    return {"paths": len(path_tokens), "params": len(param_tokens),
            "paths_file": str(paths_file), "params_file": str(params_file)}
