"""
Required request-header injection (e.g. a program-mandated identifying header).

Some programs REQUIRE every piece of test traffic to carry an identifying
header — HackerOne's ToS Test Plan mandates `X-HackerOne: <username>` on all
requests, and omitting it violates the rules of engagement. The recon pipeline
must therefore attach these headers to every request its TARGET-FACING tools
make.

Declare them once in scope.json:

    "required_headers": { "X-HackerOne": "my-h1-username" }

and this module threads them to every tool that sends HTTP to an in-scope host.

WHO GETS THE HEADER: only tools that make HTTP requests to the *target*
(httpx, katana, ffuf, nuclei, x8, whatweb, wafw00f). Tools that query
third-party data sources — subfinder / assetfinder / amass / gau / gauplus /
waybackurls, the certspotter and Wayback HTTP calls — and pure-DNS tools
(dnsx / puredns / alterx / naabu port scan) are NOT given the header: it
belongs on target traffic only, and leaking your H1 username to third-party
APIs is pointless noise.

PER-TOOL FLAG CONVENTIONS (verified against the real binaries, 2026-09-07 —
`CONTRIBUTING.md`: never trust a tool's docs, run it):
  - httpx / katana / nuclei / ffuf / whatweb : repeatable `-H "name:value"`.
  - x8                                        : one `-H` then space-separated
                                                `name:value` tokens.
  - wafw00f                                   : `-H <file>` reads headers from a
                                                TEXT FILE (not an inline value),
                                                and it OVERWRITES wafw00f's
                                                default header set (documented
                                                caveat — see wafw00f_header_file).

Header values are formatted `name:value` (no space): every tool above splits on
the first colon, and this avoids a leading space sneaking into the value on the
tools that don't trim it.
"""
from __future__ import annotations

import tempfile
from typing import Optional


def required_headers(scope: dict) -> dict[str, str]:
    """The `required_headers` map from scope.json, normalized to trimmed
    str->str with empty names/values dropped. Missing/malformed -> {} (so the
    whole feature is a no-op when unconfigured)."""
    raw = (scope or {}).get("required_headers") or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        name = str(k).strip()
        value = str(v).strip()
        if name and value:
            out[name] = value
    return out


def header_args(scope: dict, flag: str = "-H") -> list[str]:
    """Repeatable `flag name:value` args for httpx/katana/nuclei/ffuf/whatweb.
    Empty list when no headers are configured (a clean no-op appended to any
    command)."""
    args: list[str] = []
    for name, value in required_headers(scope).items():
        args += [flag, f"{name}:{value}"]
    return args


def x8_header_args(scope: dict) -> list[str]:
    """x8 takes one `-H` followed by space-separated `name:value` tokens
    (`-H a:b c:d`). Empty list when no headers are configured."""
    tokens = [f"{name}:{value}" for name, value in required_headers(scope).items()]
    return ["-H", *tokens] if tokens else []


def wafw00f_header_file(scope: dict) -> Optional[str]:
    """wafw00f reads custom headers from a FILE (`-H <file>`). Write the required
    headers as `Name: Value` lines to a temp file and return its path, or None
    when no headers are configured (caller then omits `-H`).

    CAVEAT (from wafw00f -h): supplying `-H` OVERWRITES wafw00f's default header
    set, so its probes go out with only these headers (no default User-Agent).
    We accept that: the RoE requirement to identify our traffic outranks
    wafw00f's fingerprint fidelity, and this stage is fault-isolated enrichment.
    The caller is responsible for unlinking the returned path.
    """
    headers = required_headers(scope)
    if not headers:
        return None
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for name, value in headers.items():
        f.write(f"{name}: {value}\n")
    f.close()
    return f.name
