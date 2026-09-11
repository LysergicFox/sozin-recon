"""
Shared URL-hygiene guard for asset ingestion.

Passive URL sources (gau/waybackurls) and crawlers (katana) sometimes emit
"URLs" that are really fragments of HTML the tool scraped off a page — e.g.
gau returns `https://t/%3C/a%3E` (a stray `</a>`), `https://t/about%3C/a%3E`
(`about</a>`), or a path with a trailing backslash `https://t/x%5C`.
These are not real endpoints; letting them into assets.db bloats the graph,
the scope-review queue, and every downstream stage that reads url assets.

`is_malformed_url_asset` identifies them so ingestion can drop them ONCE, at
the single choke point (main.run_stage_and_report), before scope-gating.

Design (deliberately conservative — keeping one noise row is cheaper than
losing one real asset):
  - Only the PATH is inspected. A real endpoint legitimately carries markup in
    a QUERY value — e.g. a reflected-XSS demo link
    `/?search=%3Cscript%3Eprompt(1)%3C/script%3E` has a clean path (`/`) and a
    real `search` param, so it is KEPT.
  - The path is percent-decoded first, then checked for characters that never
    occur in a real URL path: the RFC-3986 "unsafe"/delimiter set
    (< > " \\ ^ ` { } |) and any C0 control char. SPACE is intentionally NOT in
    the set — `/my%20file.pdf` decodes to a legit path containing a space.
  - A value urlsplit() cannot parse at all is treated as malformed.

Shared so the x8 candidate filter (stage 5) uses the exact same definition
rather than its own substring list (mirrors destructive_paths).
"""
from urllib.parse import urlsplit, unquote

# Characters that never legitimately appear in a URL path (RFC 3986 unsafe /
# delimiter set). SPACE is excluded on purpose: it decodes from a legit %20.
_PATH_NOISE_CHARS = frozenset('<>"\\^`{}|')


def _path_has_noise(path: str) -> bool:
    decoded = unquote(path)
    return any(c in _PATH_NOISE_CHARS or ord(c) < 0x20 for c in decoded)


def is_malformed_url_asset(value: str) -> bool:
    """True if a url/js_file asset value is crawl/history noise rather than a
    real endpoint. Inspects only the path (see module docstring); never raises.

    Examples that return True:  https://t/%3C/a%3E , https://t/x%5C ,
                                https://t/about%3C/a%3E&quot;
    Examples that return False: https://t/catalog?id=1 ,
                                https://t/?search=%3Cscript%3E... (payload in
                                the query, path is clean) , https://t/my%20file.pdf
    """
    if not isinstance(value, str):
        return True
    try:
        parts = urlsplit(value)
    except ValueError:
        return True
    return _path_has_noise(parts.path)
