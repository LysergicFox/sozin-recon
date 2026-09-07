"""
Stage 5: Hidden parameter discovery (paramspider + x8).

Placement (locked): runs BEFORE crawling (stage 6). Neither tool depends on
katana's crawl output - paramspider mines wayback/otx/commoncrawl history,
x8 response-diff-fuzzes live hosts confirmed by stage 4.

Two tools, two output shapes:
  1. paramspider - mines historical parameterized URLs for a root domain →
     new type="url" Assets through the scope gate (same as gau/waybackurls).
  2. x8 - response-diff fuzzes a LIVE url to find which injected param names
     change the response. (Track D) x8's findings are now emitted as
     first-class `parameter` records (name, endpoint, method=GET,
     location=query, reflected=True) rather than an `x8_reflected_params`
     metadata blob on the url asset. The param NAMES come from OUR SecLists
     wordlist, not the target, so these records are target_derived=False.

Like every other stage, this module does NOT classify new assets or write
assets.db itself - paramspider's new url Assets and x8's Parameter records
are returned to the caller (main.py), which scope-gates the assets and
persists the records.
"""

import json
import logging
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from state import Asset, RunState, timed, Parameter
from rate_limits import x8_rate_args

logger = logging.getLogger(__name__)

STAGE = 5
DEFAULT_TIMEOUT_SECONDS = 300


def _run_tool(cmd: list[str], timeout: int = DEFAULT_TIMEOUT_SECONDS, input_text: str | None = None) -> tuple[str, str, int]:
    import subprocess
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Tool timed out after %ss: %s", timeout, " ".join(cmd))
        return "", f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def _run_tool_in_dir(cmd: list[str], cwd: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> tuple[str, str, int]:
    """
    Same as _run_tool, but runs the subprocess with an explicit working
    directory. Needed for paramspider, which writes output to a fixed path
    (results/<domain>.txt) relative to cwd rather than accepting an
    output-path flag - see run_paramspider()'s docstring.
    """
    import subprocess
    logger.info("Running (cwd=%s): %s", cwd, " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Tool timed out after %ss: %s", timeout, " ".join(cmd))
        return "", f"timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error("Tool not found on PATH: %s", cmd[0])
        return "", f"{cmd[0]} not found on PATH", -1


def run_paramspider(domain: str, state: RunState) -> list[Asset]:
    """
    Mine historical parameterized URLs for a root domain via paramspider.

    paramspider (devanshbatham/ParamSpider, confirmed against the real
    installed tool) has NO -o/--output flag - it always writes to
    results/<domain>.txt relative to cwd. This function controls that by
    running paramspider with an explicit cwd in a temp directory, reads the
    file back, archives it, and returns new type="url" Assets for the
    caller to scope-gate.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        stdout, stderr, code = _run_tool_in_dir(
            ["paramspider", "-d", domain],
            cwd=tmpdir,
        )

        expected_path = Path(tmpdir) / "results" / f"{domain}.txt"
        try:
            with open(expected_path) as f:
                raw_output = f.read()
        except FileNotFoundError:
            logger.warning(
                "paramspider: expected output file not found at results/%s.txt "
                "(domain=%s, possibly zero results or a tool failure - stderr: %r)",
                domain, domain, stderr[:300],
            )
            raw_output = ""

    state.save_raw(STAGE, "paramspider", raw_output)

    assets = []
    for line in raw_output.splitlines():
        url = line.strip()
        if url:
            assets.append(Asset(
                value=url,
                type="url",
                discovered_by="paramspider",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,  # caller overwrites with real pass number
            ))

    logger.info("paramspider found %d parameterized URLs for %s", len(assets), domain)
    return assets


DEFAULT_X8_WORDLIST = Path.home() / "tools" / "SecLists" / "Discovery" / "Web-Content" / "burp-parameter-names.txt"


def run_x8(url: str, state: RunState, scope: dict, wordlist: Path = DEFAULT_X8_WORDLIST) -> list[str]:
    """
    Response-diff fuzz a single live URL via x8 to find parameter names that
    change the response (reflected/processed params - candidate injection
    points, not confirmed vulnerabilities). Returns a plain list of
    discovered param names, or empty on nothing/failure.

    scope is threaded for x8_rate_args() (x8 has no native requests/sec flag;
    -c/-d derive a delay). wordlist defaults to a real SecLists param-name
    list - without -w, x8 reports "wordlist len: 0" and finds nothing.
    x8's stdout with -O json has a human-readable preamble before the JSON
    array (locate by first '['); the real field is "found_params".
    """
    cmd = ["x8", "-u", url, "-O", "json"]
    if wordlist is not None:
        if not wordlist.exists():
            logger.error(
                "x8 wordlist not found at %s - proceeding without -w, x8 will "
                "have nothing to fuzz with. Check that SecLists is cloned.",
                wordlist,
            )
        else:
            cmd.extend(["-w", str(wordlist)])

    rate = x8_rate_args(scope)
    logger.info("x8 rate limit (%s): %s", url, rate.note)
    cmd.extend(rate.extra_args)

    stdout, stderr, code = _run_tool(cmd)
    state.save_raw(STAGE, "x8", stdout)

    if not stdout.strip():
        return []

    json_start = stdout.find("[")
    if json_start == -1:
        logger.warning("x8: no JSON array found in output for %s: %r", url, stdout[:200])
        return []

    try:
        obj = json.loads(stdout[json_start:])
    except json.JSONDecodeError:
        logger.warning("x8: could not parse output as JSON for %s: %r", url, stdout[:200])
        return []

    if isinstance(obj, list):
        results = obj
    elif isinstance(obj, dict):
        results = obj.get("results") or [obj]
    else:
        results = []

    params = []
    for result in results:
        if not isinstance(result, dict):
            continue
        for name in result.get("found_params") or []:
            if name:
                params.append(name)

    logger.info("x8 found %d reflected param(s) for %s", len(params), url)
    return params


def run_stage5(root_domains: list[str], live_urls: list[str],
               state: RunState, current_pass: int, scope: dict) -> tuple[list[Asset], dict[str, dict], dict[str, list]]:
    """
    Run the full stage 5 sequence: paramspider (per root domain) + x8 (per
    live URL).

    live_urls should come from the caller filtering assets.db to in_scope,
    stage-4-confirmed-live url assets.

    Returns a THREE-tuple (Track D added the third element):
      - new_assets: list[Asset] - paramspider's parameterized URLs, for the
        caller to scope-gate + add_assets().
      - metadata_updates: dict[str, dict] - kept for contract symmetry with
        stage 4/7; empty now that x8 findings are `parameter` records rather
        than an x8_reflected_params metadata blob.
      - records: dict[str, list] - {"parameters": [Parameter, ...]} from x8,
        for the caller to persist via persist_records() (which sets asset_id
        by matching the endpoint value). x8 param names come from our
        wordlist → target_derived=False; reflected=True (they changed the
        response).
    """
    new_assets: list[Asset] = []
    with timed(state, "stage5.paramspider"):
        for domain in root_domains:
            try:
                found = run_paramspider(domain, state)
                for a in found:
                    a.discovered_in_pass = current_pass
                new_assets.extend(found)
            except Exception:
                logger.exception("Stage 5 paramspider failed for domain %s", domain)
                continue

    parameters: list[Parameter] = []
    with timed(state, "stage5.x8_total"):
        for url in live_urls:
            try:
                params = run_x8(url, state, scope)
            except Exception:
                logger.exception("Stage 5 x8 failed for url %s", url)
                continue
            host = urlparse(url).hostname or ""
            for name in params:
                parameters.append(Parameter(
                    name=name,
                    host=host,
                    endpoint=url,
                    method="GET",
                    location="query",
                    reflected=True,
                    discovered_by="x8",
                    target_derived=False,  # names come from our SecLists wordlist
                    discovered_at_stage=STAGE,
                    discovered_in_pass=current_pass,
                ))

    metadata_updates: dict[str, dict] = {}
    return new_assets, metadata_updates, {"parameters": parameters}
