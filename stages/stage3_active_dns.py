"""
Stage 3: Active DNS resolution + brute force.

Unlike stage 1 (independent passive lookups merged together), stage 3 has
real sequencing dependency WITHIN each leg, but two of its legs are
independent of each other:

  1. Permutation leg: alterx generates permutation candidates
     (api-staging, api2, dev-api...) seeded from subdomains ALREADY
     CONFIRMED in_scope, then puredns resolves them. These two steps are a
     genuine chain - puredns has nothing to resolve if alterx produced
     nothing - so the leg is all-or-nothing internally.
  2. Brute-force leg: puredns brute-forces each root domain against a
     wordlist (SecLists). Independent of the permutation leg, and each root
     domain is independent of the others.
  3. dnsx enrichment: a final validation/record-capture pass over
     everything the first two legs resolved. Pure enrichment - a failure
     here loses A/CNAME record metadata but not the assets themselves,
     since puredns already validated them.

(R7) fault isolation. Each of the three legs above is wrapped so a failure
in one degrades the result rather than aborting the whole stage/run: the
permutation leg failing still lets the brute-force leg run, one root
domain's brute force failing still lets the others run, and dnsx failing
still returns the resolved assets (just without dnsx record metadata). The
WITHIN-leg alterx->puredns chain and the puredns->dnsx dependency stay
all-or-nothing by nature (a step genuinely can't proceed without the prior
step's output) - that's the "explicitly document a stage as intentionally
all-or-nothing where a tool's output is a hard prerequisite" half of R7,
applied at leg granularity rather than to the whole stage.

All discovered live subdomains are new Asset objects (type=subdomain,
discovered_by=alterx+puredns / puredns-bruteforce / dnsx) - they get
returned to the caller for scope classification exactly like stage 1's
output, NOT auto-admitted just because they were seeded from something
already in_scope. A permutation of an in-scope domain is still a NEW
asset that needs its own scope decision (it should almost always land
in_scope again since it shares the same base domain, but that's the scope
gate's call to make, not this stage's).
"""

import logging
import re
import tempfile
from pathlib import Path

from state import Asset, RunState, timed
from rate_limits import dnsx_rate_args, puredns_rate_args

logger = logging.getLogger(__name__)

STAGE = 3
DEFAULT_TIMEOUT_SECONDS = 600  # brute force against a wordlist genuinely takes a while

# Path to the wordlist used for puredns brute force. Points at the SecLists
# clone from the install steps. Kept as a small, fast list by default -
# swap for a larger SecLists wordlist once the pipeline is validated and
# runtime budget is being tuned deliberately, not by accident.
DEFAULT_WORDLIST = Path.home() / "tools" / "SecLists" / "Discovery" / "DNS" / "subdomains-top1million-5000.txt"

# Public resolvers for puredns to use. A small hardcoded set is fine for now;
# SecLists also ships resolver lists if this needs to grow later.
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _sanitize(domain: str) -> str:
    """
    (R5) Filesystem-safe token of a domain for per-target raw archive
    filenames, so the per-domain brute-force loop doesn't overwrite each
    root's raw archive with the next one's (mirrors stage 1's _sanitize()
    and stage 9's per-host whatweb filenames). Same character class as
    stage 1's copy - kept local rather than cross-importing to avoid a
    stage->stage import dependency.
    """
    return re.sub(r"[^A-Za-z0-9._-]", "_", domain)


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


def run_alterx(known_in_scope_subdomains: list[str], state: RunState) -> list[str]:
    """
    Generate permutation candidates from already-confirmed in-scope
    subdomains. Returns a plain list of candidate hostnames (not yet
    resolved/validated - that's puredns's job next). Empty input ->
    empty output, no error.
    """
    if not known_in_scope_subdomains:
        logger.info("alterx: no in-scope subdomains to seed permutations from, skipping")
        return []

    seed_input = "\n".join(known_in_scope_subdomains)
    stdout, stderr, code = _run_tool(
        ["alterx", "-silent"],
        input_text=seed_input,
    )
    state.save_raw(STAGE, "alterx", stdout)

    candidates = [line.strip() for line in stdout.splitlines() if line.strip()]
    logger.info("alterx generated %d permutation candidates from %d seeds",
                len(candidates), len(known_in_scope_subdomains))
    return candidates


def run_puredns_resolve(candidates: list[str], state: RunState, tag: str, scope: dict) -> list[Asset]:
    """
    Resolve a list of candidate hostnames via puredns (wraps massdns,
    filters wildcards). Used both for alterx's permutation output and
    could be reused for any other candidate-list source later.
    `tag` disambiguates raw-output filenames when this is called more
    than once in a stage (e.g. "permutations" vs "bruteforce").

    scope is the loaded scope.json dict, passed through for
    puredns_rate_args() - see rate_limits.py's puredns section for why
    this caps the public-resolver query stream rather than being scaled
    by candidate count the way the HTTP tools' host-count scaling works.
    """
    if not candidates:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(candidates))
        candidates_path = f.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(DEFAULT_RESOLVERS))
        resolvers_path = f.name

    rate = puredns_rate_args(scope)
    logger.info("puredns (resolve, tag=%s) rate limit: %s", tag, rate.note)

    stdout, stderr, code = _run_tool([
        "puredns", "resolve", candidates_path,
        "--resolvers", resolvers_path,
        "-q",
        *rate.extra_args,
    ])
    state.save_raw(STAGE, f"puredns_{tag}", stdout)

    assets = []
    for line in stdout.splitlines():
        host = line.strip()
        if host:
            assets.append(Asset(
                value=host,
                type="subdomain",
                discovered_by=f"puredns_{tag}",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,  # caller overwrites
            ))

    Path(candidates_path).unlink(missing_ok=True)
    Path(resolvers_path).unlink(missing_ok=True)
    return assets


def run_puredns_bruteforce(root_domain: str, state: RunState, scope: dict, wordlist: Path = DEFAULT_WORDLIST) -> list[Asset]:
    """
    Brute-force subdomains of root_domain against a wordlist via puredns.
    This is the actual "assets nobody else found" source - permutation
    (alterx) extrapolates from what's already known, brute force finds
    genuinely novel names that don't resemble anything discovered so far.

    (R5) The raw archive filename is suffixed with the sanitized root
    domain (puredns_bruteforce_{domain}), so a multi-root scope doesn't
    have each domain's brute-force output overwrite the previous root's
    (the previous fixed "puredns_bruteforce" tag silently kept only the
    last root's archive).

    scope is the loaded scope.json dict, passed through for
    puredns_rate_args() - see run_puredns_resolve()'s docstring.
    """
    if not wordlist.exists():
        logger.error(
            "Wordlist not found at %s - skipping brute force. "
            "Check that SecLists is cloned per the setup steps.",
            wordlist,
        )
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(DEFAULT_RESOLVERS))
        resolvers_path = f.name

    rate = puredns_rate_args(scope)
    logger.info("puredns (bruteforce, domain=%s) rate limit: %s", root_domain, rate.note)

    stdout, stderr, code = _run_tool([
        "puredns", "bruteforce", str(wordlist), root_domain,
        "--resolvers", resolvers_path,
        "-q",
        *rate.extra_args,
    ], timeout=1200)  # brute force against a real wordlist is the slowest step in this stage
    state.save_raw(STAGE, f"puredns_bruteforce_{_sanitize(root_domain)}", stdout)  # (R5) per-target filename

    assets = []
    for line in stdout.splitlines():
        host = line.strip()
        if host:
            assets.append(Asset(
                value=host,
                type="subdomain",
                discovered_by="puredns_bruteforce",
                discovered_at_stage=STAGE,
                discovered_in_pass=1,
            ))

    Path(resolvers_path).unlink(missing_ok=True)
    return assets


def run_dnsx_validate(hosts: list[str], state: RunState, scope: dict) -> dict[str, dict]:
    """
    Final validation pass over resolved hosts via dnsx, capturing DNS
    record details (A/CNAME/etc.) for metadata. Returns a dict keyed by
    hostname so the caller can attach record info to the right Asset's
    metadata field. Hosts that dnsx can't confirm are simply absent from
    the returned dict - callers should treat "not in this dict" as "dnsx
    could not re-confirm this", worth logging but not necessarily
    discarding the asset over, since puredns already validated it.

    scope is the loaded scope.json dict, passed through for
    dnsx_rate_args().
    """
    if not hosts:
        return {}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        hosts_path = f.name

    rate = dnsx_rate_args(scope)
    logger.info("dnsx rate limit: %s", rate.note)

    stdout, stderr, code = _run_tool([
        "dnsx", "-l", hosts_path,
        "-json", "-silent",
        "-a", "-cname",
        *rate.extra_args,
    ])
    state.save_raw(STAGE, "dnsx", stdout)

    import json
    records = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            host = obj.get("host")
            if host:
                records[host] = {
                    "a_records": obj.get("a", []),
                    "cname_records": obj.get("cname", []),
                }
        except json.JSONDecodeError:
            logger.warning("dnsx: could not parse line as JSON: %r", line)

    Path(hosts_path).unlink(missing_ok=True)
    return records


def run_stage3(root_domains: list[str], known_in_scope_subdomains: list[str],
               state: RunState, current_pass: int, scope: dict) -> list[Asset]:
    """
    Run the full stage 3 sequence: alterx -> puredns (permutations) +
    puredns (bruteforce) -> dnsx (validation/metadata).
    known_in_scope_subdomains should come from the caller filtering
    assets.json to scope_status == "in_scope" subdomains only - this
    function does not do that filtering itself, to keep it decoupled
    from the Asset/state model specifics.

    (R7) The three legs (permutation, brute force, dnsx enrichment) are
    fault-isolated from each other - see the module docstring. Within a
    leg, the tool chain stays all-or-nothing because each step is a hard
    prerequisite for the next.

    scope is the loaded scope.json dict (state.RunState.load_scope()) -
    threaded through to every rate-limited tool call in this stage. See
    stage4_live_probing.py's run_stage4() docstring for the same
    caller-already-checked-the-blocking-gate contract.
    """
    all_assets: list[Asset] = []

    # 1. permutation leg (alterx -> puredns). Isolated (R7) so a failure
    # here does not prevent the independent brute-force leg below from
    # running. The alterx->puredns chain stays all-or-nothing internally
    # (puredns has nothing to resolve without alterx's candidates).
    permutation_assets: list[Asset] = []
    try:
        with timed(state, "stage3.alterx"):
            candidates = run_alterx(known_in_scope_subdomains, state)
        with timed(state, "stage3.puredns_permutations"):
            permutation_assets = run_puredns_resolve(candidates, state, tag="permutations", scope=scope)
    except Exception:
        logger.exception(
            "stage 3 permutation leg (alterx->puredns) failed - continuing "
            "with the brute-force leg (R7 fault isolation)"
        )
    all_assets.extend(permutation_assets)
    logger.info("puredns resolved %d live hosts from alterx permutations", len(permutation_assets))

    # 2. brute-force leg, per root domain. Timed as ONE aggregate
    # "stage3.puredns_bruteforce" across every domain in root_domains
    # (usually just 1-2 in practice) rather than a separate timing entry
    # per domain - matches the locked "one aggregate number" decision used
    # for stage 5's per-URL x8 timing. Each root domain is isolated (R7):
    # one domain's brute force failing does not skip the rest.
    with timed(state, "stage3.puredns_bruteforce"):
        for domain in root_domains:
            try:
                bruteforce_assets = run_puredns_bruteforce(domain, state, scope=scope)
                all_assets.extend(bruteforce_assets)
                logger.info("puredns brute force found %d live hosts for %s", len(bruteforce_assets), domain)
            except Exception:
                logger.exception(
                    "stage 3 brute force failed for %s - continuing with the "
                    "remaining root domain(s) (R7 fault isolation)", domain,
                )
                continue

    # 3. dnsx validation/enrichment pass over everything found, attach
    # record metadata. Isolated (R7): a dnsx failure loses A/CNAME record
    # metadata but keeps the resolved assets themselves, since puredns
    # already validated them - enrichment, not a hard prerequisite.
    all_hosts = [a.value for a in all_assets]
    records: dict[str, dict] = {}
    try:
        with timed(state, "stage3.dnsx"):
            records = run_dnsx_validate(all_hosts, state, scope)
    except Exception:
        logger.exception(
            "stage 3 dnsx enrichment failed - keeping resolved assets without "
            "dnsx A/CNAME record metadata (R7 fault isolation)"
        )
    for asset in all_assets:
        if asset.value in records:
            asset.metadata.update(records[asset.value])
        else:
            logger.info("dnsx could not re-confirm %s (already validated by puredns)", asset.value)

    for a in all_assets:
        a.discovered_in_pass = current_pass

    return all_assets
