"""
Colorized logging setup for the recon agent, built on `rich`.

Drop-in replacement for the plain `logging.basicConfig(...)` call at the
top of main.py. Every existing `logger.info(...)` / `logger.warning(...)`
/ `logger.error(...)` call site elsewhere in the codebase is untouched -
this module only changes how those messages are rendered, via a
RichHandler + a regex-based highlighter that colors specific substrings
(stage banners, tool names, in/needs_review/out_of_scope, rate-limit
lines, "Running: <cmd>" lines, and bare numbers) without requiring any
Rich markup in the log calls themselves.

Usage (replaces the current logging.basicConfig(...) block in main.py):

    from logging_setup import setup_logging
    logger = setup_logging("recon_agent")

Standalone re-run scripts (run_stage5_only.py etc.) should call this
too, instead of their own basicConfig, so output is consistent whether
running the full pipeline or a single stage.
"""

import logging
import re

import pyfiglet
from rich.console import Console
from rich.highlighter import RegexHighlighter
from rich.logging import RichHandler
from rich.text import Text
from rich.theme import Theme


# Tool names that show up as the first word of a log message across the
# stage files (stage1_passive.py, stage3_active_dns.py, etc.) - kept as
# an explicit list rather than a generic "first word" rule so we don't
# accidentally highlight ordinary sentences that happen to start with a
# capitalized word ("Applied", "Seeding", "Newly", ...).
TOOL_NAMES = [
    "subfinder", "assetfinder", "amass", "chaos-client", "chaos", "gau",
    "waybackurls", "gauplus", "waymore", "gitleaks", "asnmap", "dnsx",
    "massdns", "puredns", "alterx", "httpx", "naabu", "paramspider", "x8",
    "katana", "nuclei", "jsluice", "whatweb", "ffuf",
]


class ReconHighlighter(RegexHighlighter):
    """
    Applies theme styles to substrings within a single log message based
    on regex. Matched against the rendered message text (after %-style
    interpolation), so this works with the codebase's existing lazy
    logger.info("...%s...", arg) calls unchanged - no markup needed at
    the call site.
    """
    base_style = "recon."
    highlights = [
        # --- Stage N: description --- banners (main.py's stage headers).
        # Matched and colored as one solid block, BEFORE the tool_name /
        # count rules below get a chance to fragment it (e.g. splitting
        # out the stage number or an embedded tool name into a different
        # color mid-banner).
        r"(?P<stage_banner>---\s*Stage\s+\d+:[^-]*---)",
        # tool rate-limit lines, e.g. "httpx rate limit: 5 req/s (...)"
        r"(?P<rate_limit>\b\w[\w -]* rate limit(?: \([^)]*\))?:)",
        # "Running: <shell command>" tool-invocation lines
        r"(?P<running_cmd>^Running(?: \(cwd=[^)]*\))?:)",
        # scope status words
        r"(?P<in_scope>\bin_scope\b)",
        r"(?P<needs_review>\bneeds_review\b)",
        r"(?P<out_of_scope>\bout_of_scope\b)",
        # known tool names, wherever they appear in the message
        r"(?P<tool_name>\b(?:" + "|".join(re.escape(t) for t in TOOL_NAMES) + r")\b)",
        # bare integers (counts) - word-boundaried so it doesn't eat
        # digits inside hostnames/paths. Placed last so it never
        # re-colors digits already claimed by the stage_banner rule
        # above (Rich's highlighter skips spans already matched).
        r"(?P<count>(?<![\w.])\d+(?![\w.]))",
    ]


RECON_THEME = Theme({
    "recon.stage_banner": "bold bright_cyan",
    "recon.tool_name": "bold yellow",
    "recon.rate_limit": "magenta",
    "recon.running_cmd": "dim",
    "recon.in_scope": "bold green",
    "recon.needs_review": "bold yellow",
    "recon.out_of_scope": "bold red",
    "recon.count": "bold green",
    "logging.level.warning": "bold yellow",
    "logging.level.error": "bold red",
    "logging.level.info": "bright_blue",
})


def setup_logging(logger_name: str = "recon_agent", level: int = logging.INFO) -> logging.Logger:
    """
    Configure root logging with a RichHandler + ReconHighlighter and
    return the named logger, mirroring the old
    logging.basicConfig(...) + logging.getLogger(name) pattern this
    replaces.
    """
    console = Console(theme=RECON_THEME)
    handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=False,
        rich_tracebacks=True,
        highlighter=ReconHighlighter(),
        log_time_format="[%X]",
    )
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[handler],
        force=True,  # replace any handlers a prior basicConfig call installed
    )
    return logging.getLogger(logger_name)


# Top-to-bottom RGB gradient applied to the SOZIN wordmark, orange -> red
# (evokes the "fire nation" origin of the name without being literal
# about it). One color per figlet output line, interpolated linearly.
_BANNER_GRADIENT_START = (255, 140, 0)   # dark orange
_BANNER_GRADIENT_END = (200, 20, 20)     # deep red


def _gradient_color(step: int, total: int) -> str:
    if total <= 1:
        r, g, b = _BANNER_GRADIENT_START
    else:
        t = step / (total - 1)
        r = round(_BANNER_GRADIENT_START[0] + t * (_BANNER_GRADIENT_END[0] - _BANNER_GRADIENT_START[0]))
        g = round(_BANNER_GRADIENT_START[1] + t * (_BANNER_GRADIENT_END[1] - _BANNER_GRADIENT_START[1]))
        b = round(_BANNER_GRADIENT_START[2] + t * (_BANNER_GRADIENT_END[2] - _BANNER_GRADIENT_START[2]))
    return f"#{r:02x}{g:02x}{b:02x}"


def print_banner(version: str = "v0", console: Console | None = None) -> None:
    """
    Print the SOZIN ASCII wordmark once at process startup, nuclei/
    paramspider-style: big block-letter logo (pyfiglet, ansi_shadow
    font) with a top-to-bottom orange->red gradient, followed by a dim
    subtitle line with the project name and version. Purely cosmetic -
    safe to call before or after setup_logging(); doesn't touch the
    logging config itself. Falls back to plain (uncolored) text
    automatically when stdout isn't a real terminal (piped/redirected
    output), same as everything else rendered through rich.Console.
    """
    console = console or Console(theme=RECON_THEME)

    art = pyfiglet.figlet_format("SOZIN", font="ansi_shadow")
    lines = [line for line in art.split("\n") if line.strip()]

    banner = Text()
    for i, line in enumerate(lines):
        banner.append(line + "\n", style=_gradient_color(i, len(lines)))
    banner.append("hackbot recon agent", style="bold white")
    banner.append(f"  ·  {version}\n", style="dim")

    console.print(banner)


def setup_logging_with_banner(logger_name: str = "recon_agent", level: int = logging.INFO,
                               version: str = "v0") -> logging.Logger:
    """
    Convenience wrapper: print_banner() followed by setup_logging().
    Banner prints first (raw, no log-level prefix), then the logger is
    configured for everything after it. Equivalent to calling both
    functions separately - kept as one call for main.py's single
    import line.
    """
    print_banner(version=version)
    return setup_logging(logger_name=logger_name, level=level)
