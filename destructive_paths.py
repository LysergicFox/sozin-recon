"""
Shared destructive-path guard.

recon is non-destructive by contract, but an active GET can TRIGGER a state
change when an app acts on GET (a common anti-pattern) — e.g. a GET to
/users/delete/carlos deleting the user. These helpers identify paths whose
segments name a state-changing action so active stages can avoid them.

Where it's applied (and where it deliberately is NOT):
  - x8 (stage 5): SKIP param-fuzzing such endpoints — fuzzing sends many
    requests at a known destructive handler.
  - katana (stage 6): pass crawl_out_scope_regex() as -cos so the crawler never
    FOLLOWS a destructive link the app itself surfaces. This is the real risk:
    katana follows app-provided, actionable URLs (often already carrying a
    token/id), so following one can complete the action.
  - ffuf content discovery (stage 6.5): NOT guarded. Its wordlist entries are
    synthetic path GUESSES — mostly files like delete.php / reset-db.sh with low
    GET-trigger risk and HIGH discovery value. Filtering there would hide
    valuable findings without preventing meaningful harm.

Tokens are defined ONCE here; the x8 word-level check and the katana regex both
derive from them, so the guard stays consistent across stages.
"""
import re

# Path words that signal a state-changing / destructive handler.
DESTRUCTIVE_PATH_TOKENS = frozenset({
    "delete", "remove", "destroy", "drop", "purge", "wipe", "erase",
    "logout", "signout", "deactivate", "disable", "revoke", "reset",
    "ban", "unban", "cancel", "terminate", "kill", "shutdown", "unsubscribe",
    "deregister", "unregister", "reboot", "restart",
})

_WORD_RE = re.compile(r"[a-z0-9]+")


def is_destructive_path(path: str) -> bool:
    """True if any WORD in the path is a destructive action token. Words split on
    / and -_. so compound segments like 'reset-password'/'delete-account' trip,
    while 'deleted_at' (→ 'deleted') and 'undeletable' do NOT (not the exact
    token). Case-insensitive."""
    return any(w in DESTRUCTIVE_PATH_TOKENS for w in _WORD_RE.findall(path.lower()))


def crawl_out_scope_regex() -> str:
    """A katana -cos (crawl-out-scope) regex that excludes any URL whose path
    contains a destructive action word from being FOLLOWED. Uses RE2 \\b word
    boundaries (katana is Go/RE2), so 'delete' matches in /users/delete/x and
    reset-password, but not 'deleted'/'undeletable'."""
    return r"(?i)\b(" + "|".join(sorted(DESTRUCTIVE_PATH_TOKENS)) + r")\b"
