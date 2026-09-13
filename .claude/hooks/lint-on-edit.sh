#!/usr/bin/env bash
# PostToolUse hook: fast, per-file feedback right after Claude edits a file.
#
# - .py         ruff check --fix (safe fixes) + ruff format, then report what's left; mypy on the file
# - .sh/.bash   shellcheck
# - Dockerfile  hadolint
# - .js/.ts     eslint, only if the repo has it installed
#
# Anything still outstanding is written to stderr and we exit 2, which Claude Code
# feeds back to the model so it can fix it in the same turn. Exit 0 = nothing to say.
#
# The hook is deliberately narrower than /code-review: it surfaces real errors, bugs and
# security issues (ruff F/E/W/B/S/ASYNC + mypy), not style nits, so it doesn't nag on
# every edit. The full rule set runs in /code-review.
#
# Env knobs:  REVIEW_HOOK_MYPY=0          skip mypy in the hook (full review still runs it)
#             REVIEW_HOOK_QUIET=1         disable the hook entirely (e.g. for a bulk refactor)
#             REVIEW_HOOK_RUFF_IGNORE=... override the comma list of ruff rules the hook hides
set -u

[ "${REVIEW_HOOK_QUIET:-0}" = "1" ] && exit 0

input=$(cat)
file=$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
[ -z "$file" ] && exit 0
[ -f "$file" ] || exit 0

root="${CLAUDE_PROJECT_DIR:-$(pwd)}"
relfile="${file#"$root"/}"
hook_ignore="${REVIEW_HOOK_RUFF_IGNORE:-PTH,SIM,UP,ARG,PERF,PL,N,D,C4,RET,PIE,T20,ERA,TRY,G,LOG,DTZ,RUF,C901,I,ISC,COM}"
kit="$root/.claude/skills/code-review"
[ -d "$kit" ] || kit="$HOME/.claude/skills/code-review"
cfg="$kit/configs"

case "$file" in
  */.review/*|*/.venv/*|*/venv/*|*/node_modules/*|*/.git/*|*/build/*|*/dist/*|*/migrations/*) exit 0 ;;
esac

out=""
add() { out+="$1"$'\n'; }
has() { command -v "$1" >/dev/null 2>&1; }

ruff_cfg=()
if ! { [ -f "$root/ruff.toml" ] || [ -f "$root/.ruff.toml" ] || grep -qs '^\[tool\.ruff' "$root/pyproject.toml"; }; then
  [ -f "$cfg/ruff.toml" ] && ruff_cfg=(--config "$cfg/ruff.toml")
fi
mypy_cfg=()
if ! { [ -f "$root/mypy.ini" ] || [ -f "$root/.mypy.ini" ] || grep -qs '^\[tool\.mypy' "$root/pyproject.toml" || grep -qs '^\[mypy' "$root/setup.cfg"; }; then
  [ -f "$cfg/mypy.ini" ] && mypy_cfg=(--config-file "$cfg/mypy.ini")
fi

case "$file" in
  *.py|*.pyi)
    if has ruff; then
      ruff check --fix --exit-zero --quiet "${ruff_cfg[@]}" "$file" >/dev/null 2>&1
      ruff format --quiet "${ruff_cfg[@]}" "$file" >/dev/null 2>&1
      remaining=$(cd "$root" && ruff check --output-format concise --exit-zero --ignore "$hook_ignore" "${ruff_cfg[@]}" "$relfile" 2>/dev/null \
                  | grep -vE '^(Found |All checks passed|No fixes available|\[\*\])' | head -40)
      [ -n "$remaining" ] && add "ruff (after auto-fix + format):"$'\n'"$remaining"
    fi
    if [ "${REVIEW_HOOK_MYPY:-1}" = "1" ] && has mypy; then
      m=$(cd "$root" && timeout 45 mypy --cache-dir "$root/.review/.mypy_cache" --no-error-summary --follow-imports=silent \
            "${mypy_cfg[@]}" "$relfile" 2>/dev/null | grep -E ': (error|warning):' | head -30)
      [ -n "$m" ] && add "mypy:"$'\n'"$m"
    fi
    ;;
  *.sh|*.bash)
    if has shellcheck; then
      s=$(cd "$root" && shellcheck -f gcc -x -S warning "$relfile" 2>/dev/null | head -40)
      [ -n "$s" ] && add "shellcheck:"$'\n'"$s"
    fi
    ;;
  */Dockerfile|*/Dockerfile.*|*.dockerfile)
    if has hadolint; then
      hcfg=()
      { [ -f "$root/.hadolint.yaml" ] || [ -f "$root/.hadolint.yml" ]; } || { [ -f "$cfg/hadolint.yaml" ] && hcfg=(--config "$cfg/hadolint.yaml"); }
      h=$(cd "$root" && hadolint --no-fail --no-color -t warning -f tty "${hcfg[@]}" "$relfile" 2>/dev/null | head -40)
      [ -n "$h" ] && add "hadolint:"$'\n'"$h"
    fi
    ;;
  *.js|*.jsx|*.ts|*.tsx|*.mjs|*.cjs)
    if [ -x "$root/node_modules/.bin/eslint" ]; then
      e=$(cd "$root" && ./node_modules/.bin/eslint --fix -f unix "$relfile" 2>/dev/null | grep -vE '^[0-9]+ problems?' | head -40)
      [ -n "$e" ] && add "eslint (after --fix):"$'\n'"$e"
    fi
    ;;
  *)
    # shebang'd shell script without extension
    if head -c 80 "$file" 2>/dev/null | grep -qE '^#!.*(bash|/sh)' && has shellcheck; then
      s=$(cd "$root" && shellcheck -f gcc -x -S warning "$relfile" 2>/dev/null | head -40)
      [ -n "$s" ] && add "shellcheck:"$'\n'"$s"
    fi
    ;;
esac

if [ -n "$out" ]; then
  {
    echo "Lint hook found issues in $relfile (auto-fixable ones were already applied — re-read the file before editing it again):"
    printf '%s' "$out"
    echo "Fix these, or add a targeted # noqa / # type: ignore[code] with a reason if it's a false positive."
  } >&2
  exit 2
fi
exit 0
