#!/usr/bin/env bash
# OPTIONAL Stop hook: when Claude finishes a turn, run the full review on the files
# changed in this working tree; if anything critical/high is outstanding, block the
# stop once and hand the summary back so Claude addresses it before declaring done.
#
# Wire it up by using settings.with-stop-hook.json instead of settings.json.
# The stop_hook_active guard prevents an infinite loop: if we already blocked once
# this turn, we let Claude stop even if findings remain (it will have reported them).
set -u
input=$(cat)
if [ "$(printf '%s' "$input" | jq -r '.stop_hook_active // false')" = "true" ]; then
  exit 0
fi
root="${CLAUDE_PROJECT_DIR:-$(pwd)}"
script="$root/.claude/skills/code-review/scripts/review.py"
[ -f "$script" ] || script="$HOME/.claude/skills/code-review/scripts/review.py"
[ -f "$script" ] || exit 0
# nothing changed → nothing to review
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [ -z "$(git -C "$root" status --porcelain)" ]; then exit 0; fi
fi
summary=$(cd "$root" && timeout 240 python3 "$script" --changed --fix --skip semgrep,pip-audit,sonar --json 2>/dev/null)
[ -z "$summary" ] && exit 0
crit=$(printf '%s' "$summary" | jq -r '.critical // 0')
high=$(printf '%s' "$summary" | jq -r '.high // 0')
if [ "$((crit + high))" -gt 0 ]; then
  md=$(printf '%s' "$summary" | jq -r '.report_md')
  {
    echo "Code review on changed files found $crit critical / $high high findings. Read $md, fix what's real, and note any false positives."
    awk '/^### (CRITICAL|HIGH)/{p=1;next} /^### /{p=0} p && /^- \*\*/' "$md" | head -25
  } >&2
  exit 2
fi
exit 0
