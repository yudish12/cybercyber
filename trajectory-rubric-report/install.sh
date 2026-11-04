#!/usr/bin/env bash
# Installs the trajectory-rubric-report skill and the /rubrics slash command
# into ~/.claude/ (personal scope). Re-running overwrites prior copies.
# Installs alongside sandbox_skills, blackbox-pentest-qa and the
# tb-trial-runner skills without clobbering them.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$here/skills/trajectory-rubric-report" ] || [ ! -f "$here/commands/rubrics.md" ]; then
  echo "error: expected 'skills/trajectory-rubric-report/' and 'commands/rubrics.md' next to install.sh." >&2
  echo "       Unzip the archive and run install.sh from inside the extracted folder." >&2
  exit 1
fi

mkdir -p "$HOME/.claude/skills" "$HOME/.claude/commands"

rm -rf "$HOME/.claude/skills/trajectory-rubric-report"
cp -R "$here/skills/trajectory-rubric-report" "$HOME/.claude/skills/trajectory-rubric-report"
cp "$here/commands/rubrics.md" "$HOME/.claude/commands/rubrics.md"

# Drop macOS Finder cruft and python bytecode that sneak into zips.
find "$HOME/.claude/skills/trajectory-rubric-report" \( -name '.DS_Store' -o -name '__pycache__' \) \
  -exec rm -rf {} + 2>/dev/null || true

echo "Installed:"
echo "  skill   -> ~/.claude/skills/trajectory-rubric-report/"
echo "  command -> ~/.claude/commands/rubrics.md (/rubrics)"
echo "Restart Claude Code so it re-scans ~/.claude/commands/."
