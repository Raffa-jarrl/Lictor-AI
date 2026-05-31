#!/usr/bin/env bash
#
# Lictor Security Suite — one-command installer for Claude Code skills.
#
# Copies the four lictor-* skills into your Claude Code skills directory
# (default: ~/.claude/skills). Idempotent: re-running replaces any existing
# lictor-* install with the current version. Nothing outside the lictor-*
# targets is ever touched.
#
# Usage:
#   bash install.sh                 # install to ~/.claude/skills
#   bash install.sh --dest <dir>    # install to a custom directory
#
set -euo pipefail

# Resolve this script's own directory so the installer works no matter where
# the repo was cloned or from where it's invoked.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEST="${HOME}/.claude/skills"

# --- parse args ------------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dest)
      if [ "$#" -lt 2 ]; then
        echo "error: --dest requires a directory argument" >&2
        exit 1
      fi
      DEST="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: bash install.sh [--dest <dir>]"
      echo "  --dest <dir>   Install location (default: ~/.claude/skills)"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      echo "Usage: bash install.sh [--dest <dir>]" >&2
      exit 1
      ;;
  esac
done

# --- install ---------------------------------------------------------------
mkdir -p "$DEST"

installed=0
for src in "$SCRIPT_DIR"/lictor-*/; do
  # Guard against the glob not matching anything.
  [ -d "$src" ] || continue

  name="$(basename "$src")"
  target="$DEST/$name"

  # Replace any existing copy so the install is idempotent and always current.
  # Only ever removes the specific lictor-* target — never anything else.
  rm -rf "$target"
  cp -R "$src" "$target"

  echo "  installed  $name  ->  $target"
  installed=$((installed + 1))
done

if [ "$installed" -eq 0 ]; then
  echo "error: no lictor-* skills found next to install.sh ($SCRIPT_DIR)" >&2
  exit 1
fi

echo ""
echo "Done. Installed $installed Lictor skill(s) into:"
echo "  $DEST"
echo ""
echo "Now run  /lictor-security-check  in any project (from its directory)"
echo "inside Claude Code. The skill is loaded automatically — no restart needed."
