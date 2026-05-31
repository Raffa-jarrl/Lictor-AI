#!/usr/bin/env bash
#
# Lictor Security Suite — Cursor rule installer (convenience copier).
#
# Cursor reads project rules from `.cursor/rules/*.mdc`. An .mdc file is the
# same shape as a Claude SKILL.md: a front-matter header followed by the
# instruction body. This script copies each lictor-* skill body into
# <project>/.cursor/rules/lictor-<name>.mdc, generating an mdc front-matter
# from the skill's own name/description. For lictor-security-check it also
# copies the checks/ and reports/ files so the skill's relative links resolve.
#
# This is NOT an official Cursor integration — it produces exactly the files
# you'd create by hand from the mapping in README.md ("Other AI clients").
#
# Usage:
#   bash install-cursor.sh [project-dir]   # defaults to current directory
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT_DIR="${1:-$PWD}"
if [ ! -d "$PROJECT_DIR" ]; then
  echo "error: project directory does not exist: $PROJECT_DIR" >&2
  exit 1
fi

RULES_DIR="$PROJECT_DIR/.cursor/rules"
mkdir -p "$RULES_DIR"

# Pull a single front-matter value (name:/description:) out of a SKILL.md.
# Reads only the YAML block between the first two `---` fences.
fm_value() {
  # $1 = file, $2 = key
  awk -v key="$2" '
    NR==1 && $0=="---" { infm=1; next }
    infm && $0=="---"  { exit }
    infm {
      # match "key: value" at start of line
      if (index($0, key ":") == 1) {
        sub("^" key ":[ \t]*", "")
        print
        exit
      }
    }
  ' "$1"
}

# Print a SKILL.md body with the leading YAML front-matter block stripped.
strip_frontmatter() {
  awk '
    NR==1 && $0=="---" { infm=1; next }
    infm && $0=="---"  { infm=0; started=1; next }
    !infm { print }
  ' "$1"
}

installed=0
for src in "$SCRIPT_DIR"/lictor-*/; do
  [ -d "$src" ] || continue
  [ -f "$src/SKILL.md" ] || continue

  name="$(basename "$src")"
  skill="$src/SKILL.md"

  desc="$(fm_value "$skill" description)"
  [ -n "$desc" ] || desc="Lictor skill: $name"

  out="$RULES_DIR/$name.mdc"

  # mdc front-matter: description is shown to the model; globs empty +
  # alwaysApply false means "apply when the description is relevant" (an
  # agent-requested rule), which mirrors how the Claude skill triggers.
  {
    printf -- '---\n'
    printf -- 'description: %s\n' "$desc"
    printf -- 'globs:\n'
    printf -- 'alwaysApply: false\n'
    printf -- '---\n\n'
    strip_frontmatter "$skill"
  } > "$out"

  echo "  wrote  .cursor/rules/$name.mdc"
  installed=$((installed + 1))

  # lictor-security-check links to ./checks/*.md and ./reports/*.md — copy
  # those alongside so the relative references still resolve under Cursor.
  for sub in checks reports; do
    if [ -d "$src/$sub" ]; then
      mkdir -p "$RULES_DIR/$sub"
      cp -R "$src/$sub/." "$RULES_DIR/$sub/"
      echo "  copied .cursor/rules/$sub/ (referenced by $name)"
    fi
  done
done

if [ "$installed" -eq 0 ]; then
  echo "error: no lictor-* skills found next to install-cursor.sh ($SCRIPT_DIR)" >&2
  exit 1
fi

echo ""
echo "Done. Wrote $installed Lictor rule(s) into:"
echo "  $RULES_DIR"
echo ""
echo "Open this project in Cursor — the rules load automatically. Ask Cursor"
echo "to \"run a Lictor security check\" and it will follow the rule body."
