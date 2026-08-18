#!/usr/bin/env bash
# Refuse to commit tenant identifiers, credentials, or local paths.
#
# This repository is public. Until recently it was published by exporting a
# snapshot from a private repo, and that export step was where a human swept
# for identifiers before anything became permanent. Development now happens
# here directly, so that sweep has to run automatically instead -- every
# commit is immediately publishable and cannot be un-published.
#
# Each pattern below is here because it was actually found in this codebase
# during the pre-publication audit, not because it seemed plausible:
#
#   ghslab / .ghslab.local  the internal AD domain, found in test fixtures
#   GHS_<Name>              company-prefixed deployed rule names, found in
#                           test fixtures and in a source comment
#   case ids                real SOAR case numbers, found in screenshots
#   detection ids           real Chronicle detection ids, found in tests
#   /Users/<name>           absolute paths carrying a personal name, found in
#                           a run artefact pasted into a docstring
#   AgenticSOC              an internal programme name, found in a module
#                           docstring naming a Windows dev path
#
# Usage:
#   scripts/check_no_tenant_data.sh            # staged changes (pre-commit)
#   scripts/check_no_tenant_data.sh --all      # every tracked file
#
# Install as a hook:
#   ln -sf ../../scripts/check_no_tenant_data.sh .git/hooks/pre-commit
#
# A false positive is a bug in this script, not a reason to use --no-verify.
# If a pattern is wrong, fix the pattern and say why in the commit.

set -uo pipefail

PATTERNS=(
  'ghslab'
  'GHSLAB'
  'GHS_[A-Za-z][A-Za-z_]{3,}'          # company-prefixed tenant rule names
  '\.ghslab\.local'
  'de_[0-9a-f]{8}-[0-9a-f]{4}-'        # Chronicle detection ids (see PLACEHOLDERS)
  '\bcases/39[0-9]{4}\b'               # real SOAR case ids
  '/Users/[a-z]'                       # absolute path with a local username
  'AgenticSOC'
  'sk-or-v1-[A-Za-z0-9]'               # OpenRouter key
  'AIza[0-9A-Za-z_-]{35}'              # Google API key
  '-----BEGIN [A-Z ]*PRIVATE KEY'
)

# Values that match a pattern above but are deliberately fake. Test fixtures need
# ids of the right SHAPE to exercise parsing, so the shape alone cannot be the
# signal -- these are the agreed placeholders, and anything outside this list is
# treated as real. Add to it only when introducing a new obviously-synthetic
# constant, never to silence a value that came off a live tenant.
PLACEHOLDERS='de_00000000-|de_1111aaaa-'

if [ "${1:-}" = "--all" ]; then
  # Tracked files plus untracked-but-not-ignored ones. A file staged for the
  # next commit is as publishable as one already in it, and `git ls-files`
  # alone would walk straight past a newly written file that has not been
  # committed yet.
  FILES=$(git ls-files --cached --others --exclude-standard)
  SCOPE="every tracked and untracked file"
  # Unfilled placeholders are only a problem at publish time, so they are
  # checked in the whole-tree sweep rather than on every commit. SECURITY.md
  # promising a contact that does not exist means vulnerability reports go
  # nowhere -- or into a public issue, which is the outcome it exists to avoid.
  PATTERNS+=('SECURITY_CONTACT_EMAIL')
else
  FILES=$(git diff --cached --name-only --diff-filter=ACM)
  SCOPE="staged changes"
fi

[ -z "$FILES" ] && exit 0

FAILED=0
while IFS= read -r file; do
  [ -f "$file" ] || continue
  # this script necessarily contains the patterns it searches for
  [ "$file" = "scripts/check_no_tenant_data.sh" ] && continue
  for pattern in "${PATTERNS[@]}"; do
    if match=$(grep -nEI "$pattern" "$file" 2>/dev/null | grep -vE "$PLACEHOLDERS" | head -3); then
      [ -z "$match" ] && continue
      if [ "$FAILED" -eq 0 ]; then
        echo "BLOCKED: tenant data or credentials found in $SCOPE." >&2
        echo "This repository is public; a commit here cannot be un-published." >&2
        echo >&2
        FAILED=1
      fi
      echo "  $file  (/$pattern/)" >&2
      echo "$match" | sed 's/^/    /' >&2
    fi
  done
done <<< "$FILES"

if [ "$FAILED" -eq 1 ]; then
  echo >&2
  echo "Replace the value with a placeholder -- corp.local, CORP, svc_backup," >&2
  echo "LAB_<RuleName>, 00000000-0000-0000-0000-000000000000 -- and commit again." >&2
  exit 1
fi

exit 0
