#!/usr/bin/env bash
# Clone or update the SigmaHQ rule corpus into vendor/sigma.
#
# POSIX twin of refresh_sigma.ps1 -- same job, needed because the container image
# builds the index on Linux. Keep the two in step.
#
# A shallow clone is enough: we only ever read the working tree, never history.
# Set SIGMA_REF to a commit SHA or branch to pin the corpus; a moving master means
# two images built days apart index different rules.
#
# After this, rebuild the index:  python scripts/build_index.py
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${SIGMA_REPO_DIR:-$root/vendor/sigma}"
ref="${SIGMA_REF:-master}"

if [ -d "$target/.git" ]; then
    echo "Updating existing corpus at $target (ref: $ref) ..."
    git -C "$target" fetch --depth 1 origin "$ref"
    git -C "$target" reset --hard FETCH_HEAD
else
    echo "Cloning SigmaHQ/sigma into $target (ref: $ref) ..."
    mkdir -p "$(dirname "$target")"
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$target"
    # A branch name is already checked out by the clone; a SHA is not.
    if ! git -C "$target" symbolic-ref -q HEAD >/dev/null \
       || [ "$(git -C "$target" rev-parse --abbrev-ref HEAD)" != "$ref" ]; then
        git -C "$target" fetch --depth 1 origin "$ref"
        git -C "$target" checkout --detach FETCH_HEAD
    fi
fi

echo ""
echo "Corpus ready: $(find "$target" -name '*.yml' -type f | wc -l | tr -d ' ') YAML files."
echo "Pinned at:    $(git -C "$target" rev-parse HEAD)"
echo "Next: python scripts/build_index.py"
