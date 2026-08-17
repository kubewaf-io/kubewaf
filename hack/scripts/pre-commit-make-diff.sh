#!/usr/bin/env bash
# Run a make target and fail if tracked paths drift (mirrors CI git-diff gates).
# Regenerated files are staged so a re-run / amend can pick them up cleanly.
# Usage: pre-commit-make-diff.sh <make-target> <path> [<path>...]
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <make-target> <path> [path...]" >&2
  exit 2
fi

TARGET="$1"
shift
PATHS=("$@")

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

make "${TARGET}"

# Include untracked generator output (e.g. new CRD files).
if ! git diff --quiet -- "${PATHS[@]}" 2>/dev/null \
  || [[ -n "$(git ls-files --others --exclude-standard -- "${PATHS[@]}")" ]]; then
  # Stage generator output so the next commit attempt includes the fix.
  git add -- "${PATHS[@]}"
  echo "${TARGET} updated files under: ${PATHS[*]}" >&2
  echo "Staged the regenerated output. Re-run: git commit" >&2
  git --no-pager diff --cached --stat -- "${PATHS[@]}" || true
  exit 1
fi
