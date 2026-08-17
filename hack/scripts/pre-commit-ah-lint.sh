#!/usr/bin/env bash
# Artifact Hub chart lint (mirrors .github/workflows/helm-test.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}/charts"

if command -v ah >/dev/null 2>&1; then
  exec ah lint
fi

if command -v docker >/dev/null 2>&1; then
  exec docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "${ROOT}:/work" \
    -w /work/charts \
    artifacthub/ah \
    ah lint
fi

echo "ah lint requires the Artifact Hub CLI or Docker:" >&2
echo "  go install github.com/artifacthub/ah@latest" >&2
echo "  # or: docker pull artifacthub/ah" >&2
exit 1
