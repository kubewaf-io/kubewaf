#!/usr/bin/env bash
# Thin wrapper around bats integration tests (see test/integration/bats/).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

KEEP_RUNNING="${KEEP_RUNNING:-0}"

usage() {
  cat <<'EOF'
Integration test runner for modsecurity-proxy-wasm (Envoy + envoy.wasm.runtime.v8).

Usage:
  ./test/integration/run-envoy-test.sh              # run tests, then stop Envoy
  ./test/integration/run-envoy-test.sh --keep-running
  KEEP_RUNNING=1 ./test/integration/run-envoy-test.sh

Requires dist/modsecurity-proxy-wasm.wasm. Delegates to bats (make test-bats).
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -k|--keep-running) KEEP_RUNNING=1 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

export KEEP_RUNNING
make -C "$ROOT_DIR" test-bats