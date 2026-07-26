#!/usr/bin/env bash
# Guard against re-introducing the deterministic getentropy landmine (docs/SECURITY.md Finding 1).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

fail() { echo "FAIL: $*" >&2; exit 1; }

BAD_PATTERN='i\*31\+17'

for f in "$ROOT_DIR/src/wasm_getentropy.c" "$ROOT_DIR/src/wasm_stubs.c" "$ROOT_DIR/build/docker/Dockerfile"; do
  [[ -f "$f" ]] || fail "missing $f"
  if grep -E "${BAD_PATTERN}" "$f" >/dev/null 2>&1; then
    fail "deterministic getentropy pattern (${BAD_PATTERN}) found in $f"
  fi
done

ENTROPY="$ROOT_DIR/src/wasm_getentropy.c"
grep -q '#include <wasi/api.h>' "$ENTROPY" || fail "$ENTROPY must use Emscripten wasi/api.h"
grep -q '__wasi_clock_time_get' "$ENTROPY" || fail "$ENTROPY must call __wasi_clock_time_get"
grep -q '__WASI_CLOCKID_REALTIME' "$ENTROPY" || fail "$ENTROPY must use __WASI_CLOCKID_* constants"
grep -q '__WASI_ERRNO_SUCCESS' "$ENTROPY" || fail "$ENTROPY must check __WASI_ERRNO_SUCCESS"

WASM="${WASM:-$ROOT_DIR/dist/modsecurity-proxy-wasm.wasm}"
if [[ -f "$WASM" ]] && command -v wasm-objdump >/dev/null 2>&1; then
  dump=$(wasm-objdump -x "$WASM" 2>&1 || true)
  if grep -q 'getentropy' <<<"$dump"; then
    echo "==> modsecurity-proxy-wasm.wasm exports/imports getentropy — clock_time_get import required"
    grep -q 'clock_time_get' <<<"$dump" || fail "getentropy linked but clock_time_get import missing"
  else
    echo "==> getentropy not linked in $WASM (acceptable if DCE'd)"
  fi
fi

echo "==> OK: getentropy uses Emscripten WASI (wasi/api.h)"