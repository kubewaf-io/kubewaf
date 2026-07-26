#!/usr/bin/env bash
# Assert modsecurity-proxy-wasm.wasm is loaded under envoy.wasm.runtime.v8 (not wazero).
set -euo pipefail

ADMIN_PORT="${ADMIN_PORT:-19901}"
REQUIRED_RUNTIME="${REQUIRED_RUNTIME:-envoy.wasm.runtime.v8}"
WASM="${WASM:-$(cd "$(dirname "$0")/../.." && pwd)/dist/modsecurity-proxy-wasm.wasm}"

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -f "$WASM" ]] || fail "missing $WASM"

echo "==> Checking proxy-wasm exports (V8 / Emscripten ABI)"
wasm_dump=$(wasm-objdump -x "$WASM" 2>&1)
[[ "$wasm_dump" == *"<proxy_on_configure>"* ]] || fail "missing proxy_on_configure export"
[[ "$wasm_dump" == *"<proxy_on_request_headers>"* ]] || fail "missing proxy_on_request_headers export"
[[ "$wasm_dump" != *"getaddrinfo"* ]] || fail "module imports getaddrinfo (breaks envoy.wasm.runtime.v8 load)"
echo "    proxy-wasm exports OK"

if curl -sf --max-time 2 "http://127.0.0.1:${ADMIN_PORT}/ready" >/dev/null 2>&1; then
  echo "==> Checking live Envoy admin stats on :${ADMIN_PORT}"
  active=$(curl -sf "http://127.0.0.1:${ADMIN_PORT}/stats" | grep "^wasm.${REQUIRED_RUNTIME}.active:" | awk '{print $2}' | head -1)
  [[ -n "${active:-}" && "${active}" -ge 1 ]] || fail "wasm.${REQUIRED_RUNTIME}.active < 1 (is Envoy running with test/fixtures/envoy.yaml?)"
  echo "    wasm.${REQUIRED_RUNTIME}.active=${active}"
  if curl -sf "http://127.0.0.1:${ADMIN_PORT}/stats" | grep -q '^wasm.envoy.wasm.runtime.wazero.active:'; then
    wz=$(curl -sf "http://127.0.0.1:${ADMIN_PORT}/stats" | grep '^wasm.envoy.wasm.runtime.wazero.active:' | awk '{print $2}')
    [[ -z "${wz:-}" || "${wz}" -eq 0 ]] || fail "wazero runtime active (${wz}); required runtime is v8"
  fi
  echo "==> V8 runtime confirmed (live Envoy)"
else
  echo "==> Envoy admin not reachable; binary checks passed (start Envoy to verify live v8 stats)"
fi

echo "==> OK: module is built for and compatible with ${REQUIRED_RUNTIME}"