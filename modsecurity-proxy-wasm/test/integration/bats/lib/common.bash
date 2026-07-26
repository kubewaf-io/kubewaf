# Shared helpers for modsecurity-proxy-wasm Envoy integration tests (bats).
set -euo pipefail

if [[ -z "${SCRIPT_DIR:-}" ]]; then
  if [[ -n "${BATS_TEST_FILENAME:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")" && pwd)"
  else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  fi
fi
if [[ -z "${ROOT_DIR:-}" ]]; then
  ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
fi

WASM="${WASM:-$ROOT_DIR/dist/modsecurity-proxy-wasm.wasm}"
ENVOY_YAML="${ENVOY_YAML:-$ROOT_DIR/test/fixtures/envoy.yaml}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.38-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-modsecurity-proxy-wasm-test-envoy}"
HOST_PORT="${HOST_PORT:-18080}"
ADMIN_PORT="${ADMIN_PORT:-19901}"
REQUIRED_RUNTIME="${REQUIRED_RUNTIME:-envoy.wasm.runtime.v8}"
KEEP_RUNNING="${KEEP_RUNNING:-0}"

envoy_detect_ctr() {
  if command -v docker >/dev/null 2>&1; then
    CTR=docker
  elif command -v podman >/dev/null 2>&1; then
    CTR=podman
  else
    echo "ERROR: need docker or podman" >&2
    return 1
  fi
  export CTR
}

envoy_preflight() {
  [[ -f "$WASM" ]] || {
    echo "ERROR: $WASM not found. Build first (make image)." >&2
    return 1
  }
  grep -q "runtime: \"${REQUIRED_RUNTIME}\"" "$ENVOY_YAML" || {
    echo "FAIL: $ENVOY_YAML must set vm_config.runtime to \"${REQUIRED_RUNTIME}\"" >&2
    return 1
  }
  bash "$SCRIPT_DIR/../verify-getentropy-stub.sh"
}

envoy_cleanup() {
  if [[ "$KEEP_RUNNING" == "1" ]]; then
    return 0
  fi
  $CTR rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

envoy_print_keep_running_info() {
  echo ""
  echo "==> Envoy is still running (container: ${CONTAINER_NAME})"
  echo "    HTTP:  http://127.0.0.1:${HOST_PORT}/"
  echo "    Admin: http://127.0.0.1:${ADMIN_PORT}/stats"
  echo ""
  echo "    Stop:  $CTR rm -f ${CONTAINER_NAME}"
  echo ""
}

envoy_fail() {
  local msg="${1:?}"
  local log_lines="${2:-40}"
  echo "$msg" >&2
  $CTR logs "$CONTAINER_NAME" 2>&1 | tail -n "$log_lines" >&2 || true
  if [[ "$KEEP_RUNNING" == "1" ]]; then
    envoy_print_keep_running_info
  else
    envoy_cleanup
  fi
  return 1
}

envoy_start() {
  envoy_detect_ctr
  envoy_preflight
  $CTR rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  echo "==> Starting Envoy ($ENVOY_IMAGE)"
  $CTR run -d --rm --name "$CONTAINER_NAME" \
    -v "$WASM:/etc/modsecurity-proxy-wasm.wasm:ro" \
    -v "$ENVOY_YAML:/etc/envoy.yaml:ro" \
    -p "${HOST_PORT}:8080" \
    -p "${ADMIN_PORT}:9901" \
    "$ENVOY_IMAGE" \
    envoy -c /etc/envoy.yaml --log-level warn
  envoy_wait_ready
  envoy_wait_crs_loaded
  envoy_assert_v8_runtime
}

envoy_wait_ready() {
  local i
  for i in $(seq 1 120); do
    if curl -s --max-time 1 --resolve "www.example.com:${HOST_PORT}:127.0.0.1" \
        "http://www.example.com:${HOST_PORT}/" >/dev/null; then
      echo "==> Envoy ready on :${HOST_PORT}"
      return 0
    fi
    sleep 0.5
  done
  envoy_fail "FAIL: Envoy did not become ready on :${HOST_PORT}" 50
}

envoy_wait_crs_loaded() {
  local _
  for _ in $(seq 1 60); do
    local logs
    logs=$($CTR logs "$CONTAINER_NAME" 2>&1 || true)
    if grep -F 'Minimal fallback rules loaded' <<<"$logs" >/dev/null 2>&1; then
      envoy_fail "FAIL: plugin fell back to minimal rules" 80
    fi
    if grep -F 'CRS catalog loaded' <<<"$logs" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  envoy_fail "FAIL: expected CRS catalog load message in wasm logs" 80
}

envoy_assert_v8_runtime() {
  local v8_active
  v8_active=$(curl -s "http://127.0.0.1:${ADMIN_PORT}/stats" \
    | grep "^wasm.${REQUIRED_RUNTIME}.active:" | awk '{print $2}' | head -1)
  [[ -n "${v8_active:-}" && "${v8_active}" -ge 1 ]] || \
    envoy_fail "FAIL: expected wasm.${REQUIRED_RUNTIME}.active >= 1 (got: ${v8_active:-none})" 50
  echo "    wasm.${REQUIRED_RUNTIME}.active=${v8_active}"
}

envoy_http_status() {
  curl -s -o /dev/null -w "%{http_code}" \
    --resolve "www.example.com:${HOST_PORT}:127.0.0.1" \
    -H "User-Agent: Mozilla/5.0 (modsecurity-proxy-wasm-test)" \
    -H "Accept: text/html" \
    "$@"
}

envoy_base_url() {
  echo "http://www.example.com:${HOST_PORT}"
}

envoy_admin_stats() {
  curl -s "http://127.0.0.1:${ADMIN_PORT}/stats"
}

envoy_admin_prometheus() {
  curl -s "http://127.0.0.1:${ADMIN_PORT}/stats/prometheus"
}