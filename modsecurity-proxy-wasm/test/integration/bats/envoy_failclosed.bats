#!/usr/bin/env bats

load lib/common

setup_file() {
  envoy_detect_ctr
  envoy_preflight
  # Avoid image-pull latency inside the fail-closed test (docker run -d blocks on pull).
  $CTR pull "$ENVOY_IMAGE" >/dev/null 2>&1 || true
}

@test "invalid WAF config fails closed without fallback" {
  local bad_name="${BAD_CONTAINER_NAME:-modsecurity-proxy-wasm-test-bad-config}"
  local bad_yaml="$ROOT_DIR/test/fixtures/envoy-bad-config.yaml"
  local wait_timeout="${FAILCLOSED_WAIT_TIMEOUT:-30}"

  $CTR rm -f "$bad_name" >/dev/null 2>&1 || true
  $CTR run -d --name "$bad_name" \
    -v "$WASM:/etc/modsecurity-proxy-wasm.wasm:ro" \
    -v "$bad_yaml:/etc/envoy.yaml:ro" \
    -p "18081:8080" \
    "$ENVOY_IMAGE" \
    envoy -c /etc/envoy.yaml --log-level warn >/dev/null

  # Wait for Envoy to exit after wasm onConfigure failure (fixed sleep races on CI).
  bad_status=$(timeout "$wait_timeout" $CTR wait "$bad_name" 2>/dev/null || echo "timeout")
  bad_logs=$($CTR logs "$bad_name" 2>&1 || true)
  $CTR rm -f "$bad_name" >/dev/null 2>&1 || true

  [ "$bad_status" != "timeout" ]
  [ "$bad_status" = "1" ]
  grep -F 'fail-closed' <<<"$bad_logs" >/dev/null
  ! grep -F 'Minimal fallback rules loaded' <<<"$bad_logs" >/dev/null
  ! grep -F 'CRS catalog loaded' <<<"$bad_logs" >/dev/null
}