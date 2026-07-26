#!/usr/bin/env bats

load lib/common

setup_file() {
  envoy_start
}

teardown_file() {
  if [[ "${KEEP_RUNNING:-0}" != "1" ]]; then
    envoy_cleanup
  else
    envoy_print_keep_running_info
  fi
}

@test "benign GET returns 200" {
  run envoy_http_status "$(envoy_base_url)/"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
}

@test "XSS query string is blocked with 403" {
  run envoy_http_status "$(envoy_base_url)/?q=%3Cscript%3Ealert(1)%3C/script%3E"
  [ "$status" -eq 0 ]
  [ "$output" = "403" ]
}

@test "SQLi-like query is blocked with 403" {
  run envoy_http_status "$(envoy_base_url)/?id=1+UNION+SELECT+null"
  [ "$status" -eq 0 ]
  [ "$output" = "403" ]
}

@test "benign POST JSON body returns 200" {
  run envoy_http_status -X POST \
    -H "Content-Type: application/json" \
    -d '{"name":"alice"}' \
    "$(envoy_base_url)/api/user"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
}

@test "POST body XSS is blocked with 403" {
  run envoy_http_status -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'comment=%3Cscript%3Ealert(1)%3C/script%3E' \
    "$(envoy_base_url)/api/comment"
  [ "$status" -eq 0 ]
  [ "$output" = "403" ]
}

@test "wasm transaction metrics are exported" {
  stats=$(envoy_admin_prometheus)
  grep -q 'modsecurity_proxy_wasm_tx_total' <<<"$stats"
  tx_total=$(grep -E '^modsecurity_proxy_wasm_tx_total' <<<"$stats" | awk '{print $2}' | head -1)
  [ -n "${tx_total:-}" ]
  [ "${tx_total}" -ge 3 ]
}

@test "wasm rule match metrics are exported" {
  stats=$(envoy_admin_prometheus)
  rule_matches=$(grep -E '^modsecurity_proxy_wasm_rule_matches(\{\}|[^ ]*)\s' <<<"$stats" | awk '{print $2}' | head -1)
  [ -n "${rule_matches:-}" ]
  [ "${rule_matches}" -ge 1 ]
  rule_match_series=$(envoy_admin_stats | grep -c 'modsecurity_proxy_wasm.rule.matches_' || true)
  [ "${rule_match_series:-0}" -ge 1 ]
}

@test "live v8 runtime is confirmed" {
  ADMIN_PORT="${ADMIN_PORT}" WASM="${WASM}" REQUIRED_RUNTIME="${REQUIRED_RUNTIME}" \
    bash "$SCRIPT_DIR/../verify-v8-runtime.sh"
}