#!/usr/bin/env bash
set -euo pipefail

# k6 performance harness for modsecurity-proxy-wasm.
#
# Usage:
#   ./test/perf/run-k6.sh
#   PERF_PROFILE=modsecurity-proxy-wasm-full PERF_SCENARIO=benign-get ./test/perf/run-k6.sh
#   ./test/perf/run-k6.sh --compare
#   ./test/perf/run-k6.sh --ci
#   ./test/perf/run-k6.sh --keep-running
#
# Profiles:
#   baseline | wasm-minimal | modsecurity-proxy-wasm-full | coraza-minimal | coraza-full
# Scenarios:
#   benign-get | benign-post-1k | block-xss | mixed

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.k6.yml"

PERF_PROFILE="${PERF_PROFILE:-modsecurity-proxy-wasm-full}"
PERF_SCENARIO="${PERF_SCENARIO:-benign-get}"
PERF_VUS="${PERF_VUS:-32}"
PERF_DURATION="${PERF_DURATION:-60s}"
PERF_WARMUP="${PERF_WARMUP:-15s}"
PERF_P99_MS="${PERF_P99_MS:-200}"
PERF_FAIL_RATE="${PERF_FAIL_RATE:-0.01}"
PERF_HOST_PORT="${PERF_HOST_PORT:-18080}"
PERF_ADMIN_PORT="${PERF_ADMIN_PORT:-19901}"
PERF_ENVOY_CONTAINER="${PERF_ENVOY_CONTAINER:-modsecurity-proxy-wasm-perf-envoy}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.38-latest}"
K6_IMAGE="${K6_IMAGE:-grafana/k6:0.57.0}"
KEEP_RUNNING="${KEEP_RUNNING:-0}"
PERF_CI="${PERF_CI:-0}"
RUN_COMPARE="${RUN_COMPARE:-0}"

WASM="${PERF_WASM:-$ROOT_DIR/dist/modsecurity-proxy-wasm.wasm}"
CORAZA_WASM="$SCRIPT_DIR/.coraza/main.wasm"
RESULTS_DIR="$SCRIPT_DIR/results"
STAMP="${PERF_RUN_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
PERF_RELEASE_TAG="${PERF_RELEASE_TAG:-}"
MEMORY_SAMPLER_PID=""

VALID_PROFILES=(baseline wasm-minimal modsecurity-proxy-wasm-full coraza-minimal coraza-full)
VALID_SCENARIOS=(benign-get benign-post-1k block-xss mixed)

usage() {
  sed -n '3,16p' "$0" | sed 's/^# \{0,1\}//'
  echo ""
  echo "Environment:"
  echo "  PERF_PROFILE   ${VALID_PROFILES[*]} (default: modsecurity-proxy-wasm-full)"
  echo "  PERF_SCENARIO  ${VALID_SCENARIOS[*]} (default: benign-get)"
  echo "  PERF_VUS       default: 32"
  echo "  PERF_DURATION  default: 60s"
  echo "  PERF_WARMUP    default: 15s"
  echo "  PERF_P99_MS    default: 200"
  echo ""
  echo "Flags:"
  echo "  --compare      Run modsecurity-proxy-wasm profile then matching coraza profile"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    -k|--keep-running) KEEP_RUNNING=1 ;;
    --compare) RUN_COMPARE=1 ;;
    --ci) PERF_CI=1 ;;
    --all-smoke)
      PERF_CI=1
      RUN_ALL_SMOKE=1
      ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

# Shared-runner CI: shorter runs and relaxed p99 (noisy 2-vCPU GitHub Actions).
if [[ "$PERF_CI" == "1" ]]; then
  PERF_DURATION="30s"
  PERF_WARMUP="10s"
  PERF_VUS="16"
  PERF_P99_MS="500"
fi

if command -v docker >/dev/null 2>&1; then
  CTR="docker"
  COMPOSE=(docker compose)
elif command -v podman >/dev/null 2>&1; then
  CTR="podman"
  if podman compose version >/dev/null 2>&1; then
    COMPOSE=(podman compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    echo "ERROR: need podman compose or docker-compose" >&2
    exit 1
  fi
else
  echo "ERROR: need docker or podman" >&2
  exit 1
fi

profile_valid=0
for p in "${VALID_PROFILES[@]}"; do
  [[ "$p" == "$PERF_PROFILE" ]] && profile_valid=1
done
[[ "$profile_valid" -eq 1 ]] || {
  echo "ERROR: invalid PERF_PROFILE=$PERF_PROFILE" >&2
  exit 2
}

scenario_valid=0
for s in "${VALID_SCENARIOS[@]}"; do
  [[ "$s" == "$PERF_SCENARIO" ]] && scenario_valid=1
done
[[ "$scenario_valid" -eq 1 ]] || {
  echo "ERROR: invalid PERF_SCENARIO=$PERF_SCENARIO" >&2
  exit 2
}

NOOP_WASM="$SCRIPT_DIR/.noop.wasm"
touch "$NOOP_WASM"

is_coraza_profile() {
  [[ "$1" == coraza-* ]]
}

coraza_pair_for() {
  case "$1" in
    wasm-minimal) echo "coraza-minimal" ;;
    modsecurity-proxy-wasm-full) echo "coraza-full" ;;
    coraza-minimal) echo "wasm-minimal" ;;
    coraza-full) echo "modsecurity-proxy-wasm-full" ;;
    *) echo "" ;;
  esac
}

require_coraza_wasm() {
  "$SCRIPT_DIR/fetch-coraza-wasm.sh" >&2
  [[ -f "$CORAZA_WASM" ]] || {
    echo "ERROR: coraza wasm missing at $CORAZA_WASM" >&2
    exit 1
  }
}

wasm_mounts_for_profile() {
  local profile="$1"
  local msp_wasm_mount coraza_mount
  case "$profile" in
    baseline)
      msp_wasm_mount="$NOOP_WASM"
      coraza_mount="$NOOP_WASM"
      ;;
    coraza-*)
      msp_wasm_mount="$NOOP_WASM"
      coraza_mount="$CORAZA_WASM"
      ;;
    *)
      msp_wasm_mount="$WASM"
      coraza_mount="$NOOP_WASM"
      ;;
  esac
  printf '%s %s\n' "$msp_wasm_mount" "$coraza_mount"
}

cleanup_envoy() {
  if [[ "$KEEP_RUNNING" == "1" ]]; then
    return 0
  fi
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" rm -sf envoy >/dev/null 2>&1 || true
  $CTR rm -f "$PERF_ENVOY_CONTAINER" >/dev/null 2>&1 || true
}

trap 'stop_memory_sampler; cleanup_envoy' EXIT

start_memory_sampler() {
  local run_dir="$1"
  [[ -n "$CTR" ]] || return 0
  : > "$run_dir/memory-samples.log"
  (
    while true; do
      $CTR stats --no-stream --format '{{.MemUsage}}' "$PERF_ENVOY_CONTAINER" 2>/dev/null \
        >> "$run_dir/memory-samples.log" || true
      sleep 2
    done
  ) &
  MEMORY_SAMPLER_PID=$!
}

stop_memory_sampler() {
  if [[ -n "${MEMORY_SAMPLER_PID:-}" ]]; then
    kill "$MEMORY_SAMPLER_PID" 2>/dev/null || true
    wait "$MEMORY_SAMPLER_PID" 2>/dev/null || true
    MEMORY_SAMPLER_PID=""
  fi
}

run_dir_name() {
  local profile="$1"
  local scenario="$2"
  if [[ -n "$PERF_RELEASE_TAG" ]]; then
    local tag_slug="${PERF_RELEASE_TAG//./-}"
    echo "run-${STAMP}-rel-${tag_slug}-${profile}-${scenario}"
  else
    echo "run-${STAMP}-${profile}-${scenario}"
  fi
}

wait_for_envoy() {
  local i
  for i in $(seq 1 120); do
    if curl -sf "http://127.0.0.1:${PERF_ADMIN_PORT}/stats" >/dev/null 2>&1 \
        && curl -sf --max-time 2 -H "Host: www.example.com" \
          "http://127.0.0.1:${PERF_HOST_PORT}/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: Envoy HTTP/admin not ready on :${PERF_HOST_PORT}/:${PERF_ADMIN_PORT}" >&2
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" logs envoy 2>&1 | tail -30 >&2 || true
  return 1
}

LAST_RUN_DIR=""

run_one() {
  local profile="$1"
  local scenario="$2"
  local run_dir="$RESULTS_DIR/$(run_dir_name "$profile" "$scenario")"
  mkdir -p "$run_dir"
  chmod 777 "$run_dir"
  LAST_RUN_DIR="$run_dir"
  if [[ -n "$PERF_RELEASE_TAG" ]]; then
    echo "$PERF_RELEASE_TAG" >"$run_dir/wasm-release-tag.txt"
    echo "$WASM" >"$run_dir/wasm-path.txt"
  fi

  echo "==> Perf run: profile=${profile} scenario=${scenario}"
  echo "    vus=${PERF_VUS} duration=${PERF_DURATION} warmup=${PERF_WARMUP} p99<${PERF_P99_MS}ms"

  cleanup_envoy

  if is_coraza_profile "$profile"; then
    require_coraza_wasm
  elif [[ "$profile" != "baseline" && ! -f "$WASM" ]]; then
    echo "ERROR: $WASM not found. Build first: make image or make modsecurity-proxy-wasm.wasm" >&2
    exit 1
  fi
  read -r msp_wasm_mount coraza_mount <<<"$(wasm_mounts_for_profile "$profile")"

  MODSECURITY_PROXY_WASM="$msp_wasm_mount" \
  CORAZA_WASM="$coraza_mount" \
  PERF_PROFILE="$profile" \
  PERF_HOST_PORT="$PERF_HOST_PORT" \
  PERF_ADMIN_PORT="$PERF_ADMIN_PORT" \
  PERF_ENVOY_CONTAINER="$PERF_ENVOY_CONTAINER" \
  ENVOY_IMAGE="$ENVOY_IMAGE" \
    "${COMPOSE[@]}" -f "$COMPOSE_FILE" up -d envoy

  wait_for_envoy

  if [[ "$profile" != "baseline" ]]; then
    echo "==> Waiting for WAF / CRS load..."
    sleep 5
  fi

  ADMIN_URL="http://127.0.0.1:${PERF_ADMIN_PORT}" \
    "$SCRIPT_DIR/collect-stats.sh" before "$run_dir"

  local k6_quiet=()
  if [[ "$PERF_CI" == "1" ]]; then
    k6_quiet=(--quiet)
  fi

  if [[ "$PERF_WARMUP" != "0" && "$PERF_WARMUP" != "0s" ]]; then
    echo "==> Warmup (${PERF_WARMUP})..."
    $CTR run --rm --network "container:${PERF_ENVOY_CONTAINER}" \
      -e BASE_URL="http://127.0.0.1:8080" \
      -e HOST_HEADER="www.example.com" \
      -e PERF_PROFILE="$profile" \
      -e PERF_SCENARIO="$scenario" \
      -e PERF_VUS="$PERF_VUS" \
      -e PERF_DURATION="$PERF_WARMUP" \
      -e PERF_P99_MS="$PERF_P99_MS" \
      -e PERF_FAIL_RATE="$PERF_FAIL_RATE" \
      -e PERF_SKIP_FILE_EXPORT=1 \
      -v "$SCRIPT_DIR/k6:/scripts:ro" \
      -v "$run_dir:/results" \
      "$K6_IMAGE" run "${k6_quiet[@]}" "/scripts/scenarios/${scenario}.js" >/dev/null \
      || { echo "ERROR: k6 warmup failed (profile=${profile})" >&2; return 1; }
  fi

  echo "==> k6 measured run..."
  start_memory_sampler "$run_dir"
  $CTR run --rm --network "container:${PERF_ENVOY_CONTAINER}" \
    -e BASE_URL="http://127.0.0.1:8080" \
    -e HOST_HEADER="www.example.com" \
    -e PERF_PROFILE="$profile" \
    -e PERF_SCENARIO="$scenario" \
    -e PERF_VUS="$PERF_VUS" \
    -e PERF_DURATION="$PERF_DURATION" \
    -e PERF_P99_MS="$PERF_P99_MS" \
    -e PERF_FAIL_RATE="$PERF_FAIL_RATE" \
    -v "$SCRIPT_DIR/k6:/scripts:ro" \
    -v "$run_dir:/results" \
    "$K6_IMAGE" run "${k6_quiet[@]}" \
      --summary-export "/results/k6-summary.json" \
      "/scripts/scenarios/${scenario}.js" | tee "$run_dir/k6-stdout.txt"
  stop_memory_sampler

  ADMIN_URL="http://127.0.0.1:${PERF_ADMIN_PORT}" \
    "$SCRIPT_DIR/collect-stats.sh" after "$run_dir"
  chmod +x "$SCRIPT_DIR/finalize-memory.sh"
  PERF_ENVOY_CONTAINER="$PERF_ENVOY_CONTAINER" "$SCRIPT_DIR/finalize-memory.sh" "$run_dir"

  if [[ "$profile" == "modsecurity-proxy-wasm-full" ]]; then
    if ! grep -q 'modsecurity_proxy_wasm_tx_total' "$run_dir/envoy-prometheus-after.txt" 2>/dev/null; then
      echo "WARN: modsecurity_proxy_wasm_tx_total not found in post-run stats" >&2
    fi
  fi
  if is_coraza_profile "$profile"; then
    if ! grep -q 'waf_filter_tx_total' "$run_dir/envoy-prometheus-after.txt" 2>/dev/null; then
      echo "WARN: waf_filter_tx_total not found in post-run stats" >&2
    fi
  fi

  if [[ "$PERF_CI" != "1" ]] \
      && command -v python3 >/dev/null 2>&1 \
      && python3 -c "import matplotlib" 2>/dev/null \
      && [[ -f "$run_dir/k6-summary.json" ]]; then
    python3 "$SCRIPT_DIR/render-charts.py" single "$run_dir/k6-summary.json" \
      -o "$run_dir/k6-report.png" \
      --title "${profile} / ${scenario}" 2>/dev/null \
      && echo "    PNG:   $run_dir/k6-report.png" || true
  fi

  echo "==> Results: $run_dir"
  if [[ -f "$run_dir/k6-report.html" ]]; then
    echo "    HTML:  $run_dir/k6-report.html"
  fi

  if [[ "$KEEP_RUNNING" == "1" ]]; then
    trap - EXIT
    echo ""
    echo "==> Envoy still running (container: ${PERF_ENVOY_CONTAINER})"
    echo "    HTTP:  http://127.0.0.1:${PERF_HOST_PORT}/"
    echo "    Admin: http://127.0.0.1:${PERF_ADMIN_PORT}/stats"
    echo "    Stop:  ${COMPOSE[*]} -f test/perf/docker-compose.k6.yml rm -sf envoy"
  fi
}

compare_pair() {
  local left="$1"
  local right="$2"
  local scenario="$3"
  local left_dir right_dir

  run_one "$left" "$scenario"
  left_dir="$LAST_RUN_DIR"

  run_one "$right" "$scenario"
  right_dir="$LAST_RUN_DIR"

  echo ""
  echo "==> Comparison: ${left} vs ${right} (${scenario})"
  python3 "$SCRIPT_DIR/compare-summaries.py" \
    "$left_dir/k6-summary.json" \
    "$right_dir/k6-summary.json" \
    --left-label "$left" \
    --right-label "$right"
  python3 "$SCRIPT_DIR/render-compare-html.py" \
    "$left_dir/k6-summary.json" \
    "$right_dir/k6-summary.json" \
    -o "$right_dir/k6-compare.html" \
    --left-label "$left" \
    --right-label "$right"
  echo "    HTML:  $right_dir/k6-compare.html"
  if [[ "$PERF_CI" != "1" ]] \
      && command -v python3 >/dev/null 2>&1 \
      && python3 -c "import matplotlib" 2>/dev/null; then
    python3 "$SCRIPT_DIR/render-charts.py" compare \
      "$left_dir/k6-summary.json" "$right_dir/k6-summary.json" \
      -o "$right_dir/k6-compare.png" \
      --left-label "$left" --right-label "$right" \
      --title "${left} vs ${right} (${scenario})" \
      && echo "    PNG:   $right_dir/k6-compare.png" || true
  fi
}

if [[ "${RUN_ALL_SMOKE:-0}" == "1" ]]; then
  run_one baseline benign-get
  compare_pair wasm-minimal coraza-minimal benign-get
  compare_pair modsecurity-proxy-wasm-full coraza-full benign-get
  compare_pair modsecurity-proxy-wasm-full coraza-full benign-post-1k
  exit 0
fi

if [[ "$RUN_COMPARE" == "1" ]]; then
  pair="$(coraza_pair_for "$PERF_PROFILE")"
  if [[ -z "$pair" ]]; then
    echo "ERROR: --compare requires PERF_PROFILE in wasm-minimal, modsecurity-proxy-wasm-full, coraza-minimal, or coraza-full" >&2
    exit 2
  fi
  if [[ "$PERF_PROFILE" == coraza-* ]]; then
    compare_pair "$PERF_PROFILE" "$pair" "$PERF_SCENARIO"
  else
    compare_pair "$PERF_PROFILE" "$pair" "$PERF_SCENARIO"
  fi
  exit 0
fi

run_one "$PERF_PROFILE" "$PERF_SCENARIO"