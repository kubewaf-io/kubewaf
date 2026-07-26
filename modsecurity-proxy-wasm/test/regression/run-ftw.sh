#!/usr/bin/env bash
set -euo pipefail

# CRS go-ftw regression runner for modsecurity-proxy-wasm (Envoy + albedo + go-ftw).
#
# Usage:
#   ./test/regression/run-ftw.sh
#   FTW_INCLUDE='^941.*' ./test/regression/run-ftw.sh          # subset of tests
#   KEEP_RUNNING=1 ./test/regression/run-ftw.sh                # leave stack up after run
#
# Requires dist/modsecurity-proxy-wasm.wasm built with embedded @ftw-conf (build/rules/ftw-config.conf).
# Rebuild after changing FTW overlays: make modsecurity-proxy-wasm.wasm  (or make image)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
FTW_DIR="$SCRIPT_DIR/ftw"
CRS_CACHE="$FTW_DIR/.crs-cache"
WASM="$ROOT_DIR/dist/modsecurity-proxy-wasm.wasm"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-modsecurity-proxy-wasm-ftw}"
FTW_HOST_PORT="${FTW_HOST_PORT:-18082}"
KEEP_RUNNING="${KEEP_RUNNING:-0}"

CRS_VERSION="${CRS_VERSION:-v4.27.0}"
GO_FTW_VERSION="${GO_FTW_VERSION:-2.4.0}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.38-latest}"
FTW_CLOUDMODE="${FTW_CLOUDMODE:-false}"
FTW_INCLUDE="${FTW_INCLUDE:-}"

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
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

if [[ ! -f "$WASM" ]]; then
  echo "ERROR: $WASM not found. Build first: make image  (or make modsecurity-proxy-wasm.wasm)" >&2
  exit 1
fi



# Prefer docker when both are installed: GH Actions runners ship podman but its
# socket is often unavailable; docker compose is the reliable default there.
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
  COMPOSE=(podman compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
elif command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose)
else
  echo "ERROR: need docker compose or podman compose" >&2
  exit 1
fi

prepare_crs_cache() {
  local marker="$CRS_CACHE/.crs-version"
  if [[ -f "$marker" ]] && [[ "$(cat "$marker")" == "$CRS_VERSION" ]] \
      && [[ -d "$CRS_CACHE/tests/regression/tests" ]]; then
    return 0
  fi
  echo "==> Fetching CRS $CRS_VERSION test corpus for go-ftw"
  rm -rf "$CRS_CACHE"
  mkdir -p "$CRS_CACHE"
  local tarball="$CRS_CACHE/crs.tar.gz"
  curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" -o "$tarball"
  tar -xzf "$tarball" -C "$CRS_CACHE" --strip-components 1
  rm -f "$tarball"
  echo "$CRS_VERSION" >"$marker"
}

compose() {
  MODSECURITY_PROXY_WASM="$WASM" \
  CRS_CACHE="$CRS_CACHE" \
  CRS_VERSION="$CRS_VERSION" \
  GO_FTW_VERSION="$GO_FTW_VERSION" \
  ENVOY_IMAGE="$ENVOY_IMAGE" \
  FTW_CLOUDMODE="$FTW_CLOUDMODE" \
  FTW_INCLUDE="$FTW_INCLUDE" \
  "${COMPOSE[@]}" -f "$FTW_DIR/docker-compose.yml" -p "$COMPOSE_PROJECT" "$@"
}

cleanup() {
  if [[ "$KEEP_RUNNING" == "1" ]]; then
    return 0
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "==> CRS go-ftw regression (CRS_VERSION=$CRS_VERSION, go-ftw=$GO_FTW_VERSION)"
echo "==> WASM: $WASM"
echo "==> Envoy: $ENVOY_IMAGE"
if [[ -n "$FTW_INCLUDE" ]]; then
  echo "==> FTW_INCLUDE: $FTW_INCLUDE"
fi

log_volume() {
  echo "${COMPOSE_PROJECT}_logs"
}

wait_for_http() {
  local url="http://127.0.0.1:${FTW_HOST_PORT}/"
  local retries=60
  echo "==> Waiting for Envoy HTTP (${url})"
  until curl -sf -o /dev/null "$url"; do
    retries=$((retries - 1))
    if [[ "$retries" -le 0 ]]; then
      echo "ERROR: timeout waiting for Envoy HTTP" >&2
      return 1
    fi
    sleep 2
  done
}

prime_waf_from_host() {
  local url="http://127.0.0.1:${FTW_HOST_PORT}/status/200"
  echo "==> Priming WAF logs from host"
  for _ in 1 2 3 4 5; do
    curl -sf -H "Host: localhost" -H "X-CRS-Test: ftw-prime" "$url" -o /dev/null || true
  done
}

wait_for_waf_logs() {
  local ctr vol retries
  ctr="${COMPOSE[0]}"
  vol="$(log_volume)"
  retries=90
  echo "==> Waiting for modsecurity-proxy-wasm rule lines in envoy.log"
  while [[ "$retries" -gt 0 ]]; do
    if "$ctr" run --rm -v "${vol}:/logs:ro" docker.io/library/alpine:3.20 \
        grep -qF '[modsecurity-proxy-wasm][rule]' /logs/envoy.log 2>/dev/null; then
      return 0
    fi
    curl -sf -H "Host: localhost" -H "X-CRS-Test: ftw-wait" \
      "http://127.0.0.1:${FTW_HOST_PORT}/status/200" -o /dev/null || true
    sleep 2
    retries=$((retries - 1))
  done
  echo "ERROR: timeout waiting for WAF rule logs" >&2
  "$ctr" run --rm -v "${vol}:/logs:ro" docker.io/library/alpine:3.20 \
    sh -c 'tail -n 30 /logs/envoy.log' >&2 || true
  return 1
}

prepare_crs_cache
compose down -v --remove-orphans >/dev/null 2>&1 || true
echo "==> Starting Envoy + albedo"
compose up -d --pull missing albedo chown envoy
wait_for_http
sleep "${FTW_STARTUP_WAIT:-10}"
prime_waf_from_host
wait_for_waf_logs
# Use `run --no-deps` so Envoy is not recreated (recreate would wipe primed logs and
# race go-ftw marker discovery). Propagate the container exit status explicitly.
echo "==> Running go-ftw"
set +e
compose run --rm --no-deps ftw
exit_code=$?
set -e

if [[ "$exit_code" -eq 0 ]]; then
  echo "==> CRS go-ftw regression passed"
else
  echo "==> CRS go-ftw regression failed (exit $exit_code)" >&2
  compose logs --tail=60 envoy ftw >&2 || true
fi

if [[ "$KEEP_RUNNING" == "1" ]]; then
  echo ""
  echo "==> Stack left running (project: $COMPOSE_PROJECT)"
  echo "    HTTP:  http://127.0.0.1:${FTW_HOST_PORT:-18082}/"
  echo "    Stop:  ${COMPOSE[*]} -f $FTW_DIR/docker-compose.yml -p $COMPOSE_PROJECT down -v"
fi

exit "$exit_code"
