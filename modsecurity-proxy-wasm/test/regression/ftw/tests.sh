#!/bin/sh
set -eu

cd /workspace

if ! command -v curl >/dev/null 2>&1; then
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl >/dev/null
  else
    echo "[Fail] curl is required in the go-ftw container"
    exit 1
  fi
fi

step=1
total_steps=1
max_retries=120
host="${1:-envoy}"
health_url="http://${host}:8080"

echo "[$step/$total_steps] Testing application reachability"
status_code="000"
while [ "$status_code" = "000" ]; do
  status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null "$health_url" || true)
  sleep 1
  printf "[Wait] Waiting for response from %s. Timeout: %ss   \r" "$health_url" "$max_retries"
  max_retries=$((max_retries - 1))
  if [ "$max_retries" -eq 0 ]; then
    echo ""
    echo "[Fail] Timeout waiting for response from $health_url"
    if [ -f /home/envoy/logs/envoy.log ]; then
      echo "Envoy logs:" && tail -n 80 /home/envoy/logs/envoy.log
    fi
    exit 1
  fi
done

if [ "$status_code" != "200" ]; then
  echo ""
  echo "[Fail] Unexpected status code $status_code, expected 200."
  exit 1
fi
echo ""
echo "[Ok] Got status code $status_code. Ready to run go-ftw."

# Envoy wasm logs are flushed asynchronously; go-ftw marker retries are fast.
sleep "${FTW_MARKER_SETTLE:-5}"

FTW_CLOUDMODE="${FTW_CLOUDMODE:-false}"
FTW_INCLUDE_ARG=""
if [ -n "${FTW_INCLUDE:-}" ]; then
  FTW_INCLUDE_ARG="-i ${FTW_INCLUDE}"
fi

# Envoy wasm logs flush slowly; rate-limit marker retries so they span the delay.
FTW_RATE_LIMIT="${FTW_RATE_LIMIT:-300ms}"
FTW_MAX_MARKER_RETRIES="${FTW_MAX_MARKER_RETRIES:-40}"

# shellcheck disable=SC2086
/ftw run -d coreruleset/tests/regression/tests \
  --config ftw.yml \
  --read-timeout=10s \
  --rate-limit="$FTW_RATE_LIMIT" \
  --max-marker-retries="$FTW_MAX_MARKER_RETRIES" \
  --cloud="$FTW_CLOUDMODE" \
  $FTW_INCLUDE_ARG