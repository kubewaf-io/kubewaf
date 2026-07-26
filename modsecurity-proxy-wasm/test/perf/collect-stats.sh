#!/usr/bin/env bash
set -euo pipefail

# Scrape Envoy admin stats for a perf run.
# Usage: ADMIN_URL=http://127.0.0.1:19901 ./test/perf/collect-stats.sh <label> <output-dir>

ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:19901}"
LABEL="${1:?label required}"
OUT_DIR="${2:?output dir required}"

mkdir -p "$OUT_DIR"

curl -sf "${ADMIN_URL}/stats" > "${OUT_DIR}/envoy-stats-${LABEL}.txt"
curl -sf "${ADMIN_URL}/stats/prometheus" > "${OUT_DIR}/envoy-prometheus-${LABEL}.txt"

grep -E '^(http\.ingress_http\.|wasm\.|modsecurity_proxy_wasm|waf_filter)' "${OUT_DIR}/envoy-stats-${LABEL}.txt" \
  > "${OUT_DIR}/envoy-stats-${LABEL}-filtered.txt" || true

grep -E '^modsecurity_proxy_wasm' "${OUT_DIR}/envoy-prometheus-${LABEL}.txt" \
  > "${OUT_DIR}/modsecurity-proxy-wasm-metrics-${LABEL}.txt" || true

grep -E '^modsecurity_proxy_wasm_memory_' "${OUT_DIR}/envoy-prometheus-${LABEL}.txt" \
  > "${OUT_DIR}/modsecurity-proxy-wasm-memory-${LABEL}.txt" || true

grep -E '^waf_filter' "${OUT_DIR}/envoy-prometheus-${LABEL}.txt" \
  > "${OUT_DIR}/coraza-wasm-metrics-${LABEL}.txt" || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
  PYTHONPATH="$SCRIPT_DIR" python3 - "$LABEL" "$OUT_DIR" <<'PY'
import json
import sys
from pathlib import Path

from memory import parse_prometheus_memory

label, out_dir = sys.argv[1], Path(sys.argv[2])
prom = out_dir / f"envoy-prometheus-{label}.txt"
envoy = parse_prometheus_memory(prom)
if envoy:
    (out_dir / f"memory-envoy-{label}.json").write_text(
        json.dumps(envoy, indent=2) + "\n",
        encoding="utf-8",
    )
PY
fi

echo "==> Saved Envoy stats (${LABEL}) to ${OUT_DIR}"