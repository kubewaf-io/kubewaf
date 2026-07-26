#!/usr/bin/env bash
# Compare k6 performance of modsecurity-proxy-wasm across the last two GitHub releases.
#
# Usage:
#   ./test/perf/run-release-compare.sh
#   CURRENT_TAG=v0.1.0-alpha6 PREVIOUS_TAG=v0.1.0-alpha5 ./test/perf/run-release-compare.sh
#
# Writes run dirs under test/perf/results/ tagged with wasm-release-tag.txt and
# summary metadata in test/perf/results/release-compare.json.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
COMPARE_META="$RESULTS_DIR/release-compare.json"

CURRENT_TAG="${CURRENT_TAG:-${GITHUB_REF_NAME:-}}"
PREVIOUS_TAG="${PREVIOUS_TAG:-}"
REPO="${GITHUB_REPOSITORY:-}"
PERF_CI="${PERF_CI:-1}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.38-latest}"

SCENARIOS=(benign-get benign-post-1k)

if [[ -z "$REPO" ]]; then
  REPO="$(git -C "$ROOT_DIR" remote get-url origin 2>/dev/null \
    | sed -E 's#(git@|https://)github.com[:/](.+)(\.git)?#\2#')"
fi
REPO="${REPO%.git}"

resolve_previous_tag() {
  if [[ -n "$PREVIOUS_TAG" ]]; then
    return 0
  fi
  if [[ -n "$CURRENT_TAG" ]]; then
    mapfile -t tags < <(git -C "$ROOT_DIR" tag -l 'v*' --sort=-v:refname)
    for tag in "${tags[@]}"; do
      if [[ "$tag" != "$CURRENT_TAG" ]]; then
        PREVIOUS_TAG="$tag"
        return 0
      fi
    done
  fi
  return 1
}

if [[ -z "$CURRENT_TAG" ]]; then
  CURRENT_TAG="$(git -C "$ROOT_DIR" describe --tags --abbrev=0 2>/dev/null || true)"
fi
[[ -n "$CURRENT_TAG" ]] || {
  echo "ERROR: CURRENT_TAG not set and no git tag found" >&2
  exit 2
}

resolve_previous_tag
if [[ -z "$PREVIOUS_TAG" ]]; then
  echo "WARN: no previous release tag — skipping release compare (first release?)" >&2
  exit 0
fi

echo "==> Release perf compare: ${PREVIOUS_TAG} -> ${CURRENT_TAG} (${REPO})"

chmod +x "$SCRIPT_DIR/fetch-release-wasm.sh" "$SCRIPT_DIR/run-k6.sh" \
  "$SCRIPT_DIR/collect-stats.sh"

PREV_WASM="$("$SCRIPT_DIR/fetch-release-wasm.sh" "$PREVIOUS_TAG")"
CURR_WASM="${PERF_WASM_CURRENT:-$ROOT_DIR/dist/modsecurity-proxy-wasm.wasm}"

if [[ ! -f "$CURR_WASM" ]]; then
  echo "ERROR: current wasm missing at $CURR_WASM (build or set PERF_WASM_CURRENT)" >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
declare -A RUN_DIRS=()

run_for_tag() {
  local tag="$1"
  local wasm="$2"
  local scenario="$3"
  local run_dir

  echo ""
  echo "==> k6 release run: tag=${tag} scenario=${scenario}"
  PERF_WASM="$wasm" \
  PERF_RELEASE_TAG="$tag" \
  PERF_PROFILE=modsecurity-proxy-wasm-full \
  PERF_SCENARIO="$scenario" \
  PERF_CI="$PERF_CI" \
  ENVOY_IMAGE="$ENVOY_IMAGE" \
  PERF_RUN_STAMP="${STAMP}-rel-${tag//./-}" \
    "$SCRIPT_DIR/run-k6.sh"

  run_dir="$(ls -1dt "$RESULTS_DIR"/run-"${STAMP}"-rel-*-modsecurity-proxy-wasm-full-"${scenario}" 2>/dev/null | head -1)"
  [[ -n "$run_dir" && -d "$run_dir" ]] || {
    echo "ERROR: could not locate run dir for ${tag} ${scenario}" >&2
    exit 1
  }
  RUN_DIRS["${tag}:${scenario}"]="$run_dir"
}

for scenario in "${SCENARIOS[@]}"; do
  run_for_tag "$PREVIOUS_TAG" "$PREV_WASM" "$scenario"
  run_for_tag "$CURRENT_TAG" "$CURR_WASM" "$scenario"

  prev_dir="${RUN_DIRS[${PREVIOUS_TAG}:${scenario}]}"
  curr_dir="${RUN_DIRS[${CURRENT_TAG}:${scenario}]}"
  echo ""
  echo "==> Latency compare (${scenario}): ${PREVIOUS_TAG} vs ${CURRENT_TAG}"
  python3 "$SCRIPT_DIR/compare-summaries.py" \
    "$prev_dir/k6-summary.json" \
    "$curr_dir/k6-summary.json" \
    --left-label "$PREVIOUS_TAG" \
    --right-label "$CURRENT_TAG"
done

python3 - "$COMPARE_META" "$PREVIOUS_TAG" "$CURRENT_TAG" "$STAMP" "${SCENARIOS[@]}" <<'PY'
import json
import sys
from pathlib import Path

out, prev_tag, curr_tag, stamp, *scenarios = sys.argv[1:]
results = Path(out).parent
payload = {
    "stamp": stamp,
    "previous_tag": prev_tag,
    "current_tag": curr_tag,
    "scenarios": {},
}
for scenario in scenarios:
    entry = {"previous": None, "current": None}
    for tag, key in ((prev_tag, "previous"), (curr_tag, "current")):
        matches = sorted(
            results.glob(f"run-{stamp}-rel-{tag.replace('.', '-')}-modsecurity-proxy-wasm-full-{scenario}"),
            reverse=True,
        )
        if matches:
            entry[key] = str(matches[0])
    payload["scenarios"][scenario] = entry

Path(out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"==> Wrote {out}")
PY

if command -v python3 >/dev/null 2>&1; then
  python3 -c "import matplotlib" 2>/dev/null && {
    python3 "$SCRIPT_DIR/render-charts.py" release-compare "$COMPARE_META" \
      -o "$SCRIPT_DIR/release-charts/perf-release-compare.png" || true
  } || true
fi

echo ""
echo "==> Release compare complete (${PREVIOUS_TAG} -> ${CURRENT_TAG})"