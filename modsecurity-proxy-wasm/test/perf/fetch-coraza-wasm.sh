#!/usr/bin/env bash
set -euo pipefail

# Download and verify coraza-proxy-wasm release artifact for perf comparison.
#
# Output: test/perf/.coraza/main.wasm

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=versions.env
source "$SCRIPT_DIR/versions.env"

CACHE_DIR="${CORAZA_CACHE_DIR:-$SCRIPT_DIR/.coraza}"
OUT_WASM="$CACHE_DIR/main.wasm"
ZIP_NAME="coraza-proxy-wasm-${CORAZA_VERSION}.zip"
ZIP_URL="https://github.com/corazawaf/coraza-proxy-wasm/releases/download/${CORAZA_VERSION}/${ZIP_NAME}"
ZIP_PATH="$CACHE_DIR/$ZIP_NAME"

mkdir -p "$CACHE_DIR"

if [[ -f "$OUT_WASM" ]]; then
  echo "==> coraza wasm already present: $OUT_WASM" >&2
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl required to fetch coraza-proxy-wasm" >&2
  exit 1
fi
if ! command -v unzip >/dev/null 2>&1; then
  echo "ERROR: unzip required to extract coraza-proxy-wasm" >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "ERROR: sha256sum required to verify coraza-proxy-wasm" >&2
  exit 1
fi

echo "==> Downloading coraza-proxy-wasm ${CORAZA_VERSION}" >&2
curl -fsSL -o "$ZIP_PATH" "$ZIP_URL"

echo "==> Verifying SHA256" >&2
echo "${CORAZA_ZIP_SHA256}  ${ZIP_PATH}" | sha256sum -c -

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
unzip -q "$ZIP_PATH" -d "$tmpdir"

found="$(find "$tmpdir" \( -name 'coraza-proxy-wasm.wasm' -o -name 'main.wasm' \) -type f | head -1)"
if [[ -z "$found" ]]; then
  found="$(find "$tmpdir" -name '*.wasm' -type f | head -1)"
fi
if [[ -z "$found" ]]; then
  echo "ERROR: no .wasm found inside ${ZIP_NAME}" >&2
  exit 1
fi

cp "$found" "$OUT_WASM"
echo "==> Installed coraza wasm: $OUT_WASM ($(wc -c < "$OUT_WASM") bytes)" >&2