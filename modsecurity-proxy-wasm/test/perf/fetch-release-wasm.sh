#!/usr/bin/env bash
# Download modsecurity-proxy-wasm.wasm from a GitHub release tag.
#
# Private repos (and higher rate limits) need auth:
#   GITHUB_TOKEN or GH_TOKEN (GitHub Actions injects GITHUB_TOKEN automatically).
# When a token is set, assets are resolved via the Releases API (reliable for private repos).
# Without a token, falls back to public browser download URLs.
#
# Usage:
#   ./test/perf/fetch-release-wasm.sh v0.1.0-alpha5
#   RELEASE_TAG=v0.1.0-alpha5 OUT=path/to.wasm ./test/perf/fetch-release-wasm.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="${1:-${RELEASE_TAG:-}}"
OUT="${OUT:-$SCRIPT_DIR/.releases/${TAG}/modsecurity-proxy-wasm.wasm}"
REPO="${GITHUB_REPOSITORY:-}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
ASSET_NAME="${ASSET_NAME:-modsecurity-proxy-wasm.wasm}"
SHA_ASSET_NAME="${SHA_ASSET_NAME:-modsecurity-proxy-wasm.wasm.sha256}"

if [[ -z "$TAG" ]]; then
  echo "ERROR: release tag required (arg or RELEASE_TAG)" >&2
  exit 2
fi

if [[ -z "$REPO" ]]; then
  REPO="$(git -C "$SCRIPT_DIR/../.." remote get-url origin 2>/dev/null \
    | sed -E 's#(git@|https://)github.com[:/](.+)(\.git)?#\2#')"
fi
REPO="${REPO%.git}"

if [[ -z "$REPO" ]]; then
  echo "ERROR: could not determine GitHub repository (set GITHUB_REPOSITORY)" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUT")"

if [[ -f "$OUT" ]] && [[ -f "${OUT}.sha256" ]] \
    && [[ "$(cat "${OUT}.sha256")" == "$(sha256sum "$OUT" | awk '{print $1}')" ]]; then
  echo "==> Reusing cached release wasm: $OUT"
  exit 0
fi

# Shared curl headers for GitHub API / authenticated browser downloads.
curl_headers=()
if [[ -n "$TOKEN" ]]; then
  curl_headers+=(
    -H "Authorization: Bearer ${TOKEN}"
    -H "X-GitHub-Api-Version: 2022-11-28"
  )
fi

verify_sha256() {
  local expected_file="$1"
  local expected actual
  expected="$(tr -d '[:space:]' < "$expected_file")"
  # Accept either bare hash or "hash  filename" (sha256sum style).
  expected="${expected%%[[:space:]]*}"
  actual="$(sha256sum "$OUT" | awk '{print $1}')"
  [[ "$expected" == "$actual" ]] || {
    echo "ERROR: sha256 mismatch for $TAG (expected $expected, got $actual)" >&2
    exit 1
  }
  printf '%s\n' "$actual" > "${OUT}.sha256"
}

download_api_asset() {
  local asset_id="$1"
  local dest="$2"
  curl -fsSL \
    "${curl_headers[@]}" \
    -H "Accept: application/octet-stream" \
    -L \
    -o "$dest" \
    "https://api.github.com/repos/${REPO}/releases/assets/${asset_id}"
}

asset_id_from_release_json() {
  local asset_name="$1"
  python3 -c '
import json, sys
name = sys.argv[1]
data = json.load(sys.stdin)
for asset in data.get("assets") or []:
    if asset.get("name") == name:
        print(asset["id"])
        raise SystemExit(0)
raise SystemExit(f"asset not found on release: {name}")
' "$asset_name"
}

if [[ -n "$TOKEN" ]]; then
  echo "==> Resolving ${ASSET_NAME} via GitHub API: ${REPO}@${TAG}" >&2
  release_json="$(
    curl -fsSL \
      "${curl_headers[@]}" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
  )" || {
    echo "ERROR: failed to fetch release ${TAG} for ${REPO} (check tag exists and token has contents:read)" >&2
    exit 1
  }

  wasm_id="$(asset_id_from_release_json "$ASSET_NAME" <<<"$release_json")" || {
    echo "ERROR: release ${TAG} has no asset named ${ASSET_NAME}" >&2
    exit 1
  }

  echo "==> Downloading ${ASSET_NAME} (asset id ${wasm_id})" >&2
  download_api_asset "$wasm_id" "$OUT"

  if sha_id="$(asset_id_from_release_json "$SHA_ASSET_NAME" <<<"$release_json" 2>/dev/null)"; then
    echo "==> Verifying SHA256" >&2
    download_api_asset "$sha_id" "${OUT}.expected-sha256"
    verify_sha256 "${OUT}.expected-sha256"
    rm -f "${OUT}.expected-sha256"
  else
    sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
  fi
else
  BASE="https://github.com/${REPO}/releases/download/${TAG}"
  WASM_URL="${BASE}/${ASSET_NAME}"
  SHA_URL="${BASE}/${SHA_ASSET_NAME}"

  echo "==> Downloading ${WASM_URL}" >&2
  if ! curl -fsSL -o "$OUT" "$WASM_URL"; then
    echo "ERROR: download failed for ${WASM_URL}" >&2
    echo "hint: private repositories require GITHUB_TOKEN or GH_TOKEN" >&2
    exit 1
  fi

  if curl -fsSL -o "${OUT}.expected-sha256" "$SHA_URL" 2>/dev/null; then
    echo "==> Verifying SHA256" >&2
    verify_sha256 "${OUT}.expected-sha256"
    rm -f "${OUT}.expected-sha256"
  else
    sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
  fi
fi

echo "$OUT"
