#!/usr/bin/env bash
# Inspect a finished modsecurity-proxy-wasm (or any) .wasm for embedded identity.
#
# Usage:
#   ./build/scripts/inspect-wasm.sh dist/modsecurity-proxy-wasm.wasm
#   make inspect-wasm WASM=dist/modsecurity-proxy-wasm.wasm
#
# Looks for the stable marker block emitted by src/version.cc:
#   <<<MODSECURITY_PROXY_WASM_META>>> ... <<<END_MODSECURITY_PROXY_WASM_META>>>
# Also reports SHA-256, size, and useful capability hints (e.g. @kubewaf-defaults).

set -euo pipefail

WASM="${1:-}"
if [[ -z "$WASM" || "$WASM" == "-h" || "$WASM" == "--help" ]]; then
  cat <<'EOF'
Usage: inspect-wasm.sh <path-to.wasm>

Prints build metadata embedded in modsecurity-proxy-wasm binaries, plus
file size, SHA-256, and capability hints (Include targets, source paths).

Examples:
  make inspect-wasm
  make inspect-wasm WASM=/path/to/modsecurity-proxy-wasm.wasm
  ./build/scripts/inspect-wasm.sh dist/modsecurity-proxy-wasm.wasm
EOF
  exit 0
fi

if [[ ! -f "$WASM" ]]; then
  echo "ERROR: file not found: $WASM" >&2
  exit 1
fi

if command -v realpath >/dev/null 2>&1; then
  ABS="$(realpath "$WASM")"
else
  ABS="$(cd "$(dirname "$WASM")" && pwd)/$(basename "$WASM")"
fi

SIZE="$(wc -c <"$WASM" | tr -d ' ')"
if command -v sha256sum >/dev/null 2>&1; then
  SHA="$(sha256sum "$WASM" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  SHA="$(shasum -a 256 "$WASM" | awk '{print $1}')"
else
  SHA="(sha256sum/shasum not available)"
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

if command -v strings >/dev/null 2>&1; then
  strings -n 4 "$WASM" >"$TMP" 2>/dev/null || true
else
  tr -cd '[:print:]\n' <"$WASM" >"$TMP" 2>/dev/null || true
fi

META_BEGIN='<<<MODSECURITY_PROXY_WASM_META>>>'
META_END='<<<END_MODSECURITY_PROXY_WASM_META>>>'
has_meta=0
grep -qF "$META_BEGIN" "$TMP" && has_meta=1

echo "=== file ==="
echo "path:     $ABS"
echo "size:     $SIZE bytes"
echo "sha256:   $SHA"
echo

echo "=== embedded metadata (version.cc block) ==="
if [[ "$has_meta" -eq 1 ]]; then
  awk -v b="$META_BEGIN" -v e="$META_END" '
    $0 == b { show=1; print; next }
    $0 == e { print; show=0; next }
    show { print }
  ' "$TMP"
  echo
  echo "=== parsed fields ==="
  awk -v b="$META_BEGIN" -v e="$META_END" '
    $0 == b { show=1; next }
    $0 == e { show=0; next }
    show && index($0, "=") {
      key=$0; sub(/=.*/, "", key)
      val=$0; sub(/^[^=]*=/, "", val)
      printf "%-22s %s\n", key ":", val
    }
  ' "$TMP"
else
  echo "(no <<<MODSECURITY_PROXY_WASM_META>>> block found)"
  echo "This binary was likely built before version embedding, or is not modsecurity-proxy-wasm."
  echo
  echo "=== fallback identity strings ==="
  grep -E '\[modsecurity-proxy-wasm\]|modsecurity-proxy-wasm/|kubeWAF/modsecurity|version=' "$TMP" \
    | head -30 || echo "(none)"
fi
echo

echo "=== capability / source hints ==="
hint() {
  local label="$1" pattern="$2"
  if grep -qE "$pattern" "$TMP"; then
    printf "  [yes] %s\n" "$label"
  else
    printf "  [no ] %s\n" "$label"
  fi
}
hint "Include @kubewaf-defaults" 'kubewaf-defaults|@kubewaf-defaults'
hint "Include @crs-setup-conf" 'crs-setup-conf|@crs-setup-conf'
hint "Include @owasp_crs" 'owasp_crs|@owasp_crs|REQUEST-9'
hint "Include @demo-conf" 'demo-conf|@demo-conf'
hint "CRS / rule catalog data" 'coreruleset|REQUEST-901|crs_setup_version'
hint "kubeWAF mode / product branding" 'mode=kubewaf|blocked by kubeWAF|kubeWAF/'
echo

echo "=== source path traces (debug / __FILE__) ==="
PATH_HITS="$(grep -E '/home/|/Users/|/src/[^ ]+\.(cc|h|c)|challange-proxy|modsec-wasm-plugin|modsecurity-proxy-wasm/' "$TMP" \
  | grep -vE 'modsecurity_proxy_wasm\.(memory|rule|tx|configure|response)' \
  | head -25 || true)"
if [[ -n "$PATH_HITS" ]]; then
  printf '%s\n' "$PATH_HITS"
else
  echo "(none — normal for stripped -O3 release builds with no DWARF paths)"
fi
echo

echo "=== summary ==="
if [[ "$has_meta" -eq 1 ]]; then
  VER="$(awk -v b="$META_BEGIN" -v e="$META_END" '
    $0 == b { show=1; next } $0 == e { show=0; next }
    show && $0 ~ /^version=/ { sub(/^version=/,""); print; exit }' "$TMP")"
  GIT="$(awk -v b="$META_BEGIN" -v e="$META_END" '
    $0 == b { show=1; next } $0 == e { show=0; next }
    show && $0 ~ /^git_commit=/ { sub(/^git_commit=/,""); print; exit }' "$TMP")"
  SRC="$(awk -v b="$META_BEGIN" -v e="$META_END" '
    $0 == b { show=1; next } $0 == e { show=0; next }
    show && $0 ~ /^source=/ { sub(/^source=/,""); print; exit }' "$TMP")"
  NAME="$(awk -v b="$META_BEGIN" -v e="$META_END" '
    $0 == b { show=1; next } $0 == e { show=0; next }
    show && $0 ~ /^name=/ { sub(/^name=/,""); print; exit }' "$TMP")"
  echo "module:   ${NAME:-modsecurity-proxy-wasm}"
  echo "version:  ${VER:-unknown}"
  echo "git:      ${GIT:-unknown}"
  echo "source:   ${SRC:-unknown}"
  if grep -qE 'kubewaf-defaults|@kubewaf-defaults' "$TMP"; then
    echo "status:   supports Include @kubewaf-defaults (kubeWAF-ready)"
  else
    echo "status:   WARNING: no @kubewaf-defaults marker — may reject kubeWAF configs"
  fi
else
  echo "module:   unknown / pre-metadata binary"
  if grep -qE 'challange-proxy|modsec-wasm-plugin' "$TMP"; then
    echo "status:   WARNING: old out-of-tree build path (challange-proxy-wasm/modsec-wasm-plugin)"
    echo "          rebuild from monorepo modsecurity-proxy-wasm for @kubewaf-defaults + metadata"
  else
    echo "status:   rebuild with current modsecurity-proxy-wasm to embed metadata"
  fi
  if ! grep -qE 'kubewaf-defaults|@kubewaf-defaults' "$TMP"; then
    echo "status:   WARNING: no @kubewaf-defaults — kubeWAF Include will fail fail-closed"
  fi
fi
