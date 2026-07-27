// Copyright 2025–2026 the modsecurity-proxy-wasm authors.
// SPDX-License-Identifier: Apache-2.0
//
// Build-time identity for operators debugging Envoy Wasm loads.
// Defaults are overridden via -D flags from build/build.mk.
//
// A machine-readable blob is also embedded (see version.cc) so any finished
// .wasm can be inspected offline:
//   make inspect-wasm WASM=dist/modsecurity-proxy-wasm.wasm
//   ./build/scripts/inspect-wasm.sh path/to/file.wasm

#pragma once

#ifndef MODSECURITY_PROXY_WASM_VERSION
#define MODSECURITY_PROXY_WASM_VERSION "dev"
#endif

#ifndef MODSECURITY_PROXY_WASM_GIT_COMMIT
#define MODSECURITY_PROXY_WASM_GIT_COMMIT "unknown"
#endif

#ifndef MODSECURITY_PROXY_WASM_GIT_DESCRIBE
#define MODSECURITY_PROXY_WASM_GIT_DESCRIBE "unknown"
#endif

#ifndef MODSECURITY_PROXY_WASM_CRS_VERSION
#define MODSECURITY_PROXY_WASM_CRS_VERSION "unknown"
#endif

#ifndef MODSECURITY_PROXY_WASM_MODSECURITY_VERSION
#define MODSECURITY_PROXY_WASM_MODSECURITY_VERSION "unknown"
#endif

#ifndef MODSECURITY_PROXY_WASM_SOURCE
#define MODSECURITY_PROXY_WASM_SOURCE "github.com/kubewaf-io/kubewaf/modsecurity-proxy-wasm"
#endif

#ifndef MODSECURITY_PROXY_WASM_BUILD_DATE
#define MODSECURITY_PROXY_WASM_BUILD_DATE "unknown"
#endif

#ifndef MODSECURITY_PROXY_WASM_BUILD_HOST
#define MODSECURITY_PROXY_WASM_BUILD_HOST "unknown"
#endif

// Human-readable line for Envoy logs (keep short — Envoy truncates wasm lines).
#define MODSECURITY_PROXY_WASM_VERSION_LINE                                           \
  "[modsecurity-proxy-wasm] version=" MODSECURITY_PROXY_WASM_VERSION                  \
  " git=" MODSECURITY_PROXY_WASM_GIT_COMMIT                                           \
  " crs=" MODSECURITY_PROXY_WASM_CRS_VERSION                                          \
  " modsecurity=" MODSECURITY_PROXY_WASM_MODSECURITY_VERSION

// Stable markers for offline inspection (must match inspect-wasm.sh).
#define MODSECURITY_PROXY_WASM_META_BEGIN "<<<MODSECURITY_PROXY_WASM_META>>>"
#define MODSECURITY_PROXY_WASM_META_END "<<<END_MODSECURITY_PROXY_WASM_META>>>"

// Returns the embedded multi-line metadata blob (never nullptr).
const char* modsecurity_proxy_wasm_metadata(void);
