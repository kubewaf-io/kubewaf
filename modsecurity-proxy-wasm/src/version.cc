// Copyright 2025–2026 the modsecurity-proxy-wasm authors.
// SPDX-License-Identifier: Apache-2.0
//
// Embeds a stable, strings(1)-visible identity block into the .wasm so operators
// can identify a finished binary without running Envoy.

#include "version.h"

// Force the blob into the binary even under -O3 / LTO. The unique markers make
// `strings file.wasm | grep MODSECURITY_PROXY_WASM_META` reliable.
#if defined(__GNUC__) || defined(__clang__)
#define MSPW_USED __attribute__((used))
#define MSPW_SECTION __attribute__((section(".rodata.modsecurity_proxy_wasm_meta")))
#else
#define MSPW_USED
#define MSPW_SECTION
#endif

// NOTE: keep key=value lines simple ASCII (no quotes) for easy parsing.
MSPW_USED MSPW_SECTION static const char kModsecurityProxyWasmMeta[] =
    "\n" MODSECURITY_PROXY_WASM_META_BEGIN "\n"
    "module=modsecurity-proxy-wasm\n"
    "name=modsecurity-proxy-wasm\n"
    "filter_name=kubewaf.modsecurity\n"
    "version=" MODSECURITY_PROXY_WASM_VERSION "\n"
    "git_commit=" MODSECURITY_PROXY_WASM_GIT_COMMIT "\n"
    "git_describe=" MODSECURITY_PROXY_WASM_GIT_DESCRIBE "\n"
    "source=" MODSECURITY_PROXY_WASM_SOURCE "\n"
    "source_path=modsecurity-proxy-wasm\n"
    "crs_version=" MODSECURITY_PROXY_WASM_CRS_VERSION "\n"
    "modsecurity_version=" MODSECURITY_PROXY_WASM_MODSECURITY_VERSION "\n"
    "runtime=envoy.wasm.runtime.v8\n"
    "build_date=" MODSECURITY_PROXY_WASM_BUILD_DATE "\n"
    "build_host=" MODSECURITY_PROXY_WASM_BUILD_HOST "\n"
    "features=kubewaf-defaults,crs-catalog,ecds,metrics\n"
    MODSECURITY_PROXY_WASM_META_END "\n";

const char* modsecurity_proxy_wasm_metadata(void) {
  // Touch the array so LTO cannot drop it as unused.
  return kModsecurityProxyWasmMeta;
}
