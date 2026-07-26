#ifndef MODSECURITY_PROXY_WASM_VFS_H_
#define MODSECURITY_PROXY_WASM_VFS_H_

#include <cstddef>

// Verify embedded CRS .data phrase lists are present in the rules catalog.
// Actual file bytes are served to ModSecurity via
// modsecurity_proxy_wasm_resolve_data_file (no host filesystem).
bool modsecurity_proxy_wasm_mount_crs_data_files();

// Map a virtual catalog label to the filesystem-style path passed as the
// ModSecurity rule reference (directory used by find_resource for relatives).
const char* modsecurity_proxy_wasm_rule_ref_path(const char* label);

// C ABI used by the patched ModSecurity PmFromFile operator. Returns a pointer
// into the embedded catalog (do not free); nullptr if unknown.
// name may be a basename ("scanners-user-agents.data") or a longer path.
extern "C" const char* modsecurity_proxy_wasm_resolve_data_file(const char* name,
                                                                std::size_t* out_size);

#endif
