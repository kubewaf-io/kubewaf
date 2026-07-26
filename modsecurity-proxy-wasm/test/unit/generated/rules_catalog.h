#ifndef MODSECURITY_PROXY_WASM_GENERATED_RULES_CATALOG_H_
#define MODSECURITY_PROXY_WASM_GENERATED_RULES_CATALOG_H_

#include <cstddef>

namespace modsecurity_proxy_wasm_rules {

struct RuleAsset {
  const char* path;
  const char* data;
  std::size_t size;
};

const RuleAsset* lookup(const char* path);
void foreach_owasp_crs(bool (*fn)(const RuleAsset&, void*), void* user);
void foreach_crs_data_file(bool (*fn)(const RuleAsset&, void*), void* user);

}  // namespace modsecurity_proxy_wasm_rules

#endif