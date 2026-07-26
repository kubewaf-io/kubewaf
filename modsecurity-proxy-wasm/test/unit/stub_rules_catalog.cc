// Minimal rules catalog for native unit tests (avoids full CRS embed).
#include "generated/rules_catalog.h"  // test/unit/generated (stub catalog)

#include <cstring>

namespace modsecurity_proxy_wasm_rules {
namespace {

constexpr char kDemoConfData[] =
    "SecTmpDir /tmp/modsec\n"
    "SecDataDir /tmp/modsec\n"
    "SecRuleEngine On\n";

constexpr char kKubeWafDefaultsData[] =
    "SecTmpDir /modsecurity-proxy-wasm-rules\n"
    "SecDataDir /modsecurity-proxy-wasm-rules\n"
    "SecRequestBodyAccess On\n"
    "SecResponseBodyAccess On\n"
    "SecAuditEngine Off\n";

constexpr RuleAsset kCatalog[] = {
    {"@demo-conf", kDemoConfData, sizeof(kDemoConfData) - 1},
    {"@kubewaf-defaults", kKubeWafDefaultsData, sizeof(kKubeWafDefaultsData) - 1},
};

constexpr size_t kCatalogSize = sizeof(kCatalog) / sizeof(kCatalog[0]);

}  // namespace

const RuleAsset* lookup(const char* path) {
  if (path == nullptr) {
    return nullptr;
  }
  for (size_t i = 0; i < kCatalogSize; ++i) {
    if (std::strcmp(kCatalog[i].path, path) == 0) {
      return &kCatalog[i];
    }
  }
  return nullptr;
}

void foreach_owasp_crs(bool (*fn)(const RuleAsset&, void*), void* user) {
  if (fn == nullptr) {
    return;
  }
  for (size_t i = 0; i < kCatalogSize; ++i) {
    if (std::strncmp(kCatalog[i].path, "@owasp_crs/", 11) == 0) {
      fn(kCatalog[i], user);
    }
  }
}

void foreach_crs_data_file(bool (*fn)(const RuleAsset&, void*), void* user) {
  (void)fn;
  (void)user;
}

}  // namespace modsecurity_proxy_wasm_rules
