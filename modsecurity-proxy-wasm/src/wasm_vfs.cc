#include "wasm_vfs.h"

#include <cstring>
#include <string>
#include <string_view>

#include "generated/rules_catalog.h"

namespace {

constexpr char kRulesDir[] = "/modsecurity-proxy-wasm-rules";
constexpr char kCrsDataPrefix[] = "@crs-data/";
constexpr size_t kCrsDataPrefixLen = sizeof(kCrsDataPrefix) - 1;

std::string ruleRefPathImpl(const char* label) {
  static thread_local std::string ref;
  ref.clear();
  ref.append(kRulesDir);
  ref.push_back('/');

  if (label == nullptr || label[0] == '\0') {
    ref.append("rules.conf");
    return ref;
  }

  const std::string_view l(label);
  if (l == "inline-directives") {
    ref.append("inline.conf");
    return ref;
  }
  if (l == "@demo-conf") {
    ref.append("demo-conf.conf");
    return ref;
  }
  if (l == "@kubewaf-defaults") {
    ref.append("kubewaf-defaults.conf");
    return ref;
  }
  if (l == "@crs-setup-conf") {
    ref.append("crs-setup.conf");
    return ref;
  }
  if (l.rfind("@owasp_crs/", 0) == 0) {
    ref.append(l.substr(11));
    return ref;
  }
  if (l == "plain-config") {
    ref.append("plain.conf");
    return ref;
  }
  if (l.front() == '@') {
    ref.append(l.substr(1));
    return ref;
  }
  ref.append(l);
  return ref;
}

// Count embedded CRS .data assets (sanity for configure).
int countCrsDataFiles() {
  int n = 0;
  modsecurity_proxy_wasm_rules::foreach_crs_data_file(
      [](const modsecurity_proxy_wasm_rules::RuleAsset&, void* user) -> bool {
        *static_cast<int*>(user) += 1;
        return true;
      },
      &n);
  return n;
}

}  // namespace

// Called from ModSecurity PmFromFile (patched) instead of ifstream when the
// Envoy V8 runtime has no writable filesystem. name is a CRS .data basename
// (e.g. "scanners-user-agents.data") or a path ending in that basename.
extern "C" const char* modsecurity_proxy_wasm_resolve_data_file(const char* name,
                                                                std::size_t* out_size) {
  if (name == nullptr || name[0] == '\0') {
    return nullptr;
  }
  // Basename only (find_resource may pass "dir/file.data").
  const char* base = name;
  if (const char* slash = std::strrchr(name, '/')) {
    base = slash + 1;
  }
  if (const char* bslash = std::strrchr(base, '\\')) {
    base = bslash + 1;
  }
  if (base[0] == '\0') {
    return nullptr;
  }

  std::string key;
  key.reserve(kCrsDataPrefixLen + std::strlen(base));
  key.append(kCrsDataPrefix);
  key.append(base);

  const auto* asset = modsecurity_proxy_wasm_rules::lookup(key.c_str());
  if (asset == nullptr || asset->data == nullptr) {
    return nullptr;
  }
  if (out_size != nullptr) {
    *out_size = asset->size;
  }
  return asset->data;
}

bool modsecurity_proxy_wasm_mount_crs_data_files() {
  // Envoy's wasm runtime does not provide a writable host FS for fopen/mkdir.
  // Phrase lists stay in the embedded catalog and are served to PmFromFile via
  // modsecurity_proxy_wasm_resolve_data_file (see ModSecurity patch).
  return countCrsDataFiles() > 0;
}

const char* modsecurity_proxy_wasm_rule_ref_path(const char* label) {
  static thread_local std::string storage;
  storage = ruleRefPathImpl(label);
  return storage.c_str();
}
