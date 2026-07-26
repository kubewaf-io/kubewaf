#include "waf_config.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "generated/rules_catalog.h"

namespace {

// Production baseline also shipped as build/rules/kubewaf-defaults.conf in the CRS catalog.
// Kept in-source so unit tests and pre-regeneration binaries always resolve Include @kubewaf-defaults.
constexpr char kKubeWafDefaultsConf[] =
    "# kubeWAF production baseline (virtual path: Include @kubewaf-defaults)\n"
    "SecTmpDir /modsecurity-proxy-wasm-rules\n"
    "SecDataDir /modsecurity-proxy-wasm-rules\n"
    "SecRequestBodyAccess On\n"
    "SecRequestBodyLimit 13107200\n"
    "SecRequestBodyLimitAction ProcessPartial\n"
    "SecRequestBodyNoFilesLimit 131072\n"
    "SecResponseBodyAccess On\n"
    "SecResponseBodyMimeType text/plain text/html text/xml application/json\n"
    "SecResponseBodyLimit 524288\n"
    "SecResponseBodyLimitAction ProcessPartial\n"
    "SecAuditEngine Off\n";

std::string trim(const std::string& s) {
  size_t b = 0;
  while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
  size_t e = s.size();
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
  return s.substr(b, e - b);
}

bool looksLikeJson(const std::string& s) {
  auto t = trim(s);
  return !t.empty() && t.front() == '{';
}

size_t findJsonObjectEnd(const std::string& json, size_t obj_start) {
  if (obj_start >= json.size() || json[obj_start] != '{') {
    return std::string::npos;
  }
  int depth = 0;
  bool in_string = false;
  bool escape = false;
  for (size_t i = obj_start; i < json.size(); ++i) {
    char c = json[i];
    if (in_string) {
      if (escape) {
        escape = false;
        continue;
      }
      if (c == '\\') {
        escape = true;
        continue;
      }
      if (c == '"') {
        in_string = false;
      }
      continue;
    }
    if (c == '"') {
      in_string = true;
      continue;
    }
    if (c == '{') {
      ++depth;
    } else if (c == '}') {
      --depth;
      if (depth == 0) {
        return i;
      }
    }
  }
  return std::string::npos;
}

// Extract a top-level object value for key, e.g. "metrics": { ... }.
bool extractJsonObjectSlice(const std::string& json, const std::string& key, std::string& out) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = 0;
  while (pos < json.size()) {
    size_t key_pos = json.find(needle, pos);
    if (key_pos == std::string::npos) {
      return false;
    }
    // Prefer matches that look like object keys (colon after).
    size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
      return false;
    }
    size_t obj_start = json.find('{', colon);
    if (obj_start == std::string::npos) {
      return false;
    }
    // Skip if another non-whitespace token appears before '{'.
    std::string between = trim(json.substr(colon + 1, obj_start - colon - 1));
    if (!between.empty()) {
      pos = key_pos + needle.size();
      continue;
    }
    size_t obj_end = findJsonObjectEnd(json, obj_start);
    if (obj_end == std::string::npos) {
      return false;
    }
    out = json.substr(obj_start, obj_end - obj_start + 1);
    return true;
  }
  return false;
}

bool extractStringMapFromObject(const std::string& obj,
                                std::vector<std::pair<std::string, std::string>>& out) {
  out.clear();
  if (obj.empty() || obj.front() != '{') {
    return false;
  }
  size_t i = 1;
  while (i < obj.size()) {
    size_t key_quote = obj.find('"', i);
    if (key_quote == std::string::npos) {
      break;
    }
    size_t key_end = obj.find('"', key_quote + 1);
    if (key_end == std::string::npos) {
      break;
    }
    std::string label_key = obj.substr(key_quote + 1, key_end - key_quote - 1);

    size_t colon = obj.find(':', key_end);
    if (colon == std::string::npos) {
      break;
    }
    size_t val_quote = obj.find('"', colon);
    if (val_quote == std::string::npos) {
      break;
    }
    // Only accept string values for metric labels.
    std::string between = trim(obj.substr(colon + 1, val_quote - colon - 1));
    if (!between.empty()) {
      // Non-string value — skip until next comma/brace roughly.
      size_t next = obj.find_first_of(",}", colon + 1);
      if (next == std::string::npos) {
        break;
      }
      i = next + 1;
      continue;
    }
    ++val_quote;
    std::string label_value;
    bool escape = false;
    size_t p = val_quote;
    for (; p < obj.size(); ++p) {
      char c = obj[p];
      if (escape) {
        if (c == 'n') label_value.push_back('\n');
        else if (c == 'r') label_value.push_back('\r');
        else if (c == 't') label_value.push_back('\t');
        else if (c == '"') label_value.push_back('"');
        else if (c == '\\') label_value.push_back('\\');
        else label_value.push_back(c);
        escape = false;
        continue;
      }
      if (c == '\\') {
        escape = true;
        continue;
      }
      if (c == '"') break;
      label_value.push_back(c);
    }
    if (!label_key.empty()) {
      out.emplace_back(label_key, label_value);
    }
    i = p + 1;
    size_t next = obj.find_first_not_of(" \t\n\r,", i);
    if (next == std::string::npos || obj[next] == '}') {
      break;
    }
    i = next;
  }
  return true;
}

bool extractMetricLabels(const std::string& json, std::vector<std::pair<std::string, std::string>>& out) {
  out.clear();
  std::string obj;
  if (!extractJsonObjectSlice(json, "metric_labels", obj)) {
    return true;  // optional
  }
  return extractStringMapFromObject(obj, out);
}

bool extractJsonBoolValue(const std::string& json, const std::string& key, bool default_value) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) {
    return default_value;
  }
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) {
    return default_value;
  }
  const std::string tail = trim(json.substr(pos + 1));
  if (tail.rfind("true", 0) == 0) {
    return true;
  }
  if (tail.rfind("false", 0) == 0) {
    return false;
  }
  return default_value;
}

bool extractJsonIntValue(const std::string& json, const std::string& key, int default_value) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) {
    return default_value;
  }
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) {
    return default_value;
  }
  const std::string tail = trim(json.substr(pos + 1));
  if (tail.empty() || (!std::isdigit(static_cast<unsigned char>(tail[0])) && tail[0] != '-')) {
    return default_value;
  }
  try {
    return std::stoi(tail);
  } catch (...) {
    return default_value;
  }
}

std::string extractJsonStringValue(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) return "";
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return "";
  pos = json.find('"', pos);
  if (pos == std::string::npos) return "";
  ++pos;
  std::string out;
  bool escape = false;
  for (; pos < json.size(); ++pos) {
    char c = json[pos];
    if (escape) {
      if (c == 'n') out.push_back('\n');
      else if (c == 'r') out.push_back('\r');
      else if (c == 't') out.push_back('\t');
      else if (c == '"') out.push_back('"');
      else if (c == '\\') out.push_back('\\');
      else out.push_back(c);
      escape = false;
      continue;
    }
    if (c == '\\') {
      escape = true;
      continue;
    }
    if (c == '"') break;
    out.push_back(c);
  }
  return out;
}

size_t findJsonArrayEnd(const std::string& json, size_t arr_start) {
  if (arr_start >= json.size() || json[arr_start] != '[') {
    return std::string::npos;
  }
  int depth = 0;
  bool in_string = false;
  bool escape = false;
  for (size_t i = arr_start; i < json.size(); ++i) {
    char c = json[i];
    if (in_string) {
      if (escape) {
        escape = false;
        continue;
      }
      if (c == '\\') {
        escape = true;
        continue;
      }
      if (c == '"') {
        in_string = false;
      }
      continue;
    }
    if (c == '"') {
      in_string = true;
      continue;
    }
    if (c == '[') {
      ++depth;
    } else if (c == ']') {
      --depth;
      if (depth == 0) {
        return i;
      }
    }
  }
  return std::string::npos;
}

std::vector<std::string> extractDirectiveArray(const std::string& json, const std::string& profile) {
  std::vector<std::string> out;
  const std::string map_key = "\"directives_map\"";
  size_t map_pos = json.find(map_key);
  if (map_pos == std::string::npos) return out;

  const std::string profile_key = "\"" + profile + "\"";
  size_t prof_pos = json.find(profile_key, map_pos);
  if (prof_pos == std::string::npos) return out;

  size_t arr_start = json.find('[', prof_pos);
  if (arr_start == std::string::npos) return out;

  size_t arr_end = findJsonArrayEnd(json, arr_start);
  if (arr_end == std::string::npos) return out;

  size_t i = arr_start + 1;
  while (i < arr_end) {
    size_t q = json.find('"', i);
    if (q == std::string::npos || q >= arr_end) break;

    ++q;
    std::string item;
    bool escape = false;
    for (; q < json.size(); ++q) {
      char c = json[q];
      if (escape) {
        if (c == 'n') item.push_back('\n');
        else if (c == 'r') item.push_back('\r');
        else if (c == 't') item.push_back('\t');
        else if (c == '"') item.push_back('"');
        else if (c == '\\') item.push_back('\\');
        else item.push_back(c);
        escape = false;
        continue;
      }
      if (c == '\\') {
        escape = true;
        continue;
      }
      if (c == '"') break;
      item.push_back(c);
    }
    if (!item.empty()) out.push_back(item);
    i = q + 1;
    size_t next = json.find_first_not_of(" \t\n\r,", i);
    if (next == std::string::npos || next >= arr_end) break;
    if (json[next] == ']') break;
    i = next;
  }
  return out;
}

bool loadChunk(RuleChunkLoader loader, void* user, const char* label, const char* data, std::size_t size,
               std::string& error) {
  if (loader == nullptr || data == nullptr || size == 0) {
    return true;
  }
  return loader(label, data, size, user, error);
}

bool loadAsset(RuleChunkLoader loader, void* user, const modsecurity_proxy_wasm_rules::RuleAsset& asset,
               std::set<std::string>& seen, std::string& error) {
  if (seen.count(asset.path)) {
    return true;
  }
  seen.insert(asset.path);
  return loadChunk(loader, user, asset.path, asset.data, asset.size, error);
}

bool loadKubeWafDefaults(RuleChunkLoader loader, void* user, std::set<std::string>& seen,
                         std::string& error) {
  constexpr const char* kPath = "@kubewaf-defaults";
  if (seen.count(kPath)) {
    return true;
  }
  seen.insert(kPath);
  // Prefer catalog asset when present (full wasm build); fall back to in-source constant.
  if (const auto* asset = modsecurity_proxy_wasm_rules::lookup(kPath); asset != nullptr) {
    return loadChunk(loader, user, asset->path, asset->data, asset->size, error);
  }
  return loadChunk(loader, user, kPath, kKubeWafDefaultsConf, sizeof(kKubeWafDefaultsConf) - 1, error);
}

bool appendKubeWafDefaults(std::string& out, std::set<std::string>& seen) {
  constexpr const char* kPath = "@kubewaf-defaults";
  if (seen.count(kPath)) {
    return true;
  }
  seen.insert(kPath);
  if (const auto* asset = modsecurity_proxy_wasm_rules::lookup(kPath); asset != nullptr) {
    out.append(asset->data, asset->size);
    out.push_back('\n');
    return true;
  }
  out.append(kKubeWafDefaultsConf);
  if (out.empty() || out.back() != '\n') {
    out.push_back('\n');
  }
  return true;
}

struct LoadCtx {
  RuleChunkLoader loader;
  void* user;
  std::set<std::string>* seen;
  std::string* error;
};

bool loadOwaspCrsGlob(const modsecurity_proxy_wasm_rules::RuleAsset& asset, void* user) {
  auto* ctx = static_cast<LoadCtx*>(user);
  if (std::strcmp(asset.path, "@owasp_crs/_all.conf") == 0) {
    return true;
  }
  return loadAsset(ctx->loader, ctx->user, asset, *ctx->seen, *ctx->error);
}

bool resolveIncludeLoad(const std::string& target, RuleChunkLoader loader, void* user,
                        std::set<std::string>& seen, std::string& error) {
  if (target == "@kubewaf-defaults") {
    return loadKubeWafDefaults(loader, user, seen, error);
  }

  if (target == "@demo-conf" || target == "@crs-setup-conf" || target == "@ftw-conf") {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    return loadAsset(loader, user, *asset, seen, error);
  }

  if (target == "@owasp_crs/*.conf") {
    LoadCtx ctx{loader, user, &seen, &error};
    modsecurity_proxy_wasm_rules::foreach_owasp_crs(loadOwaspCrsGlob, &ctx);
    return error.empty();
  }

  if (target.rfind("@owasp_crs/", 0) == 0) {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    return loadAsset(loader, user, *asset, seen, error);
  }

  error = "unsupported Include target: " + target;
  return false;
}

bool applyJsonConfig(const std::string& json, RuleChunkLoader loader, void* user, std::string& error) {
  std::string profile = extractJsonStringValue(json, "default_directives");
  if (profile.empty()) profile = "default";

  std::vector<std::string> directives = extractDirectiveArray(json, profile);
  if (directives.empty()) {
    error = "directives_map profile not found or empty: " + profile;
    return false;
  }

  std::set<std::string> seen;
  std::string inline_batch;
  inline_batch.reserve(8192);

  auto flushInline = [&]() -> bool {
    if (inline_batch.empty()) {
      return true;
    }
    if (!loadChunk(loader, user, "inline-directives", inline_batch.data(), inline_batch.size(), error)) {
      return false;
    }
    inline_batch.clear();
    return true;
  };

  for (const auto& raw : directives) {
    std::string line = trim(raw);
    if (line.empty() || line.rfind("#", 0) == 0) continue;

    if (line.rfind("Include ", 0) == 0) {
      if (!flushInline()) return false;
      std::string target = trim(line.substr(8));
      if (!resolveIncludeLoad(target, loader, user, seen, error)) return false;
      continue;
    }

    inline_batch.append(line);
    inline_batch.push_back('\n');
  }

  return flushInline();
}

bool resolveIncludeExpand(const std::string& target, std::string& out, std::set<std::string>& seen,
                          std::string& error);

bool appendOwaspCrsGlobExpand(const modsecurity_proxy_wasm_rules::RuleAsset& asset, void* user) {
  struct Ctx {
    std::string* out;
    std::set<std::string>* seen;
    std::string* error;
  };
  auto* ctx = static_cast<Ctx*>(user);
  if (std::strcmp(asset.path, "@owasp_crs/_all.conf") == 0) {
    return true;
  }
  if (ctx->seen->count(asset.path)) {
    return true;
  }
  ctx->seen->insert(asset.path);
  ctx->out->append(asset.data, asset.size);
  ctx->out->push_back('\n');
  return true;
}

bool resolveIncludeExpand(const std::string& target, std::string& out, std::set<std::string>& seen,
                          std::string& error) {
  if (target == "@kubewaf-defaults") {
    return appendKubeWafDefaults(out, seen);
  }

  if (target == "@demo-conf" || target == "@crs-setup-conf" || target == "@ftw-conf") {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    if (!seen.count(target)) {
      seen.insert(target);
      out.append(asset->data, asset->size);
      out.push_back('\n');
    }
    return true;
  }

  if (target == "@owasp_crs/*.conf") {
    struct Ctx {
      std::string* out;
      std::set<std::string>* seen;
      std::string* error;
    } ctx{&out, &seen, &error};
    modsecurity_proxy_wasm_rules::foreach_owasp_crs(appendOwaspCrsGlobExpand, &ctx);
    return true;
  }

  if (target.rfind("@owasp_crs/", 0) == 0) {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    if (!seen.count(target)) {
      seen.insert(target);
      out.append(asset->data, asset->size);
      out.push_back('\n');
    }
    return true;
  }

  error = "unsupported Include target: " + target;
  return false;
}

bool expandJsonConfig(const std::string& json, std::string& rules_out, std::string& error) {
  std::string profile = extractJsonStringValue(json, "default_directives");
  if (profile.empty()) profile = "default";

  std::vector<std::string> directives = extractDirectiveArray(json, profile);
  if (directives.empty()) {
    error = "directives_map profile not found or empty: " + profile;
    return false;
  }

  std::set<std::string> seen;
  rules_out.clear();

  for (const auto& raw : directives) {
    std::string line = trim(raw);
    if (line.empty() || line.rfind("#", 0) == 0) continue;

    if (line.rfind("Include ", 0) == 0) {
      std::string target = trim(line.substr(8));
      if (!resolveIncludeExpand(target, rules_out, seen, error)) return false;
      continue;
    }

    rules_out.append(line);
    rules_out.push_back('\n');
  }
  return !rules_out.empty();
}

bool hasKubeWafIdentity(const std::string& config, const WafPluginOptions* opts) {
  if (opts != nullptr) {
    if (opts->mode == "kubewaf") {
      return true;
    }
    if (!opts->config_id.empty() && opts->config_id.rfind("kubewaf/", 0) == 0) {
      return true;
    }
    for (const auto& kv : opts->metrics.labels) {
      if (kv.first == "waf_name" || kv.first == "waf_namespace") {
        return true;
      }
    }
  }
  if (!looksLikeJson(trim(config))) {
    return false;
  }
  if (extractJsonStringValue(config, "mode") == "kubewaf") {
    return true;
  }
  std::string cid = extractJsonStringValue(config, "config_id");
  if (!cid.empty() && cid.rfind("kubewaf/", 0) == 0) {
    return true;
  }
  std::vector<std::pair<std::string, std::string>> labels;
  if (extractMetricLabels(config, labels)) {
    for (const auto& kv : labels) {
      if (kv.first == "waf_name" || kv.first == "waf_namespace") {
        return true;
      }
    }
  }
  return false;
}

void fillMetricOptions(const std::string& config, WafMetricOptions& out) {
  out.labels.clear();
  out.enabled = true;
  out.per_rule_id = true;
  out.rule_tags = true;
  out.dual_prefix = true;

  if (!looksLikeJson(trim(config))) {
    return;
  }
  extractMetricLabels(config, out.labels);

  // Nested metrics object preferred; flat keys remain as aliases.
  std::string metrics_obj;
  if (extractJsonObjectSlice(config, "metrics", metrics_obj)) {
    out.enabled = extractJsonBoolValue(metrics_obj, "enabled", true);
    out.per_rule_id = extractJsonBoolValue(metrics_obj, "per_rule_id", true);
    out.rule_tags = extractJsonBoolValue(metrics_obj, "rule_tags", true);
    out.dual_prefix = extractJsonBoolValue(metrics_obj, "dual_prefix", true);
  } else {
    out.per_rule_id = extractJsonBoolValue(config, "metrics_per_rule_id", true);
    out.rule_tags = extractJsonBoolValue(config, "metrics_rule_tags", true);
    // Flat enable flag not historically present; default true.
    out.enabled = extractJsonBoolValue(config, "metrics_enabled", true);
  }

  // Flat aliases override nested when present (explicit operator knobs).
  if (config.find("\"metrics_per_rule_id\"") != std::string::npos) {
    out.per_rule_id = extractJsonBoolValue(config, "metrics_per_rule_id", out.per_rule_id);
  }
  if (config.find("\"metrics_rule_tags\"") != std::string::npos) {
    out.rule_tags = extractJsonBoolValue(config, "metrics_rule_tags", out.rule_tags);
  }
}

void fillBlockOptions(const std::string& config, WafBlockOptions& out) {
  out = WafBlockOptions{};
  if (!looksLikeJson(trim(config))) {
    return;
  }
  std::string block_obj;
  if (extractJsonObjectSlice(config, "block", block_obj)) {
    std::string msg = extractJsonStringValue(block_obj, "message");
    if (!msg.empty()) {
      out.message = msg;
    }
    out.status = extractJsonIntValue(block_obj, "status", 0);
    out.add_rule_id_header = extractJsonBoolValue(block_obj, "add_rule_id_header", false);
    std::string hdr = extractJsonStringValue(block_obj, "rule_id_header");
    if (!hdr.empty()) {
      out.rule_id_header = hdr;
    }
  } else {
    std::string msg = extractJsonStringValue(config, "block_message");
    if (!msg.empty()) {
      out.message = msg;
    }
  }
}

}  // namespace

const char* kubeWafDefaultsConf() { return kKubeWafDefaultsConf; }

const char* defaultWafJsonConfig() {
  return R"({
  "directives_map": {
    "default": [
      "Include @demo-conf",
      "SecDebugLogLevel 9",
      "SecRuleEngine On",
      "Include @crs-setup-conf",
      "Include @owasp_crs/REQUEST-901-INITIALIZATION.conf",
      "Include @owasp_crs/*.conf"
    ]
  },
  "default_directives": "default"
})";
}

bool applyWafConfiguration(const std::string& config, RuleChunkLoader loader, void* user, std::string& error) {
  error.clear();
  auto trimmed = trim(config);
  if (trimmed.empty()) {
    error = "empty configuration";
    return false;
  }
  if (!looksLikeJson(trimmed)) {
    return loadChunk(loader, user, "plain-config", trimmed.data(), trimmed.size(), error);
  }
  return applyJsonConfig(trimmed, loader, user, error);
}

bool parseWafMetricOptions(const std::string& config, WafMetricOptions& out) {
  fillMetricOptions(config, out);
  return true;
}

bool parseWafPluginOptions(const std::string& config, WafPluginOptions& out) {
  out = WafPluginOptions{};
  if (!looksLikeJson(trim(config))) {
    return true;
  }
  fillMetricOptions(config, out.metrics);
  fillBlockOptions(config, out.block);
  out.mode = extractJsonStringValue(config, "mode");
  out.config_id = extractJsonStringValue(config, "config_id");
  out.allow_fallback = extractJsonBoolValue(config, "allow_fallback", false);
  // kubeWAF operator path is always fail-closed.
  if (hasKubeWafIdentity(config, &out)) {
    out.allow_fallback = false;
    if (out.block.message == "blocked by modsecurity") {
      out.block.message = "blocked by kubeWAF";
    }
  }
  return true;
}

bool wafConfigAllowsFallback(const std::string& config) {
  if (!looksLikeJson(trim(config))) {
    return false;
  }
  if (hasKubeWafIdentity(config, nullptr)) {
    return false;
  }
  return extractJsonBoolValue(config, "allow_fallback", false);
}

bool expandWafConfiguration(const std::string& config, std::string& rules_out, std::string& error) {
  error.clear();
  auto trimmed = trim(config);
  if (trimmed.empty()) {
    error = "empty configuration";
    return false;
  }
  if (!looksLikeJson(trimmed)) {
    rules_out = trimmed;
    return true;
  }
  return expandJsonConfig(trimmed, rules_out, error);
}
