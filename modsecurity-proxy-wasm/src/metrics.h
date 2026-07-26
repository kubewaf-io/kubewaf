#ifndef MODSECURITY_PROXY_WASM_METRICS_H_
#define MODSECURITY_PROXY_WASM_METRICS_H_

#include <cstdint>
#include <list>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

struct WafMetricOptions {
  std::vector<std::pair<std::string, std::string>> labels;
  bool enabled{true};
  bool per_rule_id{true};
  bool rule_tags{true};
  // When true, core counters are also emitted under kubewaf_waf.* for product dashboards.
  bool dual_prefix{true};
};

class ModSecMetrics {
 public:
  void configure(const WafMetricOptions& options);

  void countTxTotal();
  void countTxAllowed();
  void countTxInterruption(const char* phase, int64_t rule_id);

  void countRuleMatch(int rule_phase, int severity, bool disruptive, int64_t rule_id,
                      const std::list<std::string>& tags);
  void countResponseBodySanitized();
  void countConfigureFallbackRules();
  void recordWasmMemory();

 private:
  void incrementCounter(const std::string& name);
  void incrementCoreCounter(const std::string& legacy_suffix, const std::string& product_suffix);
  void setGauge(const std::string& name, uint64_t value);
  bool trackDistinct(std::string& name, size_t& distinct_count, size_t max_distinct);
  std::string labelSuffix() const;
  static const char* phaseNameFromRule(int rule_phase);
  static bool isInterestingRuleTag(std::string_view tag);
  static std::string sanitizeTagForMetric(std::string_view tag);

  WafMetricOptions options_;
  std::unordered_map<std::string, uint32_t> metric_ids_;
  uint64_t tx_count_{0};
  size_t distinct_rule_metrics_{0};
  size_t distinct_tag_metrics_{0};
  static constexpr size_t kMaxDistinctRuleMetrics = 512;
  static constexpr size_t kMaxDistinctTagMetrics = 128;
};

namespace modsecurity_proxy_wasm_metric_phase {
constexpr const char* kRequestHeaders = "http_request_headers";
constexpr const char* kRequestBody = "http_request_body";
constexpr const char* kResponseHeaders = "http_response_headers";
constexpr const char* kResponseBody = "http_response_body";
constexpr const char* kLogging = "http_logging";
}  // namespace modsecurity_proxy_wasm_metric_phase

#endif
