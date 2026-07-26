#include "waf_config.h"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) {
    return 0;
  }
  std::string input(reinterpret_cast<const char*>(data), size);

  WafMetricOptions opts;
  (void)parseWafMetricOptions(input, opts);
  (void)wafConfigAllowsFallback(input);

  std::string rules;
  std::string error;
  (void)expandWafConfiguration(input, rules, error);

  struct Ctx {
    int chunks{0};
  } ctx;
  auto loader = +[](const char* /*label*/, const char* /*data*/, std::size_t /*size*/, void* user,
                    std::string& /*error*/) -> bool {
    static_cast<Ctx*>(user)->chunks++;
    return true;
  };
  (void)applyWafConfiguration(input, loader, &ctx, error);
  return 0;
}