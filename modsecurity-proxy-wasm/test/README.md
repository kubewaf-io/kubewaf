# Tests

| Directory | Purpose |
|-----------|---------|
| [fixtures/](fixtures/) | Envoy YAML and default WAF JSON configs |
| [integration/](integration/) | Bats smoke tests, getentropy policy, V8 runtime checks |
| [regression/](regression/) | CRS go-ftw regression (`run-ftw.sh`, `ftw/`) |
| [unit/](unit/) | Native gtest for `waf_config` |
| [fuzz/](fuzz/) | libFuzzer smoke on config parsing |
| [perf/](perf/) | k6 load tests and chart rendering |

Run from repo root:

```bash
make test-unit
make test-bats
make test-regression
```