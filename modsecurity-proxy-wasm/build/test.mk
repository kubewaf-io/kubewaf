# Test targets (bats integration, gtest unit, libFuzzer).

ROOT_DIR        := $(abspath .)
TEST_DIR        := $(ROOT_DIR)/test
WASM_OUT        := $(ROOT_DIR)/dist/modsecurity-proxy-wasm.wasm
TEST_TOOLS_DIR  := $(TEST_DIR)/.tools
BATS_BIN        := $(shell command -v bats 2>/dev/null)
ifeq ($(BATS_BIN),)
  BATS_BIN      := $(TEST_TOOLS_DIR)/bats-core/bin/bats
endif

GTEST_DIR       := $(TEST_TOOLS_DIR)/googletest
UNIT_BUILD_DIR  := $(TEST_DIR)/unit/.build
FUZZ_BUILD_DIR  := $(TEST_DIR)/fuzz/.build

UNIT_CXX        ?= g++
UNIT_CXXFLAGS   := -std=c++17 -Wall -Wextra -I$(ROOT_DIR)/src \
                   -I$(TEST_DIR)/unit -I$(GTEST_DIR)/googletest/include -I$(GTEST_DIR)/googlemock/include
UNIT_LDFLAGS    := -L$(UNIT_BUILD_DIR) -lgtest_main -lgtest -pthread

.PHONY: deps-test deps-perf-charts test-unit test-fuzz test-bats \
	test-perf-k6 test-perf-k6-compare test-perf-k6-ci test-perf-k6-keep \
	test-perf-charts test-perf-release-compare test-perf-release

deps-test:
	@bash $(TEST_DIR)/install-test-tools.sh

$(UNIT_BUILD_DIR)/libgtest.a $(UNIT_BUILD_DIR)/libgtest_main.a: deps-test
	@mkdir -p $(UNIT_BUILD_DIR)
	$(UNIT_CXX) -std=c++17 -I$(GTEST_DIR)/googletest -I$(GTEST_DIR)/googletest/include \
		-c $(GTEST_DIR)/googletest/src/gtest-all.cc -o $(UNIT_BUILD_DIR)/gtest-all.o
	$(UNIT_CXX) -std=c++17 -I$(GTEST_DIR)/googletest -I$(GTEST_DIR)/googletest/include \
		-c $(GTEST_DIR)/googletest/src/gtest_main.cc -o $(UNIT_BUILD_DIR)/gtest_main-all.o
	ar rcs $(UNIT_BUILD_DIR)/libgtest.a $(UNIT_BUILD_DIR)/gtest-all.o
	ar rcs $(UNIT_BUILD_DIR)/libgtest_main.a $(UNIT_BUILD_DIR)/gtest_main-all.o

$(UNIT_BUILD_DIR)/waf_config_test: deps-test \
		$(ROOT_DIR)/src/waf_config.cc \
		$(TEST_DIR)/unit/stub_rules_catalog.cc \
		$(TEST_DIR)/unit/waf_config_test.cc \
		$(UNIT_BUILD_DIR)/libgtest.a $(UNIT_BUILD_DIR)/libgtest_main.a
	@mkdir -p $(UNIT_BUILD_DIR)
	$(UNIT_CXX) $(UNIT_CXXFLAGS) -c $(ROOT_DIR)/src/waf_config.cc -o $(UNIT_BUILD_DIR)/waf_config.o
	$(UNIT_CXX) $(UNIT_CXXFLAGS) -c $(TEST_DIR)/unit/stub_rules_catalog.cc -o $(UNIT_BUILD_DIR)/stub_rules_catalog.o
	$(UNIT_CXX) $(UNIT_CXXFLAGS) -c $(TEST_DIR)/unit/waf_config_test.cc -o $(UNIT_BUILD_DIR)/waf_config_test.o
	$(UNIT_CXX) $(UNIT_CXXFLAGS) -o $(UNIT_BUILD_DIR)/waf_config_test \
		$(UNIT_BUILD_DIR)/waf_config_test.o $(UNIT_BUILD_DIR)/waf_config.o \
		$(UNIT_BUILD_DIR)/stub_rules_catalog.o $(UNIT_LDFLAGS)

test-unit: $(UNIT_BUILD_DIR)/waf_config_test
	$(UNIT_BUILD_DIR)/waf_config_test

$(FUZZ_BUILD_DIR)/waf_config_fuzz: deps-test \
		$(ROOT_DIR)/src/waf_config.cc \
		$(TEST_DIR)/unit/stub_rules_catalog.cc \
		$(TEST_DIR)/fuzz/waf_config_fuzz.cc
	@command -v clang++ >/dev/null 2>&1 || (echo "ERROR: clang++ required for fuzz target" >&2; exit 1)
	@mkdir -p $(FUZZ_BUILD_DIR)
	clang++ -std=c++17 -fsanitize=fuzzer,address $(UNIT_CXXFLAGS) -c $(ROOT_DIR)/src/waf_config.cc \
		-o $(FUZZ_BUILD_DIR)/waf_config.o
	clang++ -std=c++17 -fsanitize=fuzzer,address $(UNIT_CXXFLAGS) -c $(TEST_DIR)/unit/stub_rules_catalog.cc \
		-o $(FUZZ_BUILD_DIR)/stub_rules_catalog.o
	clang++ -std=c++17 -fsanitize=fuzzer,address $(UNIT_CXXFLAGS) -c $(TEST_DIR)/fuzz/waf_config_fuzz.cc \
		-o $(FUZZ_BUILD_DIR)/waf_config_fuzz.o
	clang++ -std=c++17 -fsanitize=fuzzer,address -o $(FUZZ_BUILD_DIR)/waf_config_fuzz \
		$(FUZZ_BUILD_DIR)/waf_config_fuzz.o $(FUZZ_BUILD_DIR)/waf_config.o $(FUZZ_BUILD_DIR)/stub_rules_catalog.o

test-fuzz: $(FUZZ_BUILD_DIR)/waf_config_fuzz
	$(FUZZ_BUILD_DIR)/waf_config_fuzz -max_total_time=10 -runs=10000

test-bats: deps-test verify-getentropy-stub
	@test -f $(WASM_OUT) || (echo "ERROR: $(WASM_OUT) not found. Run: make image" >&2; exit 1)
	@test -x "$(BATS_BIN)" || (echo "ERROR: bats not found at $(BATS_BIN)" >&2; exit 1)
	ENVOY_IMAGE=$(ENVOY_IMAGE) "$(BATS_BIN)" $(TEST_DIR)/integration/bats/

test-perf-k6:
	@chmod +x $(TEST_DIR)/perf/run-k6.sh $(TEST_DIR)/perf/collect-stats.sh \
		$(TEST_DIR)/perf/finalize-memory.sh $(TEST_DIR)/perf/fetch-coraza-wasm.sh
	ENVOY_IMAGE=$(ENVOY_IMAGE) $(TEST_DIR)/perf/run-k6.sh

test-perf-k6-compare:
	@chmod +x $(TEST_DIR)/perf/run-k6.sh $(TEST_DIR)/perf/collect-stats.sh \
		$(TEST_DIR)/perf/finalize-memory.sh $(TEST_DIR)/perf/fetch-coraza-wasm.sh
	ENVOY_IMAGE=$(ENVOY_IMAGE) $(TEST_DIR)/perf/run-k6.sh --compare

test-perf-k6-ci:
	@test -f $(WASM_OUT) || (echo "ERROR: $(WASM_OUT) not found. Run: make image" >&2; exit 1)
	@chmod +x $(TEST_DIR)/perf/run-k6.sh $(TEST_DIR)/perf/collect-stats.sh \
		$(TEST_DIR)/perf/finalize-memory.sh $(TEST_DIR)/perf/fetch-coraza-wasm.sh
	ENVOY_IMAGE=$(ENVOY_IMAGE) PERF_CI=1 $(TEST_DIR)/perf/run-k6.sh --ci --all-smoke

test-perf-k6-keep:
	@chmod +x $(TEST_DIR)/perf/run-k6.sh $(TEST_DIR)/perf/collect-stats.sh
	KEEP_RUNNING=1 ENVOY_IMAGE=$(ENVOY_IMAGE) $(TEST_DIR)/perf/run-k6.sh

CHARTS_VENV    := $(TEST_TOOLS_DIR)/charts-venv
CHARTS_PYTHON  := $(shell if [ -x "$(TEST_TOOLS_DIR)/charts-venv/bin/python3" ]; then echo "$(TEST_TOOLS_DIR)/charts-venv/bin/python3"; elif python3 -c "import matplotlib" 2>/dev/null; then echo python3; else echo "$(TEST_TOOLS_DIR)/charts-venv/bin/python3"; fi)

deps-perf-charts:
	@python3 -c "import matplotlib" 2>/dev/null && exit 0; \
	test -d $(CHARTS_VENV) || python3 -m venv $(CHARTS_VENV); \
	$(CHARTS_VENV)/bin/pip install -q -r $(TEST_DIR)/perf/requirements-charts.txt

test-perf-charts: deps-perf-charts
	@chmod +x $(TEST_DIR)/perf/render-charts.py
	@$(CHARTS_PYTHON) $(TEST_DIR)/perf/render-charts.py bundle $(TEST_DIR)/perf/results \
		-o $(TEST_DIR)/perf/release-charts
	@test -f $(TEST_DIR)/perf/release-charts/perf-overlay.png

test-perf-release-compare:
	@chmod +x $(TEST_DIR)/perf/run-release-compare.sh $(TEST_DIR)/perf/fetch-release-wasm.sh \
		$(TEST_DIR)/perf/run-k6.sh $(TEST_DIR)/perf/collect-stats.sh $(TEST_DIR)/perf/finalize-memory.sh
	@CURRENT_TAG="$${GITHUB_REF_NAME:-$$(git describe --tags --abbrev=0 2>/dev/null || true)}" \
		GITHUB_REPOSITORY="$${GITHUB_REPOSITORY:-}" \
		PERF_CI=1 ENVOY_IMAGE=$(ENVOY_IMAGE) \
		$(TEST_DIR)/perf/run-release-compare.sh

test-perf-release: test-perf-k6-ci test-perf-release-compare test-perf-charts