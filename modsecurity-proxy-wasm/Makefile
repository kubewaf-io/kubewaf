# Makefile for modsecurity-proxy-wasm
#
# All compile logic lives in build/build.mk (single source of truth).
# Container build: build/docker/Dockerfile (context = repo root).

IMAGE ?= modsecurity-proxy-wasm:latest
CTR ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
DAGGER ?= $(shell command -v dagger 2>/dev/null)
DOCKERFILE := build/docker/Dockerfile
DOCKERFILE_OCI := build/docker/Dockerfile.oci
WASM_OUT := dist/modsecurity-proxy-wasm.wasm

# --- Pinned dependencies (Renovate: customManagers:makefileVersions + renovate.json) ---

# renovate: datasource=github-tags depName=emscripten-core/emsdk versioning=semver-coerced
EMSDK_VERSION ?= 3.1.74

# renovate: datasource=github-tags depName=proxy-wasm/proxy-wasm-cpp-sdk versioning=git
PROXY_WASM_CPP_SDK_VERSION ?= 727de65b37507611b76123316c6832581f42d4f0

# renovate: datasource=github-tags depName=owasp-modsecurity/ModSecurity versioning=semver
MODSECURITY_VERSION ?= v3.0.15
# renovate: datasource=github-tags depName=owasp-modsecurity/ModSecurity versioning=semver digest
MODSECURITY_SHA ?= 0fb4aff98b4980cf6426697d5605c424e3d5bb60

# renovate: datasource=github-tags depName=PCRE2Project/pcre2
PCRE2_VERSION ?= pcre2-10.47
# renovate: datasource=github-tags depName=PCRE2Project/pcre2 digest
PCRE2_SHA ?= f454e231fe5006dd7ff8f4693fd2b8eb94333429

# renovate: datasource=github-tags depName=coreruleset/coreruleset versioning=semver
CRS_VERSION ?= v4.27.0

# renovate: datasource=docker depName=ghcr.io/coreruleset/go-ftw
GO_FTW_VERSION ?= 2.4.0

# renovate: datasource=docker depName=envoyproxy/envoy versioning=loose
ENVOY_IMAGE ?= envoyproxy/envoy:v1.38-latest

BUILD_ARGS := $(if $(CRS_VERSION),--build-arg CRS_VERSION=$(CRS_VERSION),) \
              $(if $(VERSION),--build-arg VERSION=$(VERSION),)

include build/build.mk
include build/test.mk

.PHONY: help image image-builder image-oci extract-wasm test-envoy test-envoy-keep \
	test-regression test-regression-keep test-unit test-fuzz test-bats deps-test \
	test-perf-k6 test-perf-k6-compare test-perf-k6-ci test-perf-k6-keep \
	test-perf-charts test-perf-release deps-perf-charts \
	verify-getentropy-stub clean dagger-build \
	dagger-test dagger-ci dagger-export-wasm dagger-export-image dagger-publish dagger-check

.DEFAULT_GOAL := help

help:
	@echo "Build (make is the single source of truth; Dockerfile runs 'make all'):"
	@echo "  make all            Build deps + dist/modsecurity-proxy-wasm.wasm + dist/modsecurity-proxy-wasm.wat"
	@echo "  make deps           Fetch/build emsdk, SDK, PCRE2, ModSecurity, CRS"
	@echo "  make modsecurity-proxy-wasm.wasm    Link plugin (implies deps + generate-rules)"
	@echo ""
	@echo "Container images:"
	@echo "  make image          Build wasm + OCI artifact (build/docker/Dockerfile)"
	@echo "  make image-builder  Builder stage only"
	@echo "  make image-oci      OCI image from dist/modsecurity-proxy-wasm.wasm"
	@echo "  make extract-wasm   Copy wasm from IMAGE into dist/"
	@echo ""
	@echo "Tests:"
	@echo "  make deps-test         Fetch bats-core + googletest into test/.tools/"
	@echo "  make test-unit         Native gtest for waf_config (fast)"
	@echo "  make test-bats         Envoy integration smoke tests (needs dist/modsecurity-proxy-wasm.wasm)"
	@echo "  make test-envoy        Alias for test-bats + verify-getentropy-stub"
	@echo "  make test-regression   CRS go-ftw regression (FTW_INCLUDE='^941.*' for subset)"
	@echo "  make test-fuzz         libFuzzer smoke on waf_config (needs clang++)"
	@echo "  make test-perf-k6          k6 load test (PERF_PROFILE / PERF_SCENARIO)"
	@echo "  make test-perf-k6-compare  modsecurity-proxy-wasm vs coraza pair for PERF_PROFILE"
	@echo "  make test-perf-k6-ci       Smoke: baseline + modsecurity-proxy-wasm/coraza pairs"
	@echo "  make test-perf-charts      Overlay chart from latest perf results"
	@echo "  make test-perf-release     Perf smoke + release overlay chart"
	@echo "  make verify-getentropy-stub  Policy check for wasm getentropy stub"

# --- OCI / Podman / Docker ---

image:
	@test -n "$(CTR)" || (echo "ERROR: install podman or docker" >&2; exit 1)
	$(CTR) build $(BUILD_ARGS) -f $(DOCKERFILE) -t $(IMAGE) .

image-builder:
	@test -n "$(CTR)" || (echo "ERROR: install podman or docker" >&2; exit 1)
	$(CTR) build $(BUILD_ARGS) -f $(DOCKERFILE) --target builder -t modsecurity-proxy-wasm-builder .

image-oci:
	@test -n "$(CTR)" || (echo "ERROR: install podman or docker" >&2; exit 1)
	@test -f $(WASM_OUT) || (echo "ERROR: $(WASM_OUT) not found. Run: make image" >&2; exit 1)
	$(CTR) build -f $(DOCKERFILE_OCI) -t $(IMAGE) .

extract-wasm:
	CTR="$(CTR)" ./build/scripts/extract-wasm-from-image.sh $(IMAGE) dist

verify-getentropy-stub:
	./test/integration/verify-getentropy-stub.sh

test-envoy: test-bats

test-envoy-keep:
	KEEP_RUNNING=1 ENVOY_IMAGE=$(ENVOY_IMAGE) $(MAKE) test-bats

test-regression: verify-getentropy-stub
	CRS_VERSION=$(CRS_VERSION) GO_FTW_VERSION=$(GO_FTW_VERSION) ENVOY_IMAGE=$(ENVOY_IMAGE) ./test/regression/run-ftw.sh

test-regression-keep:
	KEEP_RUNNING=1 CRS_VERSION=$(CRS_VERSION) GO_FTW_VERSION=$(GO_FTW_VERSION) ENVOY_IMAGE=$(ENVOY_IMAGE) ./test/regression/run-ftw.sh

clean: clean-build

# --- Dagger (local + CI) ---

dagger-build:
	@test -n "$(DAGGER)" || (echo "ERROR: install dagger CLI — https://docs.dagger.io/installation" >&2; exit 1)
	$(DAGGER) call export-wasm --path=$(WASM_OUT)

dagger-test dagger-ci:
	@test -n "$(DAGGER)" || (echo "ERROR: install dagger CLI — https://docs.dagger.io/installation" >&2; exit 1)
	$(DAGGER) call ci

dagger-export-wasm: dagger-build

dagger-export-image:
	@test -n "$(DAGGER)" || (echo "ERROR: install dagger CLI" >&2; exit 1)
	$(DAGGER) call export-image --name=$(IMAGE)

dagger-publish:
	@test -n "$(DAGGER)" || (echo "ERROR: install dagger CLI" >&2; exit 1)
	@test -n "$(IMAGE)" || (echo "ERROR: set IMAGE=registry/repo:tag" >&2; exit 1)
	@test -n "$(REGISTRY_PASSWORD)" || (echo "ERROR: set REGISTRY_PASSWORD for registry auth" >&2; exit 1)
	REGISTRY_PASSWORD=$(REGISTRY_PASSWORD) $(DAGGER) call publish \
		--image=$(IMAGE) \
		$(if $(REGISTRY),--registry=$(REGISTRY),) \
		$(if $(REGISTRY_USERNAME),--username=$(REGISTRY_USERNAME),) \
		--password=env://REGISTRY_PASSWORD

dagger-check:
	@test -n "$(DAGGER)" || (echo "ERROR: install dagger CLI" >&2; exit 1)
	$(DAGGER) check