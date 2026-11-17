# Version
GIT_HEAD_COMMIT ?= $(shell git rev-parse --short HEAD)
VERSION         ?= $(or $(shell git describe --abbrev=0 --tags --match "v*" 2>/dev/null),$(GIT_HEAD_COMMIT))

# Image URL to use all building/pushing image targets
IMG ?= controller:latest

# Defaults
REGISTRY        ?= ghcr.io
REPOSITORY      ?= kubewaf-io/kubewaf
GIT_TAG_COMMIT  ?= $(shell git rev-parse --short $(VERSION))
GIT_MODIFIED_1  ?= $(shell git diff $(GIT_HEAD_COMMIT) $(GIT_TAG_COMMIT) --quiet && echo "" || echo ".dev")
GIT_MODIFIED_2  ?= $(shell git diff --quiet && echo "" || echo ".dirty")
GIT_MODIFIED    ?= $(shell echo "$(GIT_MODIFIED_1)$(GIT_MODIFIED_2)")
GIT_REPO        ?= $(shell git config --get remote.origin.url)
BUILD_DATE      ?= $(shell git log -1 --format="%at" | xargs -I{} sh -c 'if [ "$(shell uname)" = "Darwin" ]; then date -r {} +%Y-%m-%dT%H:%M:%S; else date -d @{} +%Y-%m-%dT%H:%M:%S; fi')
IMG_BASE        ?= $(REPOSITORY)
IMG             ?= $(IMG_BASE):$(VERSION)
CONTROLLER_IMG  ?= $(REGISTRY)/$(IMG_BASE)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set).
# Soft-fail when go is not on PATH so tooling-only targets (kubectl/helm) still work.
GO_BIN := $(shell command -v go 2>/dev/null)
ifeq ($(GO_BIN),)
GOBIN :=
else ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

# Restrict controller-gen roots to API packages. Scanning ./... also walks
# website2 node_modules (broken template go.mod files).
# Object generation includes api/subresources (Probe result types).
# CRD generation must NOT include api/subresources — probes are aggregated
# APIService endpoints, not etcd-backed CRDs (would create a Local APIService
# that conflicts with aggregation).
CONTROLLER_GEN_OBJECT_PATHS ?= ./api/...
# v1alpha1 is the only served version.
CONTROLLER_GEN_CRD_PATHS ?= ./api/seclang/v1alpha1/...;./api/waf/v1alpha1/...

.PHONY: manifests
manifests: controller-gen ## Generate CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" crd paths="$(CONTROLLER_GEN_CRD_PATHS)" output:crd:artifacts:config=config/crd/v1alpha1
	mkdir -p charts/kubewaf/crds
	cp config/crd/v1alpha1/*.yaml charts/kubewaf/crds/

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="$(CONTROLLER_GEN_OBJECT_PATHS)"

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# Fast unit gate. Kind e2e is test/e2e/v1alpha1/run.sh.
.PHONY: test-unit-smoke
test-unit-smoke: setup-envtest ## Controller, webhook, and provider packages
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" \
		go test ./internal/webhook/ ./internal/controller/... ./internal/provider/... ./internal/compile/... -count=1

# Wait until CRDs report Established=True.
define wait-crd-established
	@for crd in $(1); do \
		echo "Waiting for CRD $$crd Established=True..."; \
		ok=0; \
		for i in $$(seq 1 60); do \
			st=$$($(KUBECTL) get crd $$crd -o jsonpath='{.status.conditions[?(@.type=="Established")].status}' 2>/dev/null || true); \
			if [ "$$st" = "True" ]; then echo "  $$crd established"; ok=1; break; fi; \
			sleep 1; \
		done; \
		if [ "$$ok" != "1" ]; then \
			echo "ERROR: timed out waiting for CRD $$crd Established=True" >&2; \
			$(KUBECTL) get crd $$crd -o yaml 2>/dev/null | tail -40 || true; \
			exit 1; \
		fi; \
	done
endef

KUBEWAF_CRDS ?= secrules.seclang.kubewaf.io secactions.seclang.kubewaf.io includes.seclang.kubewaf.io secpolicies.seclang.kubewaf.io protections.waf.kubewaf.io

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager ./cmd/operator

.PHONY: crs-converter
crs-converter: ## Build the CRS to v1alpha1 converter.
	go build -o bin/crs-converter ./cmd/crs-converter

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	KUBE_FEATURE_WatchListClient=false go run ./cmd/operator

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name wafv2-builder
	$(CONTAINER_TOOL) buildx use wafv2-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm wafv2-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize kubectl ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize kubectl ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize kubectl ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize kubectl ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= $(LOCALBIN)/kubectl
HELM ?= $(LOCALBIN)/helm
KUSTOMIZE ?= $(LOCALBIN)/kustomize
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
KUSTOMIZE_VERSION ?= v5.7.1
CONTROLLER_TOOLS_VERSION ?= v0.21.0
# kubectl client pin (aligned with kindest/node used by e2e Kind clusters)
KUBECTL_VERSION ?= v1.32.2
# kindest/node image tag for helm-create / chart install CI (must match a published kind node image)
KUBERNETES_SUPPORTED_VERSION ?= v1.32.2
# Helm CLI pin (https://github.com/helm/helm/releases)
HELM_VERSION ?= v3.17.3

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v2.5.0
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION))

license-headers: nwa
	$(NWA) config

####################
# -- Docker
####################

ifeq ($(GO_BIN),)
GOOS            ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
GOARCH          ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/armv7l/arm/')
else
GOOS            ?= $(shell go env GOOS)
GOARCH          ?= $(shell go env GOARCH)
endif
KO_PLATFORM     ?= $(GOOS)/$(GOARCH)
KOCACHE         ?= /tmp/ko-cache
KO_TAGS         ?= "latest"

ifdef VERSION
KO_TAGS         := $(KO_TAGS),$(VERSION)
endif


LD_FLAGS        := "-X main.Version=$(VERSION) \
					-X main.GitCommit=$(GIT_HEAD_COMMIT) \
					-X main.GitTag=$(VERSION) \
					-X main.GitTreeState=$(GIT_MODIFIED) \
					-X main.BuildDate=$(BUILD_DATE) \
					-X main.GitRepo=$(GIT_REPO)"

# Docker Image Build
# ------------------
.PHONY: ko-build-controller
ko-build-controller: ko
	echo Building Controller $(KO_TAGS) for $(KO_PLATFORM) >&2
	@LD_FLAGS=$(LD_FLAGS) KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(CONTROLLER_IMG) \
		$(KO) build ./cmd/operator --bare --tags=$(KO_TAGS) --local --push=false --platform=$(KO_PLATFORM)

.PHONY: ko-build-all
ko-build-all: ko-build-controller ## Build the operator image

# Docker Image Publish
# ------------------

REGISTRY_PASSWORD   ?= dummy
REGISTRY_USERNAME   ?= dummy

.PHONY: ko-login
ko-login: ko
	@$(KO) login $(REGISTRY) --username $(REGISTRY_USERNAME) --password $(REGISTRY_PASSWORD)

# peak-scale make-ko-publish captures ALL stdout as the image digest
# (`digest=$(make ko-publish-controller)`). Staging/login/recursive-make
# banners must stay on stderr so only `ko build`'s image ref is emitted.
# Publish uses .ko.yaml defaultPlatforms (no --platform) for multi-arch.
.PHONY: ko-publish-controller
ko-publish-controller:
	@$(MAKE) --no-print-directory ko ko-login >&2
	@LD_FLAGS=$(LD_FLAGS) KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(CONTROLLER_IMG) \
		$(KO) build ./cmd/operator --bare --tags=$(KO_TAGS) | tail -n1

.PHONY: ko-publish-all
ko-publish-all: ko-publish-controller ## Publish the operator image

####################
# -- Helm
####################

# Pin VERSION/KO_TAGS to Chart.appVersion so the image tag matches the chart
# default (templates use: image.tag | default .Chart.AppVersion). Do not add a
# "v" prefix — Chart.yaml stores a bare semver and awk on quoted YAML would also
# keep the quotes (v"0.1.0-beta.1"), which breaks kind load + pullPolicy Never.
helm-controller-version:
	$(eval VERSION := $(shell grep 'appVersion:' charts/kubewaf/Chart.yaml | sed -E 's/.*"([^"]+)".*/\1/'))
	$(eval KO_TAGS := $(VERSION))

.PHONY: helm-docs
helm-docs: helm-doc
	$(HELM_DOCS) --chart-search-root ./charts

.PHONY: helm-lint
helm-lint: ct
	@$(CT) lint --config .github/configs/ct.yaml --validate-yaml=false --all --debug

helm-schema: helm helm-plugin-schema
	cd charts/kubewaf && $(HELM) schema --use-helm-docs

helm-test: helm-create helm-install helm-destroy

helm-test-ct: ct helm-load-image
	@# Use relative path from repo root (SRC_ROOT was never set → "/.github/configs/ct.yaml").
	@$(CT) install --config .github/configs/ct.yaml --namespace=kubewaf-system --all --debug

# Cluster-level deps before chart-testing. Beta chart uses self-signed webhook
# certs (no cert-manager). Keep this target as an extension point for future deps.
.PHONY: install-dependencies
install-dependencies: kubectl ## Ensure kind cluster is ready for helm ct install
	@$(KUBECTL) cluster-info >/dev/null
	@$(KUBECTL) wait --for=condition=Ready nodes --all --timeout=120s
	@# kubewaf-crs (and chart-testing of pure CR charts) needs CRDs from the operator chart.
	@echo "Applying kubeWAF CRDs for helm chart install tests..."
	@$(KUBECTL) apply --server-side -f charts/kubewaf/crds/
	$(call wait-crd-established,$(KUBEWAF_CRDS))
	@echo "Helm install dependencies ready."

helm-install: install-dependencies helm-test-ct

helm-create: kind kubectl
	@printf '%s\n' \
		'kind: Cluster' \
		'apiVersion: kind.x-k8s.io/v1alpha4' \
		'networking:' \
		'  apiServerAddress: "0.0.0.0"' \
		| $(KIND) create cluster --wait=60s --name kubewaf --image kindest/node:$(KUBERNETES_SUPPORTED_VERSION) --config=-
	@$(KUBECTL) create ns kubewaf-system

helm-load-image: kind helm-controller-version ko-build-all
	@$(KIND) load docker-image --name kubewaf $(CONTROLLER_IMG):$(VERSION)

helm-destroy: kind
	@$(KIND) delete cluster --name kubewaf

####################
# -- Helm Plugins
####################

# Empty version = latest release of helm-values-schema-json.
HELM_SCHEMA_VERSION   ?=
helm-plugin-schema: helm
	@if ! $(HELM) plugin list 2>/dev/null | grep -q '^schema[[:space:]]'; then \
		if [ -n "$(HELM_SCHEMA_VERSION)" ]; then \
			$(HELM) plugin install https://github.com/losisin/helm-values-schema-json.git --version $(HELM_SCHEMA_VERSION) || true; \
		else \
			$(HELM) plugin install https://github.com/losisin/helm-values-schema-json.git || true; \
		fi; \
	fi

HELM_DOCS         := $(LOCALBIN)/helm-docs
HELM_DOCS_VERSION := v1.14.1
HELM_DOCS_LOOKUP  := norwoodj/helm-docs
helm-doc:
	@test -s $(HELM_DOCS) || \
	$(call go-install-tool,$(HELM_DOCS),github.com/$(HELM_DOCS_LOOKUP)/cmd/helm-docs@$(HELM_DOCS_VERSION))

CONTROLLER_GEN         := $(LOCALBIN)/controller-gen
CONTROLLER_GEN_VERSION ?= v0.21.0
CONTROLLER_GEN_LOOKUP  := kubernetes-sigs/controller-tools
controller-gen:
	@test -s $(CONTROLLER_GEN) && $(CONTROLLER_GEN) --version | grep -q $(CONTROLLER_GEN_VERSION) || \
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION))

CRD_REF_DOCS           := $(LOCALBIN)/crd-ref-docs
CRD_REF_DOCS_VERSION   ?= latest

.PHONY: crd-ref-docs
crd-ref-docs: $(CRD_REF_DOCS) ## Download crd-ref-docs locally if necessary.
	@test -s $(CRD_REF_DOCS) || $(call go-install-tool,$(CRD_REF_DOCS),github.com/elastic/crd-ref-docs@$(CRD_REF_DOCS_VERSION))

.PHONY: generate-crd-docs
generate-crd-docs: crd-ref-docs ## Generate CRD API reference documentation (for the docs website).
	$(CRD_REF_DOCS) \
		--config hack/crd-ref-docs-config.yaml \
		--source-path . \
		--renderer markdown \
		--output-path website2/content/en/docs/reference/crd-reference.md

##@ Documentation

# Docs site lives in website2/ (Hugo + Docsy, Kubernetes-style).
# Content: website2/content/en/
# Publish dir after build: website2/public/

.PHONY: docs-install
docs-install: ## Install documentation site dependencies (website2/)
	cd website2 && npm ci

.PHONY: docs-serve
docs-serve: ## Serve the documentation site locally with live reload (Hugo)
	cd website2 && $(MAKE) serve

.PHONY: docs-build
docs-build: ## Build the static documentation site into ./website2/public/ (for hosting)
	cd website2 && $(MAKE) build
	@echo "✅ Docs built → website2/public/"


CT         := $(LOCALBIN)/ct
CT_VERSION := v3.14.0
CT_LOOKUP  := helm/chart-testing
ct:
	@test -s $(CT) && $(CT) version | grep -q $(CT_VERSION) || \
	$(call go-install-tool,$(CT),github.com/$(CT_LOOKUP)/v3/ct@$(CT_VERSION))

KIND         := $(LOCALBIN)/kind
KIND_VERSION := v0.31.0
KIND_LOOKUP  := kubernetes-sigs/kind
kind:
	@test -s $(KIND) && $(KIND) --version | grep -q $(KIND_VERSION) || \
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind/cmd/kind@$(KIND_VERSION))

# helm is downloaded from the official release into bin/ (used by e2e + chart targets).
.PHONY: helm
helm: $(LOCALBIN) ## Download helm locally if missing or version-mismatched
	@os=$$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$$(uname -m); case $$arch in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; esac; \
	if [ -s "$(HELM)" ] && "$(HELM)" version --short 2>/dev/null | grep -q "$(HELM_VERSION)"; then \
		exit 0; \
	fi; \
	echo "Downloading helm $(HELM_VERSION) for $${os}/$${arch}..."; \
	tmp=$$(mktemp -d); \
	curl -fsSL "https://get.helm.sh/helm-$(HELM_VERSION)-$${os}-$${arch}.tar.gz" \
		| tar -xz -C "$$tmp"; \
	install -m 0755 "$$tmp/$${os}-$${arch}/helm" "$(HELM)"; \
	rm -rf "$$tmp"; \
	"$(HELM)" version --short

# kubectl is downloaded from the official Kubernetes release into bin/.
.PHONY: kubectl
kubectl: $(LOCALBIN) ## Download kubectl locally if missing or version-mismatched
	@os=$$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$$(uname -m); case $$arch in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; esac; \
	if [ -s "$(KUBECTL)" ] && "$(KUBECTL)" version --client 2>/dev/null | grep -q "$(KUBECTL_VERSION)"; then \
		exit 0; \
	fi; \
	echo "Downloading kubectl $(KUBECTL_VERSION) for $${os}/$${arch}..."; \
	curl -fsSL -o "$(KUBECTL)" "https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$${os}/$${arch}/kubectl"; \
	chmod +x "$(KUBECTL)"; \
	"$(KUBECTL)" version --client

KO           := $(LOCALBIN)/ko
KO_VERSION   := v0.18.1
KO_LOOKUP    := google/ko
ko:
	@test -s $(KO) && $(KO) -h | grep -q $(KO_VERSION) || \
	$(call go-install-tool,$(KO),github.com/$(KO_LOOKUP)@$(KO_VERSION))

NWA           := $(LOCALBIN)/nwa
NWA_VERSION   := v0.7.8
NWA_LOOKUP    := B1NARY-GR0UP/nwa
nwa:
	@test -s $(NWA) && $(NWA) -h | grep -q $(NWA_VERSION) || \
	$(call go-install-tool,$(NWA),github.com/$(NWA_LOOKUP)@$(NWA_VERSION))

GOLANGCI_LINT          := $(LOCALBIN)/golangci-lint
GOLANGCI_LINT_VERSION  := v2.12.2
GOLANGCI_LINT_LOOKUP   := golangci/golangci-lint
golangci-lint: ## Download golangci-lint locally if necessary.
	@test -s $(GOLANGCI_LINT) && $(GOLANGCI_LINT) -h | grep -q $(GOLANGCI_LINT_VERSION) || \
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/$(GOLANGCI_LINT_LOOKUP)/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-install-tool
[ -f $(1) ] || { \
    set -e ;\
    GOBIN=$(LOCALBIN) go install $(2) ;\
}
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

# Linting code as PR is expecting
.PHONY: golint
golint: golangci-lint
	$(GOLANGCI_LINT) run -c .golangci.yaml --verbose

