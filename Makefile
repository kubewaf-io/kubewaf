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
CONTROLLER_GEN_CRD_PATHS ?= ./api/seclang/...;./api/waf/...

.PHONY: manifests
manifests: controller-gen ## Generate CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" crd paths="$(CONTROLLER_GEN_CRD_PATHS)" output:crd:artifacts:config=charts/kubewaf/crds
	@rm -f charts/kubewaf/crds/subresources.kubewaf.io_*.yaml config/crd/bases/subresources.kubewaf.io_*.yaml 2>/dev/null || true

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

# Fast CI gate used by test-e2e-release.yml unit-smoke (controller suites need envtest binaries).
.PHONY: test-unit-smoke
test-unit-smoke: setup-envtest ## Critical packages only (webhook, config, refs, controllers)
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" \
		go test ./internal/webhook/ ./internal/dataplane/config/ ./internal/references2/ ./internal/controller/... -count=1

# E2E matrix
#   E2E_PROVIDER=all|envoy-gateway|istio|cilium|manager|probe
#   E2E_PROBE=true              force Subresource probe e2e with other providers
#   E2E_SUBRESOURCE_IMG / E2E_PROBE_TEST_IMG  optional probe stack images
#   E2E_WASM_SOURCE_URL=...   real coraza .wasm for traffic tests
#   E2E_IMG=ghcr.io/kubewaf-io/kubewaf:e2e
#   E2E_ISTIO_TRAFFIC=true|false   Istio UA traffic smoke (default: on)
#   E2E_CILIUM_TRAFFIC=true|false  Cilium UA traffic smoke (default: on)
#   E2E_FTW_PATH_B=true         first-class CRS go-ftw (path-b wasm + structured SecRules)
#   E2E_FTW_PATH_A=true         second-class Path A go-ftw (needs full-catalog wasm)
#   E2E_SKIP_FTW=true           skip go-ftw
#   E2E_FTW_INCLUDE=^913|all    go-ftw -i filter (default scanner-detection smoke)
#   E2E_CRS_FULL=true           also deploy full structured CRS RuleSet during setup
#   CERT_MANAGER_INSTALL_SKIP=true
KIND_CLUSTER ?= kubewaf-e2e
E2E_PROVIDER ?= all
E2E_IMG ?= ghcr.io/kubewaf-io/kubewaf:e2e
E2E_FTW_INCLUDE ?= ^913
# Provider traffic smoke (benign 200 / sqlmap 403). Empty = enabled (see trafficOptIn).
E2E_ISTIO_TRAFFIC ?=
E2E_CILIUM_TRAFFIC ?=
# When true, provider setup targets also run setup-test-e2e-crs-full.
E2E_CRS_FULL ?= false

# Versions for provider installs
ENVOY_GATEWAY_VERSION ?= v1.8.3
ISTIO_VERSION ?= 1.30.3
# Latest stable Cilium (helm search repo cilium/cilium --versions)
CILIUM_VERSION ?= 1.19.6
# Gateway API CRDs required when gatewayAPI.enabled=true (Cilium does not install them).
GATEWAY_API_VERSION ?= v1.6.1
# CRS go-ftw pins (https://github.com/coreruleset/go-ftw)
CRS_VERSION ?= v4.28.0
GO_FTW_VERSION ?= 2.5.0
# Namespace used by e2e manifests (demo app, WAF, structured CRS).
E2E_NAMESPACE ?= demo

# Wait until CRDs report Established=True. Prefer this over
#   kubectl wait --for condition=established crd/...
# Freshly applied CRDs often have status.conditions=null for a short window;
# kubectl wait then fails with:
#   .status.conditions accessor error: <nil> is of the type <nil>, expected []interface{}
# Usage: $(call wait-crd-established,wafs.waf.kubewaf.io rulesets.waf.kubewaf.io ...)
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

# Default kubeWAF product CRDs applied from charts/kubewaf/crds/.
KUBEWAF_CRDS ?= wafs.waf.kubewaf.io rulesets.waf.kubewaf.io secrules.seclang.kubewaf.io secruleidpools.seclang.kubewaf.io secactions.seclang.kubewaf.io phraselists.seclang.kubewaf.io iplists.seclang.kubewaf.io

.PHONY: kind-cluster
kind-cluster: kind ## Create Kind cluster if missing
	@command -v $(KIND) >/dev/null 2>&1 || { echo "Kind is not installed."; exit 1; }
	@case "$$($(KIND) get clusters 2>/dev/null)" in \
		*"$(KIND_CLUSTER)"*) echo "Kind cluster '$(KIND_CLUSTER)' already exists." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)' (kindest/node:$(KUBERNETES_SUPPORTED_VERSION))..."; \
			printf '%s\n' \
				'kind: Cluster' \
				'apiVersion: kind.x-k8s.io/v1alpha4' \
				'networking:' \
				'  apiServerAddress: "0.0.0.0"' \
				| $(KIND) create cluster --name $(KIND_CLUSTER) \
					--image kindest/node:$(KUBERNETES_SUPPORTED_VERSION) --config=- ;; \
	esac

.PHONY: kind-cluster-cilium
kind-cluster-cilium: kind ## Create Kind cluster without default CNI (for Cilium)
	@command -v $(KIND) >/dev/null 2>&1 || { echo "Kind is not installed."; exit 1; }
	@case "$$($(KIND) get clusters 2>/dev/null)" in \
		*"$(KIND_CLUSTER)"*) echo "Kind cluster '$(KIND_CLUSTER)' already exists. Delete it first for a clean Cilium CNI install." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)' with disableDefaultCNI (kindest/node:$(KUBERNETES_SUPPORTED_VERSION))..."; \
			printf '%s\n' \
				'kind: Cluster' \
				'apiVersion: kind.x-k8s.io/v1alpha4' \
				'networking:' \
				'  apiServerAddress: "0.0.0.0"' \
				'  disableDefaultCNI: true' \
				'  kubeProxyMode: none' \
				'nodes:' \
				'- role: control-plane' \
				| $(KIND) create cluster --name $(KIND_CLUSTER) \
					--image kindest/node:$(KUBERNETES_SUPPORTED_VERSION) --config=- ;; \
	esac

.PHONY: setup-test-e2e-envoy-gateway
setup-test-e2e-envoy-gateway: kind-cluster egctl helm kubectl ## Install Envoy Gateway + demo app for e2e
	@echo "Installing Envoy Gateway $(ENVOY_GATEWAY_VERSION) with kubeWAF extensionManager..."
	@$(HELM) upgrade --install eg oci://docker.io/envoyproxy/gateway-helm \
		--version $(ENVOY_GATEWAY_VERSION) \
		--namespace envoy-gateway-system \
		--create-namespace \
		--values test/e2e/manifests/envoygateway/envoy-gateway-values.yaml \
		--wait --timeout=5m
	@# Preload images used by traffic probes / go-ftw (avoids pull races under Eventually loops).
	@for img in curlimages/curl:8.5.0 ghcr.io/coreruleset/albedo:0.2.0 alpine/socat:1.8.0.0 \
		otel/opentelemetry-collector-contrib:0.128.0 \
		victoriametrics/victoria-metrics:v1.117.1 \
		victoriametrics/victoria-traces:v0.4.0; do \
		docker pull "$$img" >/dev/null 2>&1 || true; \
		$(KIND) load docker-image "$$img" --name $(KIND_CLUSTER) 2>/dev/null || true; \
	done
	@# EG extensionManager must list/watch WAF CRs (policyResources).
	@$(KUBECTL) apply -f test/e2e/manifests/envoygateway/eg-waf-rbac.yaml
	@$(KUBECTL) apply -f test/e2e/manifests/00-test-application.yaml
	@$(KUBECTL) apply -f test/e2e/manifests/envoygateway/gateway.yaml
	@$(KUBECTL) wait --for=condition=Ready pod/httpbin -n demo --timeout=2m || true
	@# Wait for Gateway to be programmed (and proxy Service endpoints) before e2e suites.
	@echo "Waiting for demo-gateway Programmed=True..."
	@for i in $$(seq 1 80); do \
		st=$$($(KUBECTL) get gateways.gateway.networking.k8s.io demo-gateway -n demo \
			-o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' 2>/dev/null || true); \
		if [ "$$st" = "True" ]; then echo "demo-gateway Programmed=True"; break; fi; \
		if [ "$$i" -eq 80 ]; then \
			echo "WARN: demo-gateway Programmed not True yet (status=$$st); e2e will wait further"; \
			$(KUBECTL) get gateways.gateway.networking.k8s.io demo-gateway -n demo -o yaml 2>/dev/null | tail -40 || true; \
		fi; \
		sleep 3; \
	done
	@# Demo SecRule/RuleSet + WAF (CRDs first; operator reconcile after helm install).
	@$(KUBECTL) apply -f charts/kubewaf/crds/
	$(call wait-crd-established,$(KUBEWAF_CRDS))
	@$(KUBECTL) apply -f test/e2e/manifests/common/rules.yaml
	@$(KUBECTL) apply -f test/e2e/manifests/envoygateway/waf.yaml
	@if [ "$(E2E_CRS_FULL)" = "true" ] || [ "$(E2E_CRS_FULL)" = "1" ] || [ "$(E2E_CRS_FULL)" = "yes" ]; then \
		$(MAKE) setup-test-e2e-crs-full; \
	fi
	@echo "Envoy Gateway e2e environment ready (extensionManager → kubewaf-ecds:5005)."
	@echo "egctl available at $(EGCTL) (version $(ENVOY_GATEWAY_VERSION))."

.PHONY: setup-test-e2e-istio
setup-test-e2e-istio: kind-cluster helm kubectl ## Install Istio + demo app for e2e
	@# Same CRDs as Cilium path: demo Gateway/HTTPRoute use gateway.networking.k8s.io/v1.
	@echo "Installing Gateway API CRDs $(GATEWAY_API_VERSION) (required for Istio Gateway API)..."
	@$(KUBECTL) apply --server-side -f \
		https://github.com/kubernetes-sigs/gateway-api/releases/download/$(GATEWAY_API_VERSION)/standard-install.yaml
	$(call wait-crd-established,gatewayclasses.gateway.networking.k8s.io gateways.gateway.networking.k8s.io httproutes.gateway.networking.k8s.io)
	@echo "Installing Istio $(ISTIO_VERSION) via Helm (node $(KUBERNETES_SUPPORTED_VERSION))..."
	@$(HELM) repo add istio https://istio-release.storage.googleapis.com/charts 2>/dev/null || true
	@$(HELM) repo update istio
	@$(HELM) upgrade --install istio-base istio/base \
		--namespace istio-system --create-namespace \
		--version $(ISTIO_VERSION) --wait --timeout=10m
	@# Pilot image pull + webhook certs often exceed 5m on cold CI runners.
	@# Do not set PILOT_ENABLE_ALPHA_GATEWAY_API: standard-install CRDs serve
	@# TCPRoute/UDPRoute only as v1; alpha v1alpha2 is unserved, so Pilot's
	@# alpha informers hang forever and /ready stays 503 (istiod never Ready).
	@# Standard Gateway/HTTPRoute v1 works without the alpha flag on Istio 1.30+.
	@$(HELM) upgrade --install istiod istio/istiod \
		--namespace istio-system \
		--version $(ISTIO_VERSION) --wait --timeout=15m \
		--set global.proxy.resources.requests.cpu=10m \
		--set global.proxy.resources.requests.memory=64Mi \
		--set pilot.resources.requests.cpu=50m \
		--set pilot.resources.requests.memory=128Mi
	@$(KUBECTL) -n istio-system rollout status deploy/istiod --timeout=10m
	@$(KUBECTL) -n istio-system wait --for=condition=Ready pod -l app=istiod --timeout=5m
	@$(HELM) upgrade --install istio-ingress istio/gateway \
		--namespace istio-system \
		--version $(ISTIO_VERSION) \
		--set service.type=ClusterIP \
		--wait --timeout=10m
	@$(KUBECTL) apply -f test/e2e/manifests/00-test-application.yaml
	@# Bootstrap-static kubewaf_ecds (+ wasm code) clusters before Gateway pods start.
	@$(KUBECTL) apply -f test/e2e/manifests/istio/ecds-bootstrap.yaml
	@$(KUBECTL) apply -f test/e2e/manifests/istio/gateway.yaml
	@# Demo SecRule/RuleSet + WAF (CRDs first; operator reconcile after helm install).
	@$(KUBECTL) apply -f charts/kubewaf/crds/
	$(call wait-crd-established,$(KUBEWAF_CRDS))
	@$(KUBECTL) apply -f test/e2e/manifests/common/rules.yaml
	@$(KUBECTL) apply -f test/e2e/manifests/istio/waf.yaml
	@if [ "$(E2E_CRS_FULL)" = "true" ] || [ "$(E2E_CRS_FULL)" = "1" ] || [ "$(E2E_CRS_FULL)" = "yes" ]; then \
		$(MAKE) setup-test-e2e-crs-full; \
	fi
	@echo "Istio e2e environment ready (version $(ISTIO_VERSION), node $(KUBERNETES_SUPPORTED_VERSION))."

.PHONY: setup-test-e2e-cilium
setup-test-e2e-cilium: kind-cluster-cilium helm kubectl ## Install Cilium + demo app for e2e
	@# Cilium 1.19 Gateway API still indexes TLSRoute at v1alpha2. Standard-channel
	@# CRDs only serve TLSRoute v1 (v1alpha2 served=false), so cilium-operator fatals:
	@#   no matches for kind "TLSRoute" in version "gateway.networking.k8s.io/v1alpha2"
	@# Experimental install keeps v1alpha2/v1alpha3 served for those resources.
	@# Install experimental on a clean cluster only (not on top of standard — VAP blocks it).
	@echo "Installing Gateway API CRDs $(GATEWAY_API_VERSION) experimental (required for Cilium Gateway)..."
	@$(KUBECTL) apply --server-side -f \
		https://github.com/kubernetes-sigs/gateway-api/releases/download/$(GATEWAY_API_VERSION)/experimental-install.yaml
	@echo "Installing Cilium $(CILIUM_VERSION)..."
	@$(HELM) repo add cilium https://helm.cilium.io/ 2>/dev/null || true
	@$(HELM) repo update cilium
	@# Kind + kubeProxyMode=none: pin API server host/port and Kind-friendly IPAM.
	@API_HOST=$$($(KUBECTL) get endpoints kubernetes -n default -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null || true); \
	API_PORT=$$($(KUBECTL) get endpoints kubernetes -n default -o jsonpath='{.subsets[0].ports[0].port}' 2>/dev/null || echo 6443); \
	$(HELM) upgrade --install cilium cilium/cilium \
		--version $(CILIUM_VERSION) \
		--namespace kube-system \
		--set gatewayAPI.enabled=true \
		--set kubeProxyReplacement=true \
		--set image.pullPolicy=IfNotPresent \
		--set ipam.mode=kubernetes \
		--set operator.replicas=1 \
		--set k8sServiceHost=$${API_HOST} \
		--set k8sServicePort=$${API_PORT} \
		--wait --timeout=15m
	@# helm --wait is not enough when CNI is broken: require Ready pods before
	# scheduling operator CRD jobs / httpbin (otherwise ContainerCreating forever).
	@echo "Waiting for Cilium agent + operator to be Ready..."
	@$(KUBECTL) -n kube-system rollout status ds/cilium --timeout=10m
	@$(KUBECTL) -n kube-system rollout status deploy/cilium-operator --timeout=10m
	@$(KUBECTL) -n kube-system wait --for=condition=Ready pod -l k8s-app=cilium --timeout=5m
	@$(KUBECTL) -n kube-system wait --for=condition=Ready pod -l name=cilium-operator --timeout=5m
	@$(KUBECTL) -n kube-system wait --for=condition=Ready pod -l k8s-app=kube-dns --timeout=5m || \
		$(KUBECTL) -n kube-system wait --for=condition=Ready pod -l k8s-app=coredns --timeout=5m || true
	@# Kind has no cloud LB: give Cilium Gateway Services IPs so Programmed=True.
	@# (Patching Service type→ClusterIP is reverted by the Cilium gateway controller.)
	@$(KUBECTL) apply -f test/e2e/manifests/cilium/lb-ip-pool.yaml
	@$(KUBECTL) apply -f test/e2e/manifests/00-test-application.yaml
	@$(KUBECTL) apply -f test/e2e/manifests/cilium/gateway.yaml
	@# Demo SecRule/RuleSet + WAF (CRDs first; operator reconcile after helm install).
	@$(KUBECTL) apply -f charts/kubewaf/crds/
	$(call wait-crd-established,$(KUBEWAF_CRDS))
	@$(KUBECTL) apply -f test/e2e/manifests/common/rules.yaml
	@$(KUBECTL) apply -f test/e2e/manifests/cilium/waf.yaml
	@if [ "$(E2E_CRS_FULL)" = "true" ] || [ "$(E2E_CRS_FULL)" = "1" ] || [ "$(E2E_CRS_FULL)" = "yes" ]; then \
		$(MAKE) setup-test-e2e-crs-full; \
	fi
	@echo "Cilium e2e environment ready (version $(CILIUM_VERSION), node $(KUBERNETES_SUPPORTED_VERSION))."

.PHONY: setup-test-e2e
setup-test-e2e: setup-test-e2e-envoy-gateway ## Default e2e env (Envoy Gateway)

# Deploy full structured OWASP CRS as SecRule CRs + RuleSet into the e2e demo
# namespace (Path B style: config/samples/crs/* + ftw-crs-path-b full selector).
# Prerequisites: cluster up, CRDs applied, demo namespace exists
#   (e.g. after make setup-test-e2e-envoy-gateway).
# Attach with: kubectl apply -f test/e2e/manifests/<provider>/waf-path-b.yaml
# Or fold into setup: make setup-test-e2e E2E_CRS_FULL=true
.PHONY: crs-phraselists
crs-phraselists: ## Regenerate stock CRS PhraseList YAMLs from internal/coraza/crsdata
	@python3 hack/scripts/generate-crs-phraselists.py

.PHONY: setup-test-e2e-crs-full
setup-test-e2e-crs-full: kubectl ## Deploy full structured CRS SecRules + PhraseLists + RuleSet (demo ns)
	@echo "Deploying full structured CRS ($(CRS_VERSION)) SecRules into $(E2E_NAMESPACE)..."
	@$(KUBECTL) get ns $(E2E_NAMESPACE) >/dev/null 2>&1 || \
		$(KUBECTL) create namespace $(E2E_NAMESPACE)
	@$(KUBECTL) apply -f charts/kubewaf/crds/
	$(call wait-crd-established,$(KUBEWAF_CRDS))
	@set -e; \
	shopt -s nullglob; \
	files=(config/samples/crs/crs-request-*.yaml config/samples/crs/crs-response-*.yaml); \
	if [ $${#files[@]} -eq 0 ]; then \
		echo "ERROR: no CRS sample files under config/samples/crs/crs-{request,response}-*.yaml" >&2; \
		exit 1; \
	fi; \
	for f in "$${files[@]}"; do \
		echo "  apply $$f"; \
		$(KUBECTL) apply -n $(E2E_NAMESPACE) -f "$$f"; \
	done
	@echo "Deploying stock CRS PhraseLists (pmFromFile data pack)..."
	@test -f config/samples/crs/phraselists/crs-data-phraselists.yaml || \
		{ echo "ERROR: missing CRS PhraseLists; run make crs-phraselists" >&2; exit 1; }
	@$(KUBECTL) apply -n $(E2E_NAMESPACE) -f config/samples/crs/phraselists/crs-data-phraselists.yaml
	@echo "Applying full CRS RuleSet (ftw-crs-path-b; basename discovery for pmFromFile)..."
	@$(KUBECTL) apply -f test/e2e/manifests/ftw/path-b-crs-ruleset-full.yaml
	@echo "Waiting for CRS SecRules to be listed..."
	@n=0; \
	until [ "$$n" -ge 20 ]; do \
		count=$$($(KUBECTL) get secrules.seclang.kubewaf.io -n $(E2E_NAMESPACE) \
			-l app.kubernetes.io/part-of=coreruleset --no-headers 2>/dev/null | wc -l | tr -d ' '); \
		if [ "$${count:-0}" -gt 20 ]; then \
			echo "  $${count} CRS SecRules present in $(E2E_NAMESPACE)"; \
			break; \
		fi; \
		n=$$((n+1)); \
		sleep 3; \
	done; \
	count=$$($(KUBECTL) get secrules.seclang.kubewaf.io -n $(E2E_NAMESPACE) \
		-l app.kubernetes.io/part-of=coreruleset --no-headers 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$${count:-0}" -le 20 ]; then \
		echo "ERROR: expected many CRS SecRules in $(E2E_NAMESPACE), got $${count:-0}" >&2; \
		exit 1; \
	fi
	@pl=$$($(KUBECTL) get phraselists.seclang.kubewaf.io -n $(E2E_NAMESPACE) \
		-l seclang.kubewaf.io/crs-data=true --no-headers 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$${pl:-0}" -lt 21 ]; then \
		echo "ERROR: expected 21 CRS PhraseLists in $(E2E_NAMESPACE), got $${pl:-0}" >&2; \
		exit 1; \
	fi; \
	echo "  $${pl} CRS PhraseLists present in $(E2E_NAMESPACE)"
	@$(KUBECTL) get rulesets.waf.kubewaf.io ftw-crs-path-b -n $(E2E_NAMESPACE)
	@echo "Full CRS RuleSet ready (ftw-crs-path-b)."
	@echo "  Path B WAF: kubectl apply -f test/e2e/manifests/envoygateway/waf-path-b.yaml"
	@echo "  (or istio/waf-path-b.yaml / cilium/waf-path-b.yaml)"
	@echo "  pmFromFile: basename discovery only (no phraseListRefs on CRS RuleSets)."
	@echo "  Note: stock CRS has no IPList pack (no @ipMatchFromFile basenames)."

# Smoke subset RuleSet only (901/905/913/949/959/980). Still expects all SecRule
# samples applied (same as full); only the RuleSet selector is narrower.
.PHONY: setup-test-e2e-crs
setup-test-e2e-crs: setup-test-e2e-crs-full kubectl ## Deploy CRS SecRules + smoke RuleSet (demo ns)
	@echo "Applying smoke CRS RuleSet (901/905/913/949/959/980) over full SecRule samples..."
	@$(KUBECTL) apply -f test/e2e/manifests/ftw/path-b-crs-ruleset.yaml
	@$(KUBECTL) get rulesets.waf.kubewaf.io ftw-crs-path-b -n $(E2E_NAMESPACE)
	@echo "Smoke CRS RuleSet ready (ftw-crs-path-b; SecRules still full set)."

##@ Local demo (interactive stack)

# Cluster/data-plane bootstrap only (no operator image build, kind load, or Helm).
# Install the operator yourself with `make run`, `make local-demo-operator`, etc.
#
#   make local-demo                         # Kind + EG + demo + full CRS + WAF CRs
#   make local-demo-with-operator           # also build/load image + Helm install
#   make local-demo-image                   # build + kind load only
#   make local-demo-operator                # Helm install only (image must exist)
#   make local-demo-smoke                   # curl benign 200 / sqlmap 403
#   make local-demo-teardown
#
# Overrides:
#   LOCAL_DEMO_IMG          operator image (default E2E_IMG)
#   LOCAL_DEMO_REPLICAS     operator replicas (default 1)
#   LOCAL_DEMO_WAF          path-b (default) | smoke
#   LOCAL_DEMO_WAIT_WAF     true → wait for WAF Ready (needs a running operator)
#   KIND_CLUSTER / E2E_NAMESPACE / E2E_WASM_SOURCE_URL
LOCAL_DEMO_IMG ?= $(E2E_IMG)
LOCAL_DEMO_REPLICAS ?= 1
LOCAL_DEMO_WAF ?= path-b
LOCAL_DEMO_WAIT_WAF ?= false
LOCAL_DEMO_OPERATOR_NS ?= kubewaf-system

.PHONY: local-demo-image
local-demo-image: kind ko ## Build operator image (wasm embedded) and load into Kind
	@img="$(LOCAL_DEMO_IMG)"; \
	if [ -z "$$img" ]; then echo "ERROR: LOCAL_DEMO_IMG empty"; exit 1; fi; \
	tag="$${img##*:}"; \
	if [ "$$tag" = "$$img" ]; then tag=e2e; fi; \
	repo="$${img%:$$tag}"; \
	if [ -z "$$repo" ] || [ "$$repo" = "$$img" ]; then repo="ghcr.io/kubewaf-io/kubewaf"; fi; \
	echo "Building $$repo:$$tag (wasm-stage-kodata + ko)..."; \
	$(MAKE) ko-build-all CONTROLLER_IMG="$$repo" KO_TAGS="$$tag"; \
	echo "Loading $$img into Kind cluster '$(KIND_CLUSTER)'..."; \
	$(KIND) load docker-image "$$img" --name "$(KIND_CLUSTER)"

.PHONY: local-demo-operator
local-demo-operator: helm kubectl ## Helm install/upgrade kubeWAF from LOCAL_DEMO_IMG
	@img="$(LOCAL_DEMO_IMG)"; \
	tag="$${img##*:}"; \
	if [ "$$tag" = "$$img" ]; then tag=e2e; fi; \
	rest="$${img%:$$tag}"; \
	if [ -z "$$rest" ] || [ "$$rest" = "$$img" ]; then rest="ghcr.io/kubewaf-io/kubewaf"; fi; \
	case "$$rest" in \
		*/*) registry="$${rest%%/*}"; repository="$${rest#*/}" ;; \
		*) registry="ghcr.io"; repository="$$rest" ;; \
	esac; \
	echo "Helm install kubewaf ($$registry/$$repository:$$tag) → $(LOCAL_DEMO_OPERATOR_NS)..."; \
	args=( \
		upgrade --install kubewaf charts/kubewaf \
		--namespace "$(LOCAL_DEMO_OPERATOR_NS)" --create-namespace \
		--set "replicaCount=$(LOCAL_DEMO_REPLICAS)" \
		--set leaderElection.enabled=true \
		--set "image.registry=$$registry" \
		--set "image.repository=$$repository" \
		--set "image.tag=$$tag" \
		--set image.pullPolicy=IfNotPresent \
		--set crds.install=true \
		--set webhooks.enabled=true \
		--set webhooks.failurePolicy=Fail \
		--wait --timeout=5m \
	); \
	if [ -n "$(E2E_WASM_SOURCE_URL)" ]; then \
		args+=( \
			--set "dataplane.modsecurityWasmSourceURL=$(E2E_WASM_SOURCE_URL)" \
			--set "dataplane.wasmSourceURL=$(E2E_WASM_SOURCE_URL)" \
		); \
	fi; \
	$(HELM) "$${args[@]}"; \
	echo "Waiting for deploy/kubewaf Ready..."; \
	$(KUBECTL) -n "$(LOCAL_DEMO_OPERATOR_NS)" rollout status deploy/kubewaf --timeout=5m; \
	$(KUBECTL) -n "$(LOCAL_DEMO_OPERATOR_NS)" wait --for=condition=Available deploy/kubewaf --timeout=3m

.PHONY: local-demo-waf-path-b
local-demo-waf-path-b: kubectl ## Attach exclusive Path B CRS WAF CRs (optional Ready wait)
	@echo "Ensuring exclusive Path B WAF on demo-gateway..."
	@for w in $$($(KUBECTL) get wafs.waf.kubewaf.io -n $(E2E_NAMESPACE) -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do \
		if [ "$$w" != "demo-waf-eg-path-b" ]; then \
			echo "  delete waf/$$w"; \
			$(KUBECTL) delete wafs.waf.kubewaf.io "$$w" -n $(E2E_NAMESPACE) --ignore-not-found --wait=false; \
		fi; \
	done
	@$(KUBECTL) apply -f test/e2e/manifests/envoygateway/waf-path-b.yaml
	@if [ "$(LOCAL_DEMO_WAIT_WAF)" = "true" ] || [ "$(LOCAL_DEMO_WAIT_WAF)" = "1" ] || [ "$(LOCAL_DEMO_WAIT_WAF)" = "yes" ]; then \
		echo "Waiting for demo-waf-eg-path-b Ready=True..."; \
		ok=0; \
		for i in $$(seq 1 90); do \
			st=$$($(KUBECTL) get wafs.waf.kubewaf.io demo-waf-eg-path-b -n $(E2E_NAMESPACE) \
				-o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true); \
			if [ "$$st" = "True" ]; then echo "demo-waf-eg-path-b Ready=True"; ok=1; break; fi; \
			sleep 2; \
		done; \
		if [ "$$ok" != "1" ]; then \
			echo "ERROR: demo-waf-eg-path-b not Ready (is the operator running?)" >&2; \
			$(KUBECTL) get wafs.waf.kubewaf.io demo-waf-eg-path-b -n $(E2E_NAMESPACE) -o yaml 2>/dev/null | tail -60 || true; \
			$(KUBECTL) -n "$(LOCAL_DEMO_OPERATOR_NS)" logs -l app.kubernetes.io/instance=kubewaf --tail=80 2>/dev/null || true; \
			exit 1; \
		fi; \
	else \
		echo "Applied demo-waf-eg-path-b (not waiting for Ready; set LOCAL_DEMO_WAIT_WAF=true after operator is up)."; \
	fi
	@$(KUBECTL) get wafs.waf.kubewaf.io -n $(E2E_NAMESPACE) -o wide 2>/dev/null || true

.PHONY: local-demo
local-demo: ## Kind + EG + demo app + full CRS + WAF CRs (no image build / no operator deploy)
	@echo "=== local-demo (infra only): Kind + Envoy Gateway + demo + full CRS ==="
	@echo "  KIND_CLUSTER=$(KIND_CLUSTER)  WAF=$(LOCAL_DEMO_WAF)"
	@echo "  (does not build/load operator image or Helm-install kubeWAF)"
	$(MAKE) setup-test-e2e-envoy-gateway E2E_CRS_FULL=true
	@case "$(LOCAL_DEMO_WAF)" in \
		path-b|pathb|PATH-B|PathB) $(MAKE) local-demo-waf-path-b LOCAL_DEMO_WAIT_WAF=false ;; \
		smoke|demo) \
			echo "Keeping smoke WAF demo-waf-eg (custom scanner rule only; full CRS RuleSet is applied but not attached)."; \
			$(KUBECTL) get wafs.waf.kubewaf.io -n $(E2E_NAMESPACE) -o wide 2>/dev/null || true ;; \
		*) echo "Unknown LOCAL_DEMO_WAF=$(LOCAL_DEMO_WAF) (use path-b or smoke)"; exit 1 ;; \
	esac
	@echo ""
	@echo "=== local-demo infra ready (operator not installed) ==="
	@echo "Cluster:  kind get kubeconfig --name $(KIND_CLUSTER)  # or: export KUBECONFIG=..."
	@echo "Demo:     kubectl -n $(E2E_NAMESPACE) get pod,svc,httproute,waf,ruleset"
	@echo "CRS:      kubectl -n $(E2E_NAMESPACE) get secrules -l app.kubernetes.io/part-of=coreruleset --no-headers | wc -l"
	@echo ""
	@echo "Next — run the operator yourself, e.g.:"
	@echo "  make run                                          # process-local against this kubeconfig"
	@echo "  make local-demo-image && make local-demo-operator # in-cluster Helm from built image"
	@echo "  make local-demo-with-operator                     # infra + build + Helm in one shot"
	@echo "  make local-demo-waf-path-b LOCAL_DEMO_WAIT_WAF=true   # after operator is up"
	@svc=$$($(KUBECTL) get svc -n envoy-gateway-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
		| awk '$$0!="" && $$0!="envoy-gateway" {print; exit}'); \
	if [ -n "$$svc" ]; then \
		echo "Gateway:  kubectl -n envoy-gateway-system port-forward svc/$$svc 8080:80"; \
		echo "Smoke:    make local-demo-smoke   # needs a running operator + Ready WAF"; \
	fi
	@echo "Teardown: make local-demo-teardown"

.PHONY: local-demo-with-operator
local-demo-with-operator: ## local-demo + build/load image + Helm install + wait WAF Ready
	@echo "=== local-demo-with-operator: infra + image + Helm ==="
	$(MAKE) local-demo
	$(MAKE) local-demo-image
	$(MAKE) local-demo-operator
	@case "$(LOCAL_DEMO_WAF)" in \
		path-b|pathb|PATH-B|PathB) $(MAKE) local-demo-waf-path-b LOCAL_DEMO_WAIT_WAF=true ;; \
		smoke|demo) \
			echo "Waiting for demo-waf-eg Ready..."; \
			ok=0; \
			for i in $$(seq 1 90); do \
				st=$$($(KUBECTL) get wafs.waf.kubewaf.io demo-waf-eg -n $(E2E_NAMESPACE) \
					-o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true); \
				if [ "$$st" = "True" ]; then echo "demo-waf-eg Ready=True"; ok=1; break; fi; \
				sleep 2; \
			done; \
			[ "$$ok" = "1" ] || { echo "ERROR: demo-waf-eg not Ready"; exit 1; } ;; \
		*) echo "Unknown LOCAL_DEMO_WAF=$(LOCAL_DEMO_WAF)"; exit 1 ;; \
	esac
	@echo "=== local-demo-with-operator ready ==="
	@echo "Smoke: make local-demo-smoke"

.PHONY: local-demo-smoke
local-demo-smoke: kubectl ## In-cluster curl: benign 200 + sqlmap 403 via demo.local
	@svc=$$($(KUBECTL) get svc -n envoy-gateway-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
		| awk '$$0!="" && $$0!="envoy-gateway" && ($$0 ~ /demo-gateway/ || $$0 ~ /envoy-demo/ || $$0 ~ /^eg-/) {print; exit}'); \
	if [ -z "$$svc" ]; then \
		svc=$$($(KUBECTL) get svc -n envoy-gateway-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
			| awk '$$0!="" && $$0!="envoy-gateway" {print; exit}'); \
	fi; \
	if [ -z "$$svc" ]; then echo "ERROR: no Envoy Gateway proxy Service in envoy-gateway-system"; exit 1; fi; \
	echo "Using gateway Service $$svc"; \
	host="$$svc.envoy-gateway-system.svc.cluster.local"; \
	run_curl() { \
		ua="$$1"; expect="$$2"; label="$$3"; \
		code=$$($(KUBECTL) run "local-demo-curl-$$$$-$$RANDOM" --rm -i --restart=Never \
			--image=curlimages/curl:8.5.0 -n envoy-gateway-system -- \
			curl -sS -o /dev/null -w '%{http_code}' \
			-H "Host: demo.local" -H "User-Agent: $$ua" \
			--connect-timeout 5 --max-time 20 \
			"http://$$host:80/get" 2>/dev/null | tail -1 | tr -d '\r'); \
		echo "$$label: HTTP $$code (want $$expect)"; \
		[ "$$code" = "$$expect" ] || return 1; \
	}; \
	ok=0; \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12; do \
		if run_curl "Mozilla/5.0" "200" "benign"; then ok=1; break; fi; \
		echo "  retry $$i/12 (ECDS may still be settling)..."; \
		sleep 5; \
	done; \
	[ "$$ok" = "1" ] || { echo "ERROR: benign request never returned 200"; exit 1; }; \
	ok=0; \
	for i in 1 2 3 4 5 6; do \
		if run_curl "sqlmap/1.0" "403" "scanner"; then ok=1; break; fi; \
		echo "  retry $$i/6..."; \
		sleep 5; \
	done; \
	[ "$$ok" = "1" ] || { echo "ERROR: scanner UA never returned 403"; exit 1; }; \
	echo "local-demo-smoke OK"

.PHONY: local-demo-teardown
local-demo-teardown: cleanup-test-e2e ## Delete Kind cluster used by local-demo / e2e

.PHONY: test-e2e
test-e2e: kind manifests generate ## Run e2e (E2E_PROVIDER=all|envoy-gateway|istio|cilium|manager|probe|headlamp)
	@echo "Running e2e with E2E_PROVIDER=$(E2E_PROVIDER)"
	@case "$(E2E_PROVIDER)" in \
		envoy-gateway) $(MAKE) setup-test-e2e-envoy-gateway ;; \
		istio) $(MAKE) setup-test-e2e-istio ;; \
		cilium) $(MAKE) setup-test-e2e-cilium ;; \
		manager) $(MAKE) kind-cluster ;; \
		probe) $(MAKE) kind-cluster ;; \
		headlamp) $(MAKE) setup-test-e2e-envoy-gateway E2E_CRS_FULL=true ;; \
		all) $(MAKE) setup-test-e2e-envoy-gateway ;; \
		*) echo "Unknown E2E_PROVIDER=$(E2E_PROVIDER) (use all|envoy-gateway|istio|cilium|manager|probe|headlamp)"; exit 1 ;; \
	esac
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) \
		E2E_PROVIDER=$(E2E_PROVIDER) E2E_IMG=$(E2E_IMG) \
		E2E_PROBE="$(E2E_PROBE)" \
		E2E_SUBRESOURCE_IMG="$(E2E_SUBRESOURCE_IMG)" \
		E2E_PROBE_TEST_IMG="$(E2E_PROBE_TEST_IMG)" \
		E2E_WASM_SOURCE_URL="$(E2E_WASM_SOURCE_URL)" \
		E2E_FTW="$(E2E_FTW)" E2E_SKIP_FTW="$(E2E_SKIP_FTW)" \
		E2E_FTW_PATH_A="$(E2E_FTW_PATH_A)" \
		E2E_FTW_PATH_B="$(E2E_FTW_PATH_B)" \
		E2E_FTW_PATH_B_FULL="$(E2E_FTW_PATH_B_FULL)" \
		E2E_HEADLAMP="$(E2E_HEADLAMP)" \
		E2E_HEADLAMP_SKIP_TRAFFIC="$(E2E_HEADLAMP_SKIP_TRAFFIC)" \
		HEADLAMP_PLUGIN_DIR="$(HEADLAMP_PLUGIN_DIR)" \
		HEADLAMP_SCREENSHOT_DIR="$(HEADLAMP_SCREENSHOT_DIR)" \
		E2E_FTW_INCLUDE="$(E2E_FTW_INCLUDE)" \
		E2E_ISTIO_TRAFFIC="$(E2E_ISTIO_TRAFFIC)" \
		E2E_CILIUM_TRAFFIC="$(E2E_CILIUM_TRAFFIC)" \
		CRS_VERSION="$(CRS_VERSION)" GO_FTW_VERSION="$(GO_FTW_VERSION)" \
		go test -tags=e2e ./test/e2e/ -v -ginkgo.v -timeout 90m
	@echo "e2e finished (cluster '$(KIND_CLUSTER)' left running; make cleanup-test-e2e to delete)"

.PHONY: test-e2e-envoy-gateway
test-e2e-envoy-gateway: ## E2E against Envoy Gateway
	$(MAKE) test-e2e E2E_PROVIDER=envoy-gateway

.PHONY: test-e2e-istio
test-e2e-istio: ## E2E against Istio
	$(MAKE) test-e2e E2E_PROVIDER=istio

.PHONY: test-e2e-cilium
test-e2e-cilium: ## E2E against Cilium
	$(MAKE) test-e2e E2E_PROVIDER=cilium

.PHONY: test-e2e-probe
test-e2e-probe: ## E2E Subresource probe API (aggregated APIService + pass-through)
	$(MAKE) test-e2e E2E_PROVIDER=probe

.PHONY: test-e2e-ftw
test-e2e-ftw: ## Alias for first-class Path B go-ftw (path-b wasm + structured CRS)
	$(MAKE) test-e2e-ftw-path-b

.PHONY: test-e2e-ftw-path-a
test-e2e-ftw-path-a: ## Second-class Path A go-ftw (needs full-catalog wasm + E2E_FTW_PATH_A)
	$(MAKE) test-e2e E2E_FTW_PATH_A=true E2E_FTW=false E2E_FTW_PATH_B=false E2E_FTW_INCLUDE="$(E2E_FTW_INCLUDE)"

.PHONY: test-e2e-ftw-full
test-e2e-ftw-full: ## Full CRS go-ftw suite via Path B (slow; first-class)
	$(MAKE) test-e2e-ftw-path-b-full

.PHONY: test-e2e-ftw-path-b
test-e2e-ftw-path-b: ## Path B go-ftw: crsEnable=false + structured CRS (path-b wasm, first-class)
	$(MAKE) test-e2e E2E_FTW=false E2E_FTW_PATH_B=true E2E_FTW_INCLUDE="$(E2E_FTW_INCLUDE)"

.PHONY: test-e2e-ftw-path-b-full
test-e2e-ftw-path-b-full: ## Path B full CRS go-ftw suite (slow; all SecRule samples)
	$(MAKE) test-e2e E2E_FTW=false E2E_FTW_PATH_B=true E2E_FTW_PATH_B_FULL=true E2E_FTW_INCLUDE=all

.PHONY: test-e2e-headlamp
test-e2e-headlamp: ## Headlamp UI screenshots against a Path B full-CRS WAF (needs plugin + Chromium)
	$(MAKE) test-e2e \
		E2E_PROVIDER=headlamp \
		E2E_HEADLAMP=true \
		E2E_CRS_FULL=true \
		E2E_FTW_PATH_B_FULL=true \
		E2E_FTW=false \
		E2E_FTW_PATH_B=false

.PHONY: test-e2e-all-providers
test-e2e-all-providers: ## Run EG + Istio + Cilium e2e sequentially
	$(MAKE) cleanup-test-e2e || true
	$(MAKE) test-e2e-envoy-gateway
	$(MAKE) cleanup-test-e2e || true
	$(MAKE) test-e2e-istio
	$(MAKE) cleanup-test-e2e || true
	$(MAKE) test-e2e-cilium

# Full release suite (local sequential). CI runs the same slices in parallel.
# All slices use path-b wasm. Override E2E_FTW_INCLUDE=all for exhaustive CRS (slow).
.PHONY: test-e2e-release
test-e2e-release: ## Full release e2e: EG smoke + Path B FTW + Istio/Cilium slot+traffic
	@echo "=== Release e2e (1/4): Envoy Gateway provider smoke (path-b wasm) ==="
	$(MAKE) cleanup-test-e2e || true
	$(MAKE) test-e2e \
		E2E_PROVIDER=envoy-gateway \
		E2E_FTW=false \
		E2E_FTW_PATH_A=false \
		E2E_FTW_PATH_B=false
	@echo "=== Release e2e (2/4): Envoy Gateway Path B go-ftw ($(E2E_FTW_INCLUDE)) ==="
	$(MAKE) cleanup-test-e2e || true
	$(MAKE) test-e2e \
		E2E_PROVIDER=envoy-gateway \
		E2E_FTW=false \
		E2E_FTW_PATH_B=true \
		E2E_CRS_FULL=false \
		E2E_FTW_INCLUDE="$(E2E_FTW_INCLUDE)"
	@echo "=== Release e2e (3/4): Istio (slot + traffic smoke) ==="
	$(MAKE) cleanup-test-e2e || true
	$(MAKE) test-e2e \
		E2E_PROVIDER=istio \
		E2E_FTW=false \
		E2E_ISTIO_TRAFFIC=true
	@echo "=== Release e2e (4/4): Cilium (slot + traffic smoke) ==="
	$(MAKE) cleanup-test-e2e || true
	$(MAKE) test-e2e \
		E2E_PROVIDER=cilium \
		E2E_FTW=false \
		E2E_CILIUM_TRAFFIC=true
	@echo "=== Release e2e complete ==="

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER) || true

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
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	KUBE_FEATURE_WatchListClient=false go run ./cmd/main.go

.PHONY: crs-converter
crs-converter: fmt vet ## Build the CRS converter tool.
	go build -o bin/crs-converter ./cmd/crs-converter

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
# Wasm modules are staged into cmd/kodata/wasm/ so `ko` embeds them (KO_DATA_PATH).
# At runtime the operator loads local files first; --*-wasm-source-url overrides still work.

.PHONY: ko-build-controller
ko-build-controller: ko wasm-stage-kodata
	echo Building Controller $(KO_TAGS) for $(KO_PLATFORM) >&2
	@LD_FLAGS=$(LD_FLAGS) KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(CONTROLLER_IMG) \
		$(KO) build ./cmd --bare --tags=$(KO_TAGS) --local --push=false --platform=$(KO_PLATFORM)

.PHONY: ko-build-subresource-api
ko-build-subresource-api: ko ## Build Subresource API Server image (local)
	@echo Building Subresource API $(KO_TAGS) for $(KO_PLATFORM) >&2
	@LD_FLAGS=$(LD_FLAGS) KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(CONTROLLER_IMG)-subresource-api \
	$(KO) build ./cmd/subresource-api --bare --tags=$(KO_TAGS) --local --push=false --platform=$(KO_PLATFORM)

.PHONY: ko-build-probe-test-server
ko-build-probe-test-server: ko ## Build probe Test HTTP Server image (local)
	@echo Building Probe Test Server $(KO_TAGS) for $(KO_PLATFORM) >&2
	@LD_FLAGS=$(LD_FLAGS) KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(CONTROLLER_IMG)-probe-test-server \
	$(KO) build ./cmd/probe-test-server --bare --tags=$(KO_TAGS) --local --push=false --platform=$(KO_PLATFORM)

.PHONY: ko-build-all
ko-build-all: ko-build-controller ko-build-subresource-api ko-build-probe-test-server ## Build controller + subresource-api + probe-test-server

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
.PHONY: ko-publish-controller
ko-publish-controller:
	@$(MAKE) --no-print-directory ko ko-login wasm-stage-kodata >&2
	@LD_FLAGS=$(LD_FLAGS) KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(CONTROLLER_IMG) \
		$(KO) build ./cmd --bare --tags=$(KO_TAGS) | tail -n1

.PHONY: ko-publish-all
ko-publish-all: ko-publish-controller

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

# egctl is the Envoy Gateway CLI; pin to ENVOY_GATEWAY_VERSION (see e2e provider setup).
EGCTL := $(LOCALBIN)/egctl
.PHONY: egctl
egctl: $(LOCALBIN) ## Download egctl (Envoy Gateway CLI) into bin/ if missing or version-mismatched
	@os=$$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$$(uname -m); case $$arch in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; esac; \
	if [ -s "$(EGCTL)" ] && "$(EGCTL)" version 2>/dev/null | head -1 | grep -q "$(ENVOY_GATEWAY_VERSION)"; then \
		exit 0; \
	fi; \
	echo "Downloading egctl $(ENVOY_GATEWAY_VERSION) for $${os}/$${arch}..."; \
	tmp=$$(mktemp -d); \
	curl -fsSL "https://github.com/envoyproxy/gateway/releases/download/$(ENVOY_GATEWAY_VERSION)/egctl_$(ENVOY_GATEWAY_VERSION)_$${os}_$${arch}.tar.gz" \
		| tar -xz -C "$$tmp"; \
	install -m 0755 "$$tmp/bin/$${os}/$${arch}/egctl" "$(EGCTL)"; \
	rm -rf "$$tmp"; \
	"$(EGCTL)" version 2>/dev/null | head -1 || true

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

##@ Wasm modules (engines/ submodules + monorepo helpers)

# Engine source trees live under engines/ as git submodules (see engines/README.md).
# CI does not require private engine sources: wasm is fetched from the public GHCR image.
ENGINES_DIR ?= engines
MODSECURITY_PROXY_WASM_DIR ?= $(ENGINES_DIR)/modsecurity-proxy-wasm
POW_PROXY_WASM_DIR ?= $(ENGINES_DIR)/pow-proxy-wasm
# Monorepo copy of the engine extract helper (so wasm-fetch works without submodules).
WASM_EXTRACT_SCRIPT ?= hack/scripts/extract-wasm-from-image.sh

# Pinned product WAF engine release (GHCR). Also used as DefaultImage for challenge
# until a dedicated challenge-proxy-wasm image is published.
#
# Dual catalog publish (engine release tags):
#   path-b (first-class, default)  :$(VERSION) and :$(VERSION)-path-b
#   full   (second-class, Path A)  :$(VERSION)-full  — embedded CRS rule confs
# Operator e2e and ko embed always use path-b. Path A (crsEnable) needs -full.
# Must include data_files / @pmFromFile runtime inject (PhraseList/IPList Path B).
# alpha8 and earlier lack parseDataFiles → custom pmFromFile configure fails → HTTP 500.
MODSECURITY_PROXY_WASM_VERSION ?= 0.1.0-alpha15
MODSECURITY_PROXY_WASM_IMAGE ?= ghcr.io/kubewaf-io/modsecurity-proxy-wasm:$(MODSECURITY_PROXY_WASM_VERSION)
MODSECURITY_PROXY_WASM_IMAGE_FULL ?= ghcr.io/kubewaf-io/modsecurity-proxy-wasm:$(MODSECURITY_PROXY_WASM_VERSION)-full
# Catalog for local engine builds staged into dist/wasm (path-b | full).
WASM_CATALOG_MODE ?= path-b

.PHONY: engines-submodules
engines-submodules: ## Init/update engine git submodules under engines/ (optional for CI)
	@git submodule update --init --recursive $(MODSECURITY_PROXY_WASM_DIR) $(POW_PROXY_WASM_DIR) || true
	@if [ ! -f $(MODSECURITY_PROXY_WASM_DIR)/Makefile ]; then \
		echo "NOTE: $(MODSECURITY_PROXY_WASM_DIR) not present — CI/local builds can use wasm-fetch-modsecurity from GHCR"; \
	fi

# Build Proxy-Wasm modules and stage under dist/wasm/ for operator images.
# Prefers a local engines/ build; falls back to extracting the pinned release image.
# Default CATALOG_MODE=path-b (no embedded CRS rules). Use wasm-build-full for Path A.
.PHONY: wasm-build
wasm-build: ## Build path-b modsecurity-proxy-wasm + challenge-proxy-wasm → dist/wasm/
	@mkdir -p dist/wasm
	@echo "Building modsecurity-proxy-wasm CATALOG_MODE=$(WASM_CATALOG_MODE) ($(MODSECURITY_PROXY_WASM_DIR))..."
	@if [ -f $(MODSECURITY_PROXY_WASM_DIR)/Makefile ]; then \
		$(MAKE) -C $(MODSECURITY_PROXY_WASM_DIR) image extract-wasm \
			CATALOG_MODE=$(WASM_CATALOG_MODE) \
			|| $(MAKE) -C $(MODSECURITY_PROXY_WASM_DIR) extract-wasm \
			|| true; \
	fi
	@if [ -f $(MODSECURITY_PROXY_WASM_DIR)/dist/modsecurity-proxy-wasm.wasm ]; then \
		cp -f $(MODSECURITY_PROXY_WASM_DIR)/dist/modsecurity-proxy-wasm.wasm dist/wasm/; \
	elif [ -f $(MODSECURITY_PROXY_WASM_DIR)/dist/modsec.wasm ]; then \
		cp -f $(MODSECURITY_PROXY_WASM_DIR)/dist/modsec.wasm dist/wasm/modsecurity-proxy-wasm.wasm; \
	else \
		echo "Local engine source/build missing; extracting $(MODSECURITY_PROXY_WASM_IMAGE)..."; \
		$(MAKE) wasm-fetch-modsecurity; \
	fi
	@echo "Building challenge-proxy-wasm ($(POW_PROXY_WASM_DIR))..."
	@if [ -f $(POW_PROXY_WASM_DIR)/Makefile ]; then \
		$(MAKE) -C $(POW_PROXY_WASM_DIR) build || true; \
	fi
	@if [ -f $(POW_PROXY_WASM_DIR)/build/main.wasm ]; then \
		cp -f $(POW_PROXY_WASM_DIR)/build/main.wasm dist/wasm/challenge-proxy-wasm.wasm; \
	elif [ -f dist/wasm/modsecurity-proxy-wasm.wasm ]; then \
		echo "WARN: challenge wasm not built; PoW image not published yet — leaving challenge optional"; \
	else \
		echo "WARN: challenge wasm not found"; \
	fi
	@ls -la dist/wasm/ || true

.PHONY: wasm-build-full
wasm-build-full: ## Build second-class Path A wasm (embedded CRS) → dist/wasm/modsecurity-proxy-wasm-full.wasm
	@mkdir -p dist/wasm
	@echo "Building modsecurity-proxy-wasm CATALOG_MODE=full (second-class Path A)..."
	@if [ -f $(MODSECURITY_PROXY_WASM_DIR)/Makefile ]; then \
		$(MAKE) -C $(MODSECURITY_PROXY_WASM_DIR) \
			CATALOG_MODE=full \
			MODSECURITY_PROXY_WASM_OUT=$(CURDIR)/dist/wasm/modsecurity-proxy-wasm-full.wasm \
			modsecurity-proxy-wasm.wasm \
			|| $(MAKE) -C $(MODSECURITY_PROXY_WASM_DIR) image-full extract-wasm \
				IMAGE_FULL=modsecurity-proxy-wasm:full CATALOG_MODE=full; \
	else \
		echo "Engine submodule missing; extracting $(MODSECURITY_PROXY_WASM_IMAGE_FULL)..."; \
		$(MAKE) wasm-fetch-modsecurity-full; \
	fi
	@if [ -f $(MODSECURITY_PROXY_WASM_DIR)/dist/modsecurity-proxy-wasm.wasm ] && \
	   [ ! -f dist/wasm/modsecurity-proxy-wasm-full.wasm ]; then \
		cp -f $(MODSECURITY_PROXY_WASM_DIR)/dist/modsecurity-proxy-wasm.wasm \
			dist/wasm/modsecurity-proxy-wasm-full.wasm; \
	fi
	@test -f dist/wasm/modsecurity-proxy-wasm-full.wasm || \
		{ echo "ERROR: full catalog wasm not produced"; exit 1; }
	@echo "Staged dist/wasm/modsecurity-proxy-wasm-full.wasm (not used by default e2e/ko)"
	@ls -la dist/wasm/modsecurity-proxy-wasm-full.wasm

.PHONY: wasm-fetch-modsecurity
wasm-fetch-modsecurity: ## Pull pinned path-b modsecurity-proxy-wasm image → dist/wasm/
	@mkdir -p dist/wasm
	@test -f $(WASM_EXTRACT_SCRIPT) || { echo "ERROR: missing $(WASM_EXTRACT_SCRIPT)"; exit 1; }
	@echo "Pulling path-b $(MODSECURITY_PROXY_WASM_IMAGE)..."
	@$(CONTAINER_TOOL) pull $(MODSECURITY_PROXY_WASM_IMAGE)
	@bash $(WASM_EXTRACT_SCRIPT) $(MODSECURITY_PROXY_WASM_IMAGE) dist/wasm
	@test -f dist/wasm/modsecurity-proxy-wasm.wasm
	@echo "Staged dist/wasm/modsecurity-proxy-wasm.wasm ($(MODSECURITY_PROXY_WASM_VERSION), path-b)"

.PHONY: wasm-fetch-modsecurity-full
wasm-fetch-modsecurity-full: ## Pull pinned full-catalog wasm (Path A, second-class) → dist/wasm/
	@mkdir -p dist/wasm
	@test -f $(WASM_EXTRACT_SCRIPT) || { echo "ERROR: missing $(WASM_EXTRACT_SCRIPT)"; exit 1; }
	@echo "Pulling full $(MODSECURITY_PROXY_WASM_IMAGE_FULL)..."
	@$(CONTAINER_TOOL) pull $(MODSECURITY_PROXY_WASM_IMAGE_FULL)
	@bash $(WASM_EXTRACT_SCRIPT) $(MODSECURITY_PROXY_WASM_IMAGE_FULL) dist/wasm/full-tmp
	@mv -f dist/wasm/full-tmp/modsecurity-proxy-wasm.wasm dist/wasm/modsecurity-proxy-wasm-full.wasm
	@rm -rf dist/wasm/full-tmp
	@test -f dist/wasm/modsecurity-proxy-wasm-full.wasm
	@echo "Staged dist/wasm/modsecurity-proxy-wasm-full.wasm ($(MODSECURITY_PROXY_WASM_VERSION)-full)"

.PHONY: wasm-stage-kodata
wasm-stage-kodata: ## Stage wasm into cmd/kodata/wasm/ for ko image embedding
	@mkdir -p cmd/kodata/wasm dist/wasm
	@# Prefer already-staged dist/wasm; otherwise build/fetch.
	@if [ ! -f dist/wasm/modsecurity-proxy-wasm.wasm ]; then \
		$(MAKE) wasm-build; \
	fi
	@if [ ! -f dist/wasm/modsecurity-proxy-wasm.wasm ]; then \
		echo "ERROR: dist/wasm/modsecurity-proxy-wasm.wasm missing after wasm-build"; exit 1; \
	fi
	@cp -f dist/wasm/modsecurity-proxy-wasm.wasm cmd/kodata/wasm/
	@# Product engine path alias used by some defaults/compat flags.
	@cp -f dist/wasm/modsecurity-proxy-wasm.wasm cmd/kodata/wasm/coraza-proxy-wasm.wasm 2>/dev/null || true
	@if [ -f dist/wasm/challenge-proxy-wasm.wasm ]; then \
		cp -f dist/wasm/challenge-proxy-wasm.wasm cmd/kodata/wasm/; \
	elif [ -f $(POW_PROXY_WASM_DIR)/build/main.wasm ]; then \
		cp -f $(POW_PROXY_WASM_DIR)/build/main.wasm cmd/kodata/wasm/challenge-proxy-wasm.wasm; \
	else \
		$(MAKE) -C $(POW_PROXY_WASM_DIR) build || true; \
		if [ -f $(POW_PROXY_WASM_DIR)/build/main.wasm ]; then \
			cp -f $(POW_PROXY_WASM_DIR)/build/main.wasm cmd/kodata/wasm/challenge-proxy-wasm.wasm; \
		else \
			echo "WARN: challenge-proxy-wasm.wasm not staged (optional until published)"; \
		fi; \
	fi
	@ls -la cmd/kodata/wasm/
	@echo "Staged wasm for ko (cmd/kodata/wasm → KO_DATA_PATH at runtime)"

.PHONY: wasm-stage-defaults
wasm-stage-defaults: ## Copy staged wasm into container paths for local runs
	@mkdir -p /wasm 2>/dev/null || mkdir -p $(CURDIR)/.wasm
	@cp -f dist/wasm/*.wasm $(CURDIR)/.wasm/ 2>/dev/null || true
