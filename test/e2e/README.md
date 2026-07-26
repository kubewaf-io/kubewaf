# kubeWAF end-to-end tests

Provider matrix e2e for **Envoy Gateway**, **Istio**, and **Cilium**.

## Quick start

```bash
# Envoy Gateway (default)
make test-e2e-envoy-gateway

# Istio
make test-e2e-istio

# Cilium (Kind with disableDefaultCNI)
make test-e2e-cilium

# All providers sequentially (recreates clusters)
make test-e2e-all-providers
```

## Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `E2E_PROVIDER` | `all` | `envoy-gateway`, `istio`, `cilium`, `manager`, `all` |
| `E2E_IMG` | `ghcr.io/kubewaf-io/kubewaf:e2e` | Operator image loaded into Kind |
| `E2E_WASM_SOURCE_URL` | (placeholder wasm) | Real modsecurity-proxy-wasm `.wasm` URL for **traffic** tests |
| `E2E_SKIP_IMAGE_BUILD` | unset | Skip `ko-build` + kind load |
| `E2E_SKIP_OPERATOR_INSTALL` | unset | Assume operator already installed |
| `E2E_CILIUM_TRAFFIC` | unset | Enable experimental Cilium traffic assertion |
| `E2E_RUN_MANAGER_SMOKE` | unset | With `E2E_PROVIDER=all`, also run kustomize manager smoke |
| `KIND_CLUSTER` | `kubewaf-e2e` | Kind cluster name |

## What each provider asserts

### Envoy Gateway
1. WAF `Ready=True`, `status.provider=EnvoyGateway`, `slotKind=ExtensionServer`
2. (Optional traffic) scanner `User-Agent: sqlmap` → **403**, benign → **200**  
   Requires `E2E_WASM_SOURCE_URL` pointing at a real modsecurity-proxy-wasm binary.

### Istio
1. WAF Ready, `slotKind=EnvoyFilter`, EnvoyFilter `kubewaf-demo-waf-istio` exists with `config_discovery` + `kubewaf_ecds`
2. (Optional traffic) same as EG when wasm URL is set

### Cilium
1. WAF Ready, `slotKind=CiliumEnvoyConfig`, CEC targets `httpbin` and documents ECDS resource
2. Traffic is **opt-in** (`E2E_CILIUM_TRAFFIC=true`) — full L7 filter merge depends on the Cilium Envoy build

## Prerequisites

- `kind`, `kubectl`, `helm`, `go`
- Docker (for Kind + `ko` image build)

## Layout

```
test/e2e/
  e2e_suite_test.go      # image build / suite wiring
  e2e_test.go            # optional kustomize manager smoke
  providers_test.go      # EG / Istio / Cilium matrix
  helpers.go
  manifests/
    00-test-application.yaml
    common/rules.yaml
    envoygateway/
    istio/
    cilium/
```
