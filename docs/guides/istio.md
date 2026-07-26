# Istio Integration

Use kubeWAF with **Istio** ingress (or mesh) Envoys. The operator creates an
**EnvoyFilter** that installs an HTTP filter stub; **rules are served over
external ECDS** (not through istiod’s ADS).

## How it works

```mermaid
flowchart TB
  WAF[WAF<br/>provider: Istio]
  OP[kubeWAF operator]
  EF[EnvoyFilter]
  IG[istio-ingressgateway<br/>Envoy]
  ECDS[ECDS :18001]
  WASM[Wasm HTTP :18002]

  WAF --> OP
  OP -->|create/update| EF
  OP --> ECDS
  OP --> WASM
  EF -->|config_discovery| IG
  IG --> ECDS
  IG --> WASM
```

```mermaid
sequenceDiagram
  participant KW as kubeWAF leader
  participant API as K8s API
  participant Istiod as istiod
  participant Envoy as istio-proxy
  participant ECDS as kubeWAF ECDS

  KW->>API: EnvoyFilter (cluster + HTTP_FILTER)
  Istiod->>Envoy: merge EnvoyFilter into xDS
  Envoy->>ECDS: separate gRPC ECDS stream
  ECDS-->>Envoy: Wasm TypedExtensionConfig
  Note over Envoy: Do not use ads:{} for ECDS config_source
```

## Prerequisites

- Istio installed (sidecars and/or ingress gateway)
- `EnvoyFilter` CRD (`networking.istio.io`)
- kubeWAF operator with ECDS + wasm ports
- Wasm binary loaded on the operator

Gateway API is optional; the EnvoyFilter uses **workload selectors** by default.

## Example

```yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: WAF
metadata:
  name: shop-waf
  namespace: shop
spec:
  provider:
    type: Istio
    istio:
      workloadSelector:
        istio: ingressgateway
      context: GATEWAY          # or SIDECAR_INBOUND, etc.
    # Optional: override ECDS Service DNS
    # ecdsService: kubewaf-ecds.kubewaf-system.svc.cluster.local:18001
  parentRefs:
    targetRef:
      group: gateway.networking.k8s.io
      kind: Gateway
      name: demo-gateway
  ruleRefs:
  - kind: RuleSet
    name: shop-rules
  crsEnable: true
  logLevel: 3
```

### What gets created

```text
EnvoyFilter/kubewaf-shop-waf  (same namespace as WAF)
```

Patches:

1. **CLUSTER** `kubewaf_ecds` → operator ECDS
2. **CLUSTER** `kubewaf_wasm_code` → wasm HTTP (if URL set)
3. **HTTP_FILTER** `INSERT_BEFORE` router with `config_discovery` named  
   `kubewaf/shop/shop-waf`

## Status

```bash
kubectl get waf shop-waf -o yaml
kubectl get envoyfilter -n shop
```

| Field | Expected |
|-------|----------|
| `status.provider` | `Istio` |
| `status.slotKind` | `EnvoyFilter` |
| `status.slotName` | `kubewaf-<waf-name>` |

## Debugging

1. **EnvoyFilter missing** — check operator RBAC for `networking.istio.io`
2. **Filter not in chain** — wrong `workloadSelector` / `context`
3. **ECDS connect fail** — NetworkPolicy / DNS for `ecdsService`
4. **Config empty on some pods** — scale operator ≥1 with dataplane sync (all replicas serve ECDS)

```bash
istioctl proxy-config listener -n istio-system deploy/istio-ingressgateway
istioctl proxy-config cluster  -n istio-system deploy/istio-ingressgateway | grep kubewaf
```

## Comparison with WasmPlugin

| Approach | Used by kubeWAF? | Rule updates |
|----------|------------------|--------------|
| **EnvoyFilter + external ECDS** | Yes (default Istio path) | gRPC ECDS only |
| Istio `WasmPlugin` | No (could be future mode) | Through istiod |

External ECDS keeps parity with Envoy Gateway: one config channel for all providers.

## Related

- [Data plane (ECDS)](dataplane-ecds.md)
- [Architecture](../concepts/architecture.md)
- [Istio EnvoyFilter](https://istio.io/latest/docs/reference/config/networking/envoy-filter/)
