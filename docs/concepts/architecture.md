# Architecture

kubeWAF is a Kubernetes operator that turns structured security CRDs into live
WAF configuration on Envoy-based data planes. The product engine is
**modsecurity-proxy-wasm**, with an optional **PoW challenge**
(**pow-proxy-wasm**). Configuration is pushed over Envoy’s **Extension Config
Discovery Service (ECDS)**; each gateway product only receives a thin **filter slot**.

## Big picture

```mermaid
flowchart TB
  subgraph authors["Authors (GitOps)"]
    SR[SecRule / SecAction]
    RS[RuleSet]
    WAF[WAF]
  end

  subgraph operator["kubeWAF Operator (1..N replicas)"]
    direction TB
    LEAD[Leader-elected controllers<br/>status · finalizers · platform slots]
    SYNC[Dataplane sync on every pod<br/>read-only resolve]
    ECDS[ECDS gRPC :18001]
    WASM[Wasm HTTP :18002]
    EGEXT[EG Extension Server :5005]
    RES[RuleRefResolver]
  end

  subgraph slots["Platform filter slots"]
    EG[Envoy Gateway<br/>Extension Server hooks]
    IST[Istio<br/>EnvoyFilter]
    CIL[Cilium<br/>CiliumEnvoyConfig]
  end

  subgraph dataplane["Envoy data plane"]
    ENV[Envoy proxy]
    COR[modsecurity-proxy-wasm]
  end

  SR --> RS --> WAF
  WAF --> LEAD
  WAF --> SYNC
  LEAD --> RES
  SYNC --> RES
  RES --> ECDS
  SYNC --> EGEXT
  LEAD --> EG & IST & CIL
  ECDS --> ENV
  WASM --> ENV
  EG & IST & CIL --> ENV
  ENV --> COR
```

## Control plane vs data plane

| Plane | Responsibility |
|-------|----------------|
| **Kubernetes API** | Desired state: rules, sets, attachment (`WAF`) |
| **kubeWAF operator** | Resolve rules → SecLang → portable config; multi-module wasm serve; ECDS; provider slots |
| **Gateway control plane** | Routing, TLS, listeners (Envoy Gateway / Istio / Cilium) |
| **Envoy + Wasm engines** | Challenge (optional) then modsecurity-proxy-wasm evaluates traffic |

kubeWAF **does not** replace the gateway’s ADS (LDS/RDS/CDS). It only owns
**extension config** (ECDS) and installs a small filter that points at that ECDS
resource.

## Operator internals

```mermaid
flowchart LR
  subgraph every["Every replica"]
    A[ECDS server]
    B[Wasm HTTP server]
    C[EG Extension Server]
    D[Dataplane sync controller<br/>NeedLeaderElection=false]
  end

  subgraph leader["Leader only"]
    E[WAF controller]
    F[RuleSet / SecRule controllers]
    G[Inventory metrics]
  end

  D -->|Resolve + Upsert| A
  D -->|Index WAF| C
  E -->|Resolve + lock + status| API[(Kubernetes API)]
  E -->|EnvoyFilter / CEC| API
  E -->|Upsert| A
  E -->|Index| C
```

### Why this split?

Envoy (and Envoy Gateway) load-balance against the operator **Service**. If only
the leader held ECDS config, non-leader pods would return empty snapshots and
requests would fail or bypass WAF randomly. Dataplane servers and the sync
controller therefore run on **every** pod; Kubernetes **writes** stay on the leader.

## Portable config artifact

After rule resolution, every path produces the same intermediate object — now with
an **ordered filter list** (optional Challenge, then WAF engine):

```mermaid
flowchart TB
  WAF[WAF CR] --> B[BuildFromWAF]
  RS[RuleSet graph] --> R[RuleRefResolver]
  R --> RULES[SecLang strings]
  RULES --> B
  B --> P[PortableConfig]
  P --> F1[Filter: challenge<br/>pow-proxy-wasm]
  P --> F2[Filter: WAF<br/>modsecurity-proxy-wasm]
  F1 --> ECDS[ECDS TypedExtensionConfigs]
  F2 --> ECDS
  P --> SLOT[Provider slot installer]

  subgraph engines["Monorepo Wasm modules"]
    M[modsecurity-proxy-wasm]
    CH[pow-proxy-wasm]
  end
  F2 -.-> M
  F1 -.-> CH
```

The ECDS resource type is always:

`type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm`

with modsecurity-proxy-wasm plugin JSON of the form
(see [`schemas/waf-plugin-config.json`](../../schemas/waf-plugin-config.json)):

```json
{
  "mode": "kubewaf",
  "config_id": "kubewaf/shop/shop-waf",
  "allow_fallback": false,
  "default_directives": "default",
  "directives_map": {
    "default": [
      "Include @kubewaf-defaults",
      "SecRuleEngine On",
      "SecDebugLogLevel 3",
      "Include @crs-setup-conf",
      "Include @owasp_crs/*.conf",
      "..."
    ]
  },
  "metric_labels": {
    "waf_namespace": "shop",
    "waf_name": "shop-waf",
    "engine": "modsecurity",
    "owner": "modsecurity-proxy-wasm",
    "team": "payments"
  },
  "metrics": { "enabled": true, "per_rule_id": true, "rule_tags": true },
  "block": { "message": "blocked by kubeWAF" }
}
```

## End-to-end request path

```mermaid
sequenceDiagram
  participant C as Client
  participant E as Envoy
  participant W as modsecurity-proxy-wasm
  participant U as Upstream
  participant K as kubeWAF ECDS

  Note over E,K: At startup / config reload
  E->>K: StreamExtensionConfigs (gRPC)
  K-->>E: TypedExtensionConfig kubewaf/ns/name
  E->>E: Fetch .wasm from operator :18002

  C->>E: HTTP request
  E->>W: on_request_headers / body
  alt Rule deny / anomaly threshold
    W-->>E: local reply 403
    E-->>C: 403 Forbidden
  else Allow
    E->>U: proxy request
    U-->>E: response
    E->>W: on_response_*
    E-->>C: response
  end
```

## Multi-provider slots

```mermaid
flowchart TB
  PC[PortableConfig + ECDS]

  PC --> EG
  PC --> IST
  PC --> CIL

  subgraph EG["provider: EnvoyGateway"]
    EG1[EG calls Extension Server :5005]
    EG2[PostHTTPListenerModify<br/>insert config_discovery filter]
    EG3[PostTranslateModify<br/>add kubewaf_ecds cluster]
    EG1 --> EG2 --> EG3
  end

  subgraph IST["provider: Istio"]
    IST1[Create EnvoyFilter]
    IST2[CLUSTER: kubewaf_ecds]
    IST3[HTTP_FILTER INSERT_BEFORE router<br/>config_discovery → ECDS]
    IST1 --> IST2 --> IST3
  end

  subgraph CIL["provider: Cilium"]
    CIL1[Create CiliumEnvoyConfig]
    CIL2[Attach to Service]
    CIL3[Resources: ECDS + wasm clusters]
    CIL1 --> CIL2 --> CIL3
  end
```

| Provider | Slot resource | How filter is installed |
|----------|---------------|-------------------------|
| **EnvoyGateway** | (none owned by kubeWAF) | EG Extension Server hooks mutate xDS |
| **Istio** | `EnvoyFilter` | `config_discovery` → external ECDS |
| **Cilium** | `CiliumEnvoyConfig` | CEC clusters + attachment to Service |

See [Data plane (ECDS)](../operator/dataplane-ecds.md) for configuration details.

## Core CRDs

| CRD | Purpose | Maturity |
|-----|---------|----------|
| `SecRule` | Individual security rule (structured YAML) | Stable |
| `RuleSet` | Named collection (selectors, recursion, `allowedRules`) | Stable |
| `WAF` | Attach RuleSets to a gateway provider + push ECDS | Stable |
| `WAFInstance` | Standalone proxy / sidecar (future) | Alpha |

## Data flow (lifecycle)

```mermaid
stateDiagram-v2
  [*] --> Author: create SecRule
  Author --> Aggregate: create RuleSet
  Aggregate --> Attach: create WAF
  Attach --> Resolve: RuleRefResolver
  Resolve --> Publish: ECDS Upsert
  Publish --> Slot: ensure platform slot
  Slot --> Enforce: Envoy + modsecurity-proxy-wasm
  Enforce --> Publish: SecRule/RuleSet change<br/>new ECDS version
  Attach --> [*]: delete WAF<br/>ECDS delete + slot GC
```

1. **Author** — `SecRule` / `SecAction` (or CRS converter).
2. **Aggregate** — `RuleSet` selects rules (names or labels).
3. **Attach** — `WAF` references RuleSets and a provider.
4. **Resolve** — flatten graph, enforce namespace policy, back-references (leader).
5. **Publish** — every pod updates its ECDS snapshot.
6. **Slot** — leader ensures EnvoyFilter / CEC / EG index.
7. **Enforce** — modsecurity-proxy-wasm evaluates traffic.

Rule content changes bump the **ECDS snapshot only**; platform slots are not rewritten unless provider or ECDS endpoint settings change.

## Operator ports and Service

```mermaid
flowchart LR
  subgraph svc["Service: release-ecds"]
    P1[":18001 ECDS gRPC"]
    P2[":5005 EG Extension Server"]
    P3[":18002 Wasm HTTP"]
  end

  ENV[Envoy] -->|extension config| P1
  ENV -->|GET /wasm/...| P3
  EGCTL[Envoy Gateway control plane] -->|xDS hooks| P2
```

| Port | Protocol | Consumers |
|------|----------|-----------|
| **18001** | gRPC ECDS | Envoy (`kubewaf_ecds` cluster) |
| **5005** | gRPC EG extension API | Envoy Gateway only |
| **18002** | HTTP | Envoy fetching the `.wasm` binary |

## Security model

- Rules are **namespaced**.
- `RuleSet.allowedRules` controls who may contribute rules (`Same` / `All` / `Selector`).
- Only `RuleSet`s attach to a `WAF` (not raw `SecRule`s).
- Platform teams own RuleSets + WAF attachment; app teams own SecRules in their namespace.

## Status and conditions

```bash
kubectl get waf -o wide
kubectl describe waf shop-waf
```

| Field / condition | Meaning |
|-------------------|---------|
| `Ready` | ECDS published and slot ensured |
| `ReferencesResolved` | All RuleSet refs resolved |
| `status.provider` | `EnvoyGateway` / `Istio` / `Cilium` |
| `status.engine` | Active WAF engine (e.g. `ModSecurity`) |
| `status.challengeEnabled` | PoW filter installed |
| `status.ecdsResourceName` | e.g. `kubewaf/shop/shop-waf` |
| `status.ecdsVersion` | Snapshot generation counter |
| `status.slotKind` | `ExtensionServer` / `EnvoyFilter` / `CiliumEnvoyConfig` |

## Current limitations

- `WAFInstance` does not yet deploy proxies.
- No validating admission webhooks yet.
- Cilium full L7 filter-chain merge depends on the cluster’s Envoy build (CEC slot is always created).
- Envoy Gateway requires `extensionManager` configured to call kubeWAF.

## Related projects

- [modsecurity-proxy-wasm](../../modsecurity-proxy-wasm/README.md) (this monorepo)
- [pow-proxy-wasm](../../pow-proxy-wasm/README.md) (this monorepo)
- [Envoy Gateway](https://gateway.envoyproxy.io/)
- [Istio EnvoyFilter](https://istio.io/latest/docs/reference/config/networking/envoy-filter/)
- [Cilium Envoy](https://docs.cilium.io/en/stable/network/servicemesh/envoy/)
- [OWASP CRS](https://coreruleset.org/)

## Next

- [Wasm engines](../modsecurity-proxy-wasm/README.md)
- [Data plane configuration](../operator/dataplane-ecds.md)
- [Envoy Gateway guide](../operator/envoy-gateway.md)
- [Istio guide](../operator/istio.md)
- [Cilium guide](../operator/cilium.md)
