# WAF CRD Reference

**Group**: `waf.kubewaf.io`  
**Version**: `v1beta1`  
**Kind**: `WAF`  
**Short name**: `waf`

## Purpose

`WAF` attaches WAF rules (via RuleSets) to Kubernetes Gateway API resources using Envoy Gateway's extension policy mechanism.

This is currently the **primary production integration path** for kubeWAF.

## Spec

```yaml
spec:
  parentRefs: PolicyTargetReferences   # from gateway.envoyproxy.io
  ruleRefs: []RuleRef
  crsEnable: bool
  logLevel: int
  corazaProxyWasmImage: string
```

### parentRefs

Uses the standard Envoy Gateway `PolicyTargetReferences` type. You can target:

- A `Gateway`
- An `HTTPRoute`
- A `GatewayClass` (affects many gateways)

Example:

```yaml
parentRefs:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: checkout
    namespace: shop   # optional
```

### ruleRefs

Same `RuleRef` type used everywhere. You should reference `RuleSet` objects (not raw `SecRule`).

### crsEnable

When `true`, the OWASP Core Rule Set is merged with your own rules.

### logLevel

WASM filter log level (0–7). Higher = more verbose. Default: `7` (debug/trace during development).

### corazaProxyWasmImage

Override the Wasm module image. Default:

```
ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0
```

### metrics

New in v0.2+: Full control over WAF metrics exposure.

```yaml
metrics:
  name: "coraza-prod"
  rootID: "coraza"
  extraLabels:
    team: payments
    env: prod
  includeRuleID: true     # default
  enableStats: true       # default
```

See the [Observability guide](../../guides/observability.md) for details and recommended Grafana queries.

## Status

Standard conditions:

- `Ready`
- `ReferencesResolved`

## Full Example

```yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: WAF
metadata:
  name: public-waf
  namespace: ingress
spec:
  parentRefs:
    targetRef:
      group: gateway.networking.k8s.io
      kind: Gateway
      name: public
  ruleRefs:
  - kind: RuleSet
    name: baseline
    namespace: platform
  - kind: RuleSet
    name: public-strict
    namespace: ingress
  crsEnable: true
  logLevel: 3
```

## Notes

- The controller creates an `EnvoyExtensionPolicy` with the same name in the same namespace.
- Multiple `WAF` objects can target the same route; Envoy Gateway merges them according to its policy precedence rules.
- Changes to referenced rules or RuleSets are picked up automatically.

## See Also

- [Envoy Gateway Integration Guide](../../guides/envoy-gateway.md)
- [Envoy Gateway Policy Attachment](https://gateway.envoyproxy.io/docs/design/policy-attachment/)