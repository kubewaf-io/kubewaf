# WAFInstance CRD Reference

**Group**: `waf.kubewaf.io`  
**Version**: `v1beta1`  
**Kind**: `WAFInstance`  
**Short name**: `wafinst`

## Purpose

`WAFInstance` is intended to deploy and manage standalone WAF proxies or sidecar WAF containers that protect workloads **without** requiring Envoy Gateway.

**Current status**: Alpha / Work in Progress.

The reference resolution logic is functional, but the actual workload (Deployment / sidecar) creation is not yet implemented.

## Spec (Current)

```yaml
spec:
  parentRefs: []gatewayv1.ParentReference
  backendRefs: []gatewayv1.BackendObjectReference
  ruleRefs: []RuleRef
```

Most fields are currently unused or reserved for future workload template configuration.

## Planned Capabilities

- Sidecar injection into existing Deployments / Pods
- Standalone Envoy + modsecurity-proxy-wasm gateway Deployment
- Automatic ConfigMap generation containing the flattened SecLang
- Health checks and metrics exposure

## Status

The controller currently only:

- Resolves RuleSet references
- Sets `ReferencesResolved` condition
- Maintains finalizers

No proxy pods are created yet.

## When to Use Today

**Do not use `WAFInstance`** in production until the controller is completed.

Use `WAF` instead if you have Envoy Gateway.

## Migration Path

When `WAFInstance` becomes functional, the same `RuleSet` objects you already created for `WAF` will be reusable — the reference system is shared.

## Tracking Progress

Watch the GitHub issues and the [project roadmap](https://github.com/kubewaf-io/kubewaf) for updates on WAFInstance implementation.

## See Also

- [Architecture](../../concepts/architecture.md)
- Source: [wafinstance_types.go](https://github.com/kubewaf-io/kubewaf/blob/main/api/waf/v1beta1/wafinstance_types.go)
- Controller: `internal/controller/waf/wafinstance_controller.go` (mostly stubbed today)