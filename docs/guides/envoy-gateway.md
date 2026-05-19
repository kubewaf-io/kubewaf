# Envoy Gateway Integration

`WAF` is the recommended way to protect live HTTP (and eventually TCP/TLS) traffic with kubeWAF today.

## How It Works

`WAF` is a **Gateway API policy attachment** resource. When you create one, the kubeWAF controller:

1. Resolves all referenced RuleSets into a flat list of SecLang strings
2. Creates (or updates) an `EnvoyExtensionPolicy` in the same namespace
3. The Envoy Gateway controller sees the policy and injects a Wasm filter using the **coraza-proxy-wasm** module into the selected listeners/routes
4. The Wasm module is initialized with your rules + CRS (if enabled)

This is the same mechanism used by Envoy Gateway for other WAF / auth / transformation policies.

## Prerequisites

- Envoy Gateway installed and its `GatewayClass` named `eg` (the default)
- Gateway API CRDs present (`gateway.networking.k8s.io`)
- The `gateway.envoyproxy.io` CRDs installed (EnvoyExtensionPolicy, etc.)

## Basic Attachment Example

Protect a single HTTPRoute:

```yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: WAF
metadata:
  name: shop-waf
  namespace: shop
spec:
  parentRefs:
    targetRef:
      group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: shop-frontend
      # namespace defaults to the WAF namespace

  ruleRefs:
  - kind: RuleSet
    name: shop-rules
    namespace: shop
```

You can also target a whole `Gateway`:

```yaml
parentRefs:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: external-gateway
```

Or a `GatewayClass` (affects all gateways of that class — use carefully).

## Multiple RuleSets + CRS

```yaml
spec:
  crsEnable: true
  ruleRefs:
  - kind: RuleSet
    name: baseline
    namespace: platform
  - kind: RuleSet
    name: shop-specific
    namespace: shop
  logLevel: 4
```

`logLevel` controls the verbosity of the Coraza WASM filter (0 = off, 7 = trace).

## Custom Coraza WASM Image

If you have built a custom `coraza-proxy-wasm` image (e.g., with additional modules or a newer Coraza version), you can override it:

```yaml
spec:
  corazaProxyWasmImage: "ghcr.io/myorg/coraza-proxy-wasm:1.2.0-custom"
```

Default: `ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0`

## How Rules Are Loaded

The controller writes the final SecLang configuration into the `EnvoyExtensionPolicy`'s Wasm filter configuration as a single string (or multiple configuration items).

Because the resolver already flattened everything, the Wasm module receives a complete, ready-to-compile rule set.

## Observing Status

```bash
kubectl get wafenvoygateway shop-waf -o yaml
```

Relevant fields:

- `status.conditions[ReferencesResolved]`
- `status.conditions[Ready]`
- Events on the resource (the controller emits normal events on resolution failures)

Also inspect the generated `EnvoyExtensionPolicy`:

```bash
kubectl get envoyextensionpolicy shop-waf -o yaml
```

## Common Patterns

### Protect Everything in a Namespace

Create one `WAF` that targets the `Gateway` resource. All HTTPRoutes attached to that Gateway inherit the policy.

### Different Policies per Route

Multiple `WAF` resources can exist. The most specific match wins (Gateway API policy precedence rules apply).

### Staging vs Production

Use two RuleSets:

- `staging-strict` (higher paranoia)
- `production-balanced`

Then different `WAF` objects reference the appropriate one, even if they protect the same backend routes.

## Debugging

1. **Rules not taking effect?**
   - Check `ReferencesResolved` condition
   - Look at Envoy Gateway logs for Wasm loading errors
   - Increase `logLevel` temporarily

2. **High latency after enabling WAF?**
   - CRS with paranoia 4 + many rules can add ~1–3 ms
   - Start with lower paranoia or exclude heavy rules

3. **403 on every request?**
   - Usually means an initialization rule is missing or your anomaly threshold is 0
   - Make sure CRS initialization rules run (id 901xxx) or that you set thresholds yourself

## Limitations (Current)

- Only HTTP is fully supported today via `HTTPRoute`
- TCPRoute / TLSRoute support depends on Envoy Gateway Wasm filter capabilities
- You cannot yet inject arbitrary Wasm configuration beyond what `WAF` exposes (future enhancement)

## Alternative (Future): WAFInstance

If you are not using Envoy Gateway, the `WAFInstance` CRD will eventually let you deploy a standalone Envoy + Coraza sidecar or gateway proxy directly managed by kubeWAF.

Today we recommend Envoy Gateway + `WAF` as the path of least resistance.

## Further Reading

- [Envoy Gateway Wasm Documentation](https://gateway.envoyproxy.io/docs/tasks/extensibility/wasm/)
- [coraza-proxy-wasm README](https://github.com/corazawaf/coraza-proxy-wasm)

Next: explore the full [CRD API reference](../reference/crds/secrule.md).