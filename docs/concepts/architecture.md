# Architecture

kubeWAF follows the standard Kubernetes Operator pattern. It watches Custom Resources and reconciles the desired security configuration into the data plane.

## High-Level Components

```
┌────────────────────────────────────────────────────────────────────┐
│                        kubeWAF Operator                            │
│                                                                    │
│  ┌──────────────┐   ┌──────────────┐   ┌───────────────────────┐  │
│  │ SecRule      │   │ RuleSet      │   │ WAF       │  │
│  │ Controller   │   │ Controller   │   │ Controller            │  │
│  └──────────────┘   └──────────────┘   └───────────────────────┘  │
│          │                 │                     │                 │
│          ▼                 ▼                     ▼                 │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                 RuleRefResolver (internal/references2)       │ │
│  │   - Label selectors, cross-namespace refs, recursion         │ │
│  │   - Back-references via finalizers + status                  │ │
│  └──────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────────────┐
                    │     Envoy Gateway +           │
                    │     coraza-proxy-wasm         │
                    │   (Wasm filter with rules)    │
                    └───────────────────────────────┘
```

## Core CRDs

| CRD                        | Purpose                                                  | Maturity |
|----------------------------|----------------------------------------------------------|----------|
| `SecRule`                  | Individual security rule in structured YAML              | Stable   |
| `RuleSet`                  | Named collection of rules (supports selectors)           | Stable   |
| `WAF`          | Attaches RuleSets to Gateway API resources               | Stable   |
| `WAFInstance`              | Standalone WAF proxy / sidecar (future)                  | Alpha    |

## Data Flow

1. **Authoring** — Users create `SecRule` resources (or import via CRS converter).
2. **Aggregation** — `RuleSet` resources select rules via label selectors or direct names.
3. **Resolution** — The shared `RuleRefResolver` flattens references, handles recursion, enforces namespace policies, and maintains back-references.
4. **Attachment** — `WAF` creates or updates an `EnvoyExtensionPolicy` (from the Envoy Gateway API) that tells Envoy to load the Coraza WASM module with the generated SecLang configuration.
5. **Enforcement** — Coraza (compiled to WebAssembly) runs inside Envoy and evaluates every request/response against the rules.

## Status and Conditions

All kubeWAF resources implement standard Kubernetes conditions:

- `Ready`
- `ReferencesResolved`
- `Accepted`

You can always inspect what the operator has understood:

```bash
kubectl describe wafenvoygateway demo-waf
kubectl get secrule -o yaml | grep -A 20 status:
```

## Security Model

- Rules are **namespaced** resources.
- `RuleSet` objects control which namespaces may contribute rules via the `allowedRules` field (modeled after Gateway API `from` / `selector`).
- Only `RuleSet` objects may be referenced from `WAF` / `WAFInstance` (direct `SecRule` references are rejected).

This design gives platform teams fine-grained control while allowing application teams to author rules safely.

## Current Limitations

- `WAFInstance` does not yet deploy proxies (only reference resolution works).
- No validating admission webhooks yet (you can still create invalid rules).
- Rule updates require the referenced `WAF` to be reconciled (usually within a few seconds).

## Related Projects

- [Coraza](https://github.com/corazawaf/coraza) — Go implementation of ModSecurity
- [coraza-proxy-wasm](https://github.com/corazawaf/coraza-proxy-wasm) — WASM module for Envoy
- [Envoy Gateway](https://gateway.envoyproxy.io/) — Kubernetes Gateway API implementation
- [OWASP Core Rule Set](https://coreruleset.org/) — Industry-standard rule set

Understanding the architecture helps you reason about why certain reference patterns are allowed or disallowed and how to debug `ReferencesResolved` conditions.