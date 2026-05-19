# Core Concepts

This page explains the fundamental building blocks of kubeWAF.

## SecRule

A `SecRule` is the atomic unit of protection. It describes a single security check using the same concepts as ModSecurity / Coraza:

- **Variables** (what to inspect)
- **Operator** (how to compare)
- **Actions** (what to do on match)
- **Metadata** (id, phase, message, tags, severity)

Example (simplified):

```yaml
spec:
  secLangRules:
  - metadata:
      id: 100100
      phase: "2"
    conditions:
    - variables: [{ name: ARGS_GET }]
      operator: { name: rx, value: <script> }
    actions:
      disruptive: { disruptiveActionType: deny }
```

See the full [SecLang YAML structure reference](../reference/seclang-structure.md).

## RuleSet

A `RuleSet` is a **named, reusable collection** of rules.

Instead of listing hundreds of individual rules on every policy attachment, you create a `RuleSet` once and reference it from `WAF`.

Key capabilities:

- Direct name references
- Label selector references (`matchLabels`)
- Cross-namespace references (subject to `allowedRules` policy)
- Recursive RuleSet references (RuleSet → RuleSet)

```yaml
spec:
  ruleRefs:
  - kind: SecRule
    selector:
      matchLabels:
        app: payment-waf
        version: v2
  allowedRules:
    from: Same          # or "All" or "Selector"
```

## WAF

This is currently the **primary way** to enforce rules on live traffic.

It uses the Envoy Gateway extension policy mechanism (`EnvoyExtensionPolicy`) to inject the Coraza WASM filter into the request path for selected Gateway API objects (Gateway, HTTPRoute, etc.).

Features:

- `parentRefs` — which Gateway API resources to protect
- `ruleRefs` — which RuleSets to apply
- `crsEnable` — automatically include the full OWASP CRS
- `logLevel` — control WASM filter verbosity

## WAFInstance (Future)

`WAFInstance` is intended for cases where you want a **standalone WAF proxy** or **sidecar injection**, independent of Envoy Gateway.

As of the current release, the controller only performs reference resolution. Full workload deployment is under development.

## Rule Reference Resolution

One of kubeWAF's most powerful features is the **RuleRefResolver**.

When you reference a `RuleSet`, the resolver:

1. Recursively expands all nested RuleSets
2. Collects matching `SecRule` / `SecAction` resources
3. Validates namespace policies (`allowedRules`)
4. Creates back-references (the SecRule knows which RuleSets use it)
5. Sets the `ReferencesResolved` condition

This means you can reorganize rules without touching your gateway policies.

## Phases

Like ModSecurity, rules run in phases:

- **Phase 1** — Request headers (very early)
- **Phase 2** — Request body
- **Phase 3** — Response headers
- **Phase 4** — Response body
- **Phase 5** — Logging

Most application-level rules live in phase 2.

## Anomaly Scoring

The OWASP CRS (and many custom rules) use **anomaly scoring** rather than immediate blocking:

1. Rules increment `TX.anomaly_score` (or per-paranoia-level scores)
2. At the end of the phase, a separate rule compares the score against a threshold
3. Only then is a blocking decision made

This dramatically reduces false positives while still catching sophisticated attacks.

kubeWAF fully supports this model because it faithfully converts your structured rules into real SecLang that Coraza executes.

## Next

Ready to start writing rules? Read the [Writing Security Rules](../guides/writing-rules.md) guide.