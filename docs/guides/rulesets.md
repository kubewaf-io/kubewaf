# Using RuleSets

`RuleSet` is the central abstraction for organizing and reusing security rules.

## Why RuleSets Exist

Without RuleSets you would have to list every individual `SecRule` on every `WAF`. RuleSets give you:

- Logical grouping ("payment protection", "API baseline", "strict mode")
- Label-based selection (add a rule → automatically appears in all matching RuleSets)
- Namespace boundaries and delegation
- Recursive composition

## Basic RuleSet

```yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: RuleSet
metadata:
  name: api-baseline
  namespace: platform-security
spec:
  ruleRefs:
  - kind: SecRule
    group: seclang.kubewaf.io
    version: v1beta1
    selector:
      matchLabels:
        waf.kubewaf.io/profile: api-baseline
```

Any `SecRule` that carries the label `waf.kubewaf.io/profile: api-baseline` will be included.

## Direct References vs Selectors

You can mix both styles:

```yaml
ruleRefs:
- kind: SecRule
  name: block-admin-bruteforce          # direct name
  namespace: production
- kind: SecRule
  selector:
    matchLabels:
      team: payments
```

**Important**: When using `name`, the namespace defaults to the RuleSet's own namespace unless you specify `namespace:`.

## Namespace Policies (`allowedRules`)

By default a RuleSet can only reference rules in the **same namespace**:

```yaml
spec:
  allowedRules:
    from: Same
```

Other options:

- `from: All` — any namespace (use with caution)
- `from: Selector` + `selector` — only namespaces matching the label selector

This is the same model used by the Kubernetes Gateway API.

Example of a cluster-wide platform RuleSet:

```yaml
spec:
  allowedRules:
    from: Selector
    selector:
      matchLabels:
        security.kubewaf.io/trusted: "true"
```

## Composing RuleSets (RuleSet → RuleSet)

RuleSets can reference other RuleSets:

```yaml
# Base profile
apiVersion: waf.kubewaf.io/v1beta1
kind: RuleSet
metadata:
  name: base
  namespace: platform
spec:
  ruleRefs: [ ... many rules ... ]

---
# Strict profile = base + extra rules
apiVersion: waf.kubewaf.io/v1beta1
kind: RuleSet
metadata:
  name: strict
  namespace: platform
spec:
  ruleRefs:
  - kind: RuleSet
    name: base
  - kind: SecRule
    selector:
      matchLabels:
        profile: strict-only
```

When a `WAF` references `strict`, the resolver automatically flattens everything into one list of rules.

## Inspecting Resolution

The operator writes rich status:

```bash
kubectl describe ruleset strict
```

Look for:

- `status.conditions[ReferencesResolved]`
- `status.ruleRefs[]` — the concrete list of resolved rules

If any reference cannot be resolved (wrong name, namespace policy violation, missing resource), the condition will be `False` and the `WAF` will also surface the problem.

## Best Practices for Platform Teams

1. **Create a small number of curated profiles** instead of letting every team build their own RuleSets.
2. **Use labels consistently** on all rules (`app`, `env`, `paranoia-level`, `owner`).
3. **Keep RuleSets small and composable** — prefer composition over giant monolithic lists.
4. **Protect your RuleSets** with RBAC so only security engineers can modify baseline profiles.

## Example: Multi-Tenant Setup

```
Namespace: platform-security
  RuleSet "baseline" (allowed from all)
  RuleSet "ecommerce" (references baseline + extra)

Namespace: team-payments
  SecRule "rate-limit-payments" (labeled for ecommerce)

Namespace: team-inventory
  SecRule "block-old-browsers"
```

A `WAF` in the payments namespace can reference the platform `ecommerce` RuleSet and automatically gets both the baseline and the team-specific rules.

## Next

Learn how to [enable the OWASP Core Rule Set](using-crs.md) on top of (or instead of) your custom RuleSets.