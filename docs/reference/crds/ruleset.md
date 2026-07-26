# RuleSet CRD Reference

**Group**: `waf.kubewaf.io`  
**Version**: `v1beta1`  
**Kind**: `RuleSet`  
**Short name**: `rs`

## Purpose

A `RuleSet` aggregates one or more `SecRule` / `SecAction` (or other RuleSets) into a named, reusable policy unit that can be attached to gateways.

## Spec

```yaml
spec:
  ruleRefs: []RuleRef
  allowedRules: RuleNamespaces
```

### RuleRef

| Field      | Description |
|------------|-------------|
| `kind`     | `SecRule`, `SecAction`, `RuleSet`, or `ConfigMap` (future) |
| `name`     | Direct name reference (mutually exclusive with `selector`) |
| `namespace`| Defaults to the RuleSet's namespace |
| `group`    | API group (e.g. `seclang.kubewaf.io`, `waf.kubewaf.io`) |
| `version`  | API version (`v1beta1`) |
| `selector` | Label selector (mutually exclusive with `name`) |

**Constraint**: Exactly one of `name` or `selector` must be present (enforced by CEL validation on the CRD).

### AllowedRules / RuleNamespaces

```yaml
allowedRules:
  from: Same | All | Selector
  selector:      # only when from=Selector
    matchLabels:
      security: trusted
```

This controls **which namespaces** the RuleSet is allowed to pull rules from.

## Status

```yaml
status:
  conditions:
  - type: ReferencesResolved
    status: "True"
  ruleRefs:
  - kind: SecRule
    name: block-sqlmap
    namespace: shop
```

The `ruleRefs` list in status is the **flattened, fully resolved** list of every concrete rule that will be included when this RuleSet is referenced.

## Example

```yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: RuleSet
metadata:
  name: payment-protection
  namespace: platform
spec:
  ruleRefs:
  - kind: SecRule
    selector:
      matchLabels:
        waf.kubewaf.io/team: payments
  allowedRules:
    from: Same
```

## Important Semantics

- RuleSets are **recursive** — referencing another RuleSet is allowed and will be expanded.
- Direct `SecRule` references from `WAF` or `WAFInstance` are **rejected** at the resolver level. You must go through a RuleSet.
- Changing a RuleSet automatically affects every `WAF` that references it (after the next reconciliation).

## Deletion & Finalizers

RuleSets use finalizers to maintain back-references on the rules they reference. Deleting a RuleSet is safe; the referenced rules are not deleted.

## See Also

- [Using RuleSets](../../operator/rulesets.md) guide
- [RuleSet types.go](https://github.com/kubewaf-io/kubewaf/blob/main/api/waf/v1beta1/ruleset_types.go)