# SecRule CRD Reference

**Group**: `seclang.kubewaf.io`  
**Version**: `v1beta1`  
**Kind**: `SecRule`  
**Short name**: `sr`

## Purpose

`SecRule` represents one or more ModSecurity SecLang rules in a structured, Kubernetes-native format.

## Example

See [Writing Security Rules](../../operator/writing-rules.md) for many examples.

## Spec

```yaml
spec:
  secLangRules: []SecLangSecRule
```

### SecLangSecRule

| Field           | Type                | Description |
|-----------------|---------------------|-------------|
| `metadata`      | `SecRuleMetadata`   | id, phase, message, severity, tags |
| `conditions`    | `[]Condition`       | Variables + operator that trigger the rule |
| `actions`       | `SecRuleActions`    | disruptive, flow, nonDisruptive actions |
| `chainedRule`   | `bool`              | Marks this rule as the start of a chain |
| `secMarker`     | `string`            | Creates a named marker for `skipAfter` |

### SecRuleMetadata

```yaml
metadata:
  id: 920100
  phase: "2"
  message: "Invalid request"
  severity: ERROR
  tags:
  - attack-protocol
  - OWASP_CRS
```

### Condition

A condition can use either `variables` + `operator` or `collections`.

See the [SecLang Structure reference](../seclang-structure.md) for the full list of supported variables, collections, and operators.

### Actions

```yaml
actions:
  disruptive:
    disruptiveActionType: deny | block | allow | pass | drop | redirect
    status: "403"
    redirectUrl: "https://example.com/blocked"
  flow:
  - flowActionType: skip | skipAfter
    value: "950000"
  nonDisruptive:
  - nonDisruptiveActionType: setvar | msg | logdata | ctl | ...
    value: "TX.anomaly_score_pl1=+5"
```

## Status

```yaml
status:
  conditions:
  - type: Ready
    status: "True"
  secRuleString: |
    SecRule REQUEST_URI "@rx ^/admin" "id:100001,phase:2,deny"
  ruleSetRefs:
  - kind: RuleSet
    name: shop-rules
    namespace: shop
```

- `secRuleString` — the exact SecLang emitted by the controller. This is what the WAF engine (modsecurity-proxy-wasm) receives.
- `ruleSetRefs` — back-references showing which RuleSets include this rule.

## Validation

- `id` should be unique within your cluster (or at least within a RuleSet).
- Phases are strings `"1"`–`"5"`.
- Only certain action combinations are valid (the CRD contains structural validation; more semantic validation is planned via webhooks).

## RBAC

The operator installs aggregated ClusterRoles:

- `secrule-viewer`
- `secrule-editor`
- `secrule-admin`

Bind them to teams that are allowed to author rules.

## Short Example for Reference

```yaml
apiVersion: seclang.kubewaf.io/v1beta1
kind: SecRule
metadata:
  name: example
spec:
  secLangRules:
  - metadata:
      id: 100001
      phase: "1"
    conditions:
    - variables: [{ name: REQUEST_METHOD }]
      operator: { name: streq, value: "TRACE" }
    actions:
      disruptive: { disruptiveActionType: deny }
```

See the [full CRD schema](https://github.com/kubewaf-io/kubewaf/blob/main/config/crd/bases/seclang.kubewaf.io_secrules.yaml) for every field.