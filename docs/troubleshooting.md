# Troubleshooting

Common issues and how to diagnose them.

## Installation Problems

**CRDs not registered**

```bash
kubectl get crd | grep kubewaf
```

If empty, re-run the Helm install or `kubectl apply -k config/crd`.

**Operator pod CrashLooping**

Check logs:

```bash
kubectl logs -n kubewaf-system -l app.kubernetes.io/name=kubewaf -f
```

Common causes:

- Missing RBAC (rare after correct install)
- Envoy Gateway CRDs not present when WAF controller starts (it registers the scheme but does not require them at startup)

## Rule Not Enforced

1. Check the `WAF` status:

   ```bash
   kubectl describe wafenvoygateway <name>
   ```

   Look for `ReferencesResolved: False`.

2. Check the referenced `RuleSet`:

   ```bash
   kubectl describe ruleset <name>
   ```

3. Verify the generated EnvoyExtensionPolicy exists and has the Wasm filter configured.

4. Increase log level:

   ```yaml
   spec:
     logLevel: 7
   ```

   Then look at the Envoy proxy pod logs for Coraza output.

## ReferencesResolved = False

Possible reasons:

- A referenced `SecRule` or `RuleSet` does not exist
- Namespace policy violation (`allowedRules.from`)
- Recursive reference cycle (the resolver detects and reports this)
- Wrong `group`/`version` in the `RuleRef`

The error is also written to the `status.conditions` message.

## Rules Work Locally but Not in Prod

- Different CRS versions between environments
- Missing initialization rules that set paranoia level / thresholds
- Label selectors that match in dev but not in prod (different labeling)

## High Latency / CPU After Enabling WAF

CRS with paranoia level 3–4 + hundreds of rules adds measurable cost.

Mitigations:

- Start with `crsEnable: true` + your own low paranoia initialization rule
- Exclude entire rule files using label selectors on your CRS RuleSet
- Use `ctl:ruleRemoveByTag` or `ctl:ruleRemoveById` in early phase-1 rules

## 403 on Legitimate Traffic (False Positive)

This is normal when first enabling CRS.

Steps:

1. Identify the rule ID from the WAF log (`[id "942100"]`)
2. Create an exclusion rule that runs before the CRS rule:

   ```yaml
   - metadata: { id: 1000001, phase: "1" }
     conditions: [ { variables: [{name: REQUEST_URI}], operator: {name: rx, value: ^/healthz} } ]
     actions:
       nonDisruptive:
       - nonDisruptiveActionType: ctl
         value: ruleRemoveById=942100
   ```

3. Or raise the anomaly threshold in your initialization rule.

## Status.secRuleString Is Empty

The `SecRule` controller only populates `secRuleString` after successful conversion. If conversion fails (bad operator name, unknown variable, etc.), the condition `Ready` will be `False` and an event will be emitted.

Inspect:

```bash
kubectl describe secrule <name>
```

## Getting Help

- Open a GitHub issue with:
  - `kubectl get wafenvoygateway, ruleset, secrule -A -o yaml` output (redact secrets)
  - Relevant operator and Envoy logs
  - Reproduction steps (minimal YAML)

- Discussions: https://github.com/kubewaf-io/kubewaf/discussions

- Email: hello@kubewaf.io

When filing bugs, please include the output of:

```bash
kubectl version
helm list -n kubewaf-system
kubectl get wafenvoygateway -o wide
```