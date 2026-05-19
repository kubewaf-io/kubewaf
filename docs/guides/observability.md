# Observability & Metrics

kubeWAF surfaces rich Prometheus metrics from the **coraza-proxy-wasm** filter running inside Envoy. These metrics give you visibility into traffic volume, blocked attacks, and which rules are firing.

## Metrics Exposed by Coraza WASM

| Metric                              | Type     | Labels                                      | Description |
|-------------------------------------|----------|---------------------------------------------|-------------|
| `waf_filter_tx_total`               | Counter  | —                                           | Total number of transactions processed by the WAF |
| `waf_filter_tx_interruptions`       | Counter  | `phase`, `rule_id`, `owner`, + custom labels | Number of requests **blocked** (interrupted) by rules |

**Important labels on `waf_filter_tx_interruptions`**:

- `phase`: `http_request_headers`, `http_request_body`, `http_response_headers`, `http_response_body`
- `rule_id`: The exact rule that caused the block (e.g. `942100`, `913100`, your custom IDs)
- Any labels you pass via `spec.metrics.extraLabels`

## Enabling Metrics in Your WAF Policy

```yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: WAF
metadata:
  name: shop-waf
spec:
  parentRefs:
    targetRef:
      kind: HTTPRoute
      name: shop-frontend

  ruleRefs:
    - kind: RuleSet
      name: shop-protection

  crsEnable: true

  metrics:
    name: "coraza-shop-prod"          # Affects metric naming
    rootID: "coraza"
    extraLabels:
      team: "payments"
      environment: "prod"
      gateway: "external"
    includeRuleID: true               # Set false to reduce cardinality
    enableStats: true
```

## Making Metrics Scrapable (Envoy Gateway)

By default, Envoy Gateway exposes the Envoy admin interface (including `/stats/prometheus`), but you usually need to configure an `EnvoyProxy` resource.

### Recommended `EnvoyProxy` Configuration

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: eg-metrics
  namespace: envoy-gateway-system
spec:
  telemetry:
    metrics:
      prometheus: {}
```

Attach it to your `Gateway`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: external
spec:
  gatewayClassName: eg
  infrastructure:
    parametersRef:
      group: gateway.envoyproxy.io
      kind: EnvoyProxy
      name: eg-metrics
```

## Scraping the Metrics

### Quick Local Debugging

```bash
# Find an Envoy pod
kubectl get pods -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=external

# Port-forward admin port (usually 19000)
kubectl -n envoy-gateway-system port-forward <pod> 19000:19000

# Query WAF metrics
curl -s http://localhost:19000/stats/prometheus | grep waf_filter
```

### Production: ServiceMonitor Example

See the full example in `config/samples/monitoring-waf-metrics.yaml`.

Key points:

- Scrape the `admin` port on Envoy pods
- Path: `/stats/prometheus`
- Use `metricRelabelings` to keep only `waf_filter_*` metrics if you want to reduce volume

## Recommended Grafana Panels

**1. WAF Block Rate (most important)**

```promql
sum(rate(waf_filter_tx_interruptions[5m])) / sum(rate(waf_filter_tx_total[5m]))
```

**2. Top Blocked Rules**

```promql
topk(15,
  sum by (rule_id, phase) (rate(waf_filter_tx_interruptions[5m]))
)
```

**3. Blocks by Phase**

```promql
sum by (phase) (rate(waf_filter_tx_interruptions[5m]))
```

**4. Per-Team / Per-Environment View** (thanks to `extraLabels`)

```promql
sum by (team, environment) (rate(waf_filter_tx_interruptions[5m]))
```

## Reducing Cardinality

The `rule_id` label can become high cardinality if you have hundreds of rules and high traffic.

Solutions:

1. Set `spec.metrics.includeRuleID: false` on your `WAF`.
2. Use `metricRelabelings` in your `ServiceMonitor` to drop the label.
3. Use recording rules in Prometheus to aggregate.

## Operator Metrics

In addition to the data-plane `waf_filter_*` metrics, the operator publishes its own high-value metrics under the `kubewaf_*` prefix:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kubewaf_waf_total` | Gauge | `namespace` | Total WAF policies |
| `kubewaf_waf_ready` | Gauge | `namespace`, `name` | 1 = Ready, 0 = unhealthy |
| `kubewaf_waf_crs_enabled` | Gauge | `namespace`, `name` | Whether CRS is enabled |
| `kubewaf_rules_loaded` | Gauge | `namespace`, `name`, `policy_type` | Number of rules resolved for a policy |
| `kubewaf_ruleset_total` / `kubewaf_secrule_total` | Gauge | `namespace` | Inventory of your security rules |
| `kubewaf_reconcile_total` | Counter | `controller`, `result` | Reconciliation activity |
| `kubewaf_reconcile_duration_seconds` | Histogram | `controller` | Performance of the operator |

These metrics are extremely useful for:
- Detecting "ghost" WAF policies that have zero rules
- Alerting on policies that stop being Ready
- Capacity planning ("how many rules do we manage?")

## Prometheus Alerts & Recording Rules

kubeWAF ships with a curated set of alerts (see `config/prometheus/kubewaf-waf-rules.yaml`):

**Data-plane alerts**
- `KubeWAFHighBlockRate` / `KubeWAFVeryHighBlockRate`
- `KubeWAFTrafficDrop`
- `KubeWAFHighRuleActivity`
- `KubeWAFDominantRule` (one rule causing most blocks)
- `KubeWAFRuleSpike` (sudden 8x increase from a specific rule)

**Operator / Policy Health alerts**
- `KubeWAFPolicyNotReady`
- `KubeWAFReferenceResolutionFailing`
- `KubeWAFNoRulesLoaded`
- `KubeWAFHighReconciliationDuration`

### Enabling Alerts via Helm

```yaml
monitoring:
  enabled: true
  rules:
    enabled: true
    wafAlerts:
      enabled: true          # ← ships the recommended alerts above
```

You can also provide your own groups under `monitoring.rules.groups`.

The full list of recommended recording rules (including `kubewaf:top10_noisy_rules:rate5m`) and alerts is maintained in the [GitHub repository](https://github.com/kubewaf-io/kubewaf/tree/main/config/prometheus).

## Future Enhancements

- Support for histograms (WAF processing latency per phase)
- Integration with OpenTelemetry
- Automatic creation of recording rules and alerts

See the [WAF CRD reference](../reference/crds/waf.md) for the full schema of the `metrics` field.

## Next Steps

- Deploy the [example with metrics enabled](../getting-started/quickstart.md)
- Import the Grafana dashboard from `docs/assets/grafana-kubewaf-dashboard.json`
- Import Grafana alert rules from `docs/assets/grafana-kubewaf-alert-rules.json` (into Grafana Alerting → Alert rules → Import)
- Set up alerts on sudden spikes in `waf_filter_tx_interruptions`