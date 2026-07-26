# kubeWAF Helm Chart

**Kubernetes-native Web Application Firewall Operator**

This chart deploys the kubeWAF operator, which enables you to manage ModSecurity-compatible WAF rules using native Kubernetes Custom Resources (`SecRule`, `RuleSet`, `WAF`, etc.).

## Quick Install

```bash
helm repo add kubewaf https://kubewaf-io.github.io/charts
helm repo update

helm install kubewaf kubewaf/kubewaf \
  --namespace kubewaf-system \
  --create-namespace
```

## Full Documentation

Please see the official documentation site:

- [Installation Guide](https://kubewaf.io/getting-started/installation/)
- [Quick Start](https://kubewaf.io/getting-started/quickstart/)
- [Observability & Metrics](https://kubewaf.io/guides/observability/) — How to scrape `modsecurity_proxy_wasm_*` metrics from modsecurity-proxy-wasm
- [Helm Values Reference](https://kubewaf.io/) (values are documented via Artifact Hub schema)

## Values

The table below is generated from `values.schema.json`. The most important ones are shown here for convenience.

The following Values are available for this chart.

### Global Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| global.jobs.kubectl.affinity | object | `{}` | Set affinity rules |
| global.jobs.kubectl.annotations | object | `{}` | Annotations to add to the job. |
| global.jobs.kubectl.image.pullPolicy | string | `"IfNotPresent"` | Set the image pull policy of the helm chart job |
| global.jobs.kubectl.image.registry | string | `"docker.io"` | Set the image repository of the helm chart job |
| global.jobs.kubectl.image.repository | string | `"clastix/kubectl"` | Set the image repository of the helm chart job |
| global.jobs.kubectl.image.tag | string | `""` | Set the image tag of the helm chart job |
| global.jobs.kubectl.labels | object | `{}` | Labels to add to the job. |
| global.jobs.kubectl.nodeSelector | object | `{}` | Set the node selector |
| global.jobs.kubectl.podAnnotations | object | `{}` | Annotations to add to the job pod |
| global.jobs.kubectl.podLabels | object | `{}` | Labels to add to the job pod |
| global.jobs.kubectl.podSecurityContext | object | `{"enabled":true,"seccompProfile":{"type":"RuntimeDefault"}}` | Security context for the job pods. |
| global.jobs.kubectl.priorityClassName | string | `""` | Set a pod priorityClassName |
| global.jobs.kubectl.resources | object | `{}` | Job resources |
| global.jobs.kubectl.restartPolicy | string | `"Never"` | Set the restartPolicy |
| global.jobs.kubectl.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"enabled":true,"readOnlyRootFilesystem":true,"runAsGroup":1002,"runAsNonRoot":true,"runAsUser":1002}` | Security context for the job containers. |
| global.jobs.kubectl.tolerations | list | `[]` | Set list of tolerations |
| global.jobs.kubectl.topologySpreadConstraints | list | `[]` | Set Topology Spread Constraints |
| global.jobs.kubectl.ttlSecondsAfterFinished | int | `60` | Sets the ttl in seconds after a finished certgen job is deleted. Set to -1 to never delete. |

### CustomResourceDefinition Lifecycle

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| crds.annnotations | object | `{}` | Extra Annotations for CRDs |
| crds.inline | bool | `false` |  |
| crds.install | bool | `true` | Install the CustomResourceDefinitions (This also manages the lifecycle of the CRDs for update operations) |
| crds.keep | bool | `false` | Keep the annotations if deleted |
| crds.labels | object | `{}` | Extra Labels for CRDs |

### General Parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Set affinity rules |
| args.extraArgs | list | `[]` | A list of extra arguments to add |
| args.logLevel | int | `4` | Log Level |
| args.pprof | bool | `false` | Enable Profiling |
| env | list | `[]` | Environment variables |
| fullnameOverride | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` | Set the image pull policy. |
| image.registry | string | `"ghcr.io"` | Set the image registry |
| image.repository | string | `"kubewaf-io/kubewaf"` | Set the image repository |
| image.tag | string | `""` | Overrides the image tag whose default is the chart appVersion. |
| imagePullSecrets | list | `[]` | Configuration for `imagePullSecrets` so that you can use a private images registry. |
| livenessProbe | object | `{"httpGet":{"path":"/healthz","port":10080}}` | Configure the liveness probe using Deployment probe spec |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` | Set the node selector |
| podAnnotations | object | `{}` | Annotations to add to pod |
| podLabels | object | `{}` | Annotations to add to pod |
| podSecurityContext | object | `{"enabled":true,"seccompProfile":{"type":"RuntimeDefault"}}` | Set the securityContext |
| priorityClassName | string | `""` | Set the priority class name |
| readinessProbe | object | `{"httpGet":{"path":"/readyz","port":10080}}` | Configure the readiness probe using Deployment probe spec |
| replicaCount | int | `1` | Amount of replicas |
| resources | object | `{}` | Set the resource requests/limits |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"enabled":true,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000}` | Set the securityContext for the container |
| serviceAccount.annotations | object | `{}` | Annotations to add to the service account. |
| serviceAccount.create | bool | `true` | Specifies whether a service account should be created. |
| serviceAccount.name | string | `""` | The name of the service account to use. |
| tolerations | list | `[]` | Set list of tolerations |
| topologySpreadConstraints | list | `[]` | Set topology spread constraints |
| volumeMounts | list | `[]` | VolumeMounts |
| volumes | list | `[]` | Volumes |

### Monitoring Parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| monitoring.enabled | bool | `false` | Enable Monitoring of the Operator |
| monitoring.rules.annotations | object | `{}` | Assign additional Annotations |
| monitoring.rules.enabled | bool | `false` | Enable deployment of PrometheusRules |
| monitoring.rules.groups | list | `[]` | Prometheus Groups for the rule |
| monitoring.rules.wafAlerts.enabled | bool | `false` | Enable the built-in recommended WAF + operator alerts |
| monitoring.rules.labels | object | `{}` | Assign additional labels |
| monitoring.rules.namespace | string | `""` | Install the rules into a different Namespace, as the monitoring stack one (default: the release one) |
| monitoring.serviceMonitor.annotations | object | `{}` | Assign additional Annotations |
| monitoring.serviceMonitor.enabled | bool | `true` | Enable ServiceMonitor |
| monitoring.serviceMonitor.endpoint.interval | string | `"15s"` | Set the scrape interval for the endpoint of the serviceMonitor |
| monitoring.serviceMonitor.endpoint.metricRelabelings | list | `[]` | Set metricRelabelings for the endpoint of the serviceMonitor |
| monitoring.serviceMonitor.endpoint.relabelings | list | `[]` | Set relabelings for the endpoint of the serviceMonitor |
| monitoring.serviceMonitor.endpoint.scrapeTimeout | string | `""` | Set the scrape timeout for the endpoint of the serviceMonitor |
| monitoring.serviceMonitor.jobLabel | string | `"app.kubernetes.io/name"` | Prometheus Joblabel |
| monitoring.serviceMonitor.labels | object | `{}` | Assign additional labels according to Prometheus' serviceMonitorSelector matching labels |
| monitoring.serviceMonitor.matchLabels | object | `{}` | Change matching labels |
| monitoring.serviceMonitor.namespace | string | `""` | Install the ServiceMonitor into a different Namespace, as the monitoring stack one (default: the release one) |
| monitoring.serviceMonitor.serviceAccount.name | string | `""` |  |
| monitoring.serviceMonitor.serviceAccount.namespace | string | `""` |  |
| monitoring.serviceMonitor.targetLabels | list | `[]` | Set targetLabels for the serviceMonitor |
