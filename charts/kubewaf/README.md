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
- [Observability & Metrics](https://kubewaf.io/guides/observability/) — Managed path is Envoy OTLP (`kubewaf_otel`) into VictoriaMetrics. DIY scrape of Envoy `/stats` is not the product API. `profile=full` converts access-log records to `waf.eval` traces in VictoriaTraces.
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
| dataplane.ecds.port | int | `18001` | Container / Service port for the ECDS gRPC server |
| dataplane.ecds.serviceHost | string | `""` | DNS name Envoy uses for the ECDS cluster (defaults to release service FQDN) |
| dataplane.extensionServer.port | int | `5005` | Container / Service port for the Envoy Gateway Extension Server |
| dataplane.wasmMountPath | string | `"/wasm"` | Mount path for shared wasm volume |
| dataplane.wasmServe.port | int | `18002` | Container / Service port for multi-module wasm HTTP |
| dataplane.wasmVolume | string | `nil` | Optional volume mounting wasm binaries under wasmMountPath |
| env | list | `[{"name":"KUBE_FEATURE_WatchListClient","value":"false"}]` | Environment variables |
| fullnameOverride | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` | Set the image pull policy. |
| image.registry | string | `"ghcr.io"` | Set the image registry |
| image.repository | string | `"kubewaf-io/kubewaf"` | Set the image repository |
| image.tag | string | `""` | Overrides the image tag whose default is the chart appVersion. |
| imagePullSecrets | list | `[]` | Configuration for `imagePullSecrets` so that you can use a private images registry. |
| leaderElection.enabled | bool | `true` | Enable leader election (required when replicaCount > 1) |
| livenessProbe | object | `{"httpGet":{"path":"/healthz","port":10080}}` | Configure the liveness probe using Deployment probe spec |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` | Set the node selector |
| observability.managed.alerts.enabled | bool | `true` |  |
| observability.managed.ciliumNetworkPolicy.enabled | bool | `false` |  |
| observability.managed.ciliumNetworkPolicy.nodeCIDRs | list | `[]` |  |
| observability.managed.collector.enabled | bool | `true` |  |
| observability.managed.collector.image.pullPolicy | string | `"IfNotPresent"` |  |
| observability.managed.collector.image.registry | string | `"docker.io"` |  |
| observability.managed.collector.image.repository | string | `"otel/opentelemetry-collector-contrib"` |  |
| observability.managed.collector.image.tag | string | `"0.128.0"` |  |
| observability.managed.collector.resources.limits.cpu | string | `"500m"` |  |
| observability.managed.collector.resources.limits.memory | string | `"512Mi"` |  |
| observability.managed.collector.resources.requests.cpu | string | `"50m"` |  |
| observability.managed.collector.resources.requests.memory | string | `"128Mi"` |  |
| observability.managed.enabled | bool | `false` | Enable the managed OTLP plane (Collector + metrics backend) |
| observability.managed.grafana.enabled | bool | `false` |  |
| observability.managed.injectConfigured | bool | `false` | Set true after applying the Envoy/Istio bootstrap fragment (cluster + sink + tags). |
| observability.managed.networkPolicy.enabled | bool | `true` |  |
| observability.managed.otlp.endpoint | string | `""` | Empty = in-cluster {{ fullname }}-otel-collector:4317 |
| observability.managed.otlp.protocol | string | `"grpc"` | Envoy sink / access logger protocol |
| observability.managed.profile | string | `"lite"` | lite = metrics only; full = metrics + security traces |
| observability.managed.prometheusRemoteWrite.enabled | bool | `false` | Prometheus remote_write (not OTLP). Use victoriaMetrics.endpoint for OTLP ingest. |
| observability.managed.prometheusRemoteWrite.endpoint | string | `""` |  |
| observability.managed.traces.includeMatchDataDefault | bool | `false` |  |
| observability.managed.traces.redact | bool | `true` |  |
| observability.managed.traces.sampleDisruptive | string | `"1.0"` |  |
| observability.managed.traces.sampleNonDisruptive | string | `"0.25"` |  |
| observability.managed.victoriaMetrics.enabled | bool | `true` | In-cluster single-node VM (required for lite/full unless endpoint or remote_write is set) |
| observability.managed.victoriaMetrics.endpoint | string | `""` | External VM / vmagent OTLP metrics ingest. Empty uses in-cluster VM when enabled. |
| observability.managed.victoriaMetrics.image.pullPolicy | string | `"IfNotPresent"` |  |
| observability.managed.victoriaMetrics.image.registry | string | `"docker.io"` |  |
| observability.managed.victoriaMetrics.image.repository | string | `"victoriametrics/victoria-metrics"` |  |
| observability.managed.victoriaMetrics.image.tag | string | `"v1.117.1"` |  |
| observability.managed.victoriaMetrics.resources.limits.cpu | string | `"1"` |  |
| observability.managed.victoriaMetrics.resources.limits.memory | string | `"1Gi"` |  |
| observability.managed.victoriaMetrics.resources.requests.cpu | string | `"50m"` |  |
| observability.managed.victoriaMetrics.resources.requests.memory | string | `"128Mi"` |  |
| observability.managed.victoriaMetrics.retentionPeriod | string | `"14d"` |  |
| observability.managed.victoriaTraces.enabled | bool | `false` |  |
| observability.managed.victoriaTraces.endpoint | string | `""` |  |
| observability.managed.victoriaTraces.image.pullPolicy | string | `"IfNotPresent"` |  |
| observability.managed.victoriaTraces.image.registry | string | `"docker.io"` |  |
| observability.managed.victoriaTraces.image.repository | string | `"victoriametrics/victoria-traces"` |  |
| observability.managed.victoriaTraces.image.tag | string | `"v0.4.0"` |  |
| observability.managed.victoriaTraces.resources.limits.cpu | string | `"1"` |  |
| observability.managed.victoriaTraces.resources.limits.memory | string | `"1Gi"` |  |
| observability.managed.victoriaTraces.resources.requests.cpu | string | `"50m"` |  |
| observability.managed.victoriaTraces.resources.requests.memory | string | `"128Mi"` |  |
| podAnnotations | object | `{}` | Annotations to add to pod |
| podDisruptionBudget.enabled | bool | `true` | Create a PDB |
| podDisruptionBudget.minAvailable | int | `1` | Minimum available pods during voluntary disruptions |
| podLabels | object | `{}` | Annotations to add to pod |
| podSecurityContext | object | `{"enabled":true,"seccompProfile":{"type":"RuntimeDefault"}}` | Set the securityContext |
| priorityClassName | string | `""` | Set the priority class name |
| probeTestServer.auth.tokenSecretName | string | `""` | Shared bearer Secret name (empty = {{ fullname }}-probe-eval-token) |
| probeTestServer.concurrency.globalMaxInFlight | int | `16` |  |
| probeTestServer.concurrency.maxConcurrentCompiles | int | `4` |  |
| probeTestServer.enabled | bool | `false` | Deploy go-coraza Test HTTP Server (required only when subresourceApi.probes.enabled) |
| probeTestServer.image.pullPolicy | string | `"IfNotPresent"` |  |
| probeTestServer.image.registry | string | `""` |  |
| probeTestServer.image.repository | string | `"kubewaf-io/kubewaf-probe-test-server"` |  |
| probeTestServer.image.tag | string | `""` |  |
| probeTestServer.networkPolicy | object | `{"enabled":true}` | Create NetworkPolicy allowing only Subresource API pods |
| probeTestServer.podAnnotations | object | `{}` |  |
| probeTestServer.podLabels | object | `{}` |  |
| probeTestServer.replicaCount | int | `1` | Replica count (compile cache is per-pod if enabled later) |
| probeTestServer.resources.limits.cpu | string | `"2"` |  |
| probeTestServer.resources.limits.memory | string | `"1Gi"` |  |
| probeTestServer.resources.requests.cpu | string | `"100m"` |  |
| probeTestServer.resources.requests.memory | string | `"256Mi"` |  |
| probeTestServer.service.port | int | `8080` |  |
| readinessProbe | object | `{"httpGet":{"path":"/readyz","port":10080}}` | Configure the readiness probe using Deployment probe spec |
| replicaCount | int | `2` | Amount of replicas (use >=2 with leader election for HA) |
| resources | object | `{}` | Set the resource requests/limits |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"enabled":true,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1000}` | Set the securityContext for the container |
| serviceAccount.annotations | object | `{}` | Annotations to add to the service account. |
| serviceAccount.create | bool | `true` | Specifies whether a service account should be created. |
| serviceAccount.name | string | `""` | The name of the service account to use. |
| subresourceApi | object | `{"concurrency":{"globalMaxInFlight":32,"perNamespace":4},"directives":{"enabled":false},"enabled":false,"image":{"pullPolicy":"IfNotPresent","registry":"","repository":"kubewaf-io/kubewaf-subresource-api","tag":""},"networkPolicy":{"enabled":true},"podAnnotations":{},"podLabels":{},"probes":{"enabled":true},"query":{"enabled":true},"replicaCount":1,"resources":{"limits":{"cpu":"1","memory":"512Mi"},"requests":{"cpu":"50m","memory":"128Mi"}},"service":{"port":443},"testServer":{"connectTimeoutSeconds":2,"tokenSecretName":"","url":""}}` | ------------------------------------------------------------------------- |
| subresourceApi.concurrency.globalMaxInFlight | int | `32` | Process-wide max concurrent probes |
| subresourceApi.concurrency.perNamespace | int | `4` | Max in-flight probes per namespace |
| subresourceApi.directives.enabled | bool | `false` | Register GET …/wafs/{name}/directives (no Test Server) |
| subresourceApi.enabled | bool | `false` | Deploy the Subresource API Server + APIService |
| subresourceApi.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| subresourceApi.image.registry | string | `""` | Image registry (empty inherits image.registry) |
| subresourceApi.image.repository | string | `"kubewaf-io/kubewaf-subresource-api"` | Image repository for cmd/subresource-api |
| subresourceApi.image.tag | string | `""` | Image tag (empty inherits image.tag / Chart.AppVersion) |
| subresourceApi.networkPolicy | object | `{"enabled":true}` | Create NetworkPolicy (defense-in-depth; kind often permissive) |
| subresourceApi.podAnnotations | object | `{}` | Optional pod annotations |
| subresourceApi.podLabels | object | `{}` | Optional pod labels |
| subresourceApi.probes.enabled | bool | `true` | Register /probes (requires probeTestServer.enabled) |
| subresourceApi.query.enabled | bool | `true` | Register GET …/metrics, /traces, /clustermetrics (operator-side VM/VT proxy) |
| subresourceApi.replicaCount | int | `1` | Replica count |
| subresourceApi.resources | object | `{"limits":{"cpu":"1","memory":"512Mi"},"requests":{"cpu":"50m","memory":"128Mi"}}` | Resources for Subresource API pods |
| subresourceApi.service.port | int | `443` | Service port exposed to apiserver (APIService) |
| subresourceApi.testServer.tokenSecretName | string | `""` | Shared bearer Secret name (empty = {{ fullname }}-probe-eval-token) |
| subresourceApi.testServer.url | string | `""` | URL of Test HTTP Server (cluster DNS) leave empty to use http://{{ fullname }}-probe-test-server:port |
| tolerations | list | `[]` | Set list of tolerations |
| topologySpreadConstraints | list | `[]` | Set topology spread constraints |
| volumeMounts | list | `[{"mountPath":"/tmp","name":"tmpfs-vol"}]` | VolumeMounts |
| volumes | list | `[{"emptyDir":{"medium":"Memory","sizeLimit":"50Mi"},"name":"tmpfs-vol"}]` | Volumes |
| webhooks.enabled | bool | `true` |  |
| webhooks.failurePolicy | string | `"Fail"` | Fail or Ignore when the webhook is unreachable |

### Monitoring Parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| monitoring.enabled | bool | `false` | Enable Monitoring of the Operator |
| monitoring.rules.annotations | object | `{}` | Assign additional Annotations |
| monitoring.rules.enabled | bool | `false` | Enable deployment of PrometheusRules |
| monitoring.rules.groups | list | `[]` | Prometheus Groups for the rule.   You can also enable the built-in WAF alerts below. |
| monitoring.rules.labels | object | `{}` | Assign additional labels |
| monitoring.rules.namespace | string | `""` | Install the rules into a different Namespace, as the monitoring stack one (default: the release one) |
| monitoring.rules.wafAlerts | object | `{"enabled":false}` | Enable the recommended WAF data-plane + operator alerts and recording rules.   When true, a solid set of alerts for modsecurity_proxy_wasm_* and kubewaf_* metrics is included. |
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
