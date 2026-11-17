# kubeWAF 0.2 chart

This chart installs the `seclang.kubewaf.io/v1alpha1` operator (`cmd/operator`). It is a clean replacement for the 0.1.x chart, not an upgrade of it.

`secrules.seclang.kubewaf.io` and `secactions.seclang.kubewaf.io` cannot serve v1beta1 and v1alpha1 without a conversion webhook. This release does not ship one. The 0.1.x chart and this chart must not be installed together.

## Hard upgrade

1. Uninstall the 0.1.x release: `helm uninstall kubewaf -n kubewaf-system`.
2. Delete the v1beta1 CRDs: `secrules`, `secactions`, `secruleidpools`, `phraselists`, `iplists` in `seclang.kubewaf.io`, and `wafs`, `rulesets` in `waf.kubewaf.io`.
3. Delete any objects of those kinds. They are not converted.
4. Install this chart. The platform team applies `config/samples/envoygateway/platform-envoyproxy.yaml` and points the Gateway `spec.infrastructure.parametersRef` at that `EnvoyProxy` before this chart is expected to program filters.

This chart does not set a Composer image, an init-container command, or a module delivery method. Those belong to the platform `EnvoyProxy`.

Values that exist: `image`, `replicaCount`, `proxyNamespace` (default `envoy-gateway-system`), `webhooks.enabled`, `leaderElection.enabled`, `metrics.enabled`.

The Deployment runs `/operator` from `cmd/operator`. It does not listen on 18001, 18002, or 5005.

The operator writes `kubewaf-seclang` (rule files plus a `kubewaf-version` key) before it writes the EnvoyExtensionPolicy. A DaemonSet in `proxyNamespace` runs the same image with `--projection-agent`, mounts that ConfigMap, and records the projected version in `kubewaf-seclang-seen`. The SecMarker is published only after every Ready Envoy pod that mounts the volume is on a node reporting that version. `Programmed` follows the EnvoyExtensionPolicy status. The chart does not grant `pods/log`.

`Protection` (`waf.kubewaf.io/v1alpha1`) is the higher-level attachment. It always includes the embedded CRS, emits paranoia and exclusion directives, and can select existing SecRule objects. It does not create those objects. A sample is `config/samples/waf/protection-edge.yaml`. The extension policy name is `kubewaf-p-<name>`. A `rateLimit` entry creates a local Envoy Gateway `BackendTrafficPolicy` named `kubewaf-ratelimit-<protection>-<name>`. A Protection and a SecPolicy cannot target the same Gateway or HTTPRoute.
