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

The first time `kubewaf-seclang` appears, kubelet may take about a minute to project it into an Envoy pod that started without the ConfigMap. The operator writes the files, waits 75s, then publishes the `EnvoyExtensionPolicy`. Later edits wait 5s so the watch can refresh the volume before the `SecMarker` changes. Publishing both in one step makes Envoy reject the listener, and it does not retry until the marker changes.
