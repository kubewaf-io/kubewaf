# Changelog

All notable changes to kubeWAF are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2026-07-30

First public **beta candidate** packaging cut. APIs remain `v1beta1` and may change.

### Added

- **Validating admission webhooks** for SecRule, SecAction, RuleSet, WAF (`internal/webhook`, Helm `webhooks.enabled`)
- **CI gate (PR)**: EG smoke (`test-e2e.yml`) + **full matrix** (`test-e2e-release.yml`: EG path-b provider smoke + Path B FTW, Istio, Cilium)
- **Wasm dual catalog**: path-b (default, CI) and full (`*-full`, Path A second-class) published from the engine release
- **CI gate (main)**: EG smoke only (full matrix not on main pushes)
- **CI gate (release tags)**: full matrix before GoReleaser; local `make test-e2e-release`
- website2 docs: Beta status page, engine matrix, security/CoC/contributing, webhooks (website2-canonical; root stubs)
- `WAF.spec.mode`: `Blocking` (default) or `DetectionOnly` (`SecRuleEngine DetectionOnly`) for safe rollouts
- WAF status: `mode`, `rulesLoaded`, `actionsLoaded`, `directivesCount`, `renderedDirectives` (size-capped)
- kubectl printer columns on `WAF` and `RuleSet`
- Kubernetes events on WAF Ready / NotReady transitions
- Accurate `kubewaf_rules_loaded` metric (SecRule count, not raw object list length)
- RuleSet `status.rulesLoaded` / `actionsLoaded` and back-reference cleanup on delete
- Enforced `RuleSet.spec.allowedRules` on the owner when resolving cross-namespace rules

### Changed

- Default `WAF.spec.logLevel` **1** (error) instead of **7** (max debug)
- Operator logger defaults to production (not development); pprof only with `--enable-pprof`
- Helm chart / app version `0.1.0-beta.1` (was `0.0.0`)
- Kustomize project name / labels: `wafv2` → `kubewaf`

### Fixed

- Scaffold RuleSet reconciler did not persist its finalizer
- `allowedRules` was effectively a no-op (type assert never matched unstructured targets)
- `CleanupBackReferences` was a stub (orphaned SecRule/SecAction finalizers)

### Security

- Removed unconditional pprof listener on `:6060`

## Unreleased

- Headlamp **Observe** (sidebar kubeWAF → Observe): Hubble-style service map, flow table, eval log stream, and catalog metrics. Data is SAR-scoped `clustermetrics` plus `wafs/{ns}/{name}/traces` (`waf.eval`). No new charting libraries — Headlamp `SectionBox` / `SimpleTable` / `TileChart` / `StatusLabel`.
- Full provider-matrix CI (Istio/Cilium) as required gates (optional today)
- cert-manager integration for webhook cert rotation (Helm self-signed today)
- **Managed observability (opt-in):** Envoy is the OTLP client. Slots/bootstrap inject cluster `kubewaf_otel` (HTTP/2 gRPC :4317), an OpenTelemetry stats sink + `stats_tags`, and (when `spec.telemetry.mode=Managed`) a second HCM OTel access logger. Wasm annotates only — no `httpCall`. Helm `observability.managed` deploys Collector + VictoriaMetrics (`lite`) and optional VictoriaTraces (`full`). Product queries use `kubewaf.waf.*` / `kubewaf_waf_*`. Status condition `TelemetrySink` does not gate `Ready`. `profile=full` converts Envoy OTel access-log records to `waf.eval` traces. In-cluster VM ingest uses Prometheus remote_write (`/api/v1/write`). The OTel stats sink no longer uses process-wide `on_no_match` DropAction (that flushed empty OTLP on Envoy 1.38); unmatched stats pass through and Collector `filter/waf_metrics` is the membership gate. Dual-prefix `modsecurity_proxy_wasm.*` leftovers are still dropped. Collector filter accepts both `kubewaf.waf.*` and `kubewaf_waf[._]*`.

### Changed

- **Cilium is ECDS-only.** CEC HTTP filters are `config_discovery` stubs (same as EG/Istio). `cilium-envoy` needs a **bootstrap-static** `kubewaf_ecds` cluster pointed at the kubeWAF ECDS Service **ClusterIP** (`:18001`). Chart NOTES and ConfigMap `*-cilium-envoy-ecds-fragment` document the merge; do not set `envoy.bootstrapConfigMap` to the fragment. Inline CEC Wasm is removed. WAF `Ready` does not imply Envoy subscribed.
- ExtraLabels cannot override reserved metric identity keys (`waf_namespace`, `waf_name`, `engine`, `owner`).
- Cilium remesh: Cilium 1.19 Envoy has no SinkConfig.DropAction; the merge omits `custom_metric_conversions`. Chart bootstrap JSON is protojson camelCase (`staticResources`); the merge normalizes to snake_case before adding clusters so Envoy does not see a duplicate field and crash-loop. If the dump omits static `xds-grpc-cilium`, the merge injects the chart's pipe cluster. Source is the chart ConfigMap (`cilium-envoy-config`) first, then exec. Cilium 1.19 protojson rejects `OpenTelemetryAccessLogConfig` (`unknown field "grpc_service"`) and withdraws the CEC listener — Managed WAFs no longer embed that access logger in the CEC.

- Access-log export: Wasm writes filter state `kubewaf.event` / `kubewaf.export` (Envoy stores `wasm.*`). The HCM OTel logger is unfiltered on Envoy 1.38 (dynamic metadata is not writable from Wasm; CEL `has(map[i])` rejects the listener). Collector transform keeps event JSON, stamps span times, and drops the rest.

[0.1.0-beta.1]: https://github.com/kubewaf-io/kubewaf/releases/tag/v0.1.0-beta.1
