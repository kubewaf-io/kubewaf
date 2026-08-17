# Managed observability samples

`spec.telemetry` is on the WAF CRD (`None` | `Managed`). Plugin JSON carries policy only.

One cluster Helm install (`helm-values-full.yaml`). The three WAF files differ only by
Gateway / provider; the `telemetry` block is identical.

**Product path (rev 15):** slots inject Envoy cluster `kubewaf_otel` (same class as
`kubewaf_ecds`) and point **Envoy** at it:

- bootstrap `envoy.stat_sinks.open_telemetry` → OTLP/gRPC metrics (`:4317`)
- HCM `envoy.access_loggers.open_telemetry` → OTLP/gRPC logs (Collector turns them
  into `waf.eval` traces)

Wasm does **not** `httpCall`. It keeps ABI counters and, when `mode=Managed`,
sets filter metadata so the access logger has something to send.

There is **no** otel-bridge, **no** Envoy `/stats` scrape, **no** Collector filelog,
**no** Wasm OTLP client, **no** allowlist ConfigMap.

kubeWAF does **not** ask you to fill `EnvoyProxy.spec.telemetry`, Istio `Telemetry`,
or Hubble. Bootstrap fragments are the same *class* as the existing ECDS cluster
patch (`test/e2e/manifests/envoygateway/gateway.yaml`, Istio `ecds-bootstrap.yaml`,
Cilium merge script).

| File | Slot |
|------|------|
| `waf-envoy-gateway.yaml` | Extension Server stub + ECDS. Bootstrap JSONPatch: `kubewaf_otel` + stats sink. HCM access log from `PostHTTPListenerModify`. |
| `waf-istio.yaml` | EnvoyFilter `CLUSTER ADD` + ECDS stub. Bootstrap override: sink + cluster. HCM MERGE access log. |
| `waf-cilium.yaml` | CEC stub + ECDS. Bootstrap-static **both** clusters (HTTP/2 ClusterIP) + sink. CEC must not define `kubewaf_otel`. |

**Cilium install order:** Helm managed plane first (Collector Service ClusterIP), then:

```bash
hack/scripts/merge-cilium-envoy-ecds-bootstrap.sh --apply --helm-upgrade \
  --ecds-service kubewaf-ecds \
  --otel-service kubewaf-otel-collector
```

The merge script writes ConfigMap `kubewaf-cilium-otel` (`ciliumOtelMerged`); Helm
must not own that object. `TelemetrySink` on Cilium is Ready only after remesh.

Helm **fails** if `observability.managed.enabled=true` and neither VictoriaMetrics
nor prometheusRemoteWrite is configured (lite and full).

- **lite:** Envoy stats sink + Collector + VictoriaMetrics (or remote_write). Grafana off.
- **full:** + Envoy OTel access log + Collector `waf.eval` span transform + VictoriaTraces.
