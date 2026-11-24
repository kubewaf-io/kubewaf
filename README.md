# kubeWAF

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)

Kubernetes operator that compiles `SecRule`, `SecAction`, and `Include` objects into SecLang and attaches them to Envoy Gateway with a dynamic module.

The platform team owns the Envoy proxy. kubeWAF does not install Composer, patch `EnvoyProxy`, or patch `Gateway.spec.infrastructure.parametersRef`. It writes one `EnvoyExtensionPolicy` per `SecPolicy`, with the SecLang inline in the filter config. Data files for `@pmFromFile` still go in ConfigMap `kubewaf-seclang`.

This is a breaking replacement of the 0.1.x / `v1beta1` operator. There is no conversion webhook.

## Install

1. Install [Envoy Gateway v1.10](https://gateway.envoyproxy.io/).
2. Apply the platform `EnvoyProxy` and point the Gateway at it. The sample is `config/samples/envoygateway/platform-envoyproxy.yaml`. It registers `composer` from `ghcr.io/tetratelabs/built-on-envoy/composer:0.13.0` (copied by an init container that has `cp`) and sets `GODEBUG=cgocheck=0` and `doNotClose: true`. Mount ConfigMap `kubewaf-seclang` at `/etc/kubewaf/seclang` only when a policy uses `@pmFromFile` or `@ipMatchFromFile`.
3. Install this chart:

```bash
helm install kubewaf charts/kubewaf -n kubewaf-system --create-namespace
```

The Deployment runs `cmd/operator`. Metrics are on 8080 and health probes on 8081. It does not listen on 18001, 18002, or 5005.

### Hard upgrade from 0.1.x

`secrules.seclang.kubewaf.io` and `secactions.seclang.kubewaf.io` cannot serve v1beta1 and v1alpha1 together.

1. Save `kubectl get secrules,secactions -A -o yaml`. On v1beta1 the rendered text is `status.secRuleString`.
2. `helm uninstall` the 0.1.x release.
3. Delete CRDs `secrules`, `secactions`, `phraselists`, `iplists`, `secruleidpools` (`seclang.kubewaf.io`) and `rulesets`, `wafs` (`waf.kubewaf.io`).
4. Delete objects of those kinds. They are not converted.
5. Install this chart and re-author rules as v1alpha1. `RuleSet`, `PhraseList`, `IPList`, `SecRuleIDPool`, and the Wasm / ECDS / extension-server ports are gone.

## Attach a rule

`config/samples/seclang/block-sqlmap.yaml` denies `User-Agent` values that contain `sqlmap`:

```yaml
apiVersion: seclang.kubewaf.io/v1alpha1
kind: SecRule
metadata:
  name: block-sqlmap
spec:
  order: 10
  metadata:
    id: 100001
    phase: 1
  chain:
    - targets:
        - name: REQUEST_HEADERS
          selector: User-Agent
      operator:
        name: rx
        value: (?i)sqlmap
      actions:
        disruptive:
          type: deny
        data:
          - type: status
            value: "403"
---
apiVersion: seclang.kubewaf.io/v1alpha1
kind: SecPolicy
metadata:
  name: edge
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: eg
  rules:
    - kind: SecRule
      name: block-sqlmap
  engine: "On"
  inspection: RequestOnly
```

`Include` is the same shape for files. OWASP CRS is two objects, not a chart:

- `@crs-setup.conf`, placement `BeforeCRS`, order 20
- `@owasp_crs/*.conf`, placement `AfterCRS`, order 10

`config/samples/waf/crs.yaml` is that ruleset as a Protection on the quickstart HTTPRoute: paranoia 1, Blocking, RequestOnly. Comments in that file show `paranoia: 2`, `inboundAnomalyThreshold`, and `removeIds`. `config/samples/seclang/crs.yaml` is the same bundle as Include plus a SecAction id 900991 (`engine: "On"`). Apply only one of them to a given route.

A ConfigMap include is mounted under `/etc/kubewaf/seclang`. `@coraza.conf` stays in the filter preamble.

An HTTPRoute `SecPolicy` replaces the Gateway policy for that route. It does not stack a second filter.

## Reload

The `SecMarker` in the filter config is the hash of the bundle. Envoy re-reads Include files only when that marker changes. If the first load is rejected because kubelet has not projected the ConfigMap yet, the operator appends `rN` to the marker and publishes again. Envoy Gateway keeps the previous listener and does not put that rejection on the Gateway status, so the operator reads it from the envoy container log (and from a Gateway or `EnvoyExtensionPolicy` condition when one is present).

## Development

```bash
make test
make build
bash test/e2e/v1alpha1/run.sh
```

The CI Kind script needs Docker, kind, kubectl, and Helm. It installs Envoy Gateway v1.10.0 and expects a clean GET to return 200 and `User-Agent: sqlmap/1.0` to return 403.

`hack/local-e2e.sh` is the same stack for a machine you can reuse. Run it from anywhere inside the checkout (`make local-e2e` does the same). It keeps the Kind cluster unless you pass `--no-keep`. `--fresh` deletes that cluster first, `--protection` adds the Protection 200/403 case, `--crs` applies `config/samples/waf/crs.yaml` to the quickstart route and expects a clean GET 200 and SQLi, XSS, path traversal, and a scanner User-Agent to return 403, `--port-forward` reaches the Gateway through kubectl, and `--cleanup` deletes the cluster and exits. The runtime is Docker when `docker info` succeeds, otherwise Podman (`KIND_EXPERIMENTAL_PROVIDER=podman`). Override with `--runtime docker|podman` or `CONTAINER_RUNTIME`. Rootless Podman uses port-forward, same as rootless Docker. On NixOS, `nix-shell -p podman` supplies a missing runtime. Kind on rootless Podman needs cgroup v2 delegated to the user; if create fails, rerun under `systemd-run --scope --user`.

```bash
hack/local-e2e.sh
hack/local-e2e.sh --fresh --protection
hack/local-e2e.sh --crs
hack/local-e2e.sh --runtime podman
CONTAINER_RUNTIME=podman make local-e2e ARGS='--crs'
```
