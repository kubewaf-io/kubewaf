# kubeWAF end-to-end tests

Provider matrix e2e for **Envoy Gateway**, **Istio**, and **Cilium**, including optional
[CRS go-ftw](https://github.com/coreruleset/go-ftw) regression against each data plane.

## Local interactive demo

Bootstrap a local data-plane stack **without** building/loading an operator image or
Helm-installing kubeWAF (run the operator yourself with `make run` or install later).

```bash
# Infra only: Kind + Envoy Gateway + demo httpbin + full CRS + Path B WAF CRs
make local-demo

# Optional: also build/load image and Helm-install the operator
make local-demo-with-operator

# Or install the operator yourself after local-demo:
make run
# or:
make local-demo-image && make local-demo-operator
make local-demo-waf-path-b LOCAL_DEMO_WAIT_WAF=true

# Traffic check (needs a running operator + Ready WAF)
make local-demo-smoke

# Tear down Kind cluster
make local-demo-teardown
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `LOCAL_DEMO_IMG` | `E2E_IMG` (`ghcr.io/kubewaf-io/kubewaf:e2e`) | Operator image for `local-demo-image` / `-operator` |
| `LOCAL_DEMO_REPLICAS` | `1` | Operator replicas (Helm path) |
| `LOCAL_DEMO_WAF` | `path-b` | `path-b` = full CRS WAF; `smoke` = custom scanner rule only |
| `LOCAL_DEMO_WAIT_WAF` | `false` | Wait for WAF Ready (set `true` once an operator is running) |

After bootstrap, port-forward the Envoy proxy Service (name printed by `local-demo`) and curl with `Host: demo.local`.

## Quick start (automated e2e)

```bash
# Envoy Gateway (default) — resource + traffic smoke (no go-ftw)
make test-e2e-envoy-gateway

# Istio
make test-e2e-istio

# Cilium (Kind with disableDefaultCNI)
make test-e2e-cilium

# All providers sequentially (recreates clusters)
make test-e2e-all-providers

# Full **release** suite (EG smoke + Path B FTW + Istio/Cilium slot+traffic)
# Same coverage as CI job "E2E Release (full)" / pre-goreleaser gate.
# All jobs use path-b wasm (no embedded CRS rule confs).
make test-e2e-release
make test-e2e-release E2E_FTW_INCLUDE=all   # exhaustive CRS go-ftw (very slow)

# Path B go-ftw (first-class): crsEnable=false + structured SecRules (config/samples/crs)
# Default operator embed is path-b wasm; needs gzip+base64 directives support.
make test-e2e-ftw E2E_PROVIDER=envoy-gateway          # alias → path-b
make test-e2e-ftw-path-b E2E_PROVIDER=envoy-gateway
make test-e2e-ftw-path-b-full E2E_PROVIDER=envoy-gateway

# Path A go-ftw (second-class): needs full-catalog wasm (CATALOG_MODE=full / *-full image)
# Not run in CI. Opt-in only.
make wasm-build-full   # or wasm-fetch-modsecurity-full
make test-e2e-ftw-path-a E2E_PROVIDER=envoy-gateway

# Deploy full structured CRS into demo (after provider setup), without go-ftw
make setup-test-e2e-envoy-gateway
make setup-test-e2e-crs-full
# or fold into setup:
make setup-test-e2e-envoy-gateway E2E_CRS_FULL=true
kubectl apply -f test/e2e/manifests/envoygateway/waf-path-b.yaml

# Headlamp UI e2e (in-cluster Headlamp + Path B full CRS + Playwright screenshots)
make test-e2e-headlamp
# Screenshots land in test/e2e/headlamp/artifacts/ (override HEADLAMP_SCREENSHOT_DIR)
```

## Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `E2E_PROVIDER` | `all` | `envoy-gateway`, `istio`, `cilium`, `manager`, `probe`, `headlamp`, `all` |
| `E2E_HEADLAMP` | unset (off) | Set `true` (or `E2E_PROVIDER=headlamp`) to run in-cluster Headlamp screenshot e2e |
| `HEADLAMP_PLUGIN_DIR` | `./headlamp-plugin` | Checkout used to `npm run build` the plugin ConfigMap |
| `HEADLAMP_SCREENSHOT_DIR` | `test/e2e/headlamp/artifacts` | PNG output directory |
| `E2E_HEADLAMP_SKIP_TRAFFIC` | unset | Set `true` to skip sample curls (useful if the dataplane CNI is unhealthy) |
| `E2E_IMG` | `ghcr.io/kubewaf-io/kubewaf:e2e` | Operator image loaded into Kind |
| `E2E_PROBE` | unset | Set `true` to force Subresource probe e2e (also runs when `E2E_PROVIDER=probe\|all`) |
| `E2E_SUBRESOURCE_IMG` | derived from `E2E_IMG` | Image for `cmd/subresource-api` (default `…/kubewaf-subresource-api:<tag>`) |
| `E2E_PROBE_TEST_IMG` | derived from `E2E_IMG` | Image for `cmd/probe-test-server` (default `…/kubewaf-probe-test-server:<tag>`) |
| `E2E_SKIP_IMAGE_BUILD` | unset | Skip `ko-build` + kind load |
| `E2E_SKIP_OPERATOR_INSTALL` | unset | Assume operator already installed |

| `E2E_CILIUM_TRAFFIC` | on (empty) | UA traffic smoke for Cilium; set `false` to slot-only. go-ftw still needs explicit `true` |
| `E2E_ISTIO_TRAFFIC` | on (empty) | UA traffic smoke for Istio (needs bootstrap-static `kubewaf_ecds`); set `false` to slot-only. go-ftw still needs explicit `true` |
| `E2E_RUN_MANAGER_SMOKE` | unset | With `E2E_PROVIDER=all`, also run kustomize manager smoke |
| `E2E_FTW` | unset (off) | Legacy; prefer `E2E_FTW_PATH_B` (first-class) or `E2E_FTW_PATH_A` |
| `E2E_FTW_PATH_B` | unset (off) | Set `true` for Path B go-ftw (structured CRS, path-b wasm) — **first-class** |
| `E2E_FTW_PATH_A` | unset (off) | Set `true` for Path A go-ftw (crsEnable + **full-catalog** wasm) — second-class |
| `E2E_CRS_FULL` | `false` | During provider setup, also run `setup-test-e2e-crs-full` |
| `E2E_SKIP_FTW` | unset | Force-skip go-ftw even if `E2E_FTW=true` / Path B |
| `E2E_FTW_INCLUDE` | `^913` | go-ftw `-i` regex; `all` = full CRS suite |
| `E2E_FTW_CLOUDMODE` | `false` | go-ftw `--cloud` (status-only; no log markers) |
| `CRS_VERSION` | `v4.27.0` | CRS tag for test corpus download |
| `GO_FTW_VERSION` | `2.5.0` | `ghcr.io/coreruleset/go-ftw` image tag |
| `KIND_CLUSTER` | `kubewaf-e2e` | Kind cluster name |
| `E2E_NAMESPACE` | `demo` | Namespace for demo app + structured CRS |

## Headlamp screenshots (Path B full CRS)

Opt-in UI e2e. Installs in-cluster [Headlamp](https://headlamp.dev/) with the kubeWAF plugin mounted from a ConfigMap, attaches `demo-waf-eg-path-b` (`crsEnable: false` + RuleSet `ftw-crs-path-b` selecting every vendored CRS SecRule), sends a handful of allow/deny requests, then drives Playwright against the plugin pages.

```bash
# Plugin checkout must be present (this monorepo path is often a local side-by-side clone)
ls headlamp-plugin/package.json

make test-e2e-headlamp
# or reuse an existing Kind cluster / operator:
E2E_SKIP_IMAGE_BUILD=true E2E_SKIP_OPERATOR_INSTALL=true make test-e2e-headlamp
```

| File | What it captures |
|------|------------------|
| `test/e2e/headlamp/artifacts/01-overview.png` | kubeWAF Overview |
| `02-waf-list.png` | WAF list with the Path B object |
| `03-waf-detail.png` | WAF detail (`crsEnable=false`, RuleSet `ftw-crs-path-b`) |
| `04-waf-detail-live.png` | Live health / requests / noisy rules |
| `05-ruleset-detail.png` | Full CRS RuleSet |
| `06-secrules-list.png` | Hundreds of structured CRS SecRules |
| `07-secrule-detail.png` | One SecRule (if a row is clickable) |
| `08-observe.png` | Observe service map + filter bar |
| `09-observe-logs.png` | Observe eval log stream |
| `10-observe-metrics.png` | Observe catalog metrics |

Headlamp is installed with `unsafeUseServiceAccountToken=true` (e2e-only) so Playwright does not have to paste a token. The Headlamp ServiceAccount is bound to `cluster-admin` plus `kubewaf-query` when that ClusterRole exists.

## Subresource probe API (aggregated)

Chart values (disabled by default):

```bash
helm upgrade --install kubewaf charts/kubewaf -n kubewaf-system --create-namespace \
  --set subresourceApi.enabled=true \
  --set probeTestServer.enabled=true \
  --set subresourceApi.image.repository=kubewaf-io/kubewaf-subresource-api \
  --set probeTestServer.image.repository=kubewaf-io/kubewaf-probe-test-server \
  --set image.tag=e2e --set subresourceApi.image.tag=e2e --set probeTestServer.image.tag=e2e
```

E2E (APIService Available, pass-through probe, SAR 403):

```bash
make test-e2e E2E_PROVIDER=probe
# or with other providers:
E2E_PROBE=true make test-e2e E2E_PROVIDER=envoy-gateway
```

Requires Kind with aggregation (`extension-apiserver-authentication` ConfigMap). Chart copies the requestheader client CA via a pre-install Job and generates a separate serving CA for the APIService.

## CI layout

| Workflow | When | Scope |
|----------|------|--------|
| [test-e2e.yml](../../.github/workflows/test-e2e.yml) | PR + **push to main** | **EG smoke only** (fast gate) |
| [test-e2e-release.yml](../../.github/workflows/test-e2e-release.yml) | **PR only** (not main), `workflow_dispatch`, **called by releaser** | **Full matrix** (EG path-b smoke + Path B FTW, Istio, Cilium) |
| [releaser.yml](../../.github/workflows/releaser.yml) | `v*` tags | Full e2e **then** GoReleaser |

Manual full suite (GitHub UI → Actions → “E2E Release (full)” → Run workflow).  
Optional input `ftw_include=all` runs the complete CRS go-ftw corpus on EG paths.

## What each provider asserts

### Envoy Gateway
1. WAF `Ready=True`, `status.provider=EnvoyGateway`, `slotKind=ExtensionServer`
2. Traffic: scanner `User-Agent: sqlmap` → **403**, benign → **200** (shared helper)
3. **go-ftw**: CRS regression (default `^913`) via gateway + Envoy proxy logs

### Istio
1. WAF Ready, `slotKind=EnvoyFilter`, EnvoyFilter with `config_discovery` + `kubewaf_ecds`
2. Traffic (default on): same UA smoke as EG — benign **200** / sqlmap **403**
3. ECDS bootstrap for Gateway API:
   - ConfigMap `ecds-bootstrap.yaml` + Gateway annotation `bootstrapOverride`
   - **Plus** Deployment patch (`ensureIstioGatewayBootstrapMount`): mount CM and
     `ISTIO_BOOTSTRAP_OVERRIDE` — Gateway pods are not sidecar-injected, so the
     annotation alone does not mount the ConfigMap (LDS would reject `kubewaf_ecds`)
   - Gateway Service type `ClusterIP` via `networking.istio.io/service-type`
4. go-ftw remains opt-in (`E2E_ISTIO_TRAFFIC=true` **and** Path A/B FTW flags)
5. Gateway API Service: `demo-gateway-istio` (label `istio=ingressgateway`)

### Cilium
1. WAF Ready, `slotKind=CiliumEnvoyConfig`, CEC with `config_discovery` + `kubewaf_ecds`
2. Traffic (default on): same UA smoke as EG/Istio via Cilium Gateway Service
3. ECDS bootstrap for `cilium-envoy`:
   - `hack/scripts/merge-cilium-envoy-ecds-bootstrap.sh --apply --otel-service kubewaf-otel-collector`
     (adds `--helm-upgrade` only if Cilium is not already pointed at the CM).
     Collector-absent → ECDS-only + note. Helm upgrade uses the **installed**
     chart `--version` and `--set-string`. Dumps `ds/cilium-envoy` bootstrap,
     adds STATIC `kubewaf_ecds` (and `kubewaf_otel` when the Collector Service
     exists). ClusterIP, port named `ecds`; hostNetwork cannot use `*.svc` DNS.
   - Traffic / go-ftw call `applyCiliumECDSBootstrap()` after the operator Service exists
4. Setup installs **experimental** Gateway API CRDs (`GATEWAY_API_VERSION`) then Cilium
   with `gatewayAPI.enabled=true` (Kind: `disableDefaultCNI`) — needed for TLSRoute
   `v1alpha2` (Cilium 1.19 operator)
5. Kind has no cloud LB: `manifests/cilium/lb-ip-pool.yaml` (`CiliumLoadBalancerIPPool`)
   assigns EXTERNAL-IPs so Gateway `Programmed=True` (patching Service→ClusterIP is
   reverted by Cilium). In-cluster curls still use the Service ClusterIP.
6. go-ftw remains opt-in (`E2E_CILIUM_TRAFFIC=true` **and** Path A/B FTW flags);
   go-ftw uses **NodePort** when needed (Cilium Gateway Services have no pod selector)

## CRS go-ftw details

[go-ftw](https://github.com/coreruleset/go-ftw) drives the official OWASP CRS regression tests.

### Path A vs Path B

| Mode | Make target | CRS load | Wasm | CI |
|------|-------------|----------|------|-----|
| **Path B** (first-class) | `make test-e2e-ftw-path-b` | `crsEnable: false` + SecRules from `config/samples/crs/` + RuleSet `ftw-crs-path-b` | path-b (default) | yes |
| **Path A** (second-class) | `make test-e2e-ftw-path-a` | `crsEnable: true` → engine `Include @owasp_crs` | **full** (`*-full` image) | no |

### Manual full CRS RuleSet (setup only)

For interactive Path B testing without running go-ftw:

```bash
make setup-test-e2e-envoy-gateway          # provider + demo rules + Path A WAF
make setup-test-e2e-crs-full               # CRS SecRules + PhraseLists + full RuleSet
# optional: switch Gateway to Path B WAF
kubectl delete waf demo-waf-eg -n demo --ignore-not-found
kubectl apply -f test/e2e/manifests/envoygateway/waf-path-b.yaml
```

| Target | What it deploys |
|--------|-----------------|
| `setup-test-e2e-crs-full` | Every `crs-request-*` / `crs-response-*` SecRule + stock CRS PhraseLists (`phraselists/`) + `path-b-crs-ruleset-full.yaml` (`ftw-crs-path-b`; basename discovery, no `phraseListRefs`) |
| `setup-test-e2e-crs` | Same SecRules/PhraseLists, then smoke RuleSet (`path-b-crs-ruleset.yaml`: 901/905/913/949/959/980) |

Path B also enables FTW profile annotation and uses the same go-ftw harness. Prefer Path B after deploying an operator image whose **modsecurity-proxy-wasm** understands `directives_encoding: gzip+base64`.

Per provider run:

1. Deploy [albedo](https://github.com/coreruleset/albedo) and point `demo.local` HTTPRoute at it
2. Annotate the WAF with `kubewaf.io/ftw-profile=true` → operator injects `Include @ftw-conf`
   (DetectionOnly, PL4 limits, `X-CRS-Test` log markers) **before** CRS includes
3. Port-forward the provider gateway Service; stream Envoy pod logs to a file
4. Run `ghcr.io/coreruleset/go-ftw` (Docker, host network) against CRS tests

Requires **Docker** in addition to Kind/kubectl. Full suite is slow; keep `E2E_FTW_INCLUDE=^913`
for CI smoke and use `E2E_FTW_INCLUDE=all` for release qualification.

Engine regression without Kubernetes still lives under:

```bash
# engines/modsecurity-proxy-wasm
./test/regression/run-ftw.sh
```

## Prerequisites

- `kind`, `kubectl`, `helm`, `go`
- Docker (for Kind + `ko` image build + go-ftw container)

## Layout

```
test/e2e/
  e2e_suite_test.go      # image build / suite wiring
  e2e_test.go            # optional kustomize manager smoke
  providers_test.go      # EG / Istio / Cilium matrix
  ftw_test.go            # CRS go-ftw per provider
  helpers.go
  helpers_ftw.go
  ftw/
    run-ftw.sh           # port-forward + log collect + go-ftw
    ftw.yml              # go-ftw config (Envoy ignore list)
  manifests/
    00-test-application.yaml
    common/rules.yaml
    envoygateway/
    istio/
    cilium/
    ftw/                 # albedo + HTTPRoute override
```
