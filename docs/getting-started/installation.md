# Installation

This guide covers installing the kubeWAF operator on a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster version **1.25 or newer**
- `kubectl` configured with cluster admin access
- `helm` (v3.8+) — recommended installation method
- (Optional but recommended) [Envoy Gateway](https://gateway.envoyproxy.io/) v1.0+ if you plan to protect HTTP traffic using `WAF`

## Recommended: Install with Helm

```bash
# Add the Helm repository
helm repo add kubewaf https://kubewaf-io.github.io/charts
helm repo update

# Install the operator into its own namespace
helm install kubewaf kubewaf/kubewaf \
  --namespace kubewaf-system \
  --create-namespace
```

Verify the installation:

```bash
kubectl get pods -n kubewaf-system
kubectl get crd | grep -E 'kubewaf|seclang'
```

You should see the following CRDs registered:

- `secrules.seclang.kubewaf.io`
- `secactions.seclang.kubewaf.io`
- `rulesets.waf.kubewaf.io`
- `wafenvoygateways.waf.kubewaf.io`
- `wafinstances.waf.kubewaf.io`

## Alternative: Manual Installation (kustomize)

```bash
# Install CRDs
kubectl apply -k https://github.com/kubewaf-io/kubewaf/config/crd

# Deploy the operator
kubectl apply -k https://github.com/kubewaf-io/kubewaf/config/default
```

## Helm Values Overview

The most commonly customized values are:

```yaml
replicaCount: 1

image:
  registry: ghcr.io
  repository: kubewaf-io/kubewaf
  tag: ""   # defaults to Chart appVersion

args:
  logLevel: 4
  pprof: false

crds:
  install: true          # set to false if you manage CRDs separately
```

See the full [values.yaml](https://github.com/kubewaf-io/kubewaf/blob/main/charts/kubewaf/values.yaml) for all options.

## Upgrading

```bash
helm upgrade kubewaf kubewaf/kubewaf -n kubewaf-system
```

## Uninstalling

```bash
helm uninstall kubewaf -n kubewaf-system
# Optionally delete the namespace
kubectl delete ns kubewaf-system
```

> **Note**: By default the CRDs are **not** removed on uninstall (`crds.keep: false`). This prevents accidental deletion of your security rules.

## Next Steps

Continue to the [Quick Start](quickstart.md) to create your first protected workload.