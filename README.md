# kubeWAF

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-%23161616.svg?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewaf)](https://artifacthub.io/packages/search?repo=kubewaf)
[![Go Reference](https://pkg.go.dev/badge/github.com/kubewaf-io/kubewaf.svg)](https://pkg.go.dev/github.com/kubewaf-io/kubewaf)
[![CI/CD](https://github.com/kubewaf-io/kubewaf/actions/workflows/test.yml/badge.svg)](https://github.com/kubewaf-io/kubewaf/actions/workflows/test.yml)

**Kubernetes-native Web Application Firewall**

Protect your Kubernetes workloads with ModSecurity-compatible rules and OWASP Core Rule Set (CRS) using native Kubernetes CRDs.

**Website:** [kubewaf.io](https://kubewaf.io)  
**Contact:** [hello@kubewaf.io](mailto:hello@kubewaf.io)  
**GitHub:** [kubewaf-io/kubewaf](https://github.com/kubewaf-io/kubewaf)

## Overview

kubeWAF is a Kubernetes operator that lets you define, manage, and apply Web Application Firewall (WAF) rules directly through Kubernetes Custom Resources.

It provides structured CRDs for SecRules and SecActions, converts them to ModSecurity SecLang, supports the OWASP CRS, and integrates with modern Kubernetes ingress and gateway solutions like Envoy Gateway.

The project is currently **beta** (`v0.1.0-beta.1` chart; APIs are `v1beta1` and may still change). Prefer Helm installs and treat this as early production-preview, not a frozen GA. See [CHANGELOG.md](CHANGELOG.md) and [TODO.md](TODO.md).

## Architecture

kubeWAF consists of the following components:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      kubeWAF Operator                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │ SecRule Reconciler│  │ RuleSet Reconciler│  │  WAF Reconciler  │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
   ┌────────────┐       ┌────────────┐       ┌────────────┐
   │  SecRule   │       │  RuleSet   │       │    WAF     │
   │ (WAF rules)│       │  (groups)  │       │ (providers)│
   └────────────┘       └────────────┘       └────────────┘
                                                  │
                                                  ▼
                                    ┌──────────────────────────┐
                                    │  modsecurity-proxy-wasm  │
                                    │  (Envoy Wasm filter)     │
                                    └──────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| **SecRule CRD** | Defines individual WAF rules with ModSecurity syntax in Kubernetes YAML |
| **RuleSet CRD** | Groups multiple SecRules using label selectors for deployment |
| **WAF CRD** | Attaches RuleSets to Envoy Gateway, Istio, or Cilium via ECDS |
| **CRS Converter** | Tool to import OWASP CRS rules into kubeWAF CRs |

## Features

### Current Features

- **Structured SecRule CRD** (`seclang.kubewaf.io/v1beta1`): Define complex security rules using Kubernetes YAML with:
  - Variables, operators, and actions in structured format
  - Metadata (phase, severity, message, tags)
  - Chaining support for multi-condition rules
  - SecMarker support for flow control

- **RuleSet CRD** (`waf.kubewaf.io/v1beta1`): Aggregate rules with:
  - Label selector-based rule referencing
  - Cross-namespace rule references
  - Automatic finalizer management

- **Automatic SecLang Generation**: Controllers convert CRs to valid ModSecurity SecLang strings stored in `.status.secRuleString`

- **OWASP CRS Support**: 
  - Tooling in `cmd/crs-converter` to convert OWASP Core Rule Set v4.x to kubeWAF CRs
  - Pre-converted CRS sample rules in `config/samples/crs/`
  - Full CRS rule compatibility (phase 1-5, transformations, chaining)

- **Envoy Gateway Integration**: 
  - WAF CRD for Kubernetes Gateway API integration
  - Support for HTTPRoute, TCPRoute, and Gateway routing
  - WebAssembly (Wasm) proxy integration with **modsecurity-proxy-wasm** (optional PoW via **pow-proxy-wasm**)

- **Status & Conditions**: Proper Kubernetes status reporting with conditions (e.g., `Ready`, `ReferencesResolved`)

- **Helm Chart**: Operator Helm chart (versioned pre-release; see `charts/kubewaf`)

- **CI/CD Pipeline**: GitHub Actions workflows for testing, building, and releasing

### Under Development / Beta gaps

- Full HA/ops hardening (metrics TLS via cert-manager, coverage gates)
- cert-manager-managed webhook cert rotation (Helm self-signed today)
- Optional: release FTW with `E2E_FTW_INCLUDE=all` (full CRS corpus; very slow)

## Documentation

Product documentation is **not** in this monorepo. It lives in a separate docs
repo ([kubewaf-io/website](https://github.com/kubewaf-io/website)) and publishes to
**[kubewaf.io](https://kubewaf.io)**.

| Topic | Link |
|-------|------|
| Docs portal | [kubewaf.io/docs/home/](https://kubewaf.io/docs/home/) |
| Beta status | [Beta status](https://kubewaf.io/docs/get-started/beta/) |
| Install (Helm) | [Installation](https://kubewaf.io/docs/platform/installation/) |
| Quick start | [Quick start](https://kubewaf.io/docs/get-started/quickstart/) |
| Engine matrix | [WAF engine](https://kubewaf.io/docs/platform/engine/) |
| Contributing | [Contributing](https://kubewaf.io/docs/contribute/contributing/) · root stub [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security reports | [Security](https://kubewaf.io/docs/contribute/security/) · root stub [SECURITY.md](SECURITY.md) |

Local docs preview (optional):

```bash
git clone https://github.com/kubewaf-io/website.git website2   # or your docs checkout path
cd website2 && make serve
```

## Quick Start (TL;DR)

### 1. Install the Operator (Helm)

```bash
helm repo add kubewaf https://kubewaf-io.github.io/charts
helm repo update
helm install kubewaf kubewaf/kubewaf -n kubewaf-system --create-namespace --version 0.1.0-beta.1
# or from this repo: helm install kubewaf ./charts/kubewaf -n kubewaf-system --create-namespace
```

### 2. Follow the Full Quick Start

See the [Quick Start Guide](https://kubewaf.io/docs/get-started/quickstart/) (Envoy Gateway + rules + CRS).

## Using the CRS Converter

Convert OWASP Core Rule Set files to kubeWAF SecRule CRs:

```bash
# Build the converter
make crs-converter

# Convert a directory of CRS rules (default: one SecRule CR per logical rule)
bin/crs-converter \
  -input=path/to/coreruleset/rules \
  -output-dir=config/samples/crs \
  -crs-version=4.27.0 \
  -namespace=default \
  -mode=one

# Convert a single file (legacy multi-rule bag per file: -mode=bag)
bin/crs-converter \
  -input=hack/crs-converted/REQUEST-911-METHOD-ENFORCEMENT.conf \
  -output-dir=config/samples/crs
```

The converter generates multi-document Kubernetes YAML with:
- One `SecRule` CR per logical rule (`metadata` + `match[]` + `actions`, `order`/`markerAfter`)
- Labels: `coreruleset/*`, `seclang.kubewaf.io/id`, tags
- Chains and SecMarkers preserved from the original CRS files

## Project Structure

```
kubewaf/
├── api/                          # CRDs (seclang + waf groups)
├── cmd/                          # Operator + crs-converter
├── config/                       # CRDs, RBAC, samples (incl. CRS)
├── engines/                      # Proxy-Wasm **git submodules**
│   ├── modsecurity-proxy-wasm/   # → kubewaf-io/modsecurity-proxy-wasm
│   └── pow-proxy-wasm/           # → kubewaf-io/pow-proxy-wasm
├── internal/                     # Controllers, dataplane (ECDS/slots), references
├── charts/kubewaf/               # Helm chart
├── test/e2e/                     # Provider + FTW e2e
└── (docs site is a separate repo — see Documentation above)
```

Wasm engine sources are **submodules** under [`engines/`](engines/). After clone:

```bash
git submodule update --init --recursive
# or: make engines-submodules
make wasm-build   # → dist/wasm/
```

## Development

### Setup

```bash
# Clone the repository (engines/ holds Proxy-Wasm submodules)
git clone --recurse-submodules https://github.com/kubewaf-io/kubewaf.git
cd kubewaf
# If you already cloned without submodules:
#   git submodule update --init --recursive
#   # or: make engines-submodules

# Install dependencies
make install
make generate
make fmt
```

### Running Locally

```bash
# Local stack: Kind + Envoy Gateway + demo + full CRS (no operator image/Helm)
make local-demo
# Optional in-cluster operator:
make local-demo-with-operator
# Or process-local operator against the Kind kubeconfig:
make run
make local-demo-smoke      # needs a running operator
make local-demo-teardown

# Run the operator against an existing kubeconfig (no Kind bootstrap)
make run

# Run tests
make test
make test-e2e

# Build container image
make docker-build

# Push container image
make docker-push IMG=your-registry/kubewaf:latest

# Generate manifests
make manifests
```

### Available Make Targets

| Target | Description |
|------------|------------------------------------------|
| `make local-demo` | Kind + EG + demo + full CRS (no operator deploy) |
| `make local-demo-with-operator` | local-demo + image build/load + Helm install |
| `make local-demo-smoke` | Curl benign/scanner check against local demo |
| `make local-demo-teardown` | Delete the local Kind cluster |
| `make install` | Install CRDs into a cluster |
| `make generate` | Generate controller code and deepcopies |
| `make fmt` | Format Go source files |
| `make vet` | Run Go vet on source files |
| `make lint` | Run golangci-lint |
| `make lint-fix` | Auto-fix linting issues |
| `make test` | Run unit tests |
| `make test-e2e` | Run end-to-end tests |
| `make docker-build` | Build Docker image |
| `make docker-push` | Push Docker image |
| `make crs-converter` | Build CRS converter binary |
| `make manifests` | Generate CRDs and manifests |
| `make deploy` | Deploy operator to cluster |
| `make undeploy` | Undeploy operator from cluster |
| `make help` | Show all available targets |

## Contributing

Contributions are welcome. **Canonical guides** are published on kubewaf.io
(root files are stubs):

- [CONTRIBUTING.md](CONTRIBUTING.md) → [docs/contribute/contributing](https://kubewaf.io/docs/contribute/contributing/)
- [SECURITY.md](SECURITY.md) → [docs/contribute/security](https://kubewaf.io/docs/contribute/security/)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) → [docs/contribute/code-of-conduct](https://kubewaf.io/docs/contribute/code-of-conduct/)
- Roadmap: [TODO.md](TODO.md) · Changelog: [CHANGELOG.md](CHANGELOG.md)

### High-priority Areas

- **Testing**: Expand unit coverage and keep EG e2e green
- **Webhooks**: Expand validation coverage; cert-manager rotation
- **Documentation**: improve the separate [website](https://github.com/kubewaf-io/website) repo

### Getting Help

- Open an [issue](https://github.com/kubewaf-io/kubewaf/issues) for bugs or feature requests
- Join our [Discussions](https://github.com/kubewaf-io/kubewaf/discussions) for questions
- Check [TODO.md](TODO.md) and [Beta status](https://kubewaf.io/docs/get-started/beta/)

## License

Copyright © 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

Made with ❤️ in Bern, Switzerland by [Buzz-IT GmbH](https://buzz-it.ch)

