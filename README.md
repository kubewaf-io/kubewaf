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

The project is currently in **Active Development**. APIs and features are stable but may evolve with community feedback.

## Architecture

kubeWAF consists of the following components:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      kubeWAF Operator                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │  SecRule Reconciler│  │  RuleSet Reconciler │  │ WAFInstance Reconciler│
│  └──────────────────┘  └──────────────────┘  └──────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │          WAF Reconciler                          │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                    │              │              │
                    ▼              ▼              ▼
          ┌────────────────┐ ┌──────────┐ ┌─────────────────┐
          │   SecRule      │ │RuleSet   │ │WAF  │
          │   (WAF Rules)  │ │(Groups)  │ │(Envoy Gateway)  │
          └────────────────┘ └──────────┘ └─────────────────┘
                    │              │
                    ▼              ▼
          ┌────────────────────────────────┐
          └───────────────────────────┐
                    │   modsecurity-proxy-wasm       │
                    │   (WAF Proxy/Envoy Filter)     │
                    └────────────────────────────────┘
          ```

### Key Components

| Component | Description |
|-----------|-------------|
| **SecRule CRD** | Defines individual WAF rules with ModSecurity syntax in Kubernetes YAML |
| **RuleSet CRD** | Groups multiple SecRules using label selectors for deployment |
| **WAFInstance CRD** | Deploys standalone WAF proxies (sidecar or gateway) |
| **WAF CRD** | Integrates WAF with Envoy Gateway via Kubernetes Gateway API |
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

- **Helm Chart**: Production-ready Helm chart for operator deployment

- **CI/CD Pipeline**: GitHub Actions workflows for testing, building, and releasing

### Under Development

- Full WAFInstance deployment (sidecar/standalone proxy)
- Validation webhooks for CRD validation
- End-to-end tests with real WAF proxies
- Additional metrics and observability

## Documentation

Comprehensive documentation is available at **[kubewaf.io](https://kubewaf.io)**.

The docs cover:

- [Installation](https://kubewaf.io/getting-started/installation/)
- [Quick Start Tutorial](https://kubewaf.io/getting-started/quickstart/)
- Writing rules, RuleSets, CRS integration, Envoy Gateway attachment
- Full CRD reference and troubleshooting

## Quick Start (TL;DR)

### 1. Install the Operator (Helm)

```bash
helm repo add kubewaf https://kubewaf-io.github.io/charts
helm repo update
helm install kubewaf kubewaf/kubewaf -n kubewaf-system --create-namespace
```

### 2. Follow the Full Quick Start

See the [Quick Start Guide](https://kubewaf.io/getting-started/quickstart/) for a complete end-to-end example with Envoy Gateway, custom rules, and the OWASP CRS.

## Using the CRS Converter

Convert OWASP Core Rule Set files to kubeWAF SecRule CRs:

```bash
# Build the converter
make crs-converter

# Convert a directory of CRS rules
bin/crs-converter \
  -input=path/to/crs/rules \
  -output-dir=config/samples/crs \
  -crs-version=4.3.0 \
  -namespace=default

# Convert a single file
bin/crs-converter \
  -input=hack/crs-converted/REQUEST-911-METHOD-ENFORCEMENT.conf \
  -output-dir=config/samples/crs
```

The converter generates Kubernetes YAML files with:
- Proper metadata and labels
- CRS version and file source information
- SecRule structures matching the original CRS rules

## Project Structure

```
kubewaf/
├── api/                          # Kubernetes API definitions
│   ├── seclang/                  # SecRule API (seclang.kubewaf.io)
│   └── waf/                      # WAF CRDs (waf.kubewaf.io)
├── cmd/                          # Main entry points
│   ├── main.go                   # Operator controller
│   └── crs-converter/            # CRS conversion tool
├── config/                       # Kubernetes manifests
│   ├── crd/                      # Custom Resource Definitions
│   ├── default/                  # Operator deployment manifests
│   └── samples/                  # Example CRs including CRS rules
├── internal/                     # Operator controllers and logic
│   ├── controller/               # Reconcilers for each CRD
│   ├── dataplane/                # ECDS, engines (modsecurity-proxy-wasm + optional challenge), provider slots
│   ├── translator/               # SecLang parser and translator
│   └── wasmregistry/             # Wasm registry for proxy integration
├── charts/                       # Helm chart for deployment
├── test/                         # E2E and integration tests
└── hack/                         # Development scripts and tools
```

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/kubewaf-io/kubewaf.git
cd kubewaf

# Install dependencies
make install
make generate
make fmt
```

### Running Locally

```bash
# Run the operator locally (requires kubeconfig)
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
| `make help` | Show all available targets |

## Contributing

Contributions are welcome! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### High-priority Areas

- **Controller Implementation**: Complete reconciliation logic for WAFInstance (standalone/sidecar)
- **Testing**: Expand unit and e2e test coverage
- **Webhooks**: Implement validation webhooks for CRD validation
- **Documentation**: Improve examples in the docs site (see `/docs`)

### Getting Help

- Open an [issue](https://github.com/kubewaf-io/kubewaf/issues) for bugs or feature requests
- Join our [Discussions](https://github.com/kubewaf-io/kubewaf/discussions) for questions
- Check the [TODO.md](TODO.md) for current priorities

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

