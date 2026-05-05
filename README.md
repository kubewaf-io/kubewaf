# kubeWAF

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go](https://img.shields.io/badge/Go-1.25-blue)](https://go.dev/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-%23161616.svg?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewaf)](https://artifacthub.io/packages/search?repo=kubewaf)
[![Go Reference](https://pkg.go.dev/badge/github.com/kubewaf-io/kubewaf.svg)](https://pkg.go.dev/github.com/kubewaf-io/kubewaf)

**Kubernetes-native Web Application Firewall**

Protect your Kubernetes workloads with ModSecurity-compatible rules and OWASP Core Rule Set (CRS) using native Kubernetes CRDs.

**Website:** [kubewaf.io](https://kubewaf.io)  
**Contact:** [hello@kubewaf.io](mailto:hello@kubewaf.io)  
**GitHub:** [kubewaf-io/kubewaf](https://github.com/kubewaf-io/kubewaf)

## Overview

kubeWAF is a Kubernetes operator that lets you define, manage, and apply Web Application Firewall (WAF) rules directly through Kubernetes Custom Resources. 

It provides structured CRDs for SecRules and SecActions, converts them to ModSecurity SecLang, supports the OWASP CRS, and is designed for seamless integration with modern Kubernetes ingress and gateway solutions.

The project is currently in **Beta / WIP** status. Breaking changes are expected.

## Current Working Features

- **SecRule CRD** (`seclang.kubewaf.io/v1beta1`): Define complex security rules using structured Kubernetes YAML (variables, operators, actions, metadata, chaining support).
- **SecAction CRD**: Manage non-rule directives like SecAction.
- **RuleSet CRD** (`waf.kubewaf.io/v1beta1`): Aggregate rules from multiple SecRule/SecAction resources with label selectors and reference resolution.
- **Automatic SecLang Generation**: Controllers convert CRs to valid ModSecurity SecLang strings (stored in `.status.secRuleString`).
- **CRS Compatibility**: Tooling in `cmd/crs-converter` to import OWASP Core Rule Set rules into kubeWAF CRs.
- **Status & Conditions**: Proper Kubernetes status reporting with conditions (e.g. `ReferencesResolved`).
- **Finalizers and Ownership**: Automatic cleanup and cross-referencing between RuleSets and rules.
- **Parser & Translator**: Integration with `coreruleset/crslang` and ANTLR-based SecLang parser for compatibility with Coraza/ModSecurity.

See `config/samples/` for examples (including converted CRS rules).

## Upcoming Features

- **Envoy Gateway Integration**: Native WAF policies using the Kubernetes Gateway API and Envoy Gateway.
- **WAF Deployment Generator**: Kubernetes-native management of WAF proxies (sidecar or standalone) with automatic backend Service routing.
- Full support for complex chained rules and complete OWASP CRS configurations.
- Validation webhooks and Helm chart packaging.
- **Testing**: Comprehensive unit tests, controller tests, and end-to-end tests.
- **Artifacts**: Automated builds and published artifacts for the operator and CRS conversion tools.

## Tools

### CRS Converter

A tool to convert OWASP Core Rule Set (or any SecLang) files into kubeWAF `SecRule` CRs:

```bash
# Build the converter
make crs-converter

# Usage example
bin/crs-converter -input=path/to/crs/rules -output-dir=config/samples/crs -crs-version=4.3.0
```

Supports individual files or directories containing `.conf` or `.rules` files. Generates one YAML file per input with appropriate labels and metadata.

## Getting Started (WIP)

### Prerequisites
- Kubernetes cluster (v1.25+ recommended)
- Go 1.25+
- kubectl, kustomize, controller-gen

### Installation

```bash
# Build and deploy the operator
make docker-build docker-push IMG=your-registry/kubewaf:latest
make deploy IMG=your-registry/kubewaf:latest
```

Apply sample rules:

```bash
kubectl apply -k config/samples/
```

See the samples in `config/samples/` for CRS-inspired examples.

### Development

```bash
# Install CRDs
make install

# Run locally
make run

# Run tests
make test
```

Run `make help` for all available targets.


## Contributing

Contributions are welcome! Please see the website, open issues on GitHub, or check `TODO.md` for current priorities.

**High-priority areas:**
- Improve the rule parser/translator (full SecLang support)
- Expand test coverage (especially e2e tests)
- Implement the Envoy Gateway integration and WAF deployment generator
- Documentation and example improvements

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
