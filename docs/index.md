# [kubeWAF](https://kubewaf.io)

**Kubernetes-native Web Application Firewall**

Protect your Kubernetes workloads with **ModSecurity-compatible rules** and the OWASP Core Rule Set — all defined as clean, version-controlled Custom Resources.

!!! warning "Alpha Software"

    **kubeWAF is currently in alpha.**  
    The project is under active development. Core features are functional and we use them in real environments, but breaking changes to APIs, CRDs, and behavior are still possible.  
    We recommend it for **experimentation, development, and non-critical workloads** today.

---

## Why kubeWAF?

<div class="grid cards" markdown>

-   :fontawesome-solid-file-code: **Structured as CRDs**

    Write rules in readable YAML (`SecRule`, `SecAction`) instead of opaque `.conf` files. Full GitOps support.

-   :fontawesome-solid-layer-group: **Powerful RuleSets**

    Group, reuse, and compose rules across namespaces with automatic resolution and status conditions.

-   :fontawesome-solid-plug: **Gateway API Native**

    Attach WAF policies to your HTTPRoutes and Gateways using the standard Kubernetes Gateway API (via Envoy Gateway today).

-   :fontawesome-solid-shield-halved: **OWASP CRS Included**

    Enable the entire OWASP Core Rule Set with one boolean flag. No manual downloads or sidecar hacks.

</div>

---

## Get Started

<div class="grid cards" markdown>

-   :fontawesome-solid-rocket: **[Quick Start →](getting-started/quickstart.md)**

    Deploy a protected service in under 10 minutes.

-   :fontawesome-solid-download: **[Installation Guide →](getting-started/installation.md)**

    Helm-based operator installation (recommended).

-   :fontawesome-brands-github: **[View on GitHub →](https://github.com/kubewaf-io/kubewaf)**

    Star the repo and follow development.

</div>

---

## Current Status (Alpha)

While still in alpha, kubeWAF already provides solid, usable functionality for many use cases:

| Status | Feature |
|--------|---------|
| ✅ | `SecRule` + `SecAction` CRDs with automatic SecLang conversion |
| ✅ | `RuleSet` with cross-namespace references and recursive expansion |
| ✅ | `WAF` policy attachment for **Envoy Gateway** (Gateway API) |
| ✅ | One-click OWASP CRS v4 integration |
| ✅ | Automatic reference resolution + rich status conditions |
| ✅ | Prometheus metrics (`waf_filter_tx_*`) with cardinality controls |

**Roadmap highlights:**
- Full `WAFInstance` support (sidecar / standalone proxy)
- Validation webhooks
- Enhanced observability integrations

---

## Next Steps

1. **[Install the operator](getting-started/installation.md)** using Helm
2. **[Follow the Quick Start](getting-started/quickstart.md)** to protect your first route
3. **[Write your first rules](guides/writing-rules.md)** or import the CRS

---

**Need help?** Open an issue on [GitHub](https://github.com/kubewaf-io/kubewaf/issues) or reach out at [hello@kubewaf.io](mailto:hello@kubewaf.io).