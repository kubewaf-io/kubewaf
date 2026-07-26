# modsecurity-proxy-wasm

ModSecurity [Proxy-Wasm](https://github.com/proxy-wasm/spec) filter for Envoy (`envoy.wasm.runtime.v8`) with embedded **OWASP CRS v4.27.0**.

**Full documentation (kubeWAF docs site):** [modsecurity-proxy-wasm](https://kubewaf.io/docs/modsecurity-proxy-wasm) · [pow-proxy-wasm](https://kubewaf.io/docs/pow-proxy-wasm) · [operator](https://kubewaf.io/docs/operator)

## Quick start

```bash
make image && make extract-wasm
make test-bats
```

```bash
podman run --rm \
  -v "$(pwd)/dist/modsecurity-proxy-wasm.wasm:/etc/modsecurity-proxy-wasm.wasm:ro" \
  -v "$(pwd)/test/fixtures/envoy.yaml:/etc/envoy.yaml:ro" \
  -p 8080:8080 envoyproxy/envoy:v1.38-latest envoy -c /etc/envoy.yaml
```

```bash
curl http://localhost:8080/                                      # 200
curl 'http://localhost:8080/?q=<script>alert(1)</script>'       # 403
```

## Features

**Envoy filter** — Emscripten wasm on the HTTP filter chain (`envoy.wasm.runtime.v8` only):

```yaml
http_filters:
- name: envoy.filters.http.wasm
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
    config:
      vm_config:
        runtime: envoy.wasm.runtime.v8
        code: { local: { filename: /etc/modsecurity-proxy-wasm.wasm } }
```

**WAF config** — JSON `directives_map` / `default_directives` profiles.
When driven by **kubeWAF**, the operator also sets `mode`, `config_id`, identity
`metric_labels`, nested `metrics`, and `block` (see
[`schemas/waf-plugin-config.json`](../schemas/waf-plugin-config.json)).

```json
{
  "mode": "kubewaf",
  "config_id": "kubewaf/shop/shop-waf",
  "allow_fallback": false,
  "directives_map": {
    "default": [
      "Include @kubewaf-defaults",
      "SecRuleEngine On",
      "SecRequestBodyAccess On"
    ]
  },
  "default_directives": "default",
  "metric_labels": {
    "waf_namespace": "shop",
    "waf_name": "shop-waf",
    "engine": "modsecurity",
    "owner": "modsecurity-proxy-wasm"
  },
  "metrics": { "enabled": true, "per_rule_id": true, "rule_tags": true },
  "block": { "message": "blocked by kubeWAF" }
}
```

**Embedded CRS** — OWASP CRS v4.27.0 and phrase lists are baked in at build; load with virtual includes (no runtime filesystem):

| Virtual include | Purpose |
|-----------------|---------|
| `@kubewaf-defaults` | Production body access / tmp dirs (kubeWAF baseline) |
| `@demo-conf` | Standalone demo overlay |
| `@crs-setup-conf` | CRS setup |
| `@owasp_crs/*.conf` | Full CRS rules |

```json
{
  "directives_map": {
    "crs": [
      "Include @kubewaf-defaults",
      "SecRuleEngine On",
      "Include @crs-setup-conf",
      "Include @owasp_crs/*.conf"
    ]
  },
  "default_directives": "crs"
}
```

**Metrics** — Envoy stats with name-embedded labels (`metric_labels`). Core series are dual-emitted as `modsecurity_proxy_wasm.*` and `kubewaf_waf.*`. All counters include the label suffix (including `tx.total` / `tx.allowed`).

```bash
curl -s http://127.0.0.1:9901/stats/prometheus | grep -E 'modsecurity_proxy_wasm|kubewaf_waf'
```

**Security logs** — rule matches and blocks emit one JSON line each:

```text
[kubewaf][security] {"event":"tx_interrupt","config_id":"kubewaf/shop/shop-waf",...}
```

**OCI artifact** — wasm, default WAF JSON, and an Envoy example in one image:

```bash
make image
make extract-wasm    # → dist/modsecurity-proxy-wasm.wasm
```

**Fail-closed** — invalid config aborts plugin startup (no silent CRS fallback unless `allow_fallback: true`).

**Tests**

```bash
make test-bats         # Envoy smoke
make test-regression   # CRS go-ftw
make test-unit         # waf_config
```

## License

Apache-2.0 (same as SDK and ModSecurity).