# CRS samples (v4.27.0)

Converted OWASP Core Rule Set rules as one `SecRule` CR per logical rule
(`metadata` + `match[]` + `actions`).

For Helm installs, use the dedicated chart **`charts/kubewaf-crs`** (same
SecRule files under `files/crs/`, plus optimized RuleSets and extras).

## Layout

| Path | Purpose |
|------|---------|
| `crs-request-*.yaml` / `crs-response-*.yaml` | Multi-doc SecRules (one CR per rule) |
| **`phraselists/crs-data-phraselists.yaml`** | Stock CRS PhraseLists (`@pmFromFile` data pack, 21 files) |
| `ruleset.yaml` / `crs-ruleset.yaml` | Full CRS (all files) |
| **`optimized-rulesets.yaml`** | Stack-optimized RuleSets |
| `waf.yaml` / `waf-api.yaml` | Example WAF attachments |

### CRS PhraseLists (always deploy with Path B)

Stock OWASP CRS rules that use `@pmFromFile <basename>.data` resolve lists by
**basename only** (SecRule `operator.value`). No `phraseListRefs` on CRS
RuleSets — the WAF discovers basenames from assembled SecLang and injects
`data_files` from the pack PhraseList (or operator embed fallback).

```bash
# Regenerate from internal/coraza/crsdata/*.data
make crs-phraselists

kubectl apply -n <ns> -f config/samples/crs/phraselists/crs-data-phraselists.yaml
# then SecRules + RuleSet (RuleSets only select SecRules)
```

There is **no stock CRS IPList pack** (CRS v4 has no `@ipMatchFromFile` data
files). Use `config/samples/iplist/` for custom IP blocklists only.

Pack PhraseLists are labeled `seclang.kubewaf.io/crs-data=true` and inject
without `allow-crs-override`. Custom overrides of CRS basenames still need that
annotation. `RuleSet.spec.phraseListRefs` remains available for **custom**
packaging checks, but is not used for CRS.

## Optimized RuleSets

Apply CRS SecRules first, then:

```bash
kubectl apply -f config/samples/crs/  # or selective files
kubectl apply -f config/samples/crs/optimized-rulesets.yaml
```

| RuleSet | Best for | Notable includes | Skips |
|---------|----------|------------------|--------|
| `crs-core` | Foundation (compose only) | 901/905/911/913/920/921/949/959/980 | Attack packs |
| `ruleset-php` | WordPress, Laravel, Symfony | PHP pack, webshells, PHP/SQL leakages | Java/IIS/Ruby |
| `ruleset-java` | Spring, Tomcat, Jakarta | Java pack, Java leakages | PHP/IIS/Ruby |
| `ruleset-golang` | Go services (Gin, Echo, chi) | LFI/RCE/SQLi/XSS/generic | Language packs |
| `ruleset-dotnet` | ASP.NET Core / IIS | IIS leakages, webshells | PHP/Java/Ruby |
| `ruleset-frontend` | SPA / HTML UI / BFF | XSS + light SQLi + protocol | RCE/LFI/RFI packs, language packs |
| `ruleset-backend` | Language-agnostic backends | Full generic attacks | PHP/Java/IIS/Ruby packs |
| `ruleset-api` | JSON REST / microservices | Injection + protocol (no XSS pack) | XSS, language packs, webshells |

All profiles set `waf.kubewaf.io/optimized=true` and `waf.kubewaf.io/profile=<name>`.

### Attach to a WAF (Path B — no `crsEnable`)

```yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: WAF
metadata:
  name: my-app
spec:
  crsEnable: false
  # Tuning without engine includes (setup before rules, exclusions after):
  crs:
    paranoiaLevel: 1
    inboundAnomalyThreshold: 5
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: my-app
  ruleRefs:
    - kind: RuleSet
      name: ruleset-api   # or ruleset-php, ruleset-java, ruleset-golang, ...
      group: waf.kubewaf.io
      version: v1beta1
```

See `waf-api.yaml` for a complete Path B example.

### Re-convert CRS

```bash
make crs-converter
bin/crs-converter \
  -input=/path/to/coreruleset/rules \
  -output-dir=config/samples/crs \
  -crs-version=4.27.0 \
  -mode=one
# Optional: refresh the Helm chart copy
cp config/samples/crs/crs-request-*.yaml charts/kubewaf-crs/files/crs/
cp config/samples/crs/crs-response-*.yaml charts/kubewaf-crs/files/crs/
```

The converter collapses runs of blank lines in CRS comments (and in the
written YAML) to at most two consecutive empties so output stays
`yamllint`-clean (`.github/configs/lintconf.yaml` `empty-lines.max: 2`).

After re-conversion, keep `optimized-rulesets.yaml` (not overwritten by the converter).
