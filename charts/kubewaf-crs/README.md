# # kubewaf-crs

![Version: 0.1.0-beta.1](https://img.shields.io/badge/Version-0.1.0--beta.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 4.27.0](https://img.shields.io/badge/AppVersion-4.27.0-informational?style=flat-square)

OWASP Core Rule Set (CRS) packaged as kubeWAF SecRule CRs plus optimized RuleSet profiles and optional extras. Install after the kubewaf operator chart (requires seclang.kubewaf.io / waf.kubewaf.io CRDs).

## Prerequisites

- Kubernetes 1.28+
- [kubeWAF operator](https://github.com/kubewaf-io/kubewaf) chart installed (CRDs: `SecRule`, `RuleSet`, `WAF`)

## What it deploys

| Resource | Purpose |
|----------|---------|
| `SecRule` (many) | Converted CRS rules under `files/crs/` |
| `PhraseList` (21) | Stock CRS `@pmFromFile` data pack under `files/phraselists/` (Path B `data_files`, basename discovery) |
| `RuleSet/crs-core` | Foundation (init, protocol, scanners, scoring) |
| `RuleSet/ruleset-*` | Profiles: api, backend, frontend, golang, php, java, dotnet |
| Extras SecRules + `ruleset-extras-baseline` | Sensitive paths, TRACE, Log4Shell, CMS noise |

CRS RuleSets do **not** use `phraseListRefs`; lists are resolved from SecRule
`@pmFromFile` basenames. There is **no stock CRS IPList pack**.

## Install

```bash
helm upgrade --install kubewaf ./charts/kubewaf -n kubewaf-system --create-namespace
helm upgrade --install kubewaf-crs ./charts/kubewaf-crs -n demo --create-namespace
```

Path B WAF (no engine CRS includes):

```yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: WAF
metadata:
  name: my-api
spec:
  crsEnable: false
  crs:
    paranoiaLevel: 1
    inboundAnomalyThreshold: 5
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: my-api
  ruleRefs:
    - kind: RuleSet
      name: ruleset-api
      group: waf.kubewaf.io
      version: v1beta1
    - kind: RuleSet
      name: ruleset-extras-baseline
      group: waf.kubewaf.io
      version: v1beta1
```

**Homepage:** <https://github.com/kubewaf-io/kubewaf>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| kubeWAF |  | <https://github.com/kubewaf-io> |

## Source Code

* <https://github.com/kubewaf-io/kubewaf>
* <https://github.com/coreruleset/coreruleset>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| commonLabels | object | `{}` |  |
| crs | object | `{"includeFiles":[],"installPhraseLists":true,"installSecRules":true,"labels":{},"version":"4.27.0"}` | ------------------------------------------------------------------------- |
| crs.includeFiles | list | `[]` | Only install SecRules whose coreruleset/file is listed. Empty = all files. Example: [REQUEST-901-INITIALIZATION.conf, REQUEST-913-SCANNER-DETECTION.conf] |
| crs.installPhraseLists | bool | `true` | Install stock CRS PhraseLists (@pmFromFile data pack) from files/phraselists/ Path B inject uses basename discovery from SecRules (no phraseListRefs on CRS RuleSets). |
| crs.installSecRules | bool | `true` | Install SecRule CRs from files/crs/*.yaml |
| crs.labels | object | `{}` | Extra labels on every CRS SecRule (merged onto existing labels) |
| crs.version | string | `"4.27.0"` | Label value coreruleset/version on packaged rules (must match RuleSet selectors) |
| exampleWAF.attachExtras | bool | `true` |  |
| exampleWAF.crs.inboundAnomalyThreshold | int | `5` |  |
| exampleWAF.crs.outboundAnomalyThreshold | int | `4` |  |
| exampleWAF.crs.paranoiaLevel | int | `1` |  |
| exampleWAF.crsEnable | bool | `false` |  |
| exampleWAF.enabled | bool | `false` |  |
| exampleWAF.name | string | `"waf-crs-api-example"` |  |
| exampleWAF.profile | string | `"api"` |  |
| exampleWAF.targetRef.group | string | `"gateway.networking.k8s.io"` |  |
| exampleWAF.targetRef.kind | string | `"HTTPRoute"` |  |
| exampleWAF.targetRef.name | string | `"api"` |  |
| extras | object | `{"cmsNoise":{"enabled":true},"enabled":true,"log4shell":{"enabled":true},"methodBlock":{"enabled":true},"rulesetName":"ruleset-extras-baseline","sensitivePaths":{"enabled":true}}` | ------------------------------------------------------------------------- |
| extras.enabled | bool | `true` | Master switch for all extras |
| fullnameOverride | string | `""` |  |
| nameOverride | string | `""` |  |
| profiles | object | `{"api":{"enabled":true},"backend":{"enabled":true},"core":{"enabled":true},"dotnet":{"enabled":false},"frontend":{"enabled":false},"golang":{"enabled":false},"java":{"enabled":false},"php":{"enabled":false}}` | ------------------------------------------------------------------------- |
