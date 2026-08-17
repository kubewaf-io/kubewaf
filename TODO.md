# kubeWAF — Living roadmap

**Branch:** `feat/beta-prep-ship`  
**Last cleaned:** 2026-07-30

## Done (recent)

- Safety defaults (pprof gate, prod zap, logLevel 1, `WAF.spec.mode`)
- `allowedRules` + `CleanupBackReferences`
- Validating webhooks (SecRule / SecAction / RuleSet / WAF)
- Helm `0.1.0-beta.1` + webhook certs
- Status / printer columns / events / accurate `rules_loaded`
- Engines as git submodules; `website2/` **not** tracked (separate website repo)
- CI: PR EG smoke + full matrix; main EG only; release full e2e before GoReleaser
- Scaffold cleanup (wafv2 → kubewaf labels, dead WasmRegistry, e2e fossils)

## Next (Beta ship)

1. **Push `feat/beta-prep-ship` + open PR** (needs git credentials in env)
2. **CI green** on full PR e2e matrix
3. **Verify helm/docker publish** against real registry
4. **Wasm install story** documented (kodata / SHA256 / upgrade) — on website repo
5. **Tag `v0.1.0-beta.1`** (runs full e2e then GoReleaser)

## After Beta (Prod)

| Item | Notes |
|------|--------|
| cert-manager webhook cert rotation | Helm self-signed is fine for beta |
| API field deprecations | `parentRefs` vs `targetRef`, Coraza* vs wasm* |
| Coverage gates | controllers + references + build |
| `lockObject` conflict/retry | CRS-scale churn |
| Grafana dashboard metric names | Align with live series |
| Cilium real traffic path | Slot smoke only today |
| Multi-tenant isolation review | ECDS identity, challenge secrets, RBAC |

## Explicit non-goals for Beta

- Stable v1 API
- Full CRS false-positive UX
- Headlamp UI as operator dependency (plugin ships from a dedicated repo)
- Equal support for every mesh
