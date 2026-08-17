# Beta prep: P0–P2 + webhooks + e2e CI

## Summary

Lands the beta-prep workstream on `feat/beta-prep-ship`:

- **Engines** as git submodules under `engines/`
- **API**: remove WAFInstance; WAF `mode` / status / printer columns; SecRuleIDPool
- **Operator**: validating webhooks, allowedRules fix, finalizer cleanup, safe defaults
- **Helm**: `0.1.0-beta.1`, admission webhooks (self-signed CA)
- **Docs**: separate website repo (kubewaf.io); monorepo root stubs only
- **CI**: PR EG smoke + full matrix; main EG only; release full e2e before GoReleaser
- **Layout**: engines as git submodules; `website2/` not tracked

## Commits

See `git log main..feat/beta-prep-ship --oneline`

## Test plan

- [x] `go test ./internal/... ./api/...`
- [ ] `make test-e2e-envoy-gateway` (EG smoke)
- [ ] CI full matrix on this PR (`test-e2e-release.yml`)
- [ ] Helm install quickstart with webhooks enabled

## Notes

- `headlamp-plugin/` left untracked for a follow-up PR
- Submodule worktrees may show dirty locally; pins are recorded in `.gitmodules` / gitlinks
