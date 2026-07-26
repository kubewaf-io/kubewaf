# kubeWAF TODOs Before Publishing as WIP on GitHub

This document lists tasks to complete before publishing the repository publicly as a Work-in-Progress (WIP) project.

## Critical Pre-Publish Cleanup

- **Git State**:
  - Stage untracked files: `git add LICENSE cmd/crs-converter/ config/samples/crs/ internal/translator/`
  - Handle modified files and deletions: `git add -u` (this will stage deletes and mods)
  - Commit changes: `git commit -m "chore: prepare for WIP release"`
  - Consider creating a new branch or cleaning history if needed (currently ahead by 4 commits)
  - Remove old cruft from .git if history is too noisy (optional)

- **Regenerate Generated Code**:
  - Run `make manifests generate fmt vet` to update CRDs, deepcopies, etc. (many api/ files are modified)
  - Commit the regenerated files
  - Run `make lint` and fix any issues

- **Module and Import Paths**:
  - Decide on final GitHub location: currently `github.com/kubewaf-io/kubewaf`, README suggests `github.com/kubewaf-io/kubewaf`
  - If changing, update go.mod, all imports, PROJECT file, and references

## Code Implementation TODOs

- **Controllers**:
  - Implement full reconciliation logic in all controllers (beyond just status.SecRuleString generation)
  - Improve RuleSet reference resolution and finalizers
  - Add proper error handling, conditions, and events

- **Translator and Parser**:
  - Complete `internal/translator/translator.go`: Replace string-hacking parser with full ANTLR context traversal
  - Support full chained rules, complex CRS rules, transformations, etc.
  - Improve `api/seclang/v1beta1/convert/` package for better crslang compatibility
  - Add more comprehensive tests for FromSecLangString/ToSecLangString

- **API Types**:
  - Complete `api/waf/v1beta1/ruleset_types.go` (AllowedRules TODO)
  - Add validation tags, better OpenAPI descriptions
  - Consider adding webhook validation for rules

## Testing and Quality

- **Tests**:
  - Replace all boilerplate TODOs in *_test.go files with actual test logic and assertions
  - Expand unit tests for translator and convert packages
  - Implement meaningful e2e tests in test/e2e/ (currently skeleton)
  - Run full `make test test-e2e`

- **Linting and Formatting**:
  - Ensure `make lint-fix` passes cleanly
  - Fix any remaining golangci-lint issues

## Documentation and UX

- **README.md**:
  - Update Getting Started section (references to deleted test.yaml, old paths)
  - Add architecture diagram (text or link)
  - Clarify current limitations (config gen only, no proxy deployment yet)
  - Add installation badges, quickstart kubectl commands, links to website
  - Update copyright year if needed

- **Other Docs**:
  - Add CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md
  - Document CRS converter usage with current cmd/crs-converter
  - Add examples for full RuleSet usage
  - Update config samples if needed
  - Fill in all Kubebuilder TODO comments in code and YAMLs

## Features for Future (Post-WIP)

- Implement WAF proxy deployment (WAFInstance, sidecar, Envoy Gateway integration)
- Full OWASP CRS support with chaining and phases
- Helm chart
- Validation webhooks
- Integration with modsecurity-proxy-wasm (and optional alternate engines)
- Metrics, observability
- Proper CRD versioning (v1beta1 -> v1?)

## GitHub Repo Setup

- Repo is now at https://github.com/kubewaf-io/kubewaf
- Topics: kubernetes, operator, waf, modsecurity, owasp-crs, security
- Enable issues, discussions, projects (if not already)
- GitHub Actions and workflows are present
- Consider adding release workflow with goreleaser later
- Update any website links once live

The project demonstrates a solid foundation for Kubernetes-native WAF rules management using structured CRDs.

Last updated: 2025-03-24
