# RuleRef Resolution

The `RuleRef` type (in `api/waf/v1beta1/ruleset_types.go`) is used across multiple CRDs (RuleSet, WAFInstance, and future ones) to reference SecRules, SecActions, RuleSets, or ConfigMaps.

## Reusable Resolver

All resolution logic is centralized in `internal/references/resolver.go`:

- **RuleRefResolver.ResolveAndReconcile()**: Handles name/selector resolution, namespace policies (`RuleNamespaces`), recursive flattening of RuleSet references (with cycle detection), automatic back-references (finalizers + `status.RuleSetRefs` on targets via `SecLang` interface), and `ReferencesResolved` status condition.
- Errors are aggregated.
- Used by both `RuleSetReconciler` and `WAFInstanceReconciler`.
- `CleanupBackReferences()` in `internal/controller/controller.go` handles deletion cleanup (placeholder for full implementation).

## Usage for New Resources

1. Embed `[]RuleRef` in your Spec.
2. Call `references.NewRuleRefResolver(client, scheme).ResolveAndReconcile(...)` in your Reconciler.
3. Add appropriate `// +kubebuilder:rbac` markers for target resources.
4. Implement deletion finalizer handling using `controller.CleanupBackReferences`.

This eliminates duplication and ensures consistent behavior across the operator.
