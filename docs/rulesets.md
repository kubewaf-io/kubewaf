# RuleSet references

`RuleSet` is namespaced. `ClusterRuleSet` is cluster-scoped. Both live in `seclang.kubewaf.io/v1alpha1`. A set is an ordered `spec.ruleRefs` list. Each entry is `group`, `kind`, `name` or `selector`, and an optional `namespace`. There is no `apiVersion` and no version.

Allowed kinds are `RuleSet`, `ClusterRuleSet`, `SecRule`, `SecAction`, and `Include`. `group` is only `seclang.kubewaf.io`. Exactly one of `name` or `selector` is set.

`SecPolicy.spec.rules` is unchanged and still selects `SecRule`, `SecAction`, and `Include` in the policy namespace. `SecPolicy.spec.ruleSetRefs` selects sets. A policy sets either list or both. `spec.rules` are expanded first, then `ruleSetRefs`, in list order. Selector matches are sorted by name.

Sets compose. `java-frontend` can name `java`, and `java` can name `base`. The resolver walks each hop with that set as the referrer.

## Namespace and selectors

A selector runs only in the namespace of the object that holds it. It cannot set `namespace`. `ClusterRuleSet` has no namespace, so it cannot use a selector.

An empty `namespace` on a named namespaced ref means the referrer's namespace. A `ClusterRuleSet` target never takes a namespace.

## ReferenceGrant

Cross-namespace names need a `gateway.networking.k8s.io/v1` `ReferenceGrant` in the **target** namespace. The operator does not install or ship that CRD. Gateway API has served `ReferenceGrant` as v1 since 1.5. This module is `sigs.k8s.io/gateway-api` v1.6.1, whose v1 type matches a 1.7 CRD that serves v1 and stores v1beta1. A cluster that only serves v1beta1 is treated as having no grant API.

The grant is checked on the direct edge:

- `from.group`, `from.kind`, and `from.namespace` must be the referrer. A `SecPolicy` grant does not authorize a nested `RuleSet` to `RuleSet` hop.
- `to.group` and `to.kind` must be the target. `to.name` is that object, or empty for every name of that kind.

The target is read only after the grant matches. `RefNotPermitted` does not say whether the object exists. Same-namespace refs do not consult grants.

If discovery does not serve `referencegrants` at v1, the operator still starts, same-namespace refs still resolve, and cross-namespace refs are `ReferenceGrantUnavailable`. Grant create and delete are watched only when that resource is served at startup. Installing the CRD later needs an operator restart before the watch exists. Removing a grant retracts the extension policy.

Label selectors are not a substitute for a missing grant.

## ClusterRuleSet

`ReferenceGrant.from.namespace` is required and names a namespace. A cluster-scoped referrer has none, and this API does not invent one. `ClusterRuleSet` may name other `ClusterRuleSet` objects with no namespace and no grant. A namespaced leaf or `RuleSet` ref must set `namespace`, and it is refused with `RefNotPermitted` before the object is read, even if some grant's `from.kind` is `ClusterRuleSet`.

Share namespaced rules by putting them in a namespaced `RuleSet` and granting the real referrer. A namespaced `RuleSet` or `SecPolicy` may name a `ClusterRuleSet` with no grant, because that target is not in a namespace. That set still cannot pull namespaced objects back out.

## Failures

The walk is deterministic. A cycle, a second inclusion of the same object, a duplicate rule id, an empty selector, a depth above 8, or more than 128 expanded objects fails the policy. `RulesResolved` is False and nothing from that pass is programmed. An authorization failure also deletes the extension policy already written for that `SecPolicy`.
