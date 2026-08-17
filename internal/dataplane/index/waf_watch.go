/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package index provides field indexes and reverse maps from SecRule/RuleSet
// back to WAFs so controllers do not requeue every WAF on every rule change.
package index

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

// WAFRuleRefField is the field indexer key for WAF.spec.ruleRefs entries.
// Values are "namespace/name" of referenced RuleSets (namespace defaults to WAF ns).
const WAFRuleRefField = "spec.ruleRefs"

// RuleSetRuleRefField indexes RuleSet.spec.ruleRefs for one-hop parent lookup.
const RuleSetRuleRefField = "ruleset.spec.ruleRefs"

// RuleRefIndexKeys returns indexer keys for a list of RuleRefs owned by ownerNS.
func RuleRefIndexKeys(ownerNS string, refs []wafv1beta1.RuleRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Name == "" {
			// Selector-based refs cannot be field-indexed by name; skip.
			continue
		}
		ns := ref.Namespace
		if ns == "" {
			ns = ownerNS
		}
		// Kind defaults to RuleSet for WAF refs; include kind prefix for clarity.
		kind := ref.Kind
		if kind == "" {
			kind = "RuleSet"
		}
		out = append(out, kind+"/"+ns+"/"+ref.Name)
	}
	return out
}

// IndexWAFRuleRefs is a controller-runtime IndexerFunc for *wafv1beta1.WAF.
func IndexWAFRuleRefs(obj client.Object) []string {
	waf, ok := obj.(*wafv1beta1.WAF)
	if !ok || waf == nil {
		return nil
	}
	return RuleRefIndexKeys(waf.Namespace, waf.Spec.RuleSetRefs)
}

// IndexRuleSetRuleRefs is a controller-runtime IndexerFunc for *wafv1beta1.RuleSet.
func IndexRuleSetRuleRefs(obj client.Object) []string {
	rs, ok := obj.(*wafv1beta1.RuleSet)
	if !ok || rs == nil {
		return nil
	}
	return RuleRefIndexKeys(rs.Namespace, rs.Spec.RuleRefs)
}

// MapSecLangToWAFs enqueues WAFs that own (directly or via one RuleSet hop) the object.
// obj must be *SecRule or *SecAction (status.RuleSetRefs back-references).
func MapSecLangToWAFs(ctx context.Context, c client.Client, obj client.Object) []reconcile.Request {
	refs := seclangBackRefs(obj)
	if len(refs) == 0 {
		return nil
	}
	wafs := map[types.NamespacedName]struct{}{}
	for _, ref := range refs {
		switch ref.Kind {
		case "WAF":
			wafs[types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}] = struct{}{}
		case "RuleSet", "":
			collectWAFsForRuleSet(ctx, c, ref.Namespace, ref.Name, wafs)
			// One hop: parent RuleSets that reference this RuleSet.
			var parents wafv1beta1.RuleSetList
			key := "RuleSet/" + ref.Namespace + "/" + ref.Name
			if err := c.List(ctx, &parents, client.MatchingFields{RuleSetRuleRefField: key}); err == nil {
				for i := range parents.Items {
					p := &parents.Items[i]
					collectWAFsForRuleSet(ctx, c, p.Namespace, p.Name, wafs)
				}
			}
		}
	}
	return mapKeysToRequests(wafs)
}

// MapPhraseListToWAFs enqueues all WAFs in the PhraseList namespace (v1 same-ns fan-out).
func MapPhraseListToWAFs(ctx context.Context, c client.Client, obj client.Object) []reconcile.Request {
	pl, ok := obj.(*seclangv1beta1.PhraseList)
	if !ok || pl == nil {
		return nil
	}
	return mapNamespaceWAFs(ctx, c, pl.Namespace)
}

// MapIPListToWAFs enqueues all WAFs in the IPList namespace (v1 same-ns fan-out).
func MapIPListToWAFs(ctx context.Context, c client.Client, obj client.Object) []reconcile.Request {
	ipl, ok := obj.(*seclangv1beta1.IPList)
	if !ok || ipl == nil {
		return nil
	}
	return mapNamespaceWAFs(ctx, c, ipl.Namespace)
}

func mapNamespaceWAFs(ctx context.Context, c client.Client, ns string) []reconcile.Request {
	var list wafv1beta1.WAFList
	if err := c.List(ctx, &list, client.InNamespace(ns)); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		w := &list.Items[i]
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: w.Namespace,
			Name:      w.Name,
		}})
	}
	return reqs
}

// MapRuleSetToWAFs enqueues WAFs that reference this RuleSet (direct or one parent hop).
func MapRuleSetToWAFs(ctx context.Context, c client.Client, obj client.Object) []reconcile.Request {
	rs, ok := obj.(*wafv1beta1.RuleSet)
	if !ok || rs == nil {
		return nil
	}
	wafs := map[types.NamespacedName]struct{}{}
	collectWAFsForRuleSet(ctx, c, rs.Namespace, rs.Name, wafs)
	var parents wafv1beta1.RuleSetList
	key := "RuleSet/" + rs.Namespace + "/" + rs.Name
	if err := c.List(ctx, &parents, client.MatchingFields{RuleSetRuleRefField: key}); err == nil {
		for i := range parents.Items {
			p := &parents.Items[i]
			collectWAFsForRuleSet(ctx, c, p.Namespace, p.Name, wafs)
		}
	}
	return mapKeysToRequests(wafs)
}

func collectWAFsForRuleSet(ctx context.Context, c client.Client, ns, name string, out map[types.NamespacedName]struct{}) {
	if name == "" {
		return
	}
	if ns == "" {
		ns = "default"
	}
	key := "RuleSet/" + ns + "/" + name
	var list wafv1beta1.WAFList
	if err := c.List(ctx, &list, client.MatchingFields{WAFRuleRefField: key}); err != nil {
		// Index may be unregistered in unit tests — fall back to full list filter.
		if err2 := c.List(ctx, &list); err2 != nil {
			return
		}
		for i := range list.Items {
			w := &list.Items[i]
			for _, ref := range w.Spec.RuleSetRefs {
				refNS := ref.Namespace
				if refNS == "" {
					refNS = w.Namespace
				}
				kind := ref.Kind
				if kind == "" {
					kind = "RuleSet"
				}
				if kind == "RuleSet" && ref.Name == name && refNS == ns {
					out[types.NamespacedName{Namespace: w.Namespace, Name: w.Name}] = struct{}{}
				}
			}
		}
		return
	}
	for i := range list.Items {
		w := &list.Items[i]
		out[types.NamespacedName{Namespace: w.Namespace, Name: w.Name}] = struct{}{}
	}
}

func seclangBackRefs(obj client.Object) []seclangv1beta1.RuleSetRef {
	switch o := obj.(type) {
	case *seclangv1beta1.SecRule:
		return o.Status.RuleSetRefs
	case *seclangv1beta1.SecAction:
		return o.Status.RuleSetRefs
	default:
		return nil
	}
}

func mapKeysToRequests(wafs map[types.NamespacedName]struct{}) []reconcile.Request {
	if len(wafs) == 0 {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(wafs))
	for nn := range wafs {
		reqs = append(reqs, reconcile.Request{NamespacedName: nn})
	}
	return reqs
}
