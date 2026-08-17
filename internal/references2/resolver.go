package references2

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// AddUpdateReconcile resolves references and writes back-references / finalizers
// on target objects. Use Resolve for read-only expansion (e.g. non-leader
// dataplane syncers).
func (r *RuleRefResolver) AddUpdateReconcile(
	ctx context.Context,
	refs []wafv1beta1.RuleRef,
	source client.Object,
) ([]unstructured.Unstructured, []ReferenceError, error) {
	return r.reconcileRefs(ctx, refs, source, true)
}

// Resolve expands RuleRefs into objects without mutating them (no finalizers /
// back-references). Safe to run on every operator replica.
func (r *RuleRefResolver) Resolve(
	ctx context.Context,
	refs []wafv1beta1.RuleRef,
	source client.Object,
) ([]unstructured.Unstructured, []ReferenceError, error) {
	return r.reconcileRefs(ctx, refs, source, false)
}

func (r *RuleRefResolver) reconcileRefs(
	ctx context.Context,
	refs []wafv1beta1.RuleRef,
	source client.Object,
	lock bool,
) ([]unstructured.Unstructured, []ReferenceError, error) {

	var (
		refError   []ReferenceError
		refObjects []unstructured.Unstructured
	)

	for _, ref := range refs {
		var (
			uList *unstructured.UnstructuredList
			err   error
		)

		ownerNS := ""
		if source != nil {
			ownerNS = source.GetNamespace()
		}
		if uList, err = r.lookupRef(ctx, applyRuleRefDefaults(ref, ownerNS)); err != nil {
			refError = append(refError, ReferenceError{Index: 0, Ref: ref, Err: fmt.Errorf("lookupRef=%s", err)})
			continue
		}
		for _, refObject := range uList.Items {
			if err := r.allowedObject(ctx, &refObject, source); err != nil {
				refError = append(refError, ReferenceError{Index: 1, Ref: ref, Err: fmt.Errorf("allowedObject=%s", err)})
				continue
			}

			if lock {
				if err := r.lockObject(ctx, &refObject, source); err != nil {
					// Conflict is expected under high churn (SecRule status/label updates while
					// locking hundreds of CRS CRs). Do not fail the whole resolve — the object
					// is still usable for SecLang assembly; finalizers are best-effort.
					if !apierrors.IsConflict(err) {
						refError = append(refError, ReferenceError{Index: 2, Ref: ref, Err: fmt.Errorf("lockObject=%s", err)})
						continue
					}
				}
			}

			switch refObject.GetKind() {
			case "RuleSet":
				var ruleSet wafv1beta1.RuleSet
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(refObject.Object, &ruleSet); err != nil {
					return refObjects, refError, err
				}
				objects, errs, err := r.reconcileRefs(ctx, ruleSet.Spec.RuleRefs, &ruleSet, lock)
				if err != nil {
					return refObjects, refError, err
				}
				refObjects = append(refObjects, objects...)
				refError = append(refError, errs...)
			}

			refObjects = append(refObjects, refObject)
		}

	}

	return refObjects, refError, nil
}

// applyRuleRefDefaults fills omitted namespace / GVK (RuleRef docs: namespace
// defaults to the referencing object; kinds map to product groups).
func applyRuleRefDefaults(ref wafv1beta1.RuleRef, ownerNS string) wafv1beta1.RuleRef {
	if ref.Namespace == "" {
		ref.Namespace = ownerNS
	}
	switch ref.Kind {
	case "SecRule", "SecAction":
		if ref.Group == "" {
			ref.Group = "seclang.kubewaf.io"
		}
		if ref.Version == "" {
			ref.Version = "v1beta1"
		}
	case "RuleSet", "":
		if ref.Kind == "" {
			ref.Kind = "RuleSet"
		}
		if ref.Group == "" {
			ref.Group = "waf.kubewaf.io"
		}
		if ref.Version == "" {
			ref.Version = "v1beta1"
		}
	}
	return ref
}

func (r *RuleRefResolver) lookupRef(ctx context.Context, ref wafv1beta1.RuleRef) (*unstructured.UnstructuredList, error) {
	groupVersionKind := schema.GroupVersionKind{Kind: ref.Kind, Group: ref.Group, Version: ref.Version}
	if ref.Selector != nil {
		selector, err := metav1.LabelSelectorAsSelector(ref.Selector)
		if err != nil {
			return nil, err
		}
		return r.listDynamicObjects(ctx, groupVersionKind, selector)
	}
	if ref.Name != "" {
		return r.getDynamicObjects(ctx, groupVersionKind, ref.Name, ref.Namespace)
	}

	return nil, fmt.Errorf("wrong reference definition")
}

func (r *RuleRefResolver) getDynamicObjects(ctx context.Context, gvk schema.GroupVersionKind, name, namespace string) (*unstructured.UnstructuredList, error) {
	// Prefer a direct Get — works without a field indexer (required for multi-replica caches).
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, obj); err != nil {
		return nil, err
	}

	listGVK := gvk
	if !strings.HasSuffix(listGVK.Kind, "List") {
		listGVK.Kind = listGVK.Kind + "List"
	}
	uList := &unstructured.UnstructuredList{}
	uList.SetGroupVersionKind(listGVK)
	uList.Items = []unstructured.Unstructured{*obj}
	return uList, nil
}

func (r *RuleRefResolver) listDynamicObjects(ctx context.Context, gvk schema.GroupVersionKind, selector labels.Selector) (*unstructured.UnstructuredList, error) {
	// Make sure the Kind ends with "List"
	listGVK := gvk
	if !strings.HasSuffix(listGVK.Kind, "List") {
		listGVK.Kind = listGVK.Kind + "List"
	}

	uList := &unstructured.UnstructuredList{}
	uList.SetGroupVersionKind(listGVK)

	err := r.List(ctx, uList,
		client.MatchingLabelsSelector{Selector: selector},
	)

	return uList, err
}

// lockObject will set finalizer on Object and set reference
func (r *RuleRefResolver) lockObject(ctx context.Context, refObject client.Object, source client.Object) error {

	var (
		updatedFirst  bool
		updatedSecond bool
	)
	updatedFirst = controllerutil.AddFinalizer(refObject, controller.RuleSetRefFinalizer)

	switch v := refObject.(type) {
	case v1beta1.SecLang:
		updatedSecond = v.AddRuleSetRef(source)
	case *unstructured.Unstructured:
		// Dynamic resolve path uses unstructured; convert for SecLang back-refs.
		switch v.GetKind() {
		case "SecRule":
			var sr v1beta1.SecRule
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(v.Object, &sr); err == nil {
				if sr.AddRuleSetRef(source) {
					if m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&sr); err == nil {
						v.Object = m
						updatedSecond = true
					}
				}
			}
		case "SecAction":
			var sa v1beta1.SecAction
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(v.Object, &sa); err == nil {
				if sa.AddRuleSetRef(source) {
					if m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&sa); err == nil {
						v.Object = m
						updatedSecond = true
					}
				}
			}
		}
	}

	if updatedFirst || updatedSecond {
		if err := r.Update(ctx, refObject); err != nil {
			// Conflict: another controller (e.g. SecRuleReconciler) updated the object.
			// Caller should still use the resolved object for assembly.
			if apierrors.IsConflict(err) {
				return err // surface to reconcileRefs which treats conflict as non-fatal
			}
			return err
		}
	}

	return nil
}

// allowedObject enforces cross-namespace policy when the owner declares one.
//
// RuleSet.spec.allowedRules controls which namespaces may contribute rules to
// that RuleSet (Gateway API–style From=Same|All|Selector). The policy lives on
// the *owner* (source), not the target — targets are often unstructured SecRules
// that never implement CrossNamespaceObject.
//
// Owners without a policy (e.g. WAF attaching RuleSets) allow cross-namespace
// references so platform RuleSets can live in a shared namespace.
func (r *RuleRefResolver) allowedObject(ctx context.Context, refObject client.Object, source client.Object) error {
	if source.GetNamespace() == refObject.GetNamespace() {
		return nil
	}

	policy, ok := namespacesPolicy(source)
	if !ok {
		return nil
	}

	from := "Same"
	if policy.From != nil {
		from = string(*policy.From)
	}
	switch from {
	case "All":
		return nil
	case "Same", "":
		return fmt.Errorf("cross-namespace reference from %s/%s to %s/%s not allowed (allowedRules.from=Same)",
			source.GetNamespace(), source.GetName(), refObject.GetNamespace(), refObject.GetName())
	case "Selector":
		if policy.Selector == nil {
			return fmt.Errorf("allowedRules.selector required when from=Selector")
		}
		ns := &corev1.Namespace{}
		if err := r.Get(ctx, types.NamespacedName{Name: refObject.GetNamespace()}, ns); err != nil {
			return fmt.Errorf("failed to get namespace %s: %w", refObject.GetNamespace(), err)
		}
		selector, err := metav1.LabelSelectorAsSelector(policy.Selector)
		if err != nil {
			return fmt.Errorf("invalid allowedRules.selector: %w", err)
		}
		if !selector.Matches(labels.Set(ns.Labels)) {
			return fmt.Errorf("namespace %s does not match allowedRules.selector", refObject.GetNamespace())
		}
		return nil
	default:
		return fmt.Errorf("unknown allowedRules.from %q", from)
	}
}

// namespacesPolicy returns AllowedRules when source is a RuleSet (typed or unstructured).
func namespacesPolicy(source client.Object) (wafv1beta1.RuleNamespaces, bool) {
	switch v := source.(type) {
	case wafv1beta1.CrossNamespaceObject:
		// RuleSet implements CrossNamespaceObject; keep interface case first.
		return v.GetRuleNamespaces(), true
	case *unstructured.Unstructured:
		if v.GetKind() != "RuleSet" {
			return wafv1beta1.RuleNamespaces{}, false
		}
		var rs wafv1beta1.RuleSet
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(v.Object, &rs); err != nil {
			return wafv1beta1.RuleNamespaces{}, false
		}
		return rs.Spec.AllowedRules, true
	default:
		return wafv1beta1.RuleNamespaces{}, false
	}
}
