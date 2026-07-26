package references2

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
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

		if uList, err = r.lookupRef(ctx, ref); err != nil {
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
					refError = append(refError, ReferenceError{Index: 2, Ref: ref, Err: fmt.Errorf("lockObject=%s", err)})
					continue
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
	}

	if updatedFirst || updatedSecond {
		if err := r.Update(ctx, refObject); err != nil {
			return err
		}
	}

	return nil
}

func (r *RuleRefResolver) allowedObject(ctx context.Context, refObject client.Object, source client.Object) error {
	// in same ns always allowed
	if source.GetNamespace() == refObject.GetNamespace() {
		return nil
	}
	switch v := refObject.(type) {
	case wafv1beta1.CrossNamespaceObject:
		policy := v.GetRuleNamespaces()
		// default to Same
		from := "Same"
		if policy.From != nil {
			from = string(*policy.From)
		}
		switch from {
		case "All":
			return nil
		case "Same":
			if source.GetNamespace() == refObject.GetNamespace() {
				return nil
			}
			return fmt.Errorf("CrossNamespace Reference not allowed")
		case "Selector":
			if policy.Selector == nil {
				return fmt.Errorf("selector required when From=Selector")
			}

			ns := &corev1.Namespace{}
			if err := r.Get(ctx, types.NamespacedName{Name: refObject.GetNamespace()}, ns); err != nil {
				return fmt.Errorf("failed to get namespace %s: %w", refObject.GetNamespace(), err)
			}
			selector, err := metav1.LabelSelectorAsSelector(policy.Selector)
			if err != nil {
				return fmt.Errorf("invalid selector: %w", err)
			}
			if !selector.Matches(labels.Set(ns.Labels)) {
				return fmt.Errorf("namespace %s does not match the allowed selector", refObject.GetNamespace())
			}
		}
	}
	return nil
}
