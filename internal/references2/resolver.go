package references2

import (
	"context"
	"fmt"
	"strings"

	"github.com/buzz-it/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/buzz-it/kubewaf/api/waf/v1beta1"
	"github.com/buzz-it/kubewaf/internal/controller"
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

func (r *RuleRefResolver) AddUpdateReconcile(
	ctx context.Context,
	refs []wafv1beta1.RuleRef,
	source client.Object,
) ([]unstructured.Unstructured, []ReferenceError, error) {

	var (
		refError   []ReferenceError
		refObjects []unstructured.Unstructured
	)

	for idx, ref := range refs {
		// allowed is used to verify if object ref is allowed
		var (
			//	refObject client.Object
			uList *unstructured.UnstructuredList
			err   error
		)

		// get ref
		if uList, err = r.lookupRef(ctx, ref); err != nil {
			refError = append(refError, ReferenceError{Index: idx, Ref: ref, Err: err})
			continue
		}
		for _, refObject := range uList.Items {
			if err := r.allowedObject(ctx, &refObject, source); err != nil {
				refError = append(refError, ReferenceError{Index: idx, Ref: ref, Err: err})
				continue
			}

			if err := r.lockObject(ctx, &refObject, source); err != nil {
				refError = append(refError, ReferenceError{Index: idx, Ref: ref, Err: err})
				continue
			}

			switch refObject.GetKind() {
			case "RuleSet":
				var ruleSet wafv1beta1.RuleSet
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(refObject.Object, &ruleSet); err != nil {
					return refObjects, refError, err
				}
				objects, errs, err := r.AddUpdateReconcile(ctx, ruleSet.Spec.RuleRefs, &ruleSet)
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
	fmt.Println(ref.Version)
	groupVersionKind := schema.GroupVersionKind{Kind: ref.Kind, Group: ref.Group, Version: ref.Version}
	fmt.Println(groupVersionKind)
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

	return nil, fmt.Errorf("Wrong refernce defintion")
}

func (r *RuleRefResolver) getDynamicObjects(ctx context.Context, gvk schema.GroupVersionKind, name, namespace string) (*unstructured.UnstructuredList, error) {
	// Make sure the Kind ends with "List"
	listGVK := gvk
	if !strings.HasSuffix(listGVK.Kind, "List") {
		listGVK.Kind = listGVK.Kind + "List"
	}

	uList := &unstructured.UnstructuredList{}
	uList.SetGroupVersionKind(listGVK)

	err := r.List(ctx, uList,
		client.InNamespace(namespace),
		client.MatchingFields{"metadata.name": name},
	)

	return uList, err
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
	if source.GetNamespace() != refObject.GetNamespace() {
		return fmt.Errorf("CrossNamespace Reference not allowed")
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
