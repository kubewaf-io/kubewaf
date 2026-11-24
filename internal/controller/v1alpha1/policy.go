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

package v1alpha1

import (
	"context"
	"errors"
	"fmt"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	wafv1alpha1 "github.com/kubewaf-io/kubewaf/api/waf/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	"github.com/kubewaf-io/kubewaf/internal/provider"
	"github.com/kubewaf-io/kubewaf/internal/provider/registry"
	"github.com/kubewaf-io/kubewaf/internal/resolve"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	policyFinalizer = "seclang.kubewaf.io/policy"
	ruleIndexKey    = "spec.rules.name"

	conditionAccepted      = "Accepted"
	conditionRulesResolved = "RulesResolved"
	conditionEngineReady   = "EngineReady"
	conditionProgrammed    = "Programmed"

	reasonReady             = "Ready"
	reasonDualAttachment    = "DualAttachment"
	reasonMultipleParents   = "MultipleParents"
	reasonDuplicateID       = "DuplicateID"
	reasonNotFound          = "NotFound"
	reasonNotReady          = "NotReady"
	reasonSelectorEmpty     = "SelectorEmpty"
	reasonParseError        = "ParseError"
	reasonDataFileConflict  = "DataFileConflict"
	reasonConfigMapTooLarge = "ConfigMapTooLarge"
	reasonPending           = "Pending"
)

// SecPolicyReconciler attaches compiled rules to Envoy Gateway.
// It writes only through the provider: a ConfigMap and an EnvoyExtensionPolicy.
type SecPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Registry *registry.Registry
	// ProxyNamespace is where data files are written when a policy has them.
	ProxyNamespace string
	// WatchReferenceGrants is set when gateway.networking.k8s.io/v1 ReferenceGrant is served.
	// The operator still starts when it is not, and cross-namespace refs stay denied.
	WatchReferenceGrants bool
}

// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secactions,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=includes,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=rulesets,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=clusterrulesets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyextensionpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyproxies,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=referencegrants,verbs=get;list;watch

// Reconcile runs the SecPolicy algorithm. A failure to resolve rules leaves the last good ConfigMap in place.
func (r *SecPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	policy := &seclangv1alpha1.SecPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	p, ok := r.Registry.Get(provider.NameEnvoyGateway)
	if !ok {
		return ctrl.Result{}, fmt.Errorf("provider %s is not registered", provider.NameEnvoyGateway)
	}
	if !policy.DeletionTimestamp.IsZero() {
		if err := p.Delete(ctx, r.Client, policy.Namespace, policy.Name, r.ProxyNamespace); err != nil {
			return ctrl.Result{}, err
		}
		if controllerHasFinalizer(policy, policyFinalizer) {
			policy.Finalizers = removeString(policy.Finalizers, policyFinalizer)
			if err := r.Update(ctx, policy); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	if !controllerHasFinalizer(policy, policyFinalizer) {
		policy.Finalizers = append(policy.Finalizers, policyFinalizer)
		if err := r.Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
	}

	input, resolved, reason, message := r.resolve(ctx, policy)
	if !resolved {
		return r.unresolved(ctx, p, policy, reason, message)
	}
	setCondition(&policy.Status.Conditions, policy.Generation, conditionRulesResolved, metav1.ConditionTrue, reasonReady, "rules are ready")

	conflict, message, err := r.dualAttachment(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}
	if conflict {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionAccepted, metav1.ConditionFalse, reasonDualAttachment, message)
		_ = p.Retract(ctx, r.Client, policy.Namespace, policy.Name)
		setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionFalse, reasonDualAttachment, message)
		return ctrl.Result{}, r.writeStatus(ctx, policy)
	}

	gateways, reason, message, err := gatewaysFor(ctx, r.Client, policy.Namespace, policy.Spec.TargetRefs)
	if err != nil {
		return ctrl.Result{}, err
	}
	if reason != "" {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionAccepted, metav1.ConditionFalse, reason, message)
		return ctrl.Result{}, r.writeStatus(ctx, policy)
	}
	setCondition(&policy.Status.Conditions, policy.Generation, conditionAccepted, metav1.ConditionTrue, reasonReady, "targets are owned by this policy")

	module := policy.Spec.ModuleName
	if module == "" {
		module = "composer"
	}
	engine, err := p.CheckEngine(ctx, r.Client, gateways, module, r.ProxyNamespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	policy.Status.GatewayName = engine.GatewayName
	policy.Status.EnvoyProxyNamespace = engine.EnvoyProxyNamespace
	policy.Status.EnvoyProxyName = engine.EnvoyProxyName
	if !engine.Ready {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionEngineReady, metav1.ConditionFalse, engine.Reason, engine.Message)
		if err := p.Retract(ctx, r.Client, policy.Namespace, policy.Name); err != nil {
			return ctrl.Result{}, err
		}
		setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionFalse, engine.Reason, "extension policy removed because the engine is not ready")
		return ctrl.Result{}, r.writeStatus(ctx, policy)
	}
	setCondition(&policy.Status.Conditions, policy.Generation, conditionEngineReady, metav1.ConditionTrue, reasonReady, engine.Message)

	bundle, err := compile.Build(input)
	if err != nil {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionFalse, reasonParseError, err.Error())
		return ctrl.Result{}, r.writeStatus(ctx, policy)
	}
	if err := compile.ParseFiles(bundle.Before+"\n"+bundle.After, bundle.Files); err != nil {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionFalse, reasonParseError, err.Error())
		return ctrl.Result{}, r.writeStatus(ctx, policy)
	}
	if len(bundle.Files) > 0 && !engine.Mounted {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionEngineReady, metav1.ConditionFalse, provider.ReasonMountMissing, "data files need the kubewaf-seclang volume")
		_ = p.Retract(ctx, r.Client, policy.Namespace, policy.Name)
		setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionFalse, provider.ReasonMountMissing, "extension policy removed because data files are not mounted")
		return ctrl.Result{}, r.writeStatus(ctx, policy)
	}
	if err := p.Apply(ctx, r.Client, bundle, policy.Spec.TargetRefs, r.ProxyNamespace); err != nil {
		return ctrl.Result{}, r.failApply(ctx, policy, err)
	}

	policy.Status.SecLangHash = bundle.Hash
	policy.Status.RulesLoaded = int32(len(input.Rules))
	policy.Status.ActionsLoaded = int32(len(input.Actions))
	policy.Status.IncludesLoaded = int32(len(input.Includes))
	policy.Status.EnvoyExtensionPolicyName = "kubewaf-" + policy.Name
	policy.Status.ConfigMapName = compile.ConfigMapName
	policy.Status.ConfigMapNamespace = r.ProxyNamespace
	view, err := p.Programmed(ctx, r.Client, policy.Namespace, policy.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	if view.Accepted {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionTrue, reasonReady, "EnvoyExtensionPolicy is accepted")
		if err := r.writeStatus(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	reason = view.Reason
	if reason == "" {
		reason = reasonPending
	}
	setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionFalse, reason, view.Message)
	if err := r.writeStatus(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *SecPolicyReconciler) unresolved(ctx context.Context, p provider.Provider, policy *seclangv1alpha1.SecPolicy, reason, message string) (ctrl.Result, error) {
	setCondition(&policy.Status.Conditions, policy.Generation, conditionRulesResolved, metav1.ConditionFalse, reason, message)
	if reason == resolve.ReasonRefNotPermitted || reason == resolve.ReasonReferenceGrantUnavailable {
		if err := p.Retract(ctx, r.Client, policy.Namespace, policy.Name); err != nil {
			return ctrl.Result{}, err
		}
		setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionFalse, reason, "extension policy removed because the reference is not permitted")
	}
	return ctrl.Result{}, r.writeStatus(ctx, policy)
}

func (r *SecPolicyReconciler) failApply(ctx context.Context, policy *seclangv1alpha1.SecPolicy, err error) error {
	reason := reasonParseError
	if errors.Is(err, provider.ErrDataFileConflict) {
		reason = reasonDataFileConflict
	}
	if errors.Is(err, provider.ErrConfigMapTooLarge) {
		reason = reasonConfigMapTooLarge
	}
	setCondition(&policy.Status.Conditions, policy.Generation, conditionProgrammed, metav1.ConditionFalse, reason, err.Error())
	return r.writeStatus(ctx, policy)
}

// writeStatus sets Ready from the four attachment conditions, then writes status.
func (r *SecPolicyReconciler) writeStatus(ctx context.Context, policy *seclangv1alpha1.SecPolicy) error {
	ready := apimeta.IsStatusConditionTrue(policy.Status.Conditions, conditionRulesResolved) &&
		apimeta.IsStatusConditionTrue(policy.Status.Conditions, conditionAccepted) &&
		apimeta.IsStatusConditionTrue(policy.Status.Conditions, conditionEngineReady) &&
		apimeta.IsStatusConditionTrue(policy.Status.Conditions, conditionProgrammed)
	if ready {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionReady, metav1.ConditionTrue, reasonReady, "rules are programmed on a ready engine")
	} else {
		setCondition(&policy.Status.Conditions, policy.Generation, conditionReady, metav1.ConditionFalse, reasonPending, "not all attachment conditions are True")
	}
	return r.Status().Update(ctx, policy)
}

func (r *SecPolicyReconciler) resolve(ctx context.Context, policy *seclangv1alpha1.SecPolicy) (compile.Input, bool, string, string) {
	in, err := resolve.New(r.Client).Policy(ctx, policy)
	if err != nil {
		var re *resolve.Error
		if errors.As(err, &re) {
			return in, false, re.Reason, re.Message
		}
		return in, false, reasonNotFound, err.Error()
	}
	for i, file := range policy.Spec.DataFiles {
		content := file.Content
		if file.ConfigMapRef != nil {
			cm := &corev1.ConfigMap{}
			if err := r.Get(ctx, types.NamespacedName{Namespace: policy.Namespace, Name: file.ConfigMapRef.Name}, cm); err != nil {
				return in, false, reasonNotFound, fmt.Sprintf("data file %s: %v", file.Name, err)
			}
			var ok bool
			content, ok = cm.Data[file.ConfigMapRef.Key]
			if !ok {
				return in, false, reasonNotFound, fmt.Sprintf("data file %s: key %s not found", file.Name, file.ConfigMapRef.Key)
			}
		}
		in.Data = append(in.Data, compile.DataInput{File: policy.Spec.DataFiles[i], Content: content})
	}
	return in, true, "", ""
}

func (r *SecPolicyReconciler) dualAttachment(ctx context.Context, policy *seclangv1alpha1.SecPolicy) (bool, string, error) {
	var others seclangv1alpha1.SecPolicyList
	if err := r.List(ctx, &others, client.InNamespace(policy.Namespace)); err != nil {
		return false, "", err
	}
	for _, other := range others.Items {
		if other.Name == policy.Name {
			continue
		}
		if overlap(policy.Spec.TargetRefs, other.Spec.TargetRefs) {
			return true, fmt.Sprintf("SecPolicy %s already targets the same resource", other.Name), nil
		}
	}
	var protections wafv1alpha1.ProtectionList
	if err := r.List(ctx, &protections, client.InNamespace(policy.Namespace)); err != nil {
		if apierrors.IsNotFound(err) || apimeta.IsNoMatchError(err) {
			return false, "", nil
		}
		return false, "", err
	}
	for i := range protections.Items {
		item := &protections.Items[i]
		if !item.DeletionTimestamp.IsZero() {
			continue
		}
		if overlap(policy.Spec.TargetRefs, item.Spec.TargetRefs) {
			return true, fmt.Sprintf("Protection %s already targets the same resource", item.Name), nil
		}
	}
	return false, "", nil
}

func overlap(a, b []gatewayv1.LocalPolicyTargetReference) bool {
	for _, left := range a {
		for _, right := range b {
			if left.Name == right.Name && left.Kind == right.Kind && left.Group == right.Group {
				return true
			}
		}
	}
	return false
}

func gatewaysFor(ctx context.Context, c client.Client, namespace string, refs []gatewayv1.LocalPolicyTargetReference) ([]provider.GatewayRef, string, string, error) {
	var out []provider.GatewayRef
	for _, ref := range refs {
		switch ref.Kind {
		case "Gateway":
			out = append(out, provider.GatewayRef{Namespace: namespace, Name: string(ref.Name)})
		case "HTTPRoute":
			route := &gatewayv1.HTTPRoute{}
			if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: string(ref.Name)}, route); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, reasonNotFound, fmt.Sprintf("HTTPRoute %s not found", ref.Name), nil
				}
				return nil, "", "", err
			}
			gw, reason, message := parentGateway(route, namespace)
			if reason != "" {
				return nil, reason, message, nil
			}
			out = append(out, gw)
		default:
			return nil, reasonNotFound, fmt.Sprintf("unsupported target kind %s", ref.Kind), nil
		}
	}
	return out, "", "", nil
}

func parentGateway(route *gatewayv1.HTTPRoute, namespace string) (provider.GatewayRef, string, string) {
	var parents []provider.GatewayRef
	for _, p := range route.Spec.ParentRefs {
		kind := "Gateway"
		if p.Kind != nil && *p.Kind != "" {
			kind = string(*p.Kind)
		}
		if kind != "Gateway" {
			continue
		}
		ns := namespace
		if p.Namespace != nil && *p.Namespace != "" && string(*p.Namespace) != namespace {
			return provider.GatewayRef{}, reasonMultipleParents, "HTTPRoute parent Gateway must be in the same namespace"
		}
		parents = append(parents, provider.GatewayRef{Namespace: ns, Name: string(p.Name)})
	}
	if len(parents) == 0 {
		return provider.GatewayRef{}, reasonNotFound, "HTTPRoute has no Gateway parent"
	}
	if len(parents) > 1 {
		return provider.GatewayRef{}, reasonMultipleParents, "HTTPRoute has more than one parent Gateway"
	}
	return parents[0], "", ""
}

// SetupWithManager registers watches. A rule change enqueues policies by name and by label selector.
func (r *SecPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &seclangv1alpha1.SecPolicy{}, ruleIndexKey, indexRuleNames); err != nil {
		return err
	}
	b := ctrl.NewControllerManagedBy(mgr).
		For(&seclangv1alpha1.SecPolicy{}).
		Watches(&seclangv1alpha1.SecRule{}, handler.EnqueueRequestsFromMapFunc(r.requestsFor("SecRule"))).
		Watches(&seclangv1alpha1.SecAction{}, handler.EnqueueRequestsFromMapFunc(r.requestsFor("SecAction"))).
		Watches(&seclangv1alpha1.Include{}, handler.EnqueueRequestsFromMapFunc(r.requestsFor("Include"))).
		Watches(&seclangv1alpha1.RuleSet{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&seclangv1alpha1.ClusterRuleSet{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.requestsForConfigMap)).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.requestsInNamespace)).
		Watches(&gatewayv1.GatewayClass{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.requestsInNamespace)).
		Watches(&wafv1alpha1.Protection{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll))
	if r.WatchReferenceGrants {
		b = b.Watches(&gatewayv1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll))
	}
	if p, ok := r.Registry.Get(provider.NameEnvoyGateway); ok {
		for _, obj := range p.WatchObjects() {
			b = b.Watches(obj, handler.EnqueueRequestsFromMapFunc(r.requestsAll))
		}
	}
	return b.Complete(r)
}

func indexRuleNames(obj client.Object) []string {
	policy, ok := obj.(*seclangv1alpha1.SecPolicy)
	if !ok {
		return nil
	}
	var keys []string
	for _, rule := range policy.Spec.Rules {
		if rule.Name != "" {
			keys = append(keys, rule.Kind+"/"+rule.Name)
		}
	}
	return keys
}

func (r *SecPolicyReconciler) requestsFor(kind string) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		var indexed seclangv1alpha1.SecPolicyList
		_ = r.List(ctx, &indexed, client.InNamespace(obj.GetNamespace()), client.MatchingFields{ruleIndexKey: kind + "/" + obj.GetName()})
		var all seclangv1alpha1.SecPolicyList
		if err := r.List(ctx, &all, client.InNamespace(obj.GetNamespace())); err != nil {
			return nil
		}
		seen := map[string]struct{}{}
		var out []reconcile.Request
		add := func(namespace, name string) {
			key := namespace + "/" + name
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}})
		}
		for _, p := range indexed.Items {
			add(obj.GetNamespace(), p.Name)
		}
		for _, p := range all.Items {
			if selectorMatches(p, kind, obj) {
				add(obj.GetNamespace(), p.Name)
			}
		}
		// A RuleSet in this namespace may be named by a SecPolicy elsewhere.
		var cluster seclangv1alpha1.SecPolicyList
		if err := r.List(ctx, &cluster); err != nil {
			return out
		}
		for _, p := range cluster.Items {
			if len(p.Spec.RuleSetRefs) > 0 {
				add(p.Namespace, p.Name)
			}
		}
		return out
	}
}

func selectorMatches(policy seclangv1alpha1.SecPolicy, kind string, obj client.Object) bool {
	for _, rule := range policy.Spec.Rules {
		if rule.Kind != kind || rule.Selector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(rule.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(obj.GetLabels())) {
			return true
		}
	}
	return false
}

func (r *SecPolicyReconciler) requestsInNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	var list seclangv1alpha1.SecPolicyList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	return requestsFrom(list)
}

func (r *SecPolicyReconciler) requestsAll(ctx context.Context, _ client.Object) []reconcile.Request {
	var list seclangv1alpha1.SecPolicyList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	return requestsFrom(list)
}

func (r *SecPolicyReconciler) requestsForConfigMap(ctx context.Context, obj client.Object) []reconcile.Request {
	if obj.GetName() == compile.ConfigMapName {
		return r.requestsAll(ctx, obj)
	}
	return r.requestsInNamespace(ctx, obj)
}

func requestsFrom(list seclangv1alpha1.SecPolicyList) []reconcile.Request {
	out := make([]reconcile.Request, 0, len(list.Items))
	for _, p := range list.Items {
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: p.Namespace, Name: p.Name}})
	}
	return out
}

func controllerHasFinalizer(obj client.Object, f string) bool {
	for _, cur := range obj.GetFinalizers() {
		if cur == f {
			return true
		}
	}
	return false
}

func removeString(in []string, drop string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

func ready(conds []metav1.Condition) bool {
	return apimeta.IsStatusConditionTrue(conds, conditionReady)
}

func listRules(ctx context.Context, c client.Client, namespace string, sel seclangv1alpha1.RuleSelector) ([]seclangv1alpha1.SecRule, bool, string, string) {
	if sel.Name != "" {
		obj := &seclangv1alpha1.SecRule{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: sel.Name}, obj); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, false, reasonNotFound, fmt.Sprintf("SecRule %s not found", sel.Name)
			}
			return nil, false, reasonNotFound, err.Error()
		}
		return []seclangv1alpha1.SecRule{*obj}, true, "", ""
	}
	var list seclangv1alpha1.SecRuleList
	if err := c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, false, reasonNotFound, err.Error()
	}
	selector, err := metav1.LabelSelectorAsSelector(sel.Selector)
	if err != nil {
		return nil, false, reasonNotFound, err.Error()
	}
	var out []seclangv1alpha1.SecRule
	for _, item := range list.Items {
		if selector.Matches(labels.Set(item.Labels)) {
			out = append(out, item)
		}
	}
	return out, true, "", ""
}

func listActions(ctx context.Context, c client.Client, namespace string, sel seclangv1alpha1.RuleSelector) ([]seclangv1alpha1.SecAction, bool, string, string) {
	if sel.Name != "" {
		obj := &seclangv1alpha1.SecAction{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: sel.Name}, obj); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, false, reasonNotFound, fmt.Sprintf("SecAction %s not found", sel.Name)
			}
			return nil, false, reasonNotFound, err.Error()
		}
		return []seclangv1alpha1.SecAction{*obj}, true, "", ""
	}
	var list seclangv1alpha1.SecActionList
	if err := c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, false, reasonNotFound, err.Error()
	}
	selector, err := metav1.LabelSelectorAsSelector(sel.Selector)
	if err != nil {
		return nil, false, reasonNotFound, err.Error()
	}
	var out []seclangv1alpha1.SecAction
	for _, item := range list.Items {
		if selector.Matches(labels.Set(item.Labels)) {
			out = append(out, item)
		}
	}
	return out, true, "", ""
}

func listIncludes(ctx context.Context, c client.Client, namespace string, sel seclangv1alpha1.RuleSelector) ([]seclangv1alpha1.Include, bool, string, string) {
	if sel.Name != "" {
		obj := &seclangv1alpha1.Include{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: sel.Name}, obj); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, false, reasonNotFound, fmt.Sprintf("Include %s not found", sel.Name)
			}
			return nil, false, reasonNotFound, err.Error()
		}
		return []seclangv1alpha1.Include{*obj}, true, "", ""
	}
	var list seclangv1alpha1.IncludeList
	if err := c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, false, reasonNotFound, err.Error()
	}
	selector, err := metav1.LabelSelectorAsSelector(sel.Selector)
	if err != nil {
		return nil, false, reasonNotFound, err.Error()
	}
	var out []seclangv1alpha1.Include
	for _, item := range list.Items {
		if selector.Matches(labels.Set(item.Labels)) {
			out = append(out, item)
		}
	}
	return out, true, "", ""
}

func includeContent(ctx context.Context, c client.Client, namespace string, inc seclangv1alpha1.Include) (string, error) {
	if inc.Spec.ConfigMapRef == nil {
		return "", nil
	}
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: inc.Spec.ConfigMapRef.Name}, cm); err != nil {
		return "", fmt.Errorf("include %s: %w", inc.Name, err)
	}
	content, ok := cm.Data[inc.Spec.ConfigMapRef.Key]
	if !ok {
		return "", fmt.Errorf("include %s: key %s not found", inc.Name, inc.Spec.ConfigMapRef.Key)
	}
	return content, nil
}
