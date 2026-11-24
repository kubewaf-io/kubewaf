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

// Package resolve expands SecPolicy rules and RuleSet references.
// Cross-namespace names are allowed only after a gateway.networking.k8s.io/v1
// ReferenceGrant in the target namespace matches that direct edge. The target
// is read only after that check, so a denied ref does not reveal whether the
// object exists. A missing ReferenceGrant CRD keeps same-namespace refs working
// and denies cross-namespace refs.
package resolve

import (
	"context"
	"fmt"
	"slices"
	"strings"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	ReasonNotFound                  = "NotFound"
	ReasonNotReady                  = "NotReady"
	ReasonSelectorEmpty             = "SelectorEmpty"
	ReasonDuplicateID               = "DuplicateID"
	ReasonDuplicate                 = "Duplicate"
	ReasonCycle                     = "Cycle"
	ReasonInvalidRef                = "InvalidRef"
	ReasonDepthExceeded             = "DepthExceeded"
	ReasonRefNotPermitted           = "RefNotPermitted"
	ReasonReferenceGrantUnavailable = "ReferenceGrantUnavailable"

	maxDepth    = 8
	maxExpanded = 128
)

// Error is a resolution failure the controller copies onto RulesResolved.
type Error struct {
	Reason  string
	Message string
}

func (e *Error) Error() string { return e.Message }

func invalid(format string, args ...any) error {
	return &Error{Reason: ReasonInvalidRef, Message: fmt.Sprintf(format, args...)}
}

// Referrer is the object that owns a reference edge.
type Referrer struct {
	Group     string
	Kind      string
	Namespace string
	Name      string
}

// Resolver reads rules, sets, and ReferenceGrants.
type Resolver struct {
	Client client.Client
	// grants is nil until the first cross-namespace check. false means the v1
	// ReferenceGrant type is not installed.
	grants *bool
}

// New returns a resolver.
func New(c client.Client) *Resolver { return &Resolver{Client: c} }

// Policy expands policy.Spec.Rules and then policy.Spec.RuleSetRefs.
// spec.rules stay in the policy namespace. ruleSetRefs may name another namespace.
func (r *Resolver) Policy(ctx context.Context, policy *seclangv1alpha1.SecPolicy) (compile.Input, error) {
	in := compile.Input{Policy: *policy}
	st := &state{seen: map[string]struct{}{}, seenID: map[int]string{}, in: in}
	self := Referrer{
		Group: seclangv1alpha1.GroupName, Kind: "SecPolicy",
		Namespace: policy.Namespace, Name: policy.Name,
	}
	for _, sel := range policy.Spec.Rules {
		ref := seclangv1alpha1.ObjectRef{Group: seclangv1alpha1.GroupName, Kind: sel.Kind, Name: sel.Name, Selector: sel.Selector}
		if err := st.expand(ctx, r, self, ref, 0, false); err != nil {
			return st.in, err
		}
	}
	for _, ref := range policy.Spec.RuleSetRefs {
		if ref.Kind != seclangv1alpha1.KindRuleSet && ref.Kind != seclangv1alpha1.KindClusterRuleSet {
			return st.in, invalid("ruleSetRefs kind %s is not a RuleSet", ref.Kind)
		}
		if err := st.expand(ctx, r, self, ref, 0, true); err != nil {
			return st.in, err
		}
	}
	if st.count == 0 {
		return st.in, &Error{Reason: ReasonNotFound, Message: "policy selected no objects"}
	}
	return st.in, nil
}

type state struct {
	stack  []string
	seen   map[string]struct{}
	seenID map[int]string
	count  int
	in     compile.Input
}

func (s *state) expand(ctx context.Context, r *Resolver, from Referrer, ref seclangv1alpha1.ObjectRef, depth int, setOnly bool) error {
	if err := validateRef(from, ref, setOnly); err != nil {
		return err
	}
	if from.Kind == seclangv1alpha1.KindClusterRuleSet && ref.Kind != seclangv1alpha1.KindClusterRuleSet {
		return &Error{Reason: ReasonRefNotPermitted, Message: fmt.Sprintf(
			"ClusterRuleSet %s is not permitted to reference %s %s/%s: ReferenceGrant cannot name a cluster-scoped referrer",
			from.Name, ref.Kind, ref.Namespace, ref.Name)}
	}
	if ref.Selector != nil {
		return s.expandSelector(ctx, r, from, ref, depth)
	}
	targetNS, err := targetNamespace(from, ref)
	if err != nil {
		return err
	}
	if err := r.authorize(ctx, from, ref.Kind, targetNS, ref.Name); err != nil {
		return err
	}
	return s.expandOne(ctx, r, ref.Kind, targetNS, ref.Name, depth)
}

func (s *state) expandSelector(ctx context.Context, r *Resolver, from Referrer, ref seclangv1alpha1.ObjectRef, depth int) error {
	selector, err := metav1.LabelSelectorAsSelector(ref.Selector)
	if err != nil {
		return invalid("selector: %v", err)
	}
	names, err := r.listNames(ctx, ref.Kind, from.Namespace, selector)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return &Error{Reason: ReasonSelectorEmpty, Message: fmt.Sprintf("selector matched no %s", ref.Kind)}
	}
	for _, name := range names {
		if err := s.expandOne(ctx, r, ref.Kind, from.Namespace, name, depth); err != nil {
			return err
		}
	}
	return nil
}

func (s *state) expandOne(ctx context.Context, r *Resolver, kind, namespace, name string, depth int) error {
	if s.count >= maxExpanded {
		return &Error{Reason: ReasonDepthExceeded, Message: fmt.Sprintf("expansion stopped at %d objects", maxExpanded)}
	}
	id := kind + "/" + namespace + "/" + name
	if slices.Contains(s.stack, id) {
		return &Error{Reason: ReasonCycle, Message: "reference cycle: " + strings.Join(append(append([]string{}, s.stack...), id), " -> ")}
	}
	if _, ok := s.seen[id]; ok {
		return &Error{Reason: ReasonDuplicate, Message: fmt.Sprintf("%s %s/%s is already included", kind, namespace, name)}
	}
	s.seen[id] = struct{}{}
	s.count++

	switch kind {
	case seclangv1alpha1.KindSecRule:
		obj := &seclangv1alpha1.SecRule{}
		if err := get(ctx, r.Client, seclangv1alpha1.KindSecRule, namespace, name, obj); err != nil {
			return err
		}
		if !ready(obj.Status.Conditions) {
			return &Error{Reason: ReasonNotReady, Message: fmt.Sprintf("SecRule %s/%s is not Ready", namespace, name)}
		}
		if prev, ok := s.seenID[obj.Spec.Metadata.ID]; ok {
			return &Error{Reason: ReasonDuplicateID, Message: fmt.Sprintf("id %d is used by %s and %s/%s", obj.Spec.Metadata.ID, prev, namespace, name)}
		}
		s.seenID[obj.Spec.Metadata.ID] = namespace + "/" + name
		s.in.Rules = append(s.in.Rules, *obj)
		return nil
	case seclangv1alpha1.KindSecAction:
		obj := &seclangv1alpha1.SecAction{}
		if err := get(ctx, r.Client, seclangv1alpha1.KindSecAction, namespace, name, obj); err != nil {
			return err
		}
		if !ready(obj.Status.Conditions) {
			return &Error{Reason: ReasonNotReady, Message: fmt.Sprintf("SecAction %s/%s is not Ready", namespace, name)}
		}
		if prev, ok := s.seenID[obj.Spec.Metadata.ID]; ok {
			return &Error{Reason: ReasonDuplicateID, Message: fmt.Sprintf("id %d is used by %s and %s/%s", obj.Spec.Metadata.ID, prev, namespace, name)}
		}
		s.seenID[obj.Spec.Metadata.ID] = namespace + "/" + name
		s.in.Actions = append(s.in.Actions, *obj)
		return nil
	case seclangv1alpha1.KindInclude:
		obj := &seclangv1alpha1.Include{}
		if err := get(ctx, r.Client, seclangv1alpha1.KindInclude, namespace, name, obj); err != nil {
			return err
		}
		if !ready(obj.Status.Conditions) {
			return &Error{Reason: ReasonNotReady, Message: fmt.Sprintf("Include %s/%s is not Ready", namespace, name)}
		}
		content, err := includeContent(ctx, r.Client, namespace, *obj)
		if err != nil {
			return &Error{Reason: ReasonNotFound, Message: err.Error()}
		}
		s.in.Includes = append(s.in.Includes, compile.IncludeInput{Include: *obj, Content: content})
		return nil
	case seclangv1alpha1.KindRuleSet:
		if depth >= maxDepth {
			return &Error{Reason: ReasonDepthExceeded, Message: fmt.Sprintf("RuleSet nesting is deeper than %d", maxDepth)}
		}
		obj := &seclangv1alpha1.RuleSet{}
		if err := get(ctx, r.Client, seclangv1alpha1.KindRuleSet, namespace, name, obj); err != nil {
			return err
		}
		s.stack = append(s.stack, id)
		next := Referrer{Group: seclangv1alpha1.GroupName, Kind: seclangv1alpha1.KindRuleSet, Namespace: namespace, Name: name}
		for _, child := range obj.Spec.RuleRefs {
			if err := s.expand(ctx, r, next, child, depth+1, false); err != nil {
				return err
			}
		}
		s.stack = s.stack[:len(s.stack)-1]
		return nil
	case seclangv1alpha1.KindClusterRuleSet:
		if depth >= maxDepth {
			return &Error{Reason: ReasonDepthExceeded, Message: fmt.Sprintf("RuleSet nesting is deeper than %d", maxDepth)}
		}
		obj := &seclangv1alpha1.ClusterRuleSet{}
		if err := get(ctx, r.Client, seclangv1alpha1.KindClusterRuleSet, "", name, obj); err != nil {
			return err
		}
		s.stack = append(s.stack, id)
		next := Referrer{Group: seclangv1alpha1.GroupName, Kind: seclangv1alpha1.KindClusterRuleSet, Name: name}
		for _, child := range obj.Spec.RuleRefs {
			if err := s.expand(ctx, r, next, child, depth+1, false); err != nil {
				return err
			}
		}
		s.stack = s.stack[:len(s.stack)-1]
		return nil
	default:
		return invalid("unknown kind %s", kind)
	}
}

func validateRef(from Referrer, ref seclangv1alpha1.ObjectRef, setOnly bool) error {
	if ref.Group != seclangv1alpha1.GroupName {
		return invalid("group %q is not %s", ref.Group, seclangv1alpha1.GroupName)
	}
	switch ref.Kind {
	case seclangv1alpha1.KindRuleSet, seclangv1alpha1.KindClusterRuleSet:
	case seclangv1alpha1.KindSecRule, seclangv1alpha1.KindSecAction, seclangv1alpha1.KindInclude:
		if setOnly {
			return invalid("ruleSetRefs kind %s is not a RuleSet", ref.Kind)
		}
	default:
		return invalid("unknown kind %s", ref.Kind)
	}
	named := ref.Name != ""
	selected := ref.Selector != nil
	if named == selected {
		return invalid("ref sets exactly one of name or selector")
	}
	if ref.Kind == seclangv1alpha1.KindClusterRuleSet {
		if ref.Namespace != "" || selected {
			return invalid("ClusterRuleSet %s is named and has no namespace", ref.Name)
		}
	}
	if selected {
		if from.Kind == seclangv1alpha1.KindClusterRuleSet || from.Namespace == "" {
			return invalid("a selector needs the referrer's namespace")
		}
		if ref.Namespace != "" {
			return invalid("a selector cannot set namespace")
		}
		if ref.Kind == seclangv1alpha1.KindClusterRuleSet {
			return invalid("ClusterRuleSet cannot be selected")
		}
	}
	if from.Kind == seclangv1alpha1.KindClusterRuleSet && ref.Kind != seclangv1alpha1.KindClusterRuleSet {
		if selected || ref.Namespace == "" {
			return invalid("ClusterRuleSet refs to %s require namespace and a name", ref.Kind)
		}
	}
	return nil
}

func targetNamespace(from Referrer, ref seclangv1alpha1.ObjectRef) (string, error) {
	if ref.Kind == seclangv1alpha1.KindClusterRuleSet {
		return "", nil
	}
	if ref.Namespace != "" {
		return ref.Namespace, nil
	}
	if from.Namespace == "" {
		return "", invalid("ClusterRuleSet refs to %s require namespace", ref.Kind)
	}
	return from.Namespace, nil
}

func (r *Resolver) authorize(ctx context.Context, from Referrer, kind, namespace, name string) error {
	if kind == seclangv1alpha1.KindClusterRuleSet || namespace == from.Namespace {
		return nil
	}
	if from.Namespace == "" {
		return &Error{Reason: ReasonRefNotPermitted, Message: fmt.Sprintf(
			"ClusterRuleSet %s is not permitted to reference %s %s/%s: ReferenceGrant cannot name a cluster-scoped referrer",
			from.Name, kind, namespace, name)}
	}
	ok, err := r.grantsInstalled(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return &Error{Reason: ReasonReferenceGrantUnavailable, Message: fmt.Sprintf(
			"ReferenceGrant is not served, so %s %s/%s cannot reference %s %s/%s",
			from.Kind, from.Namespace, from.Name, kind, namespace, name)}
	}
	allowed, err := r.granted(ctx, from, kind, namespace, name)
	if err != nil {
		return err
	}
	if !allowed {
		return &Error{Reason: ReasonRefNotPermitted, Message: fmt.Sprintf(
			"%s %s/%s is not permitted to reference %s %s/%s",
			from.Kind, from.Namespace, from.Name, kind, namespace, name)}
	}
	return nil
}

func (r *Resolver) grantsInstalled(ctx context.Context) (bool, error) {
	if r.grants != nil {
		return *r.grants, nil
	}
	listErr := r.Client.List(ctx, &gatewayv1.ReferenceGrantList{}, client.Limit(1))
	installed := true
	if listErr != nil {
		if apimeta.IsNoMatchError(listErr) || apierrors.IsNotFound(listErr) {
			installed = false
		} else {
			return false, listErr
		}
	}
	r.grants = &installed
	return installed, nil
}

func (r *Resolver) granted(ctx context.Context, from Referrer, kind, namespace, name string) (bool, error) {
	var list gatewayv1.ReferenceGrantList
	if err := r.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		if apimeta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for i := range list.Items {
		grant := &list.Items[i]
		if grantMatches(grant, from, kind, name) {
			return true, nil
		}
	}
	return false, nil
}

func grantMatches(grant *gatewayv1.ReferenceGrant, from Referrer, kind, name string) bool {
	fromOK := false
	for _, src := range grant.Spec.From {
		if string(src.Group) == from.Group && string(src.Kind) == from.Kind && string(src.Namespace) == from.Namespace {
			fromOK = true
			break
		}
	}
	if !fromOK {
		return false
	}
	for _, dst := range grant.Spec.To {
		if string(dst.Group) != seclangv1alpha1.GroupName || string(dst.Kind) != kind {
			continue
		}
		if dst.Name != nil && string(*dst.Name) != name {
			continue
		}
		return true
	}
	return false
}

func (r *Resolver) listNames(ctx context.Context, kind, namespace string, selector labels.Selector) ([]string, error) {
	var names []string
	switch kind {
	case seclangv1alpha1.KindSecRule:
		var list seclangv1alpha1.SecRuleList
		if err := r.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
			return nil, err
		}
		for _, item := range list.Items {
			if selector.Matches(labels.Set(item.Labels)) {
				names = append(names, item.Name)
			}
		}
	case seclangv1alpha1.KindSecAction:
		var list seclangv1alpha1.SecActionList
		if err := r.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
			return nil, err
		}
		for _, item := range list.Items {
			if selector.Matches(labels.Set(item.Labels)) {
				names = append(names, item.Name)
			}
		}
	case seclangv1alpha1.KindInclude:
		var list seclangv1alpha1.IncludeList
		if err := r.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
			return nil, err
		}
		for _, item := range list.Items {
			if selector.Matches(labels.Set(item.Labels)) {
				names = append(names, item.Name)
			}
		}
	case seclangv1alpha1.KindRuleSet:
		var list seclangv1alpha1.RuleSetList
		if err := r.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
			return nil, err
		}
		for _, item := range list.Items {
			if selector.Matches(labels.Set(item.Labels)) {
				names = append(names, item.Name)
			}
		}
	default:
		return nil, invalid("kind %s cannot be selected", kind)
	}
	slices.Sort(names)
	return names, nil
}

func get(ctx context.Context, c client.Client, kind, namespace, name string, obj client.Object) error {
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, obj)
	if err == nil {
		return nil
	}
	if apierrors.IsNotFound(err) {
		where := name
		if namespace != "" {
			where = namespace + "/" + name
		}
		return &Error{Reason: ReasonNotFound, Message: fmt.Sprintf("%s %s not found", kind, where)}
	}
	return err
}

func ready(conds []metav1.Condition) bool {
	return apimeta.IsStatusConditionTrue(conds, "Ready")
}

func includeContent(ctx context.Context, c client.Client, namespace string, inc seclangv1alpha1.Include) (string, error) {
	if inc.Spec.ConfigMapRef == nil {
		return "", nil
	}
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: inc.Spec.ConfigMapRef.Name}, cm); err != nil {
		return "", fmt.Errorf("include %s/%s: %w", namespace, inc.Name, err)
	}
	content, ok := cm.Data[inc.Spec.ConfigMapRef.Key]
	if !ok {
		return "", fmt.Errorf("include %s/%s: key %s not found", namespace, inc.Name, inc.Spec.ConfigMapRef.Key)
	}
	return content, nil
}
