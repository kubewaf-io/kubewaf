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
	"encoding/json"
	"testing"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	wafv1alpha1 "github.com/kubewaf-io/kubewaf/api/waf/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	"github.com/kubewaf-io/kubewaf/internal/provider"
	"github.com/kubewaf-io/kubewaf/internal/provider/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestSecRuleSetsSecLang(t *testing.T) {
	rule := readyRule()
	rule.Status = seclangv1alpha1.SecLangStatus{}
	c := testClient(t, rule)
	r := &SecRuleReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), req("default", "block-sqlmap")); err != nil {
		t.Fatal(err)
	}
	got := &seclangv1alpha1.SecRule{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "block-sqlmap"}, got); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, conditionReady) || got.Status.SecLang == "" {
		t.Fatalf("status %+v", got.Status)
	}
	got.Spec.Chain[0].Operator.Value = "("
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req("default", "block-sqlmap")); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "block-sqlmap"}, got); err != nil {
		t.Fatal(err)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, conditionReady) || got.Status.SecLang != "" {
		t.Fatalf("invalid rule kept status %+v", got.Status)
	}
}

func TestSecPolicyProgramsAndLeavesTheProxyAlone(t *testing.T) {
	rule := readyRule()
	proxy := platformProxy()
	gw := platformGateway()
	before, _ := json.Marshal(proxy.Spec)
	c := testClient(t, rule, proxy, gw)
	ctx := context.Background()
	pol := policy("edge", "block-sqlmap")
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	r := newPolicyReconciler(c)
	if _, err := r.Reconcile(ctx, req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	got := &seclangv1alpha1.SecPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "edge"}, got); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, conditionRulesResolved) || !meta.IsStatusConditionTrue(got.Status.Conditions, conditionEngineReady) {
		t.Fatalf("conditions %+v", got.Status.Conditions)
	}
	if !meta.IsStatusConditionFalse(got.Status.Conditions, conditionProgrammed) {
		t.Fatal("expected pending until Envoy Gateway accepts")
	}
	ext := &egv1a1.EnvoyExtensionPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, ext); err != nil {
		t.Fatal(err)
	}
	ext.Status.Ancestors = []gatewayv1.PolicyAncestorStatus{{
		ControllerName: "gateway.envoyproxy.io/gatewayclass-controller",
		Conditions:     []metav1.Condition{{Type: string(gatewayv1.PolicyConditionAccepted), Status: metav1.ConditionTrue, Reason: "Accepted"}},
	}}
	if err := c.Status().Update(ctx, ext); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "edge"}, got); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, conditionProgrammed) || got.Status.SecLangHash == "" || got.Status.EnvoyProxyName != "platform" {
		t.Fatalf("programmed %+v", got.Status)
	}
	gotProxy := &egv1a1.EnvoyProxy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "platform"}, gotProxy); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(gotProxy.Spec)
	if string(before) != string(after) {
		t.Fatal("EnvoyProxy spec changed")
	}

	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "platform"}, gotProxy); err != nil {
		t.Fatal(err)
	}
	gotProxy.Spec.DynamicModules = nil
	if err := c.Update(ctx, gotProxy); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "edge"}, got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionEngineReady)
	if cond == nil || cond.Reason != provider.ReasonModuleMissing {
		t.Fatalf("engine %+v", cond)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, ext); err == nil {
		t.Fatal("extension policy should be retracted")
	}
}

func TestSecPolicyWaitsForProjectionBeforePublishing(t *testing.T) {
	c := testClient(t, readyRule(), platformProxy(), platformGateway())
	ctx := context.Background()
	if err := c.Create(ctx, policy("edge", "block-sqlmap")); err != nil {
		t.Fatal(err)
	}
	r := newPolicyReconciler(c)
	r.WaitForProjection = true
	if _, err := r.Reconcile(ctx, req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	ext := &egv1a1.EnvoyExtensionPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, ext); err == nil {
		t.Fatal("filter was published before the version file was projected")
	}
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, cm); err != nil {
		t.Fatal(err)
	}
	if cm.Data[compile.VersionKey] == "" {
		t.Fatal("version key was not staged")
	}
	got := &seclangv1alpha1.SecPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "edge"}, got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionProgrammed)
	if cond == nil || cond.Reason != provider.ReasonEnvoyNotReady {
		t.Fatalf("programmed %+v", cond)
	}
}

func TestDualAttachmentAndRouteOverride(t *testing.T) {
	rule := readyRule()
	proxy := platformProxy()
	gw := platformGateway()
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{
			Name: "eg",
		}}}},
	}
	c := testClient(t, rule, proxy, gw, route)
	ctx := context.Background()
	edge := policy("edge", "block-sqlmap")
	routePol := policy("route", "block-sqlmap")
	routePol.Spec.TargetRefs = []gatewayv1.LocalPolicyTargetReference{{
		Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "backend",
	}}
	if err := c.Create(ctx, edge); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, routePol); err != nil {
		t.Fatal(err)
	}
	r := newPolicyReconciler(c)
	if _, err := r.Reconcile(ctx, req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req("default", "route")); err != nil {
		t.Fatal(err)
	}
	gotRoute := &seclangv1alpha1.SecPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "route"}, gotRoute); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(gotRoute.Status.Conditions, conditionEngineReady) {
		t.Fatalf("route policy should program against the parent gateway: %+v", gotRoute.Status.Conditions)
	}
	ext := &egv1a1.EnvoyExtensionPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-route"}, ext); err != nil {
		t.Fatal(err)
	}
	if ext.Spec.TargetRefs[0].Kind != "HTTPRoute" {
		t.Fatalf("route extension targets %s", ext.Spec.TargetRefs[0].Kind)
	}

	second := policy("other", "block-sqlmap")
	if err := c.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req("default", "other")); err != nil {
		t.Fatal(err)
	}
	got := &seclangv1alpha1.SecPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "other"}, got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionAccepted)
	if cond == nil || cond.Reason != reasonDualAttachment {
		t.Fatalf("second policy %+v", got.Status.Conditions)
	}

	prot := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "waf.kubewaf.io/v1alpha1",
		"kind":       "Protection",
		"metadata":   map[string]any{"name": "prot", "namespace": "ns2"},
		"spec": map[string]any{"targetRefs": []any{map[string]any{
			"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "eg",
		}}},
	}}
	prot.SetAPIVersion("waf.kubewaf.io/v1alpha1")
	prot.SetKind("Protection")
	alone := policy("solo", "block-sqlmap")
	alone.Namespace = "ns2"
	rule2 := rule.DeepCopy()
	rule2.Namespace = "ns2"
	gw2 := gw.DeepCopy()
	gw2.Namespace = "ns2"
	proxy2 := proxy.DeepCopy()
	proxy2.Namespace = "ns2"
	c2 := testClient(t, rule2, proxy2, gw2, prot, alone)
	r2 := newPolicyReconciler(c2)
	if _, err := r2.Reconcile(ctx, req("ns2", "solo")); err != nil {
		t.Fatal(err)
	}
	got = &seclangv1alpha1.SecPolicy{}
	if err := c2.Get(ctx, types.NamespacedName{Namespace: "ns2", Name: "solo"}, got); err != nil {
		t.Fatal(err)
	}
	cond = meta.FindStatusCondition(got.Status.Conditions, conditionAccepted)
	if cond == nil || cond.Reason != reasonDualAttachment || cond.Status != metav1.ConditionFalse {
		t.Fatalf("protection %+v", got.Status.Conditions)
	}
}

func TestMissingRuleLeavesConfigMapAlone(t *testing.T) {
	c := testClient(t, platformProxy(), platformGateway(), policy("edge", "missing"))
	r := newPolicyReconciler(c)
	if _, err := r.Reconcile(context.Background(), req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	got := &seclangv1alpha1.SecPolicy{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "edge"}, got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionRulesResolved)
	if cond == nil || cond.Reason != reasonNotFound {
		t.Fatalf("%+v", cond)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, &corev1.ConfigMap{}); err == nil {
		t.Fatal("configmap was written for an unresolved policy")
	}
}

func TestFinalizerDeletesExtensionPolicy(t *testing.T) {
	rule := readyRule()
	c := testClient(t, rule, platformProxy(), platformGateway())
	ctx := context.Background()
	if err := c.Create(ctx, policy("edge", "block-sqlmap")); err != nil {
		t.Fatal(err)
	}
	r := newPolicyReconciler(c)
	if _, err := r.Reconcile(ctx, req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	got := &seclangv1alpha1.SecPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "edge"}, got); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, &egv1a1.EnvoyExtensionPolicy{}); err == nil {
		t.Fatal("extension policy remains after finalizer")
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, &corev1.ConfigMap{}); err == nil {
		t.Fatal("configmap remains after the only policy is deleted")
	}
}

func TestNameAndLabelIndex(t *testing.T) {
	named := policy("by-name", "block-sqlmap")
	selected := policy("by-label", "unused")
	selected.Spec.Rules = []seclangv1alpha1.RuleSelector{{
		Kind: "SecRule", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "edge"}},
	}}
	s := runtime.NewScheme()
	if err := seclangv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(named, selected).
		WithIndex(&seclangv1alpha1.SecPolicy{}, ruleIndexKey, indexRuleNames).Build()
	r := &SecPolicyReconciler{Client: c}
	rule := readyRule()
	rule.Labels = map[string]string{"app": "edge"}
	got := r.requestsFor("SecRule")(context.Background(), rule)
	if len(got) != 2 {
		t.Fatalf("requests %+v", got)
	}
}

func newPolicyReconciler(c client.Client) *SecPolicyReconciler {
	return &SecPolicyReconciler{Client: c, Registry: registry.New("envoy-gateway-system"), ProxyNamespace: "envoy-gateway-system"}
}

func req(ns, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}
}

func readyRule() *seclangv1alpha1.SecRule {
	rule := &seclangv1alpha1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "block-sqlmap", Namespace: "default"},
		Spec: seclangv1alpha1.SecRuleSpec{
			Metadata: seclangv1alpha1.Metadata{ID: 100001, Phase: 1},
			Chain: []seclangv1alpha1.ChainLink{{
				Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_URI}},
				Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: "sqlmap"},
				Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny}},
			}},
		},
	}
	rule.Status.SecLang = "compiled"
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{Type: conditionReady, Status: metav1.ConditionTrue, Reason: reasonCompiled})
	return rule
}

func policy(name, rule string) *seclangv1alpha1.SecPolicy {
	return &seclangv1alpha1.SecPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: seclangv1alpha1.SecPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReference{{
				Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "eg",
			}},
			Rules: []seclangv1alpha1.RuleSelector{{Kind: "SecRule", Name: rule}},
		},
	}
}

func platformGateway() *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "eg", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "eg",
			Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{
				Group: "gateway.envoyproxy.io", Kind: "EnvoyProxy", Name: "platform",
			}},
		},
	}
}

func platformProxy() *egv1a1.EnvoyProxy {
	optional := true
	return &egv1a1.EnvoyProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "platform", Namespace: "default"},
		Spec: egv1a1.EnvoyProxySpec{
			Provider: &egv1a1.EnvoyProxyProvider{
				Type: egv1a1.EnvoyProxyProviderTypeKubernetes,
				Kubernetes: &egv1a1.EnvoyProxyKubernetesProvider{EnvoyDeployment: &egv1a1.KubernetesDeploymentSpec{
					Pod: &egv1a1.KubernetesPodSpec{Volumes: []corev1.Volume{{
						Name: "kubewaf-seclang",
						VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: compile.ConfigMapName},
							Optional:             &optional,
						}},
					}}},
					Container: &egv1a1.KubernetesContainerSpec{VolumeMounts: []corev1.VolumeMount{{
						Name: "kubewaf-seclang", MountPath: compile.MountDir, ReadOnly: true,
					}}},
				}},
			},
			DynamicModules: []egv1a1.DynamicModuleEntry{{
				Name:   "composer",
				Source: egv1a1.DynamicModuleSource{Local: &egv1a1.LocalDynamicModuleSource{Path: "/etc/envoy/dynamic-modules/libcomposer.so"}},
			}},
		},
	}
}

func testClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := seclangv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(s); err != nil {
		t.Fatal(err)
	}
	if err := egv1a1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := wafv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(&seclangv1alpha1.SecRule{}, &seclangv1alpha1.SecAction{}, &seclangv1alpha1.Include{}, &seclangv1alpha1.SecPolicy{}, &wafv1alpha1.Protection{}, &egv1a1.EnvoyExtensionPolicy{}, &egv1a1.BackendTrafficPolicy{}).
		WithObjects(objs...).
		Build()
}
