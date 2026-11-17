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
	"testing"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	wafv1alpha1 "github.com/kubewaf-io/kubewaf/api/waf/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestProtectionCompilesCRSAndRateLimit(t *testing.T) {
	c := testClient(t, readyRule(), platformProxy(), platformGateway())
	ctx := context.Background()
	obj := protection("edge")
	if err := c.Create(ctx, obj); err != nil {
		t.Fatal(err)
	}
	r := newProtectionReconciler(c)
	if _, err := r.Reconcile(ctx, req("default", "edge")); err != nil {
		t.Fatal(err)
	}
	ext := &egv1a1.EnvoyExtensionPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-p-edge"}, ext); err != nil {
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
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, cm); err != nil {
		t.Fatal(err)
	}
	before := cm.Data[compile.BeforeKey("default", "p-edge")]
	if before == "" || cm.Data[compile.VersionKey] == "" {
		t.Fatalf("configmap %#v", cm.Data)
	}
	limit := &egv1a1.BackendTrafficPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-ratelimit-edge-login"}, limit); err != nil {
		t.Fatal(err)
	}
	if limit.Spec.RateLimit == nil || limit.Spec.RateLimit.Local == nil || limit.Spec.RateLimit.Local.Rules[0].Limit.Requests != 10 {
		t.Fatalf("rate limit %+v", limit.Spec.RateLimit)
	}
	got := &wafv1alpha1.Protection{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "edge"}, got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionProgrammed)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("programmed %+v", got.Status.Conditions)
	}
}

func TestProtectionConflictsWithSecPolicy(t *testing.T) {
	c := testClient(t, readyRule(), platformProxy(), platformGateway(), policy("edge", "block-sqlmap"))
	ctx := context.Background()
	if err := c.Create(ctx, protection("app")); err != nil {
		t.Fatal(err)
	}
	r := newProtectionReconciler(c)
	if _, err := r.Reconcile(ctx, req("default", "app")); err != nil {
		t.Fatal(err)
	}
	got := &wafv1alpha1.Protection{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "app"}, got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionAccepted)
	if cond == nil || cond.Reason != reasonDualAttachment {
		t.Fatalf("accepted %+v", cond)
	}
	ext := &egv1a1.EnvoyExtensionPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-p-app"}, ext); err == nil {
		t.Fatal("extension policy was written for a conflicting protection")
	}
}

func newProtectionReconciler(c client.Client) *ProtectionReconciler {
	return &ProtectionReconciler{Client: c, Registry: newPolicyReconciler(c).Registry, ProxyNamespace: "envoy-gateway-system"}
}

func protection(name string) *wafv1alpha1.Protection {
	return &wafv1alpha1.Protection{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: wafv1alpha1.ProtectionSpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReference{{
				Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "eg",
			}},
			Mode: "Blocking",
			CRS:  &wafv1alpha1.CRSSpec{Paranoia: 1},
			CustomRules: []seclangv1alpha1.RuleSelector{{
				Kind: "SecRule", Name: "block-sqlmap",
			}},
			RateLimit: []wafv1alpha1.RateLimit{{
				Name: "login",
				TargetRef: gatewayv1.LocalPolicyTargetReference{
					Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "login",
				},
				Requests: 10,
				Unit:     "Second",
			}},
		},
	}
}
