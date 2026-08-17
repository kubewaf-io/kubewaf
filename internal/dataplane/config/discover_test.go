/*
Copyright 2025 Buzz-IT GmbH.
*/
package config

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

func TestNeedsProviderDiscovery(t *testing.T) {
	if !NeedsProviderDiscovery(nil) {
		t.Fatal("nil waf")
	}
	if !NeedsProviderDiscovery(&wafv1beta1.WAF{}) {
		t.Fatal("empty provider")
	}
	if !NeedsProviderDiscovery(&wafv1beta1.WAF{Spec: wafv1beta1.WAFSpec{
		Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderAuto},
	}}) {
		t.Fatal("Auto")
	}
	if NeedsProviderDiscovery(&wafv1beta1.WAF{Spec: wafv1beta1.WAFSpec{
		Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderCilium},
	}}) {
		t.Fatal("explicit Cilium should not need discovery")
	}
}

func TestProviderFromControllerName(t *testing.T) {
	cases := []struct {
		in   string
		want wafv1beta1.ProviderType
		ok   bool
	}{
		{"gateway.envoyproxy.io/gatewayclass-controller", wafv1beta1.ProviderEnvoyGateway, true},
		{"istio.io/gateway-controller", wafv1beta1.ProviderIstio, true},
		{"io.cilium/gateway-controller", wafv1beta1.ProviderCilium, true},
		{"example.com/unknown", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := ProviderFromControllerName(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%q: got %q %v want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDiscoverProvider_FromTargetRef_AllImplementations(t *testing.T) {
	cases := []struct {
		name       string
		className  string
		controller gwapiv1.GatewayController
		want       wafv1beta1.ProviderType
		wantCtrl   string
		withRoute  bool // HTTPRoute backend for Cilium service fill
	}{
		{
			name:       "cilium",
			className:  "cilium",
			controller: "io.cilium/gateway-controller",
			want:       wafv1beta1.ProviderCilium,
			wantCtrl:   "io.cilium/gateway-controller",
			withRoute:  true,
		},
		{
			name:       "envoy-gateway",
			className:  "eg",
			controller: "gateway.envoyproxy.io/gatewayclass-controller",
			want:       wafv1beta1.ProviderEnvoyGateway,
			wantCtrl:   "gateway.envoyproxy.io/gatewayclass-controller",
		},
		{
			name:       "istio",
			className:  "istio",
			controller: "istio.io/gateway-controller",
			want:       wafv1beta1.ProviderIstio,
			wantCtrl:   "istio.io/gateway-controller",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = gwapiv1.Install(scheme)
			_ = wafv1beta1.AddToScheme(scheme)

			gc := &gwapiv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: tc.className},
				Spec: gwapiv1.GatewayClassSpec{
					ControllerName: tc.controller,
				},
			}
			gw := &gwapiv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "demo-gateway", Namespace: "demo"},
				Spec: gwapiv1.GatewaySpec{
					GatewayClassName: gwapiv1.ObjectName(tc.className),
				},
			}
			objs := []client.Object{gc, gw}
			if tc.withRoute {
				objs = append(objs, &gwapiv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{Name: "httpbin", Namespace: "demo"},
					Spec: gwapiv1.HTTPRouteSpec{
						CommonRouteSpec: gwapiv1.CommonRouteSpec{
							ParentRefs: []gwapiv1.ParentReference{{Name: "demo-gateway"}},
						},
						Rules: []gwapiv1.HTTPRouteRule{{
							BackendRefs: []gwapiv1.HTTPBackendRef{{
								BackendRef: gwapiv1.BackendRef{
									BackendObjectReference: gwapiv1.BackendObjectReference{
										Name: "httpbin",
									},
								},
							}},
						}},
					},
				})
			}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

			waf := &wafv1beta1.WAF{
				ObjectMeta: metav1.ObjectMeta{Name: "w", Namespace: "demo"},
				Spec: wafv1beta1.WAFSpec{
					// No provider block — Auto discovery only via targetRef.
					PolicyTargetReferences: egv1a1.PolicyTargetReferences{
						TargetRef: &gwapiv1.LocalPolicyTargetReferenceWithSectionName{
							LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
								Group: "gateway.networking.k8s.io",
								Kind:  "Gateway",
								Name:  "demo-gateway",
							},
						},
					},
				},
			}

			res, err := DiscoverProvider(context.Background(), cl, waf)
			if err != nil {
				t.Fatal(err)
			}
			if res.Provider != tc.want {
				t.Fatalf("provider=%s reason=%s want=%s", res.Provider, res.Reason, tc.want)
			}
			if !strings.Contains(res.Reason, "targetRef Gateway demo/demo-gateway") {
				t.Fatalf("reason should mention targetRef: %q", res.Reason)
			}
			if !strings.Contains(res.Reason, tc.wantCtrl) {
				t.Fatalf("reason should mention controller %q: %q", tc.wantCtrl, res.Reason)
			}
			if !strings.Contains(res.Reason, tc.className) {
				t.Fatalf("reason should mention GatewayClass %q: %q", tc.className, res.Reason)
			}
			if tc.withRoute {
				if res.CiliumServiceName != "httpbin" || res.CiliumServiceNamespace != "demo" {
					t.Fatalf("cilium service=%s/%s", res.CiliumServiceNamespace, res.CiliumServiceName)
				}
			}
		})
	}
}

func TestResolveProvider_UsesDetected(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w", Namespace: "ns"},
		Spec:       wafv1beta1.WAFSpec{}, // no provider
	}
	opts := BuildOptions{
		DetectedProvider:               wafv1beta1.ProviderCilium,
		DetectedCiliumServiceName:      "app",
		DetectedCiliumServiceNamespace: "ns",
	}
	p, _, _, _, _, _, svc, svcNS := resolveProvider(waf, opts)
	if p != wafv1beta1.ProviderCilium {
		t.Fatalf("provider=%s", p)
	}
	if svc != "app" || svcNS != "ns" {
		t.Fatalf("svc=%s/%s", svcNS, svc)
	}

	// Explicit type wins over detection.
	waf.Spec.Provider = &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderIstio}
	p, _, _, _, _, _, _, _ = resolveProvider(waf, opts)
	if p != wafv1beta1.ProviderIstio {
		t.Fatalf("explicit should win: %s", p)
	}
}

func TestResolveProvider_ExplicitCiliumServiceWins(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w", Namespace: "ns"},
		Spec: wafv1beta1.WAFSpec{
			Provider: &wafv1beta1.WAFProvider{
				Type: wafv1beta1.ProviderCilium,
				Cilium: &wafv1beta1.CiliumProvider{
					ServiceName:      "explicit",
					ServiceNamespace: "other",
				},
			},
		},
	}
	opts := BuildOptions{
		DetectedProvider:          wafv1beta1.ProviderCilium,
		DetectedCiliumServiceName: "detected",
	}
	_, _, _, _, _, _, svc, svcNS := resolveProvider(waf, opts)
	if svc != "explicit" || svcNS != "other" {
		t.Fatalf("got %s/%s", svcNS, svc)
	}
}
