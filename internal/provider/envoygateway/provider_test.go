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

package envoygateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	"github.com/kubewaf-io/kubewaf/internal/provider"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestApplyWritesOnlyConfigMapAndExtensionPolicy(t *testing.T) {
	proxy := platformProxy(true, true)
	gw := platformGateway()
	beforeProxy := proxy.Spec.DeepCopy()
	beforeGW := gw.Spec.DeepCopy()
	c := fakeClient(t, proxy, gw)
	p := New("envoy-gateway-system")
	p.SetImmediate()
	ctx := context.Background()

	view, err := p.CheckEngine(ctx, c, []provider.GatewayRef{{Namespace: "default", Name: "eg"}}, "composer", "envoy-gateway-system")
	if err != nil || !view.Ready {
		t.Fatalf("engine %+v %v", view, err)
	}
	bundle := sampleBundle("default", "edge", "KUBEWAF0123456789abcdef", "SecRule ARGS \"@rx a\" \"id:1,phase:1,pass\"\n")
	if err := p.Apply(ctx, c, bundle, gatewayRef(), "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	assertPlatformUnchanged(t, c, beforeProxy, beforeGW)

	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, cm); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cm.Data["default_edge-before.conf"], "id:1") {
		t.Fatalf("keys %v", cm.Data)
	}
	ext := &egv1a1.EnvoyExtensionPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, ext); err != nil {
		t.Fatal(err)
	}
	if len(ext.Spec.DynamicModule) != 1 || ext.Spec.DynamicModule[0].Name != "composer" || ext.Spec.DynamicModule[0].FilterName == nil || *ext.Spec.DynamicModule[0].FilterName != "coraza-waf" {
		t.Fatalf("module %+v", ext.Spec.DynamicModule)
	}
	var cfg filterJSON
	if err := json.Unmarshal(ext.Spec.DynamicModule[0].Config.Raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "REQUEST_ONLY" || !cfg.RequestURIPathOnly || cfg.Metrics.AuthorityLabel != "route_name" {
		t.Fatalf("config %+v", cfg)
	}
	joined := strings.Join(cfg.Directives, "\n")
	if !strings.Contains(joined, "SecMarker KUBEWAF0123456789abcdef") || !strings.Contains(joined, "Include @coraza.conf") {
		t.Fatal(joined)
	}
	if ext.Spec.TargetRefs[0].Kind != "Gateway" {
		t.Fatal(ext.Spec.TargetRefs)
	}

	other := sampleBundle("default", "extra", "KUBEWAFaaaaaaaaaaaaaaaa", "SecAction \"id:2,phase:1,pass\"\n")
	if err := p.Apply(ctx, c, other, gatewayRef(), "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, cm); err != nil {
		t.Fatal(err)
	}
	if _, ok := cm.Data["default_edge-before.conf"]; !ok {
		t.Fatal("first policy keys were dropped")
	}
	if _, ok := cm.Data["default_extra-before.conf"]; !ok {
		t.Fatal("second policy keys missing")
	}
	assertPlatformUnchanged(t, c, beforeProxy, beforeGW)

	changed := sampleBundle("default", "edge", "KUBEWAFbbbbbbbbbbbbbbbb", "SecRule ARGS \"@rx b\" \"id:1,phase:1,pass\"\n")
	if err := p.Apply(ctx, c, changed, gatewayRef(), "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, ext); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ext.Spec.DynamicModule[0].Config.Raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(cfg.Directives, "\n"), "SecMarker KUBEWAFbbbbbbbbbbbbbbbb") {
		t.Fatal(cfg.Directives)
	}
	assertPlatformUnchanged(t, c, beforeProxy, beforeGW)
}

func TestRoutePolicyTargetsTheRoute(t *testing.T) {
	proxy := platformProxy(true, true)
	gw := platformGateway()
	beforeProxy := proxy.Spec.DeepCopy()
	beforeGW := gw.Spec.DeepCopy()
	c := fakeClient(t, proxy, gw)
	p := New("envoy-gateway-system")
	p.SetImmediate()
	ctx := context.Background()
	if err := p.Apply(ctx, c, sampleBundle("default", "edge", "KUBEWAF0123456789abcdef", "x\n"), gatewayRef(), "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	route := []gatewayv1.LocalPolicyTargetReference{{
		Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "backend",
	}}
	if err := p.Apply(ctx, c, sampleBundle("default", "route", "KUBEWAFcccccccccccccccc", "y\n"), route, "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	edge := &egv1a1.EnvoyExtensionPolicy{}
	got := &egv1a1.EnvoyExtensionPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, edge); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-route"}, got); err != nil {
		t.Fatal(err)
	}
	if edge.Spec.TargetRefs[0].Kind != "Gateway" || got.Spec.TargetRefs[0].Kind != "HTTPRoute" || got.Spec.TargetRefs[0].Name != "backend" {
		t.Fatalf("edge %s route %s", edge.Spec.TargetRefs[0].Kind, got.Spec.TargetRefs[0].Kind)
	}
	assertPlatformUnchanged(t, c, beforeProxy, beforeGW)
}

func TestEngineNotReady(t *testing.T) {
	ctx := context.Background()
	p := New("envoy-gateway-system")
	p.SetImmediate()
	missing := platformProxy(false, true)
	c := fakeClient(t, missing, platformGateway())
	view, err := p.CheckEngine(ctx, c, []provider.GatewayRef{{Namespace: "default", Name: "eg"}}, "composer", "envoy-gateway-system")
	if err != nil || view.Ready || view.Reason != provider.ReasonModuleMissing {
		t.Fatalf("%+v %v", view, err)
	}
	unmounted := platformProxy(true, false)
	c = fakeClient(t, unmounted, platformGateway())
	view, err = p.CheckEngine(ctx, c, []provider.GatewayRef{{Namespace: "default", Name: "eg"}}, "composer", "envoy-gateway-system")
	if err != nil || view.Ready || view.Reason != provider.ReasonMountMissing {
		t.Fatalf("%+v %v", view, err)
	}
	bare := platformGateway()
	bare.Spec.Infrastructure = nil
	c = fakeClient(t, platformProxy(true, true), bare)
	view, err = p.CheckEngine(ctx, c, []provider.GatewayRef{{Namespace: "default", Name: "eg"}}, "composer", "envoy-gateway-system")
	if err != nil || view.Ready || view.Reason != provider.ReasonModuleMissing {
		t.Fatalf("class fallback %+v %v", view, err)
	}
}

func TestGatewayClassParametersRef(t *testing.T) {
	gw := platformGateway()
	gw.Spec.Infrastructure = nil
	gw.Spec.GatewayClassName = "eg"
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "eg"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "gateway.envoyproxy.io/gatewayclass-controller",
			ParametersRef: &gatewayv1.ParametersReference{
				Group:     "gateway.envoyproxy.io",
				Kind:      "EnvoyProxy",
				Name:      "platform",
				Namespace: ptrNS("default"),
			},
		},
	}
	c := fakeClient(t, platformProxy(true, true), gw, gc)
	view, err := New("envoy-gateway-system").CheckEngine(context.Background(), c, []provider.GatewayRef{{Namespace: "default", Name: "eg"}}, "composer", "envoy-gateway-system")
	if err != nil || !view.Ready || view.EnvoyProxyName != "platform" {
		t.Fatalf("%+v %v", view, err)
	}
}

func TestDeleteRemovesKeysAndPolicyOnly(t *testing.T) {
	proxy := platformProxy(true, true)
	gw := platformGateway()
	beforeProxy := proxy.Spec.DeepCopy()
	c := fakeClient(t, proxy, gw)
	p := New("envoy-gateway-system")
	p.SetImmediate()
	ctx := context.Background()
	if err := p.Apply(ctx, c, sampleBundle("default", "edge", "KUBEWAF0123456789abcdef", "x\n"), gatewayRef(), "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, c, sampleBundle("default", "extra", "KUBEWAFaaaaaaaaaaaaaaaa", "y\n"), gatewayRef(), "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, c, "default", "edge", "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, &egv1a1.EnvoyExtensionPolicy{}); err == nil {
		t.Fatal("extension policy still exists")
	}
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, cm); err != nil {
		t.Fatal(err)
	}
	if _, ok := cm.Data["default_edge-before.conf"]; ok {
		t.Fatal("deleted policy key remains")
	}
	if _, ok := cm.Data["default_extra-before.conf"]; !ok {
		t.Fatal("other policy key was removed")
	}
	assertPlatformUnchanged(t, c, beforeProxy, gw.Spec.DeepCopy())
	if err := p.Delete(ctx, c, "default", "extra", "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, cm); err == nil {
		t.Fatal("empty configmap should be deleted")
	}
}

func TestDataFileConflictAndSize(t *testing.T) {
	c := fakeClient(t)
	p := New("envoy-gateway-system")
	p.SetImmediate()
	ctx := context.Background()
	first := sampleBundle("default", "edge", "KUBEWAF0123456789abcdef", "x\n")
	if err := p.Apply(ctx, c, first, gatewayRef(), "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	clash := sampleBundle("other", "policy", "KUBEWAFaaaaaaaaaaaaaaaa", "y\n")
	clash.Files = map[string]string{"default_edge-before.conf": "nope\n"}
	if err := p.Apply(ctx, c, clash, gatewayRef(), "envoy-gateway-system"); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("conflict: %v", err)
	}
	huge := sampleBundle("default", "big", "KUBEWAFbbbbbbbbbbbbbbbb", "")
	huge.Files = map[string]string{"default_big-before.conf": strings.Repeat("a", 900*1024)}
	if err := p.Apply(ctx, c, huge, gatewayRef(), "envoy-gateway-system"); err == nil {
		t.Fatal("expected size error")
	}
}

func TestApplyWaitsUntilTheVolumeCanRefresh(t *testing.T) {
	c := fakeClient(t)
	p := New("envoy-gateway-system")
	start := time.Date(2026, 11, 17, 16, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return start }
	ctx := context.Background()
	b := sampleBundle("default", "edge", "KUBEWAF0123456789abcdef", "x\n")
	if err := p.Apply(ctx, c, b, gatewayRef(), "envoy-gateway-system"); !errors.Is(err, provider.ErrMountSettling) {
		t.Fatalf("first apply: %v", err)
	}
	ext := &egv1a1.EnvoyExtensionPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, ext); err == nil {
		t.Fatal("extension policy was written before the volume could refresh")
	}
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "envoy-gateway-system", Name: compile.ConfigMapName}, cm); err != nil {
		t.Fatal(err)
	}
	if cm.Data["default_edge-before.conf"] != "x\n" {
		t.Fatalf("configmap keys missing: %#v", cm.Data)
	}
	p.now = func() time.Time { return start.Add(firstMountSettle) }
	if err := p.Apply(ctx, c, b, gatewayRef(), "envoy-gateway-system"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubewaf-edge"}, ext); err != nil {
		t.Fatal(err)
	}
}

func sampleBundle(ns, name, marker, before string) compile.Bundle {
	return compile.Bundle{
		Namespace: ns, Name: name, Hash: strings.TrimPrefix(marker, "KUBEWAF"), Marker: marker,
		Engine: "On", RequestBodyAccess: true, Inspection: "REQUEST_ONLY", ModuleName: "composer",
		Before: before,
		Files: map[string]string{
			ns + "_" + name + "-before.conf": before,
			ns + "_" + name + "-after.conf":  "",
		},
	}
}

func gatewayRef() []gatewayv1.LocalPolicyTargetReference {
	return []gatewayv1.LocalPolicyTargetReference{{
		Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "eg",
	}}
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

func platformProxy(withModule, withMount bool) *egv1a1.EnvoyProxy {
	proxy := &egv1a1.EnvoyProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "platform", Namespace: "default"},
		Spec: egv1a1.EnvoyProxySpec{
			Provider: &egv1a1.EnvoyProxyProvider{
				Type:       egv1a1.EnvoyProxyProviderTypeKubernetes,
				Kubernetes: &egv1a1.EnvoyProxyKubernetesProvider{},
			},
		},
	}
	if withModule {
		proxy.Spec.DynamicModules = []egv1a1.DynamicModuleEntry{{
			Name: "composer",
			Source: egv1a1.DynamicModuleSource{
				Local: &egv1a1.LocalDynamicModuleSource{Path: "/etc/envoy/dynamic-modules/libcomposer.so"},
			},
		}}
	}
	if withMount {
		optional := true
		proxy.Spec.Provider.Kubernetes.EnvoyDeployment = &egv1a1.KubernetesDeploymentSpec{
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
		}
	}
	return proxy
}

func fakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(s); err != nil {
		t.Fatal(err)
	}
	if err := egv1a1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&egv1a1.EnvoyExtensionPolicy{}).WithObjects(objs...).Build()
}

func assertPlatformUnchanged(t *testing.T, c client.Client, proxy *egv1a1.EnvoyProxySpec, gw *gatewayv1.GatewaySpec) {
	t.Helper()
	gotP := &egv1a1.EnvoyProxy{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "platform"}, gotP); err != nil {
		t.Fatal(err)
	}
	gotG := &gatewayv1.Gateway{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "eg"}, gotG); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(mustJSON(gotP.Spec)) != strings.TrimSpace(mustJSON(proxy)) {
		t.Fatalf("EnvoyProxy spec changed")
	}
	if strings.TrimSpace(mustJSON(gotG.Spec)) != strings.TrimSpace(mustJSON(gw)) {
		t.Fatalf("Gateway spec changed")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func ptrNS(ns string) *gatewayv1.Namespace {
	n := gatewayv1.Namespace(ns)
	return &n
}
