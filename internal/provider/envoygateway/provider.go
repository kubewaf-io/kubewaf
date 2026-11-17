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

// Package envoygateway writes the kubewaf-seclang ConfigMap and one
// EnvoyExtensionPolicy. It reads EnvoyProxy and Gateway. It never writes them.
package envoygateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	"github.com/kubewaf-io/kubewaf/internal/provider"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	defaultProxyNamespace = "envoy-gateway-system"
	filterName            = "coraza-waf"
	managedByLabel        = "app.kubernetes.io/managed-by"
	managedByValue        = "kubewaf"
	policyLabel           = "seclang.kubewaf.io/policy"
	ownersAnnotation      = "seclang.kubewaf.io/key-owners"
	maxConfigMapBytes     = 900 * 1024
)

// Envoy is the Envoy Gateway provider.
type Envoy struct {
	proxyNamespace string
}

// New returns the provider. An empty proxy namespace uses envoy-gateway-system.
func New(proxyNamespace string) *Envoy {
	if proxyNamespace == "" {
		proxyNamespace = defaultProxyNamespace
	}
	return &Envoy{proxyNamespace: proxyNamespace}
}

// Name is the registry key.
func (e *Envoy) Name() string { return provider.NameEnvoyGateway }

// WatchObjects are the Envoy kinds the policy controller should watch.
func (e *Envoy) WatchObjects() []client.Object {
	return []client.Object{&egv1a1.EnvoyProxy{}, &egv1a1.EnvoyExtensionPolicy{}}
}

// ExtensionName is the EnvoyExtensionPolicy name for a SecPolicy.
func ExtensionName(policyName string) string { return "kubewaf-" + policyName }

// CheckEngine reads parametersRef and the EnvoyProxy. It does not write.
func (e *Envoy) CheckEngine(ctx context.Context, c client.Client, refs []provider.GatewayRef, moduleName, proxyNamespace string) (provider.EngineView, error) {
	if moduleName == "" {
		moduleName = "composer"
	}
	if len(refs) == 0 {
		return provider.EngineView{Ready: false, Reason: provider.ReasonModuleMissing, Message: "policy has no Gateway to check"}, nil
	}
	var last provider.EngineView
	for _, ref := range refs {
		view, err := e.checkOne(ctx, c, ref, moduleName, proxyNamespace)
		if err != nil {
			return view, err
		}
		if !view.Ready {
			return view, nil
		}
		last = view
	}
	return last, nil
}

func (e *Envoy) checkOne(ctx context.Context, c client.Client, ref provider.GatewayRef, moduleName, proxyNamespace string) (provider.EngineView, error) {
	view := provider.EngineView{GatewayName: ref.Name}
	gw := &gatewayv1.Gateway{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, gw); err != nil {
		if apierrors.IsNotFound(err) {
			view.Reason = provider.ReasonModuleMissing
			view.Message = fmt.Sprintf("Gateway %s/%s not found", ref.Namespace, ref.Name)
			return view, nil
		}
		return view, err
	}
	ns, name, ok := parametersRef(gw)
	if !ok {
		gc := &gatewayv1.GatewayClass{}
		if err := c.Get(ctx, types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}, gc); err != nil {
			if apierrors.IsNotFound(err) {
				view.Reason = provider.ReasonModuleMissing
				view.Message = "Gateway has no parametersRef and its GatewayClass was not found"
				return view, nil
			}
			return view, err
		}
		ns, name, ok = classParametersRef(gc, ref.Namespace)
		if !ok {
			view.Reason = provider.ReasonModuleMissing
			view.Message = "Gateway and GatewayClass have no EnvoyProxy parametersRef"
			return view, nil
		}
	}
	view.EnvoyProxyNamespace = ns
	view.EnvoyProxyName = name
	proxy := &egv1a1.EnvoyProxy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, proxy); err != nil {
		if apierrors.IsNotFound(err) {
			view.Reason = provider.ReasonModuleMissing
			view.Message = fmt.Sprintf("EnvoyProxy %s/%s not found", ns, name)
			return view, nil
		}
		return view, err
	}
	if !moduleRegistered(proxy, moduleName) {
		view.Reason = provider.ReasonModuleMissing
		view.Message = fmt.Sprintf("EnvoyProxy %s/%s has no dynamic module %q", ns, name, moduleName)
		return view, nil
	}
	if !mountPresent(proxy) {
		view.Reason = provider.ReasonMountMissing
		view.Message = fmt.Sprintf("EnvoyProxy %s/%s does not mount ConfigMap %s at %s", ns, name, compile.ConfigMapName, compile.MountDir)
		return view, nil
	}
	view.Ready = true
	view.Reason = "Ready"
	view.Message = "platform module is registered and the SecLang ConfigMap is mounted"
	_ = proxyNamespace
	return view, nil
}

func parametersRef(gw *gatewayv1.Gateway) (namespace, name string, ok bool) {
	if gw.Spec.Infrastructure == nil || gw.Spec.Infrastructure.ParametersRef == nil {
		return "", "", false
	}
	ref := gw.Spec.Infrastructure.ParametersRef
	if string(ref.Group) != egv1a1.GroupVersion.Group || string(ref.Kind) != egv1a1.KindEnvoyProxy {
		return "", "", false
	}
	return gw.Namespace, ref.Name, ref.Name != ""
}

func classParametersRef(gc *gatewayv1.GatewayClass, gatewayNamespace string) (namespace, name string, ok bool) {
	if gc.Spec.ParametersRef == nil {
		return "", "", false
	}
	ref := gc.Spec.ParametersRef
	if string(ref.Group) != egv1a1.GroupVersion.Group || string(ref.Kind) != egv1a1.KindEnvoyProxy {
		return "", "", false
	}
	ns := gatewayNamespace
	if ref.Namespace != nil && *ref.Namespace != "" {
		ns = string(*ref.Namespace)
	}
	return ns, ref.Name, ref.Name != ""
}

func moduleRegistered(proxy *egv1a1.EnvoyProxy, moduleName string) bool {
	for _, m := range proxy.Spec.DynamicModules {
		if m.Name == moduleName {
			return true
		}
	}
	return false
}

func mountPresent(proxy *egv1a1.EnvoyProxy) bool {
	if proxy.Spec.Provider == nil || proxy.Spec.Provider.Kubernetes == nil {
		return false
	}
	k := proxy.Spec.Provider.Kubernetes
	if deploymentMounted(k.EnvoyDeployment) {
		return true
	}
	return daemonSetMounted(k.EnvoyDaemonSet)
}

func deploymentMounted(dep *egv1a1.KubernetesDeploymentSpec) bool {
	if dep == nil {
		return false
	}
	return podMounted(dep.Pod, dep.Container)
}

func daemonSetMounted(ds *egv1a1.KubernetesDaemonSetSpec) bool {
	if ds == nil {
		return false
	}
	return podMounted(ds.Pod, ds.Container)
}

func podMounted(pod *egv1a1.KubernetesPodSpec, container *egv1a1.KubernetesContainerSpec) bool {
	if pod == nil || container == nil {
		return false
	}
	var volumeName string
	for _, v := range pod.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == compile.ConfigMapName {
			volumeName = v.Name
			break
		}
	}
	if volumeName == "" {
		return false
	}
	for _, m := range container.VolumeMounts {
		if m.Name == volumeName && m.MountPath == compile.MountDir {
			return true
		}
	}
	return false
}

// Apply merges this policy's keys into kubewaf-seclang and writes one EnvoyExtensionPolicy.
// It does not write an EnvoyProxy or a Gateway.
func (e *Envoy) Apply(ctx context.Context, c client.Client, b compile.Bundle, refs []gatewayv1.LocalPolicyTargetReference, proxyNamespace string) error {
	if proxyNamespace == "" {
		proxyNamespace = e.proxyNamespace
	}
	if err := e.writeConfigMap(ctx, c, b, proxyNamespace); err != nil {
		return err
	}
	return e.writeExtension(ctx, c, b, refs)
}

func (e *Envoy) writeConfigMap(ctx context.Context, c client.Client, b compile.Bundle, proxyNamespace string) error {
	owner := b.Namespace + "/" + b.Name
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: proxyNamespace, Name: compile.ConfigMapName}
	err := c.Get(ctx, key, cm)
	if apierrors.IsNotFound(err) {
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: proxyNamespace, Name: compile.ConfigMapName}}
		err = nil
	}
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	owners := decodeOwners(cm.Annotations[ownersAnnotation])
	for k := range ownedKeys(cm.Data, owners, owner) {
		if _, keep := b.Files[k]; !keep {
			delete(cm.Data, k)
			delete(owners, k)
		}
	}
	for k := range b.Files {
		if prev, ok := owners[k]; ok && prev != owner {
			return fmt.Errorf("%w: %s", provider.ErrDataFileConflict, k)
		}
	}
	for k, v := range b.Files {
		cm.Data[k] = v
		owners[k] = owner
	}
	if configMapSize(cm.Data) > maxConfigMapBytes {
		return provider.ErrConfigMapTooLarge
	}
	if cm.Annotations == nil {
		cm.Annotations = map[string]string{}
	}
	raw, err := json.Marshal(owners)
	if err != nil {
		return err
	}
	cm.Annotations[ownersAnnotation] = string(raw)
	if cm.Labels == nil {
		cm.Labels = map[string]string{}
	}
	cm.Labels[managedByLabel] = managedByValue
	if cm.ResourceVersion == "" {
		return c.Create(ctx, cm)
	}
	return c.Update(ctx, cm)
}

func (e *Envoy) writeExtension(ctx context.Context, c client.Client, b compile.Bundle, refs []gatewayv1.LocalPolicyTargetReference) error {
	desired := extensionPolicy(b, refs)
	current := &egv1a1.EnvoyExtensionPolicy{}
	err := c.Get(ctx, types.NamespacedName{Namespace: b.Namespace, Name: desired.Name}, current)
	if apierrors.IsNotFound(err) {
		return c.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	current.Labels = desired.Labels
	current.Spec = desired.Spec
	return c.Update(ctx, current)
}

func extensionPolicy(b compile.Bundle, refs []gatewayv1.LocalPolicyTargetReference) *egv1a1.EnvoyExtensionPolicy {
	name := filterName
	raw, _ := json.Marshal(filterConfig(b))
	targets := make([]gatewayv1.LocalPolicyTargetReferenceWithSectionName, 0, len(refs))
	for _, ref := range refs {
		targets = append(targets, gatewayv1.LocalPolicyTargetReferenceWithSectionName{
			LocalPolicyTargetReference: ref,
		})
	}
	return &egv1a1.EnvoyExtensionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ExtensionName(b.Name),
			Namespace: b.Namespace,
			Labels: map[string]string{
				managedByLabel: managedByValue,
				policyLabel:    b.Name,
			},
		},
		Spec: egv1a1.EnvoyExtensionPolicySpec{
			PolicyTargetReferences: egv1a1.PolicyTargetReferences{TargetRefs: targets},
			DynamicModule: []egv1a1.DynamicModule{{
				Name:       b.ModuleName,
				FilterName: &name,
				Config:     &apiextensionsv1.JSON{Raw: raw},
			}},
		},
	}
}

type filterJSON struct {
	Mode               string   `json:"mode"`
	RequestURIPathOnly bool     `json:"request_uri_path_only"`
	Metrics            metrics  `json:"metrics"`
	Directives         []string `json:"directives"`
}

type metrics struct {
	AuthorityLabel string `json:"authority_label"`
}

func filterConfig(b compile.Bundle) filterJSON {
	mode := b.Inspection
	if mode == "" {
		mode = "REQUEST_ONLY"
	}
	return filterJSON{
		Mode:               mode,
		RequestURIPathOnly: true,
		Metrics:            metrics{AuthorityLabel: "route_name"},
		Directives: []string{
			"Include @coraza.conf",
			"SecRuleEngine " + orEngine(b.Engine),
			"SecRequestBodyAccess " + onOff(b.RequestBodyAccess),
			"SecResponseBodyAccess " + onOff(b.ResponseBodyAccess),
			"SecMarker " + b.Marker,
			"Include " + compile.MountDir + "/" + compile.BeforeKey(b.Namespace, b.Name),
			"Include " + compile.MountDir + "/" + compile.AfterKey(b.Namespace, b.Name),
		},
	}
}

func orEngine(v string) string {
	if v == "" {
		return "On"
	}
	return v
}

func onOff(v bool) string {
	if v {
		return "On"
	}
	return "Off"
}

// Retract deletes the EnvoyExtensionPolicy and leaves ConfigMap keys in place.
func (e *Envoy) Retract(ctx context.Context, c client.Client, policyNamespace, policyName string) error {
	return deleteExtension(ctx, c, policyNamespace, policyName)
}

// Delete removes the extension policy and this policy's keys.
func (e *Envoy) Delete(ctx context.Context, c client.Client, policyNamespace, policyName, proxyNamespace string) error {
	if err := deleteExtension(ctx, c, policyNamespace, policyName); err != nil {
		return err
	}
	if proxyNamespace == "" {
		proxyNamespace = e.proxyNamespace
	}
	return e.deleteKeys(ctx, c, policyNamespace, policyName, proxyNamespace)
}

func deleteExtension(ctx context.Context, c client.Client, policyNamespace, policyName string) error {
	obj := &egv1a1.EnvoyExtensionPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: policyNamespace, Name: ExtensionName(policyName)}}
	err := c.Delete(ctx, obj)
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (e *Envoy) deleteKeys(ctx context.Context, c client.Client, policyNamespace, policyName, proxyNamespace string) error {
	cm := &corev1.ConfigMap{}
	err := c.Get(ctx, types.NamespacedName{Namespace: proxyNamespace, Name: compile.ConfigMapName}, cm)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	owner := policyNamespace + "/" + policyName
	owners := decodeOwners(cm.Annotations[ownersAnnotation])
	for k := range ownedKeys(cm.Data, owners, owner) {
		delete(cm.Data, k)
		delete(owners, k)
	}
	if len(cm.Data) == 0 {
		return c.Delete(ctx, cm)
	}
	if cm.Annotations == nil {
		cm.Annotations = map[string]string{}
	}
	raw, err := json.Marshal(owners)
	if err != nil {
		return err
	}
	cm.Annotations[ownersAnnotation] = string(raw)
	return c.Update(ctx, cm)
}

// Programmed reports whether Envoy Gateway has accepted the extension policy.
func (e *Envoy) Programmed(ctx context.Context, c client.Client, policyNamespace, policyName string) (provider.ProgramView, error) {
	obj := &egv1a1.EnvoyExtensionPolicy{}
	err := c.Get(ctx, types.NamespacedName{Namespace: policyNamespace, Name: ExtensionName(policyName)}, obj)
	if apierrors.IsNotFound(err) {
		return provider.ProgramView{Found: false, Reason: "Pending", Message: "EnvoyExtensionPolicy is not written"}, nil
	}
	if err != nil {
		return provider.ProgramView{}, err
	}
	for _, anc := range obj.Status.Ancestors {
		for _, cond := range anc.Conditions {
			if cond.Type != string(gatewayv1.PolicyConditionAccepted) {
				continue
			}
			return provider.ProgramView{
				Found:    true,
				Accepted: cond.Status == metav1.ConditionTrue,
				Reason:   cond.Reason,
				Message:  cond.Message,
			}, nil
		}
	}
	return provider.ProgramView{Found: true, Reason: "Pending", Message: "Envoy Gateway has not reported Accepted"}, nil
}

func decodeOwners(raw string) map[string]string {
	out := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	if out == nil {
		out = map[string]string{}
	}
	return out
}

func ownedKeys(data map[string]string, owners map[string]string, owner string) map[string]struct{} {
	out := map[string]struct{}{}
	for k := range data {
		if owners[k] == owner {
			out[k] = struct{}{}
		}
	}
	return out
}

func configMapSize(data map[string]string) int {
	n := 0
	for k, v := range data {
		n += len(k) + len(v)
	}
	return n
}
