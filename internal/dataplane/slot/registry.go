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

// Package slot defines the platform filter-slot registry (Istio EnvoyFilter,
// Cilium CEC, Envoy Gateway extension index). Provider-specific resource
// builders stay in subpackages; only Ensure/Delete lifecycle is unified here.
package slot

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/extensionserver"
	ciliumslot "github.com/kubewaf-io/kubewaf/internal/dataplane/slot/cilium"
	istioslot "github.com/kubewaf-io/kubewaf/internal/dataplane/slot/istio"
)

// Provider installs/removes the mesh-specific filter attachment for a WAF.
type Provider interface {
	// Type is the concrete provider this adapter handles (never Auto).
	Type() wafv1beta1.ProviderType
	// Kind is the Kubernetes/status slot kind label (EnvoyFilter, CiliumEnvoyConfig, ExtensionServer).
	Kind() string
	// Ensure creates or updates the slot resource(s).
	Ensure(ctx context.Context, c client.Client, owner client.Object, p *config.PortableConfig) (name string, err error)
	// Delete removes the slot resource(s). Missing CRDs/objects are success.
	Delete(ctx context.Context, c client.Client, namespace, wafName string) error
}

// Registry maps concrete provider types to slot adapters.
type Registry struct {
	byType map[wafv1beta1.ProviderType]Provider
	// eg is optional; used by the Envoy Gateway adapter (concrete to avoid typed-nil interface traps).
	eg *extensionserver.Server
}

// NewRegistry returns adapters for Istio, Cilium, and Envoy Gateway.
// eg may be nil (EG slot then only clears other mesh resources).
func NewRegistry(eg *extensionserver.Server) *Registry {
	r := &Registry{
		byType: make(map[wafv1beta1.ProviderType]Provider, 3),
		eg:     eg,
	}
	r.Register(&istioAdapter{})
	r.Register(&ciliumAdapter{})
	r.Register(&egAdapter{eg: eg})
	return r
}

// Register adds or replaces a provider adapter.
func (r *Registry) Register(p Provider) {
	if r.byType == nil {
		r.byType = make(map[wafv1beta1.ProviderType]Provider)
	}
	r.byType[p.Type()] = p
}

// Get returns the adapter for a concrete provider type.
func (r *Registry) Get(t wafv1beta1.ProviderType) (Provider, error) {
	if t == "" || t == wafv1beta1.ProviderAuto {
		t = wafv1beta1.ProviderEnvoyGateway
	}
	p, ok := r.byType[t]
	if !ok {
		return nil, fmt.Errorf("unsupported provider %q", t)
	}
	return p, nil
}

// EnsureDesired installs the slot for p.Provider and deletes every other
// registered provider's resources (so provider switches do not leave orphans).
// Prefer calling DeleteOthers only when the provider actually changes if you
// want to avoid thrash; the default is safe correctness over minimal API traffic.
func (r *Registry) EnsureDesired(
	ctx context.Context,
	c client.Client,
	owner client.Object,
	p *config.PortableConfig,
) (kind, name string, err error) {
	if p == nil {
		return "", "", fmt.Errorf("portable config is nil")
	}
	desired, err := r.Get(p.Provider)
	if err != nil {
		return "", "", err
	}
	if err := r.DeleteOthers(ctx, c, p.Namespace, p.Name, desired.Type()); err != nil {
		return "", "", err
	}
	name, err = desired.Ensure(ctx, c, owner, p)
	if err != nil {
		return "", "", err
	}
	return desired.Kind(), name, nil
}

// DeleteOthers removes slots for every provider except keep.
func (r *Registry) DeleteOthers(ctx context.Context, c client.Client, namespace, wafName string, keep wafv1beta1.ProviderType) error {
	for t, p := range r.byType {
		if t == keep {
			continue
		}
		if err := p.Delete(ctx, c, namespace, wafName); err != nil {
			return fmt.Errorf("delete %s slot: %w", t, err)
		}
	}
	return nil
}

// DeleteAll removes every registered provider slot for the WAF.
func (r *Registry) DeleteAll(ctx context.Context, c client.Client, namespace, wafName string) error {
	for t, p := range r.byType {
		if err := p.Delete(ctx, c, namespace, wafName); err != nil {
			return fmt.Errorf("delete %s slot: %w", t, err)
		}
	}
	return nil
}

// --- adapters ---

type istioAdapter struct{}

func (a *istioAdapter) Type() wafv1beta1.ProviderType { return wafv1beta1.ProviderIstio }
func (a *istioAdapter) Kind() string                  { return "EnvoyFilter" }
func (a *istioAdapter) Ensure(ctx context.Context, c client.Client, owner client.Object, p *config.PortableConfig) (string, error) {
	if err := istioslot.EnsureEnvoyFilter(ctx, c, owner, p); err != nil {
		return "", err
	}
	return istioslot.ResourceName(p.Name), nil
}
func (a *istioAdapter) Delete(ctx context.Context, c client.Client, namespace, wafName string) error {
	return istioslot.DeleteEnvoyFilter(ctx, c, namespace, wafName)
}

type ciliumAdapter struct{}

func (a *ciliumAdapter) Type() wafv1beta1.ProviderType { return wafv1beta1.ProviderCilium }
func (a *ciliumAdapter) Kind() string                  { return "CiliumEnvoyConfig" }
func (a *ciliumAdapter) Ensure(ctx context.Context, c client.Client, owner client.Object, p *config.PortableConfig) (string, error) {
	if err := ciliumslot.EnsureCiliumEnvoyConfig(ctx, c, owner, p); err != nil {
		return "", err
	}
	return ciliumslot.ResourceName(p.Name), nil
}
func (a *ciliumAdapter) Delete(ctx context.Context, c client.Client, namespace, wafName string) error {
	return ciliumslot.DeleteCiliumEnvoyConfig(ctx, c, namespace, wafName)
}

type egAdapter struct {
	eg *extensionserver.Server
}

func (a *egAdapter) Type() wafv1beta1.ProviderType { return wafv1beta1.ProviderEnvoyGateway }
func (a *egAdapter) Kind() string                  { return "ExtensionServer" }
func (a *egAdapter) Ensure(_ context.Context, _ client.Client, _ client.Object, p *config.PortableConfig) (string, error) {
	if a.eg != nil {
		a.eg.Upsert(p)
	}
	return p.ExtensionName, nil
}
func (a *egAdapter) Delete(_ context.Context, _ client.Client, namespace, wafName string) error {
	if a.eg != nil {
		a.eg.Delete(namespace, wafName)
	}
	return nil
}
