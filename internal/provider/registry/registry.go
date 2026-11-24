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

// Package registry constructs the provider set. It is separate from package
// provider so the Envoy Gateway implementation can depend on the interface
// without a cycle.
package registry

import (
	"github.com/kubewaf-io/kubewaf/internal/provider"
	"github.com/kubewaf-io/kubewaf/internal/provider/envoygateway"
)

// Registry maps a provider name to an implementation.
// There is no SecPolicy field for the name. The controller asks for envoygateway.
type Registry struct {
	providers map[string]provider.Provider
}

// New returns a registry whose only entry is Envoy Gateway.
func New(proxyNamespace string) *Registry {
	return &Registry{providers: map[string]provider.Provider{
		provider.NameEnvoyGateway: envoygateway.New(proxyNamespace),
	}}
}

// Get returns the provider or false.
func (r *Registry) Get(name string) (provider.Provider, bool) {
	if r == nil {
		return nil, false
	}
	p, ok := r.providers[name]
	return p, ok
}
