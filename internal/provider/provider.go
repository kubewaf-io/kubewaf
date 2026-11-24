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

// Package provider is the seam between a compiled SecLang bundle and a dataplane.
// The compiler does not import Envoy Gateway. A provider writes the objects that
// platform already knows how to attach, and it does not own that platform's proxy.
package provider

import (
	"context"
	"errors"

	"github.com/kubewaf-io/kubewaf/internal/compile"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// NameEnvoyGateway is the only registered provider.
	NameEnvoyGateway = "envoygateway"

	// ReasonModuleMissing means the platform EnvoyProxy does not register the module.
	ReasonModuleMissing = "ModuleMissing"
	// ReasonMountMissing means a policy has data files and the platform proxy does not mount kubewaf-seclang.
	ReasonMountMissing = "MountMissing"
)

// ErrDataFileConflict means a ConfigMap key this policy needs is owned by another policy.
var ErrDataFileConflict = errors.New("data file key is owned by another policy")

// ErrConfigMapTooLarge means data files or the inline directive document exceed 900KiB.
var ErrConfigMapTooLarge = errors.New("compiled policy exceeds 900KiB")

// GatewayRef is a Gateway in a namespace. HTTPRoute parents are resolved to this
// before the provider is asked whether the engine is ready.
type GatewayRef struct {
	Namespace string
	Name      string
}

// EngineView is the read-only result of looking at the platform EnvoyProxy.
type EngineView struct {
	Ready bool
	// Mounted is true when the platform proxy mounts kubewaf-seclang.
	// Inline rules do not need it. Data files do.
	Mounted             bool
	Reason              string
	Message             string
	GatewayName         string
	EnvoyProxyNamespace string
	EnvoyProxyName      string
}

// ProgramView is the EnvoyExtensionPolicy status the provider observed.
type ProgramView struct {
	// Found is false when this policy has not written an extension policy.
	Found    bool
	Accepted bool
	Reason   string
	Message  string
}

// Provider writes and deletes the dataplane objects for one SecPolicy.
// Apply and Delete must not create, patch, or delete an EnvoyProxy, and must
// not patch a Gateway.
type Provider interface {
	Name() string
	// CheckEngine reads Gateway parametersRef and the EnvoyProxy. It does not write.
	CheckEngine(ctx context.Context, c client.Client, refs []GatewayRef, moduleName, proxyNamespace string) (EngineView, error)
	Apply(ctx context.Context, c client.Client, b compile.Bundle, refs []gatewayv1.LocalPolicyTargetReference, proxyNamespace string) error
	// Retract removes the EnvoyExtensionPolicy when the engine is not ready.
	// ConfigMap keys stay, so the last good files are still there. The proxy is not touched.
	Retract(ctx context.Context, c client.Client, policyNamespace, policyName string) error
	// Delete removes the extension policy and this policy's ConfigMap keys.
	// The ConfigMap is removed when it has no remaining keys.
	Delete(ctx context.Context, c client.Client, policyNamespace, policyName, proxyNamespace string) error
	// Programmed reads the extension policy status. It does not write.
	Programmed(ctx context.Context, c client.Client, policyNamespace, policyName string) (ProgramView, error)
	// WatchObjects are the extra kinds a controller should watch. They are
	// returned as client.Object so the controller does not import Envoy types.
	WatchObjects() []client.Object
}
