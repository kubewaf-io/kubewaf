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

package ecds

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	wasm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
)

// WasmCodeCluster is the Envoy cluster used to fetch remote Wasm binaries over HTTP.
const WasmCodeCluster = "kubewaf_wasm_code"

// CECResourceName is the CiliumEnvoyConfig object name for a WAF.
// Must match internal/dataplane/slot/cilium.ResourceName.
func CECResourceName(wafName string) string {
	return "kubewaf-" + wafName
}

// CiliumPrefixedCluster is how Cilium Envoy names a CEC-local cluster.
func CiliumPrefixedCluster(namespace, wafName, local string) string {
	return namespace + "/" + CECResourceName(wafName) + "/" + local
}

// BuildTypedExtensionConfigs builds ECDS TypedExtensionConfig for every filter
// in the portable config (challenge then WAF).
func BuildTypedExtensionConfigs(p *config.PortableConfig) ([]*core.TypedExtensionConfig, error) {
	if p == nil {
		return nil, fmt.Errorf("portable config is nil")
	}
	filters := p.Filters
	if len(filters) == 0 {
		// Compat: single WAF filter from top-level fields.
		filters = []config.PortableFilter{{
			ExtensionName: p.ExtensionName,
			Role:          config.FilterRoleWAF,
			WasmName:      p.WasmName,
			RootID:        p.RootID,
			HTTPURL:       p.HTTPURL,
			SHA256:        p.SHA256,
			PluginJSON:    p.PluginJSON,
		}}
	}
	wasmCluster := wasmFetchCluster(p)
	out := make([]*core.TypedExtensionConfig, 0, len(filters))
	for _, f := range filters {
		tec, err := buildOne(f, wasmCluster)
		if err != nil {
			return nil, fmt.Errorf("filter %s: %w", f.ExtensionName, err)
		}
		out = append(out, tec)
	}
	return out, nil
}

// wasmFetchCluster is the RemoteDataSource cluster name. Cilium prefixes CEC
// cluster names; ECDS TypedExtensionConfig is not rewritten.
func wasmFetchCluster(p *config.PortableConfig) string {
	if p != nil && p.Provider == wafv1beta1.ProviderCilium && p.Namespace != "" && p.Name != "" {
		return CiliumPrefixedCluster(p.Namespace, p.Name, WasmCodeCluster)
	}
	return WasmCodeCluster
}

// BuildTypedExtensionConfig builds a single TypedExtensionConfig for the primary WAF filter (compat).
func BuildTypedExtensionConfig(p *config.PortableConfig) (*core.TypedExtensionConfig, error) {
	all, err := BuildTypedExtensionConfigs(p)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no filters")
	}
	// Return the last filter (WAF) for callers that expect a single resource.
	return all[len(all)-1], nil
}

func buildOne(f config.PortableFilter, wasmCluster string) (*core.TypedExtensionConfig, error) {
	if f.HTTPURL == "" {
		return nil, fmt.Errorf("wasm HTTP URL is required for ECDS (module %s)", f.ModuleID)
	}
	// Envoy RemoteDataSource.sha256 is required (min_len=1). Publishing without it
	// causes: "Sha256: value length must be at least 1 characters".
	if strings.TrimSpace(f.SHA256) == "" {
		return nil, fmt.Errorf("wasm SHA-256 is required for remote ECDS code (module %s, url %s); load the .wasm into the operator image or /wasm mount", f.ModuleID, f.HTTPURL)
	}
	pluginBytes, err := json.Marshal(f.PluginJSON)
	if err != nil {
		return nil, fmt.Errorf("marshal plugin JSON: %w", err)
	}
	vmConfig, err := buildVMConfig(f.HTTPURL, f.SHA256, f.ExtensionName, wasmCluster)
	if err != nil {
		return nil, err
	}
	cfgAny, err := anypb.New(wrapperspb.String(string(pluginBytes)))
	if err != nil {
		return nil, fmt.Errorf("pack plugin configuration: %w", err)
	}
	pluginConfig := &v3.PluginConfig{
		Name:          f.WasmName,
		RootId:        f.RootID,
		Configuration: cfgAny,
		Vm: &v3.PluginConfig_VmConfig{
			VmConfig: vmConfig,
		},
	}
	wasmFilter := &wasm.Wasm{Config: pluginConfig}
	anyCfg, err := anypb.New(wasmFilter)
	if err != nil {
		return nil, fmt.Errorf("pack wasm filter: %w", err)
	}
	return &core.TypedExtensionConfig{
		Name:        f.ExtensionName,
		TypedConfig: anyCfg,
	}, nil
}

func buildVMConfig(httpURL, sha256sum, vmID, wasmCluster string) (*v3.VmConfig, error) {
	u, err := url.Parse(httpURL)
	if err != nil {
		return nil, fmt.Errorf("parse wasm HTTP URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("wasm HTTP URL must be http(s), got %q", u.Scheme)
	}
	sha := strings.TrimSpace(sha256sum)
	if sha == "" {
		return nil, fmt.Errorf("remote wasm code requires a non-empty sha256 (url %s)", httpURL)
	}
	if wasmCluster == "" {
		wasmCluster = WasmCodeCluster
	}
	remote := &core.RemoteDataSource{
		HttpUri: &core.HttpUri{
			Uri: httpURL,
			HttpUpstreamType: &core.HttpUri_Cluster{
				Cluster: wasmCluster,
			},
			Timeout: durationpb.New(30 * time.Second),
		},
		Sha256: sha,
	}
	return &v3.VmConfig{
		Runtime: "envoy.wasm.runtime.v8",
		VmId:    vmID,
		Code: &core.AsyncDataSource{
			Specifier: &core.AsyncDataSource_Remote{
				Remote: remote,
			},
		},
		AllowPrecompiled: true,
	}, nil
}

// WasmCodeClusterHostPort extracts host and port for the Wasm HTTP fetch cluster.
func WasmCodeClusterHostPort(httpURL string) (host string, port uint32, err error) {
	u, err := url.Parse(httpURL)
	if err != nil {
		return "", 0, err
	}
	host = u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("no host in wasm URL %q", httpURL)
	}
	port = 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		var p64 uint64
		_, scanErr := fmt.Sscanf(u.Port(), "%d", &p64)
		if scanErr != nil {
			return "", 0, scanErr
		}
		port = uint32(p64)
	}
	return host, port, nil
}

// IsHTTPS reports whether the wasm URL uses TLS.
func IsHTTPS(httpURL string) bool {
	return strings.HasPrefix(httpURL, "https://")
}
