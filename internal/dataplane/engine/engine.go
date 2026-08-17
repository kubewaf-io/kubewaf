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

// Package engine catalogs Proxy-Wasm modules integrated with kubeWAF:
// modsecurity-proxy-wasm (WAF) and challenge/pow-proxy-wasm.
package engine

import (
	"fmt"
	"path"
	"strings"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

// ModuleID identifies a served wasm binary / filter role.
type ModuleID string

const (
	// ModuleModSecurity is the ModSecurity WAF engine.
	ModuleModSecurity ModuleID = "modsecurity"
	// ModuleChallenge is the Proof-of-Work browser challenge filter.
	ModuleChallenge ModuleID = "challenge"

	// DefaultModSecurityFile is the on-disk path for the WAF wasm binary.
	DefaultModSecurityFile = "/wasm/modsecurity-proxy-wasm.wasm"
	// DefaultChallengeFile is the on-disk path for the challenge wasm binary.
	DefaultChallengeFile = "/wasm/challenge-proxy-wasm.wasm"
)

// Module describes a wasm artifact and its default serve path.
type Module struct {
	ID          ModuleID
	DisplayName string
	// HTTPPath is the path on the operator wasm HTTP server.
	HTTPPath string
	// DefaultFile is the on-disk path (image / mount layout).
	DefaultFile string
	// DefaultImage is an optional OCI reference for docs.
	DefaultImage string
	// DefaultWasmName is the Envoy Wasm filter name / metric prefix.
	DefaultWasmName string
}

// Catalog is the set of engines kubeWAF knows how to serve and configure.
var Catalog = map[ModuleID]Module{
	ModuleModSecurity: {
		ID:              ModuleModSecurity,
		DisplayName:     "ModSecurity",
		HTTPPath:        "/wasm/modsecurity-proxy-wasm.wasm",
		DefaultFile:     DefaultModSecurityFile,
		DefaultImage:    "ghcr.io/kubewaf-io/modsecurity-proxy-wasm:0.1.0-alpha15",
		DefaultWasmName: "kubewaf.modsecurity",
	},
	ModuleChallenge: {
		ID:              ModuleChallenge,
		DisplayName:     "Challenge (PoW)",
		HTTPPath:        "/wasm/challenge-proxy-wasm.wasm",
		DefaultFile:     DefaultChallengeFile,
		DefaultImage:    "ghcr.io/kubewaf-io/modsecurity-proxy-wasm:0.1.0-alpha15",
		DefaultWasmName: "kubewaf.challenge",
	},
}

// ProductEngine returns the WAF engine type used by kubeWAF.
func ProductEngine() wafv1beta1.EngineType {
	return wafv1beta1.EngineModSecurity
}

// ProductModule returns the catalog entry for the WAF engine.
func ProductModule() Module {
	return Catalog[ModuleModSecurity]
}

// PublicURL builds the operator-hosted HTTP URL for a module.
func PublicURL(serviceHost string, port uint32, id ModuleID) string {
	m, ok := Catalog[id]
	if !ok {
		return fmt.Sprintf("http://%s:%d/wasm/%s.wasm", serviceHost, port, id)
	}
	return fmt.Sprintf("http://%s:%d%s", serviceHost, port, m.HTTPPath)
}

// HTTPPath returns the serve path for a module id.
func HTTPPath(id ModuleID) string {
	if m, ok := Catalog[id]; ok {
		return m.HTTPPath
	}
	return "/wasm/" + string(id) + ".wasm"
}

// Basename returns the filename portion of a module path.
func Basename(id ModuleID) string {
	return path.Base(HTTPPath(id))
}

// ParseModuleFromPath maps a request path to a ModuleID.
func ParseModuleFromPath(p string) (ModuleID, bool) {
	p = strings.TrimSuffix(p, "/")
	for id, m := range Catalog {
		if p == m.HTTPPath {
			return id, true
		}
	}
	// Aliases
	switch p {
	case "/wasm/modsec.wasm":
		return ModuleModSecurity, true
	case "/wasm/pow-proxy-wasm.wasm", "/wasm/challenge.wasm":
		return ModuleChallenge, true
	}
	return "", false
}

// AllModules returns catalog modules in stable order.
func AllModules() []Module {
	return []Module{
		Catalog[ModuleModSecurity],
		Catalog[ModuleChallenge],
	}
}
