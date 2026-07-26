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
// coraza-proxy-wasm, modsecurity-proxy-wasm, and challenge/pow-proxy-wasm.
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
	// ModuleCoraza is the default Coraza WAF engine.
	ModuleCoraza ModuleID = "coraza"
	// ModuleModSecurity is the in-tree ModSecurity WAF engine.
	ModuleModSecurity ModuleID = "modsecurity"
	// ModuleChallenge is the Proof-of-Work browser challenge filter.
	ModuleChallenge ModuleID = "challenge"
)

// Module describes a wasm artifact and its default serve path.
type Module struct {
	ID          ModuleID
	DisplayName string
	// HTTPPath is the path on the operator wasm HTTP server.
	HTTPPath string
	// DefaultFile is a conventional on-disk path (monorepo / container layout).
	DefaultFile string
	// DefaultImage is an optional OCI reference for docs.
	DefaultImage string
	// DefaultWasmName is the Envoy Wasm filter name / metric prefix.
	DefaultWasmName string
}

// Catalog is the set of engines kubeWAF knows how to serve and configure.
var Catalog = map[ModuleID]Module{
	ModuleCoraza: {
		ID:              ModuleCoraza,
		DisplayName:     "Coraza",
		HTTPPath:        "/wasm/coraza-proxy-wasm.wasm",
		DefaultFile:     "/wasm/coraza-proxy-wasm.wasm",
		DefaultImage:    "ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0",
		DefaultWasmName: "kubewaf.coraza",
	},
	ModuleModSecurity: {
		ID:              ModuleModSecurity,
		DisplayName:     "ModSecurity",
		HTTPPath:        "/wasm/modsecurity-proxy-wasm.wasm",
		DefaultFile:     "/wasm/modsecurity-proxy-wasm.wasm",
		DefaultImage:    "ghcr.io/kubewaf-io/modsecurity-proxy-wasm:latest",
		DefaultWasmName: "kubewaf.modsecurity",
	},
	ModuleChallenge: {
		ID:              ModuleChallenge,
		DisplayName:     "Challenge (PoW)",
		HTTPPath:        "/wasm/challenge-proxy-wasm.wasm",
		DefaultFile:     "/wasm/challenge-proxy-wasm.wasm",
		DefaultImage:    "ghcr.io/kubewaf-io/challenge-proxy-wasm:latest",
		DefaultWasmName: "kubewaf.challenge",
	},
}

// ModuleForEngine maps a WAF engine enum to a catalog module.
func ModuleForEngine(e wafv1beta1.EngineType) Module {
	switch e {
	case wafv1beta1.EngineModSecurity:
		return Catalog[ModuleModSecurity]
	case wafv1beta1.EngineCoraza, "":
		return Catalog[ModuleCoraza]
	default:
		return Catalog[ModuleCoraza]
	}
}

// NormalizeEngine returns Coraza when empty.
func NormalizeEngine(e wafv1beta1.EngineType) wafv1beta1.EngineType {
	if e == "" {
		return wafv1beta1.EngineCoraza
	}
	return e
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
	case "/wasm/main.wasm":
		return ModuleCoraza, true
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
		Catalog[ModuleCoraza],
		Catalog[ModuleModSecurity],
		Catalog[ModuleChallenge],
	}
}
