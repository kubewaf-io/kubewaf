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

// Package config builds portable Proxy-Wasm configuration for WAF engines
// (Coraza, ModSecurity) and the optional Challenge (PoW) filter.
package config

import (
	"fmt"
	"strconv"
	"strings"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
)

const (
	// DefaultECDSCluster is the Envoy cluster name used to reach kubeWAF ECDS.
	DefaultECDSCluster = "kubewaf_ecds"
	// DefaultProvider is used when WAF.spec.provider.type is empty or Auto.
	DefaultProvider = wafv1beta1.ProviderEnvoyGateway
)

// FilterRole identifies a filter in the ordered chain.
type FilterRole string

const (
	// FilterRoleChallenge is the optional PoW filter (runs first).
	FilterRoleChallenge FilterRole = "challenge"
	// FilterRoleWAF is the WAF engine filter (Coraza or ModSecurity).
	FilterRoleWAF FilterRole = "waf"
)

// PortableFilter is one ECDS Wasm extension config entry.
type PortableFilter struct {
	// ExtensionName is the ECDS resource / HTTP filter name.
	ExtensionName string
	Role          FilterRole
	ModuleID      engine.ModuleID

	WasmName string
	RootID   string
	HTTPURL  string
	SHA256   string
	// PluginJSON is the module-specific configuration object.
	PluginJSON map[string]any
}

// PortableConfig is the provider-agnostic attachment artifact.
// Filters is ordered: challenge (optional) then WAF.
type PortableConfig struct {
	ExtensionName string // primary WAF extension name (compat)
	Namespace     string
	Name          string

	Provider wafv1beta1.ProviderType
	Engine   wafv1beta1.EngineType

	// Filters ordered for insertion before the router.
	Filters []PortableFilter

	// Compat single-filter fields (primary WAF filter).
	WasmName   string
	RootID     string
	Image      string
	HTTPURL    string
	SHA256     string
	PluginJSON map[string]any
	Directives []string

	ECDSCluster string
	ECDSHost    string
	ECDSPort    uint32

	ParentRefs wafv1beta1.WAFSpec

	IstioWorkloadSelector  map[string]string
	IstioContext           string
	CiliumServiceName      string
	CiliumServiceNamespace string
}

// BuildOptions supplies operator-level defaults.
type BuildOptions struct {
	DefaultECDSHost string
	DefaultECDSPort uint32

	// DefaultModuleHTTP maps engine module id → HTTP URL Envoy should fetch.
	DefaultModuleHTTP map[engine.ModuleID]string
	// DefaultModuleSHA256 maps engine module id → sha256.
	DefaultModuleSHA256 map[engine.ModuleID]string

	// Deprecated single-module defaults (Coraza) — still honored.
	DefaultWasmHTTPURL string
	DefaultWasmSHA256  string

	// ChallengeSecret resolves SecretRef when set by the reconciler.
	// Keyed by "namespace/name/key".
	ChallengeSecrets map[string]string
}

// BuildFromWAF resolves directives and returns a PortableConfig ready for ECDS + slots.
func BuildFromWAF(waf *wafv1beta1.WAF, rules []string, opts BuildOptions) (*PortableConfig, error) {
	if waf == nil {
		return nil, fmt.Errorf("waf is nil")
	}

	eng := engine.NormalizeEngine(waf.Spec.Engine)
	mod := engine.ModuleForEngine(eng)

	wasmName := mod.DefaultWasmName
	rootID := ""
	if m := waf.Spec.Metrics; m != nil {
		if m.Name != nil && *m.Name != "" {
			wasmName = *m.Name
		}
		if m.RootID != nil {
			rootID = *m.RootID
		}
	}

	directives := BuildDirectives(waf, rules, eng)
	plugin := buildWAFPluginJSON(waf, eng, directives)

	httpURL := firstNonEmpty(
		waf.Spec.WasmHTTP,
		waf.Spec.CorazaProxyWasmHTTP,
		opts.moduleURL(mod.ID),
		opts.DefaultWasmHTTPURL,
	)
	sha256sum := firstNonEmpty(
		waf.Spec.WasmSHA256,
		waf.Spec.CorazaProxyWasmSHA256,
		opts.moduleSHA(mod.ID),
		opts.DefaultWasmSHA256,
	)
	image := firstNonEmpty(waf.Spec.WasmImage, waf.Spec.CorazaProxyWasmImage, mod.DefaultImage)

	providerType, ecdsCluster, ecdsHost, ecdsPort, istioSel, istioCtx, ciliumSvc, ciliumNS := resolveProvider(waf, opts)

	extName := ExtensionName(waf.Namespace, waf.Name)
	filters := make([]PortableFilter, 0, 2)

	// Optional challenge filter first in the chain.
	if challengeEnabled(waf.Spec.Challenge) {
		chFilter, err := buildChallengeFilter(waf, opts)
		if err != nil {
			return nil, err
		}
		filters = append(filters, *chFilter)
	}

	// WAF engine filter.
	filters = append(filters, PortableFilter{
		ExtensionName: extName,
		Role:          FilterRoleWAF,
		ModuleID:      mod.ID,
		WasmName:      wasmName,
		RootID:        rootID,
		HTTPURL:       httpURL,
		SHA256:        sha256sum,
		PluginJSON:    plugin,
	})

	return &PortableConfig{
		ExtensionName:          extName,
		Namespace:              waf.Namespace,
		Name:                   waf.Name,
		Provider:               providerType,
		Engine:                 eng,
		Filters:                filters,
		WasmName:               wasmName,
		RootID:                 rootID,
		Image:                  image,
		HTTPURL:                httpURL,
		SHA256:                 sha256sum,
		PluginJSON:             plugin,
		Directives:             directives,
		ECDSCluster:            ecdsCluster,
		ECDSHost:               ecdsHost,
		ECDSPort:               ecdsPort,
		ParentRefs:             waf.Spec,
		IstioWorkloadSelector:  istioSel,
		IstioContext:           istioCtx,
		CiliumServiceName:      ciliumSvc,
		CiliumServiceNamespace: ciliumNS,
	}, nil
}

func buildWAFPluginJSON(waf *wafv1beta1.WAF, eng wafv1beta1.EngineType, directives []string) map[string]any {
	// Both Coraza and modsecurity-proxy-wasm accept the same shape (see
	// schemas/waf-plugin-config.json). kubeWAF always emits mode + identity labels.
	plugin := map[string]any{
		"default_directives": "default",
		"directives_map": map[string]any{
			"default": directives,
		},
		"mode":           "kubewaf",
		"allow_fallback": false,
		"config_id":      ExtensionName(waf.Namespace, waf.Name),
	}

	engineLabel := "coraza"
	owner := "coraza-proxy-wasm"
	if eng == wafv1beta1.EngineModSecurity {
		engineLabel = "modsecurity"
		owner = "modsecurity-proxy-wasm"
	}

	// Stable multi-tenant identity labels (overridable via extraLabels).
	labels := map[string]string{
		"waf_namespace": waf.Namespace,
		"waf_name":      waf.Name,
		"engine":        engineLabel,
		"owner":         owner,
	}
	if m := waf.Spec.Metrics; m != nil && len(m.ExtraLabels) > 0 {
		for k, v := range m.ExtraLabels {
			labels[k] = v
		}
	}
	plugin["metric_labels"] = labels

	// Nested metrics object (preferred) + flat aliases for older filters.
	perRuleID := true
	ruleTags := true
	enabled := true
	if m := waf.Spec.Metrics; m != nil {
		if m.IncludeRuleID != nil {
			perRuleID = *m.IncludeRuleID
		}
		if m.EnableStats != nil {
			enabled = *m.EnableStats
		}
	}
	plugin["metrics"] = map[string]any{
		"enabled":     enabled,
		"per_rule_id": perRuleID,
		"rule_tags":   ruleTags,
	}
	plugin["metrics_per_rule_id"] = perRuleID
	plugin["metrics_rule_tags"] = ruleTags

	// Product-branded local replies from the ModSecurity engine.
	if eng == wafv1beta1.EngineModSecurity {
		plugin["block"] = map[string]any{
			"message":            "blocked by kubeWAF",
			"add_rule_id_header": false,
			"rule_id_header":     "x-kubewaf-rule-id",
		}
	}
	return plugin
}

func buildChallengeFilter(waf *wafv1beta1.WAF, opts BuildOptions) (*PortableFilter, error) {
	ch := waf.Spec.Challenge
	if ch == nil {
		return nil, fmt.Errorf("challenge is nil")
	}
	secret := ch.Secret
	if ch.SecretRef != nil {
		key := waf.Namespace + "/" + ch.SecretRef.Name + "/" + ch.SecretRef.Key
		if opts.ChallengeSecrets != nil {
			if v, ok := opts.ChallengeSecrets[key]; ok {
				secret = v
			}
		}
		if secret == "" {
			return nil, fmt.Errorf("challenge secretRef %s/%s key %q not resolved",
				waf.Namespace, ch.SecretRef.Name, ch.SecretRef.Key)
		}
	}
	if secret == "" {
		// Dev default — pow-proxy-wasm logs a reminder; operators should set secret.
		secret = "kubewaf-dev-challenge-secret-change-me"
	}

	plugin := map[string]any{
		"secret": secret,
	}
	if ch.BaseDifficulty != nil {
		plugin["base_difficulty"] = *ch.BaseDifficulty
	} else {
		plugin["base_difficulty"] = 18
	}
	if ch.MinDifficulty != nil {
		plugin["min_difficulty"] = *ch.MinDifficulty
	}
	if ch.MaxDifficulty != nil {
		plugin["max_difficulty"] = *ch.MaxDifficulty
	}
	if ch.Header != "" {
		plugin["header"] = ch.Header
		if ch.HeaderValue != "" {
			plugin["value"] = ch.HeaderValue
		}
	}

	mod := engine.Catalog[engine.ModuleChallenge]
	httpURL := firstNonEmpty(ch.WasmHTTP, opts.moduleURL(engine.ModuleChallenge))
	sha := firstNonEmpty(ch.WasmSHA256, opts.moduleSHA(engine.ModuleChallenge))

	return &PortableFilter{
		ExtensionName: ChallengeExtensionName(waf.Namespace, waf.Name),
		Role:          FilterRoleChallenge,
		ModuleID:      engine.ModuleChallenge,
		WasmName:      mod.DefaultWasmName,
		HTTPURL:       httpURL,
		SHA256:        sha,
		PluginJSON:    plugin,
	}, nil
}

func challengeEnabled(ch *wafv1beta1.ChallengeSpec) bool {
	if ch == nil {
		return false
	}
	if ch.Enabled == nil {
		return true // presence of block with default enabled=true
	}
	return *ch.Enabled
}

// BuildDirectives constructs the ordered SecLang directive list for a WAF.
//
// Order is intentional:
//  1. Include @kubewaf-defaults — ModSecurity only: body access, tmp dirs
//  2. SecRuleEngine / SecDebugLogLevel
//  3. CRS setup + rules (when enabled)
//  4. User RuleSet SecLang
func BuildDirectives(waf *wafv1beta1.WAF, rules []string, eng ...wafv1beta1.EngineType) []string {
	logLevel := waf.Spec.LogLevel
	if logLevel == 0 {
		logLevel = 7
	}
	engineType := engine.NormalizeEngine(waf.Spec.Engine)
	if len(eng) > 0 && eng[0] != "" {
		engineType = engine.NormalizeEngine(eng[0])
	}
	out := make([]string, 0, 8+len(rules))
	// @kubewaf-defaults is embedded in modsecurity-proxy-wasm only.
	if engineType == wafv1beta1.EngineModSecurity {
		out = append(out, "Include @kubewaf-defaults")
	}
	out = append(out,
		"SecRuleEngine On",
		"SecDebugLogLevel "+strconv.Itoa(logLevel),
	)
	if waf.Spec.CRSEnable {
		// ModSecurity engine embeds CRS; Coraza proxy-wasm also supports virtual includes.
		out = append(out, "Include @crs-setup-conf")
		if crs := waf.Spec.CRS; crs != nil {
			out = append(out, CRSSetupActions(crs)...)
		}
		out = append(out, "Include @owasp_crs/*.conf")
		if crs := waf.Spec.CRS; crs != nil {
			out = append(out, CRSExclusions(crs)...)
		}
	}
	out = append(out, rules...)
	return out
}

// ExtensionName returns the stable ECDS / HTTP filter name for the WAF engine.
func ExtensionName(namespace, name string) string {
	return fmt.Sprintf("kubewaf/%s/%s", namespace, name)
}

// ChallengeExtensionName returns the ECDS name for the optional PoW filter.
func ChallengeExtensionName(namespace, name string) string {
	return fmt.Sprintf("kubewaf/%s/%s/challenge", namespace, name)
}

// AllExtensionNames returns ECDS names for a portable config (for delete).
func AllExtensionNames(p *PortableConfig) []string {
	if p == nil {
		return nil
	}
	if len(p.Filters) > 0 {
		out := make([]string, 0, len(p.Filters))
		for _, f := range p.Filters {
			out = append(out, f.ExtensionName)
		}
		return out
	}
	return []string{p.ExtensionName}
}

// CRSSetupActions returns zero or one SecAction directive for CRS thresholds.
func CRSSetupActions(crs *wafv1beta1.CRSTuning) []string {
	if crs == nil {
		return nil
	}
	var sets []string
	if crs.ParanoiaLevel != nil {
		pl := *crs.ParanoiaLevel
		sets = append(sets,
			fmt.Sprintf("setvar:tx.detection_paranoia_level=%d", pl),
			fmt.Sprintf("setvar:tx.blocking_paranoia_level=%d", pl),
		)
	}
	if crs.InboundAnomalyThreshold != nil {
		sets = append(sets, fmt.Sprintf("setvar:tx.inbound_anomaly_score_threshold=%d", *crs.InboundAnomalyThreshold))
	}
	if crs.OutboundAnomalyThreshold != nil {
		sets = append(sets, fmt.Sprintf("setvar:tx.outbound_anomaly_score_threshold=%d", *crs.OutboundAnomalyThreshold))
	}
	if len(sets) == 0 {
		return nil
	}
	action := fmt.Sprintf(`SecAction "id:900000,phase:1,nolog,pass,%s"`, strings.Join(sets, ","))
	return []string{action}
}

// CRSExclusions returns removal / target-update directives after CRS includes.
func CRSExclusions(crs *wafv1beta1.CRSTuning) []string {
	if crs == nil {
		return nil
	}
	var out []string
	for _, id := range crs.RemoveByID {
		out = append(out, fmt.Sprintf("SecRuleRemoveById %d", id))
	}
	for _, tag := range crs.RemoveByTag {
		out = append(out, fmt.Sprintf("SecRuleRemoveByTag %s", tag))
	}
	for _, te := range crs.UpdateTargetByID {
		if len(te.RemoveTargets) == 0 {
			continue
		}
		quoted := make([]string, len(te.RemoveTargets))
		for i, t := range te.RemoveTargets {
			quoted[i] = "!" + t
		}
		out = append(out, fmt.Sprintf(`SecRuleUpdateTargetById %d "%s"`, te.ID, strings.Join(quoted, "|")))
	}
	return out
}

func (o BuildOptions) moduleURL(id engine.ModuleID) string {
	if o.DefaultModuleHTTP != nil {
		return o.DefaultModuleHTTP[id]
	}
	return ""
}

func (o BuildOptions) moduleSHA(id engine.ModuleID) string {
	if o.DefaultModuleSHA256 != nil {
		return o.DefaultModuleSHA256[id]
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func resolveProvider(waf *wafv1beta1.WAF, opts BuildOptions) (
	provider wafv1beta1.ProviderType,
	cluster, host string,
	port uint32,
	istioSel map[string]string,
	istioCtx string,
	ciliumSvc, ciliumNS string,
) {
	cluster = DefaultECDSCluster
	host = opts.DefaultECDSHost
	port = opts.DefaultECDSPort
	if port == 0 {
		port = 18001
	}
	provider = DefaultProvider
	istioCtx = "GATEWAY"
	istioSel = map[string]string{"istio": "ingressgateway"}
	ciliumSvc = waf.Name
	ciliumNS = waf.Namespace

	p := waf.Spec.Provider
	if p == nil {
		return provider, cluster, host, port, istioSel, istioCtx, ciliumSvc, ciliumNS
	}

	switch p.Type {
	case wafv1beta1.ProviderIstio:
		provider = wafv1beta1.ProviderIstio
	case wafv1beta1.ProviderCilium:
		provider = wafv1beta1.ProviderCilium
	case wafv1beta1.ProviderEnvoyGateway:
		provider = wafv1beta1.ProviderEnvoyGateway
	case wafv1beta1.ProviderAuto, "":
		provider = DefaultProvider
	default:
		provider = p.Type
	}

	if p.ECDSCluster != "" {
		cluster = p.ECDSCluster
	}
	if p.ECDSService != "" {
		h, pt, err := ParseHostPort(p.ECDSService, port)
		if err == nil {
			host = h
			port = pt
		}
	}
	if p.Istio != nil {
		if len(p.Istio.WorkloadSelector) > 0 {
			istioSel = p.Istio.WorkloadSelector
		}
		if p.Istio.Context != "" {
			istioCtx = p.Istio.Context
		}
	}
	if p.Cilium != nil {
		if p.Cilium.ServiceName != "" {
			ciliumSvc = p.Cilium.ServiceName
		}
		if p.Cilium.ServiceNamespace != "" {
			ciliumNS = p.Cilium.ServiceNamespace
		}
	}
	return provider, cluster, host, port, istioSel, istioCtx, ciliumSvc, ciliumNS
}

// ParseHostPort splits "host:port" (or host only) into host and port.
func ParseHostPort(service string, defaultPort uint32) (string, uint32, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		return "", 0, fmt.Errorf("empty service")
	}
	service = strings.TrimPrefix(service, "https://")
	service = strings.TrimPrefix(service, "http://")

	host := service
	port := defaultPort
	if i := strings.LastIndex(service, ":"); i > 0 {
		hostPart := service[:i]
		portPart := service[i+1:]
		if p, err := strconv.ParseUint(portPart, 10, 32); err == nil {
			host = hostPart
			port = uint32(p)
		}
	}
	return host, port, nil
}
