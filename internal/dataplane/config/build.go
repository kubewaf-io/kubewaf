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

// Package config builds portable Proxy-Wasm configuration for the WAF engine
// (ModSecurity) and the optional Challenge (PoW) filter.
package config

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	envoygatewayv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
)

const (
	// DefaultECDSCluster is the Envoy cluster name used to reach kubeWAF ECDS.
	DefaultECDSCluster = "kubewaf_ecds"
	// DefaultOTelCluster is the Envoy cluster name used by OTLP exporters.
	DefaultOTelCluster = "kubewaf_otel"
	// DefaultOTelPort is the Collector OTLP/gRPC port.
	DefaultOTelPort = 4317
	// DefaultProvider is used when WAF.spec.provider.type is empty or Auto.
	DefaultProvider = wafv1beta1.ProviderEnvoyGateway
)

// reservedMetricLabelKeys are pinned after extraLabels (KD-32).
var reservedMetricLabelKeys = []string{"waf_namespace", "waf_name", "engine", "owner"}

// FilterRole identifies a filter in the ordered chain.
type FilterRole string

const (
	// FilterRoleChallenge is the optional PoW filter (runs first).
	FilterRoleChallenge FilterRole = "challenge"
	// FilterRoleWAF is the WAF engine filter (ModSecurity).
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

	// OTelCluster is always kubewaf_otel when a destination host is known.
	OTelCluster string
	OTelHost    string
	OTelPort    uint32
	// TelemetryManaged is true when spec.telemetry.mode is Managed.
	// Slots use this to append the HCM OTel access logger.
	TelemetryManaged bool

	// PolicyTargets is the resolved Gateway API attachment surface only
	// (not the full WAFSpec). Prefer this over embedding the CR.
	PolicyTargets envoygatewayv1alpha1.PolicyTargetReferences

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

	// Single-module HTTP/SHA defaults used when DefaultModule* maps omit the WAF module.
	DefaultWasmHTTPURL string
	DefaultWasmSHA256  string

	// ChallengeSecret resolves SecretRef when set by the reconciler.
	// Keyed by "namespace/name/key".
	ChallengeSecrets map[string]string

	// ChallengeHMAC is the resolved HMAC secret string for the challenge filter
	// (set by the controller after auto-generating or reading a Secret).
	// Preferred over Spec.Challenge.Secret when non-empty.
	ChallengeHMAC string

	// DetectedProvider is set by the controller when spec.provider.type is
	// empty or Auto (via DiscoverProvider). Concrete type only — never Auto.
	DetectedProvider wafv1beta1.ProviderType
	// DetectedProviderReason is a short explanation for logs/status.
	DetectedProviderReason string
	// DetectedCiliumServiceName/Namespace fill provider.cilium when Auto/Cilium
	// and the WAF did not set serviceName (from target Service or HTTPRoute).
	DetectedCiliumServiceName      string
	DetectedCiliumServiceNamespace string

	// PhraseFiles maps basename → uncompressed body for plugin data_files inject
	// (ModSecurity Path B custom @pmFromFile / CRS overrides).
	PhraseFiles map[string][]byte

	// DirectivesOverride, when non-nil, replaces BuildDirectives output entirely
	// (used after IgnoreUnknown rewrites the full SecLang line set).
	DirectivesOverride []string

	// OverrideCRSCount is recorded in data_files_stats when PhraseFiles inject CRS overrides.
	OverrideCRSCount int

	// DefaultOTelHost is the Collector DNS name (empty = do not advertise the cluster).
	DefaultOTelHost string
	// DefaultOTelPort is the Collector OTLP/gRPC port (default 4317).
	DefaultOTelPort uint32

	// TelemetryDefaults are Helm-profile defaults when the CR omits a traces field.
	TelemetryDefaults TelemetryDefaults
}

// TelemetryDefaults fill spec.telemetry.traces when the CR omits a field.
type TelemetryDefaults struct {
	// Profile is lite (traces.enabled default false) or full (default true).
	Profile string
	// SampleNonDisruptive is the default traces.sample_rate string (e.g. "0.25").
	SampleNonDisruptive string
	// SampleDisruptive is the default traces.sample_disruptive string (e.g. "1.0").
	SampleDisruptive string
	// Redact omits client.address when the CR does not set traces.redact.
	Redact bool
	// IncludeMatchData is the default traces.include_match_data.
	IncludeMatchData bool
}

// BuildFromWAF resolves directives and returns a PortableConfig ready for ECDS + slots.
func BuildFromWAF(waf *wafv1beta1.WAF, rules []string, opts BuildOptions) (*PortableConfig, error) {
	if waf == nil {
		return nil, fmt.Errorf("waf is nil")
	}

	eng := engine.ProductEngine()
	mod := engine.ProductModule()

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

	directives := BuildDirectives(waf, rules)
	if opts.DirectivesOverride != nil {
		directives = opts.DirectivesOverride
	}
	plugin := buildWAFPluginJSON(waf, directives, opts.PhraseFiles, opts.OverrideCRSCount, opts.TelemetryDefaults)

	// Operator-hosted module URL/SHA (paths under /wasm on the operator).
	httpURL := firstNonEmpty(
		opts.moduleURL(mod.ID),
		opts.DefaultWasmHTTPURL,
	)
	sha256sum := firstNonEmpty(
		opts.moduleSHA(mod.ID),
		opts.DefaultWasmSHA256,
	)
	if httpURL == "" {
		return nil, fmt.Errorf("wasm HTTP URL is not configured for ModSecurity; ensure the operator loaded %s", mod.DefaultFile)
	}
	// Envoy rejects remote Wasm AsyncDataSource when sha256 is empty.
	if strings.TrimSpace(sha256sum) == "" {
		return nil, fmt.Errorf("wasm SHA-256 is not configured for ModSecurity (url %s); ensure the operator loaded the module", httpURL)
	}
	image := mod.DefaultImage

	providerType, ecdsCluster, ecdsHost, ecdsPort, istioSel, istioCtx, ciliumSvc, ciliumNS := resolveProvider(waf, opts)

	otelPort := opts.DefaultOTelPort
	if otelPort == 0 {
		otelPort = DefaultOTelPort
	}
	telemetryManaged := waf.Spec.Telemetry != nil && waf.Spec.Telemetry.Mode == wafv1beta1.TelemetryModeManaged

	extName := ExtensionName(waf.Namespace, waf.Name)
	filters := make([]PortableFilter, 0, 2)

	// Optional challenge filter first in the chain.
	if ChallengeEnabled(waf.Spec.Challenge) {
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
		OTelCluster:            DefaultOTelCluster,
		OTelHost:               opts.DefaultOTelHost,
		OTelPort:               otelPort,
		TelemetryManaged:       telemetryManaged,
		PolicyTargets:          waf.Spec.EffectivePolicyTargets(),
		IstioWorkloadSelector:  istioSel,
		IstioContext:           istioCtx,
		CiliumServiceName:      ciliumSvc,
		CiliumServiceNamespace: ciliumNS,
	}, nil
}

func buildWAFPluginJSON(waf *wafv1beta1.WAF, directives []string, phraseFiles map[string][]byte, overrideCRS int, telDefaults TelemetryDefaults) map[string]any {
	// modsecurity-proxy-wasm plugin shape (schemas/waf-plugin-config.json).
	// Path B with large SecLang lists: gzip+base64 compress directives so ECDS
	// plugin config stays small.
	plugin := map[string]any{
		"default_directives": "default",
		"mode":               "kubewaf",
		"allow_fallback":     false,
		"config_id":          ExtensionName(waf.Namespace, waf.Name),
	}
	attachDirectives(plugin, directives)
	attachDataFiles(plugin, phraseFiles, overrideCRS)

	// ExtraLabels first; reserved identity keys are pinned after (KD-32).
	labels := map[string]string{}
	if m := waf.Spec.Metrics; m != nil && len(m.ExtraLabels) > 0 {
		for k, v := range m.ExtraLabels {
			labels[k] = v
		}
	}
	for _, k := range reservedMetricLabelKeys {
		delete(labels, k)
	}
	labels["waf_namespace"] = waf.Namespace
	labels["waf_name"] = waf.Name
	labels["engine"] = "modsecurity"
	labels["owner"] = "modsecurity-proxy-wasm"
	plugin["metric_labels"] = labels

	if tel := buildTelemetryPluginJSON(waf, telDefaults); tel != nil {
		plugin["telemetry"] = tel
	}

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

	// Client-facing deny replies stay product-neutral (no vendor names in body/headers).
	plugin["block"] = buildBlockPluginJSON(waf.Spec.Block)
	return plugin
}

// buildTelemetryPluginJSON emits policy only. Absent spec.telemetry → omit.
// Explicit mode None → {mode: None} only. Never emit telemetry.otel.
func buildTelemetryPluginJSON(waf *wafv1beta1.WAF, defaults TelemetryDefaults) map[string]any {
	if waf == nil || waf.Spec.Telemetry == nil {
		return nil
	}
	t := waf.Spec.Telemetry
	mode := t.Mode
	if mode == "" {
		mode = wafv1beta1.TelemetryModeNone
	}
	out := map[string]any{"mode": string(mode)}
	if mode != wafv1beta1.TelemetryModeManaged {
		return out
	}

	enabled := strings.EqualFold(defaults.Profile, "full")
	sampleRate := defaults.SampleNonDisruptive
	if sampleRate == "" {
		sampleRate = "0.25"
	}
	sampleDisruptive := defaults.SampleDisruptive
	if sampleDisruptive == "" {
		sampleDisruptive = "1.0"
	}
	// Product default is redact=true. Helm/operator set TelemetryDefaults.Redact
	// explicitly; a zero-value defaults struct must not flip that off.
	redact := true
	if defaults.Profile != "" {
		redact = defaults.Redact
	}
	includeMatch := defaults.IncludeMatchData
	if tr := t.Traces; tr != nil {
		if tr.Enabled != nil {
			enabled = *tr.Enabled
		}
		if tr.SampleRate != "" {
			sampleRate = tr.SampleRate
		}
		if tr.SampleDisruptive != "" {
			sampleDisruptive = tr.SampleDisruptive
		}
		if tr.Redact != nil {
			redact = *tr.Redact
		}
		if tr.IncludeMatchData != nil {
			includeMatch = *tr.IncludeMatchData
		}
	}

	out["traces"] = map[string]any{
		"enabled":            enabled,
		"sample_rate":        sampleRate,
		"sample_disruptive":  sampleDisruptive,
		"redact":             redact,
		"include_match_data": includeMatch,
	}
	return out
}

// buildBlockPluginJSON maps WAF.spec.block into the engine plugin `block` object.
// Defaults match product-neutral deny replies (Forbidden / x-blocked).
func buildBlockPluginJSON(b *wafv1beta1.WAFBlock) map[string]any {
	message := "Forbidden"
	blockedHeader := "x-blocked"
	addBlockedHeader := true
	addRequestIDHeader := false
	requestIDHeader := "x-request-id"

	if b != nil {
		if b.Message != "" {
			message = b.Message
		}
		if b.AddBlockedHeader != nil {
			addBlockedHeader = *b.AddBlockedHeader
		}
		if b.BlockedHeader != "" {
			blockedHeader = b.BlockedHeader
		}
		if b.AddRequestIDHeader != nil {
			addRequestIDHeader = *b.AddRequestIDHeader
		}
		if b.RequestIDHeader != "" {
			requestIDHeader = b.RequestIDHeader
		}
	}

	// Empty blocked_header tells the wasm filter to omit the marker entirely.
	if !addBlockedHeader {
		blockedHeader = ""
	}

	return map[string]any{
		"message":               message,
		"blocked_header":        blockedHeader,
		"add_rule_id_header":    false,
		"rule_id_header":        "x-blocked-rule-id",
		"add_request_id_header": addRequestIDHeader,
		"request_id_header":     requestIDHeader,
	}
}

// attachDataFiles sets data_files (+ optional encoding) on plugin JSON for wasm runtime map.
func attachDataFiles(plugin map[string]any, files map[string][]byte, overrideCRS int) {
	if len(files) == 0 {
		return
	}
	// Prefer plain base64 map when small; gzip+base64 each body when large.
	const plainThreshold = 4 * 1024
	rawTotal := 0
	for _, b := range files {
		rawTotal += len(b)
	}
	out := make(map[string]any, len(files))
	useGzip := rawTotal >= plainThreshold
	var encCount, rawSum, compSum int
	for name, body := range files {
		rawSum += len(body)
		if useGzip {
			encoded, rawN, compN, err := CompressBytesGzipBase64(body)
			if err != nil {
				// Fall back to plain base64 for this entry.
				out[name] = base64Encode(body)
				continue
			}
			out[name] = encoded
			encCount++
			compSum += compN
			_ = rawN
		} else {
			out[name] = base64Encode(body)
		}
	}
	plugin["data_files"] = out
	if useGzip && encCount > 0 {
		plugin["data_files_encoding"] = DirectivesEncodingGzipBase64
	} else {
		plugin["data_files_encoding"] = "base64"
	}
	plugin["data_files_stats"] = map[string]any{
		"count":              len(files),
		"raw_bytes":          rawSum,
		"compressed_bytes":   compSum,
		"override_crs_count": overrideCRS,
	}
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// attachDirectives sets directives_map (+ optional directives_encoding) on plugin JSON.
func attachDirectives(plugin map[string]any, directives []string) {
	// Tiny configs: plain string array (debug-friendly). Large lists: gzip+base64.
	if !ShouldCompressDirectives(directives) {
		plugin["directives_map"] = map[string]any{
			"default": directives,
		}
		return
	}
	encoded, rawN, compN, err := CompressDirectivesGzipBase64(directives)
	if err != nil {
		// Fall back to plain on compress failure (must never block WAF publish).
		plugin["directives_map"] = map[string]any{
			"default": directives,
		}
		return
	}
	plugin["directives_encoding"] = DirectivesEncodingGzipBase64
	plugin["directives_map"] = map[string]any{
		"default": encoded,
	}
	plugin["directives_stats"] = map[string]any{
		"raw_bytes":        rawN,
		"compressed_bytes": compN,
		"encoding":         DirectivesEncodingGzipBase64,
	}
}

func buildChallengeFilter(waf *wafv1beta1.WAF, opts BuildOptions) (*PortableFilter, error) {
	ch := waf.Spec.Challenge
	if ch == nil {
		return nil, fmt.Errorf("challenge is nil")
	}

	// Resolve HMAC: controller-injected value first, then inline / SecretRef map.
	// Identity-only builds (e.g. EG extension_resources stubs) may omit the secret;
	// ECDS publish paths always inject ChallengeHMAC via the reconciler.
	secret := opts.ChallengeHMAC
	if secret == "" {
		secret = ch.Secret
	}
	if secret == "" && ch.SecretRef != nil {
		key := waf.Namespace + "/" + ch.SecretRef.Name + "/" + ch.SecretRef.Key
		if opts.ChallengeSecrets != nil {
			if v, ok := opts.ChallengeSecrets[key]; ok {
				secret = v
			}
		}
	}

	plugin := map[string]any{}
	if secret != "" {
		if len(secret) < 32 {
			return nil, fmt.Errorf("challenge HMAC secret must be at least 32 bytes (got %d)", len(secret))
		}
		plugin["secret"] = secret
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
	httpURL := opts.moduleURL(engine.ModuleChallenge)
	sha := opts.moduleSHA(engine.ModuleChallenge)
	if httpURL == "" {
		return nil, fmt.Errorf("challenge wasm HTTP URL is not configured; ensure challenge-proxy-wasm is loaded on the operator")
	}
	if strings.TrimSpace(sha) == "" {
		return nil, fmt.Errorf("challenge wasm SHA-256 is not configured (url %s); ensure the module is loaded on the operator", httpURL)
	}

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

// ChallengeEnabled reports whether the PoW challenge filter should be installed.
func ChallengeEnabled(ch *wafv1beta1.ChallengeSpec) bool {
	if ch == nil {
		return false
	}
	if ch.Enabled == nil {
		return true // presence of block with default enabled=true
	}
	return *ch.Enabled
}

// AnnotationFTWProfile enables the embedded ModSecurity FTW overlay
// (Include @ftw-conf) for CRS go-ftw regression: DetectionOnly, PL4 limits,
// and X-CRS-Test log markers. Must load before CRS includes.
const AnnotationFTWProfile = "kubewaf.io/ftw-profile"

// BuildDirectives constructs the ordered SecLang directive list for a WAF.
//
// Order is intentional:
//  1. Include @kubewaf-defaults — ModSecurity only: body access, tmp dirs
//  2. SecRuleEngine / SecDebugLogLevel
//  3. Include @ftw-conf — when annotation kubewaf.io/ftw-profile=true (ModSecurity)
//  4. Path A (crsEnable): Include @crs-setup-conf + CRSSetupActions + Include @owasp_crs + exclusions
//  5. Path B (no crsEnable): CRSSetupActions when spec.crs is set (before user rules)
//  6. User RuleSet SecLang (structured CRS / custom)
//  7. Path B: CRSExclusions after user rules (removeById/tag/updateTarget apply to loaded CRs)
//
// WAF.spec.crs tuning works with Path A (crsEnable) or Path B structured RuleSets with
// crsEnable:false and still set paranoia / thresholds / exclusions.
func BuildDirectives(waf *wafv1beta1.WAF, rules []string) []string {
	// Production-safe default when unset (0). CRD default is also 1.
	// Note: ModSecurity treats 0 as "off"; with an int field we cannot distinguish
	// unset from off — prefer error-level logging over silent max-debug (old default 7).
	logLevel := waf.Spec.LogLevel
	if logLevel == 0 {
		logLevel = 1
	}
	out := make([]string, 0, 8+len(rules))
	// @kubewaf-defaults is embedded in modsecurity-proxy-wasm.
	out = append(out, "Include @kubewaf-defaults")
	out = append(out,
		"SecRuleEngine "+secRuleEngineValue(waf),
		"SecDebugLogLevel "+strconv.Itoa(logLevel),
	)
	// FTW profile must precede CRS so DetectionOnly + markers apply first.
	if ftwProfileEnabled(waf) {
		out = append(out, "Include @ftw-conf")
	}

	crs := waf.Spec.CRS
	if waf.Spec.CRSEnable {
		// Path A: engine-embedded CRS via virtual includes.
		out = append(out, "Include @crs-setup-conf")
		if crs != nil {
			out = append(out, CRSSetupActions(crs)...)
		}
		out = append(out, "Include @owasp_crs/*.conf")
		// Exclusions immediately after includes (classic CRS load order).
		if crs != nil {
			out = append(out, CRSExclusions(crs)...)
		}
	} else if crs != nil {
		// Path B: no engine includes — setup SecAction before RuleSet SecLang so
		// thresholds/paranoia apply before anomaly-scoring rules evaluate.
		out = append(out, CRSSetupActions(crs)...)
	}

	out = append(out, rules...)

	// Path B exclusions after structured rules so SecRuleRemoveById/Tag and
	// SecRuleUpdateTargetById apply to CRs loaded from RuleSets.
	if !waf.Spec.CRSEnable && crs != nil {
		out = append(out, CRSExclusions(crs)...)
	}
	return out
}

// secRuleEngineValue maps WAF.spec.mode to the SecRuleEngine argument.
func secRuleEngineValue(waf *wafv1beta1.WAF) string {
	if waf != nil && waf.Spec.Mode == wafv1beta1.WAFModeDetectionOnly {
		return "DetectionOnly"
	}
	return "On"
}

func ftwProfileEnabled(waf *wafv1beta1.WAF) bool {
	if waf == nil {
		return false
	}
	v, ok := waf.Annotations[AnnotationFTWProfile]
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
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

// crsSetupVersionStamp is the tx.crs_setup_version value expected by OWASP CRS 4.x
// REQUEST-901-INITIALIZATION rule 901001. Without this stamp, 901001 denies every
// request with status 500 ("CRS is deployed without configuration").
// Path A sets it via Include @crs-setup-conf (rule 900990); Path B must set it here.
const crsSetupVersionStamp = 427 // CRS 4.27.x

// CRSSetupActions returns zero or one SecAction directive for CRS thresholds.
// When non-nil, always stamps tx.crs_setup_version so structured CRS SecRules
// (Path B) do not trip rule 901001.
func CRSSetupActions(crs *wafv1beta1.CRSTuning) []string {
	if crs == nil {
		return nil
	}
	// Always set setup version first — required by CRS REQUEST-901-INITIALIZATION.
	sets := []string{fmt.Sprintf("setvar:tx.crs_setup_version=%d", crsSetupVersionStamp)}
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
	// Use 900990 (official CRS setup-version id) so we do not collide with
	// REQUEST-901 defaults that also use 900000-range ids for paranoia.
	action := fmt.Sprintf(`SecAction "id:900990,phase:1,nolog,pass,%s"`, strings.Join(sets, ","))
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
	// Default / Auto: prefer controller discovery, then DefaultProvider.
	provider = DefaultProvider
	if opts.DetectedProvider != "" && opts.DetectedProvider != wafv1beta1.ProviderAuto {
		provider = opts.DetectedProvider
	}
	istioCtx = "GATEWAY"
	istioSel = map[string]string{"istio": "ingressgateway"}
	ciliumSvc = waf.Name
	ciliumNS = waf.Namespace
	if opts.DetectedCiliumServiceName != "" {
		ciliumSvc = opts.DetectedCiliumServiceName
		if opts.DetectedCiliumServiceNamespace != "" {
			ciliumNS = opts.DetectedCiliumServiceNamespace
		}
	}

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
		// Keep discovery / default already set above.
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
