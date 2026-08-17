package config

import (
	"strings"
	"testing"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

func TestBuildFromWAF_ModSecurityEngine(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			LogLevel: 3,
			Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
			Metrics: &wafv1beta1.WAFMetrics{
				IncludeRuleID: boolPtr(false),
				EnableStats:   boolPtr(true),
				ExtraLabels:   map[string]string{"team": "payments"},
			},
		},
	}
	opts := BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://ecds.svc:18002/wasm/modsecurity-proxy-wasm.wasm",
		},
		DefaultModuleSHA256: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	p, err := BuildFromWAF(waf, []string{`SecRule ARGS "@rx x" "id:100001,phase:2,pass"`}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if p.Engine != wafv1beta1.EngineModSecurity {
		t.Fatalf("engine=%s", p.Engine)
	}
	if len(p.Filters) != 1 || p.Filters[0].ModuleID != engine.ModuleModSecurity {
		t.Fatalf("filters=%+v", p.Filters)
	}
	labels, _ := p.PluginJSON["metric_labels"].(map[string]string)
	if labels["owner"] != "modsecurity-proxy-wasm" {
		t.Fatalf("labels=%v", labels)
	}
	if labels["waf_namespace"] != "ns1" || labels["waf_name"] != "shop" {
		t.Fatalf("identity labels=%v", labels)
	}
	if labels["engine"] != "modsecurity" {
		t.Fatalf("engine label=%v", labels)
	}
	if labels["team"] != "payments" {
		t.Fatalf("extra labels=%v", labels)
	}
	if _, ok := p.PluginJSON["telemetry"]; ok {
		t.Fatalf("telemetry must be omitted when spec.telemetry is absent: %v", p.PluginJSON["telemetry"])
	}
	if p.PluginJSON["mode"] != "kubewaf" {
		t.Fatalf("mode=%v", p.PluginJSON["mode"])
	}
	if p.PluginJSON["config_id"] != "kubewaf/ns1/shop" {
		t.Fatalf("config_id=%v", p.PluginJSON["config_id"])
	}
	if p.PluginJSON["allow_fallback"] != false {
		t.Fatalf("allow_fallback=%v", p.PluginJSON["allow_fallback"])
	}
	metrics, ok := p.PluginJSON["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("metrics type %T", p.PluginJSON["metrics"])
	}
	if metrics["per_rule_id"] != false {
		t.Fatalf("per_rule_id=%v", metrics["per_rule_id"])
	}
	if metrics["enabled"] != true {
		t.Fatalf("enabled=%v", metrics["enabled"])
	}
	if p.PluginJSON["metrics_per_rule_id"] != false {
		t.Fatalf("flat metrics_per_rule_id=%v", p.PluginJSON["metrics_per_rule_id"])
	}
	block, ok := p.PluginJSON["block"].(map[string]any)
	if !ok {
		t.Fatalf("block type %T", p.PluginJSON["block"])
	}
	if block["message"] != "Forbidden" {
		t.Fatalf("block.message=%v", block["message"])
	}
	if block["blocked_header"] != "x-blocked" {
		t.Fatalf("block.blocked_header=%v", block["blocked_header"])
	}
	if block["rule_id_header"] != "x-blocked-rule-id" {
		t.Fatalf("block.rule_id_header=%v", block["rule_id_header"])
	}
	if block["add_request_id_header"] != false {
		t.Fatalf("block.add_request_id_header=%v", block["add_request_id_header"])
	}
	if block["request_id_header"] != "x-request-id" {
		t.Fatalf("block.request_id_header=%v", block["request_id_header"])
	}
}

func TestBuildFromWAF_BlockHeaders(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			LogLevel: 3,
			Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
			Block: &wafv1beta1.WAFBlock{
				Message:            "Access Denied",
				AddBlockedHeader:   boolPtr(true),
				BlockedHeader:      "x-blocked",
				AddRequestIDHeader: boolPtr(true),
				RequestIDHeader:    "x-request-id",
			},
		},
	}
	opts := BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://ecds.svc:18002/wasm/modsecurity-proxy-wasm.wasm",
		},
		DefaultModuleSHA256: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	p, err := BuildFromWAF(waf, []string{`SecRule ARGS "@rx x" "id:100001,phase:2,pass"`}, opts)
	if err != nil {
		t.Fatal(err)
	}
	block, ok := p.PluginJSON["block"].(map[string]any)
	if !ok {
		t.Fatalf("block type %T", p.PluginJSON["block"])
	}
	if block["message"] != "Access Denied" {
		t.Fatalf("block.message=%v", block["message"])
	}
	if block["blocked_header"] != "x-blocked" {
		t.Fatalf("block.blocked_header=%v", block["blocked_header"])
	}
	if block["add_request_id_header"] != true {
		t.Fatalf("block.add_request_id_header=%v", block["add_request_id_header"])
	}
	if block["request_id_header"] != "x-request-id" {
		t.Fatalf("block.request_id_header=%v", block["request_id_header"])
	}
}

func TestBuildFromWAF_BlockOmitBlockedHeader(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
			Block: &wafv1beta1.WAFBlock{
				AddBlockedHeader:   boolPtr(false),
				AddRequestIDHeader: boolPtr(true),
			},
		},
	}
	opts := BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://ecds.svc:18002/wasm/modsecurity-proxy-wasm.wasm",
		},
		DefaultModuleSHA256: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	p, err := BuildFromWAF(waf, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	block := p.PluginJSON["block"].(map[string]any)
	if block["blocked_header"] != "" {
		t.Fatalf("expected empty blocked_header, got %v", block["blocked_header"])
	}
	if block["add_request_id_header"] != true {
		t.Fatalf("add_request_id_header=%v", block["add_request_id_header"])
	}
	// Directives must start with production baseline virtual include.
	if len(p.Directives) == 0 || p.Directives[0] != "Include @kubewaf-defaults" {
		t.Fatalf("directives[0]=%v full=%v", firstOrEmpty(p.Directives), p.Directives)
	}
}

func firstOrEmpty(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

func TestBuildDirectives_Order(t *testing.T) {
	waf := &wafv1beta1.WAF{
		Spec: wafv1beta1.WAFSpec{
			LogLevel:  3,
			CRSEnable: true,
			CRS: &wafv1beta1.CRSTuning{
				ParanoiaLevel: intPtr(2),
			},
		},
	}
	dirs := BuildDirectives(waf, []string{`SecRule ARGS "@rx x" "id:100001,phase:2,pass"`})
	if dirs[0] != "Include @kubewaf-defaults" {
		t.Fatalf("want kubewaf-defaults first, got %v", dirs)
	}
	joined := strings.Join(dirs, "\n")
	for _, want := range []string{
		"SecRuleEngine On",
		"Include @crs-setup-conf",
		"Include @owasp_crs/*.conf",
		"id:100001",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("directives missing %q: %v", want, dirs)
		}
	}
}

func TestBuildDirectives_DefaultsAndMode(t *testing.T) {
	// Unset logLevel → production-safe default 1; mode unset → SecRuleEngine On.
	waf := &wafv1beta1.WAF{Spec: wafv1beta1.WAFSpec{}}
	dirs := BuildDirectives(waf, nil)
	joined := strings.Join(dirs, "\n")
	if !strings.Contains(joined, "SecRuleEngine On") {
		t.Fatalf("want SecRuleEngine On, got %v", dirs)
	}
	if !strings.Contains(joined, "SecDebugLogLevel 1") {
		t.Fatalf("want default SecDebugLogLevel 1, got %v", dirs)
	}

	waf.Spec.Mode = wafv1beta1.WAFModeDetectionOnly
	waf.Spec.LogLevel = 3
	dirs = BuildDirectives(waf, nil)
	joined = strings.Join(dirs, "\n")
	if !strings.Contains(joined, "SecRuleEngine DetectionOnly") {
		t.Fatalf("want DetectionOnly, got %v", dirs)
	}
	if !strings.Contains(joined, "SecDebugLogLevel 3") {
		t.Fatalf("want log level 3, got %v", dirs)
	}
}

func TestBuildDirectives_PathB_CRSTuningWithoutEnable(t *testing.T) {
	pl := 2
	inTh := 10
	waf := &wafv1beta1.WAF{
		Spec: wafv1beta1.WAFSpec{
			LogLevel:  3,
			CRSEnable: false, // Path B: structured RuleSets only
			CRS: &wafv1beta1.CRSTuning{
				ParanoiaLevel:           &pl,
				InboundAnomalyThreshold: &inTh,
				RemoveByID:              []int{942100},
				RemoveByTag:             []string{"attack-php"},
				UpdateTargetByID: []wafv1beta1.TargetExclusion{
					{ID: 920273, RemoveTargets: []string{"ARGS:json_blob"}},
				},
			},
		},
	}
	user := `SecRule ARGS "@rx x" "id:942100,phase:2,pass"`
	dirs := BuildDirectives(waf, []string{user})
	joined := strings.Join(dirs, "\n")

	// No engine includes when crsEnable is false.
	for _, ban := range []string{"Include @crs-setup-conf", "Include @owasp_crs"} {
		if strings.Contains(joined, ban) {
			t.Fatalf("Path B must not emit %q: %v", ban, dirs)
		}
	}
	// Setup before user rules; exclusions after.
	iSetup := -1
	iUser := -1
	iRemove := -1
	for i, d := range dirs {
		if strings.Contains(d, "id:900990") && strings.Contains(d, "crs_setup_version=427") {
			iSetup = i
		}
		if strings.Contains(d, "id:942100") && strings.HasPrefix(d, "SecRule ") {
			iUser = i
		}
		if d == "SecRuleRemoveById 942100" {
			iRemove = i
		}
	}
	if iSetup < 0 || iUser < 0 || iRemove < 0 {
		t.Fatalf("missing setup/user/remove: setup=%d user=%d remove=%d dirs=%v", iSetup, iUser, iRemove, dirs)
	}
	if iSetup >= iUser || iUser >= iRemove {
		t.Fatalf("want setup < user rules < exclusions, got setup=%d user=%d remove=%d\n%v", iSetup, iUser, iRemove, dirs)
	}
	if !strings.Contains(joined, "detection_paranoia_level=2") {
		t.Fatalf("missing paranoia setup: %v", dirs)
	}
	if !strings.Contains(joined, "SecRuleRemoveByTag attack-php") {
		t.Fatalf("missing tag exclusion: %v", dirs)
	}
	if !strings.Contains(joined, `SecRuleUpdateTargetById 920273 "!ARGS:json_blob"`) {
		t.Fatalf("missing updateTarget: %v", dirs)
	}
}

func TestBuildDirectives_FTWProfile(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{AnnotationFTWProfile: "true"},
		},
		Spec: wafv1beta1.WAFSpec{
			LogLevel:  3,
			CRSEnable: true,
		},
	}
	dirs := BuildDirectives(waf, nil)
	joined := strings.Join(dirs, "\n")
	if !strings.Contains(joined, "Include @ftw-conf") {
		t.Fatalf("ftw-profile annotation should Include @ftw-conf: %v", dirs)
	}
	// FTW overlay must load before CRS includes.
	ftwIdx, crsIdx := -1, -1
	for i, d := range dirs {
		if d == "Include @ftw-conf" {
			ftwIdx = i
		}
		if d == "Include @owasp_crs/*.conf" {
			crsIdx = i
		}
	}
	if ftwIdx < 0 || crsIdx < 0 || ftwIdx > crsIdx {
		t.Fatalf("want @ftw-conf before CRS includes, got ftw=%d crs=%d dirs=%v", ftwIdx, crsIdx, dirs)
	}

	// Without annotation: no ftw-conf.
	waf.Annotations = nil
	dirs = BuildDirectives(waf, nil)
	for _, d := range dirs {
		if d == "Include @ftw-conf" {
			t.Fatalf("unexpected @ftw-conf without annotation: %v", dirs)
		}
	}
}

func TestBuildFromWAF_ChallengeFilter(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Challenge: &wafv1beta1.ChallengeSpec{
				Enabled:        boolPtr(true),
				BaseDifficulty: intPtr(16),
			},
		},
	}
	opts := BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		// Controller-resolved HMAC (auto-generated Secret).
		ChallengeHMAC: "super-secret-hmac-key-for-tests-32b",
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://ecds.svc:18002/wasm/modsecurity-proxy-wasm.wasm",
			engine.ModuleChallenge:   "http://ecds.svc:18002/wasm/challenge-proxy-wasm.wasm",
		},
		DefaultModuleSHA256: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			engine.ModuleChallenge:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	p, err := BuildFromWAF(waf, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Filters) != 2 {
		t.Fatalf("want 2 filters, got %d", len(p.Filters))
	}
	if p.Filters[0].Role != FilterRoleChallenge {
		t.Fatalf("first filter should be challenge: %s", p.Filters[0].Role)
	}
	if p.Filters[1].Role != FilterRoleWAF {
		t.Fatalf("second filter should be waf: %s", p.Filters[1].Role)
	}
	if p.Filters[0].PluginJSON["secret"] != "super-secret-hmac-key-for-tests-32b" {
		t.Fatalf("secret not set: %v", p.Filters[0].PluginJSON["secret"])
	}
	if p.Filters[0].ExtensionName != "kubewaf/ns1/shop/challenge" {
		t.Fatalf("challenge name=%s", p.Filters[0].ExtensionName)
	}
}

func TestBuildFromWAF_ChallengeFilter_InlineSecretFallback(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Challenge: &wafv1beta1.ChallengeSpec{
				Enabled: boolPtr(true),
				Secret:  "inline-secret-at-least-32-bytes!!",
			},
		},
	}
	opts := BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://ecds.svc:18002/wasm/modsecurity-proxy-wasm.wasm",
			engine.ModuleChallenge:   "http://ecds.svc:18002/wasm/challenge-proxy-wasm.wasm",
		},
		DefaultModuleSHA256: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			engine.ModuleChallenge:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	p, err := BuildFromWAF(waf, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if p.Filters[0].PluginJSON["secret"] != "inline-secret-at-least-32-bytes!!" {
		t.Fatalf("inline secret not used: %v", p.Filters[0].PluginJSON["secret"])
	}
}

func TestBuildFromWAF_IstioProvider(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			LogLevel: 3,
			Provider: &wafv1beta1.WAFProvider{
				Type:        wafv1beta1.ProviderIstio,
				ECDSCluster: "my_ecds",
				ECDSService: "ecds.ns.svc:18001",
				Istio: &wafv1beta1.IstioProvider{
					WorkloadSelector: map[string]string{"app": "istio-ingress"},
					Context:          "GATEWAY",
				},
			},
		},
	}
	p, err := BuildFromWAF(waf, []string{`SecRule ARGS "@rx x" "id:100001,phase:2,pass"`}, BuildOptions{
		DefaultECDSHost: "default-host",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://h/m.wasm",
		},
		DefaultModuleSHA256: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Provider != wafv1beta1.ProviderIstio {
		t.Fatalf("provider=%s", p.Provider)
	}
	if p.ExtensionName != "kubewaf/ns1/shop" {
		t.Fatalf("extension name=%s", p.ExtensionName)
	}
}

func TestBuildFromWAF_IdentityPinIgnoresExtraLabelSpoof(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
			Metrics: &wafv1beta1.WAFMetrics{
				ExtraLabels: map[string]string{
					"waf_namespace": "other-ns",
					"waf_name":      "other-waf",
					"engine":        "spoof",
					"owner":         "spoof-owner",
					"team":          "payments",
				},
			},
		},
	}
	p, err := BuildFromWAF(waf, nil, testBuildOpts())
	if err != nil {
		t.Fatal(err)
	}
	labels, _ := p.PluginJSON["metric_labels"].(map[string]string)
	if labels["waf_namespace"] != "ns1" || labels["waf_name"] != "shop" {
		t.Fatalf("identity spoofed: %v", labels)
	}
	if labels["engine"] != "modsecurity" || labels["owner"] != "modsecurity-proxy-wasm" {
		t.Fatalf("reserved labels spoofed: %v", labels)
	}
	if labels["team"] != "payments" {
		t.Fatalf("extra label dropped: %v", labels)
	}
}

func TestBuildFromWAF_TelemetryNone(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Provider:  &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
			Telemetry: &wafv1beta1.WAFTelemetry{Mode: wafv1beta1.TelemetryModeNone},
		},
	}
	p, err := BuildFromWAF(waf, nil, testBuildOpts())
	if err != nil {
		t.Fatal(err)
	}
	tel, ok := p.PluginJSON["telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("telemetry type %T", p.PluginJSON["telemetry"])
	}
	if tel["mode"] != "None" {
		t.Fatalf("mode=%v", tel["mode"])
	}
	if _, has := tel["traces"]; has {
		t.Fatalf("None must not emit traces: %v", tel)
	}
	if _, has := tel["otel"]; has {
		t.Fatalf("must not emit telemetry.otel: %v", tel)
	}
	if p.TelemetryManaged {
		t.Fatal("TelemetryManaged should be false")
	}
}

func TestBuildFromWAF_TelemetryManagedPolicy(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
			Telemetry: &wafv1beta1.WAFTelemetry{
				Mode: wafv1beta1.TelemetryModeManaged,
				Traces: &wafv1beta1.WAFTelemetryTraces{
					Enabled:          boolPtr(true),
					SampleRate:       "0.25",
					SampleDisruptive: "1.0",
					Redact:           boolPtr(true),
					IncludeMatchData: boolPtr(false),
				},
			},
		},
	}
	opts := testBuildOpts()
	opts.TelemetryDefaults = TelemetryDefaults{Profile: "lite"}
	opts.DefaultOTelHost = "kubewaf-otel-collector.kubewaf-system.svc.cluster.local"
	p, err := BuildFromWAF(waf, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !p.TelemetryManaged {
		t.Fatal("TelemetryManaged")
	}
	if p.OTelCluster != DefaultOTelCluster || p.OTelPort != DefaultOTelPort {
		t.Fatalf("otel cluster=%s port=%d", p.OTelCluster, p.OTelPort)
	}
	if p.OTelHost != opts.DefaultOTelHost {
		t.Fatalf("otel host=%s", p.OTelHost)
	}
	tel := p.PluginJSON["telemetry"].(map[string]any)
	if tel["mode"] != "Managed" {
		t.Fatalf("mode=%v", tel["mode"])
	}
	if _, has := tel["otel"]; has {
		t.Fatalf("must not emit telemetry.otel: %v", tel)
	}
	tr := tel["traces"].(map[string]any)
	if tr["enabled"] != true || tr["sample_rate"] != "0.25" || tr["sample_disruptive"] != "1.0" {
		t.Fatalf("traces=%v", tr)
	}
	if tr["redact"] != true || tr["include_match_data"] != false {
		t.Fatalf("traces redact/match=%v", tr)
	}
}

func TestBuildFromWAF_TelemetryManagedProfileDefaults(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Provider:  &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
			Telemetry: &wafv1beta1.WAFTelemetry{Mode: wafv1beta1.TelemetryModeManaged},
		},
	}
	lite, err := BuildFromWAF(waf, nil, func() BuildOptions {
		o := testBuildOpts()
		o.TelemetryDefaults = TelemetryDefaults{Profile: "lite", Redact: true}
		return o
	}())
	if err != nil {
		t.Fatal(err)
	}
	tr := lite.PluginJSON["telemetry"].(map[string]any)["traces"].(map[string]any)
	if tr["enabled"] != false {
		t.Fatalf("lite traces.enabled=%v", tr["enabled"])
	}

	full, err := BuildFromWAF(waf, nil, func() BuildOptions {
		o := testBuildOpts()
		o.TelemetryDefaults = TelemetryDefaults{Profile: "full", Redact: true, SampleNonDisruptive: "0.25", SampleDisruptive: "1.0"}
		return o
	}())
	if err != nil {
		t.Fatal(err)
	}
	tr = full.PluginJSON["telemetry"].(map[string]any)["traces"].(map[string]any)
	if tr["enabled"] != true {
		t.Fatalf("full traces.enabled=%v", tr["enabled"])
	}
	if tr["sample_rate"] != "0.25" || tr["sample_disruptive"] != "1.0" {
		t.Fatalf("full rates=%v", tr)
	}
}

func TestBuildFromWAF_EnableStatsFalseStillManaged(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
			Metrics:  &wafv1beta1.WAFMetrics{EnableStats: boolPtr(false)},
			Telemetry: &wafv1beta1.WAFTelemetry{
				Mode:   wafv1beta1.TelemetryModeManaged,
				Traces: &wafv1beta1.WAFTelemetryTraces{Enabled: boolPtr(true)},
			},
		},
	}
	p, err := BuildFromWAF(waf, nil, testBuildOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !p.TelemetryManaged {
		t.Fatal("TelemetryManaged")
	}
	metrics := p.PluginJSON["metrics"].(map[string]any)
	if metrics["enabled"] != false {
		t.Fatalf("metrics.enabled=%v", metrics["enabled"])
	}
	tel := p.PluginJSON["telemetry"].(map[string]any)
	if tel["mode"] != "Managed" {
		t.Fatalf("telemetry=%v", tel)
	}
}

func testBuildOpts() BuildOptions {
	return BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://ecds.svc:18002/wasm/modsecurity-proxy-wasm.wasm",
		},
		DefaultModuleSHA256: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
}

func TestExtensionNames(t *testing.T) {
	if got := ExtensionName("a", "b"); got != "kubewaf/a/b" {
		t.Fatalf("got %s", got)
	}
	if got := ChallengeExtensionName("a", "b"); got != "kubewaf/a/b/challenge" {
		t.Fatalf("got %s", got)
	}
}
