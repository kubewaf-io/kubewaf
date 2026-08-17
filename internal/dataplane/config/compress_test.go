/*
Copyright 2025 Buzz-IT GmbH.
*/
package config

import (
	"fmt"
	"strings"
	"testing"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCompressDirectives_RoundTrip(t *testing.T) {
	dirs := []string{
		"Include @kubewaf-defaults",
		"SecRuleEngine On",
		`SecRule ARGS "@rx select" "id:942100,phase:2,block"`,
	}
	enc, raw, comp, err := CompressDirectivesGzipBase64(dirs)
	if err != nil {
		t.Fatal(err)
	}
	if raw == 0 || comp == 0 || enc == "" {
		t.Fatalf("raw=%d comp=%d enc empty=%v", raw, comp, enc == "")
	}
	if comp >= raw && raw > 200 {
		t.Fatalf("expected compression for larger payload raw=%d comp=%d", raw, comp)
	}
	plain, err := DecompressDirectivesGzipBase64(enc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range dirs {
		if !strings.Contains(plain, want) {
			t.Fatalf("missing %q in:\n%s", want, plain)
		}
	}
}

func TestShouldCompressDirectives_Threshold(t *testing.T) {
	old := DirectivesCompressThreshold
	t.Cleanup(func() { DirectivesCompressThreshold = old })

	DirectivesCompressThreshold = 100
	small := []string{"SecRuleEngine On"}
	if ShouldCompressDirectives(small) {
		t.Fatal("small should not compress")
	}
	big := []string{strings.Repeat("SecRule ARGS \"@rx x\" \"id:1,phase:2,pass\"\n", 20)}
	// Join of one huge line
	if !ShouldCompressDirectives(big) {
		t.Fatal("large should compress")
	}
	DirectivesCompressThreshold = 0
	if !ShouldCompressDirectives(small) {
		t.Fatal("threshold 0 always compresses non-empty")
	}
}

func TestBuildWAFPluginJSON_CompressesLargeModSecurity(t *testing.T) {
	old := DirectivesCompressThreshold
	DirectivesCompressThreshold = 50
	t.Cleanup(func() { DirectivesCompressThreshold = old })

	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w", Namespace: "ns"},
		Spec:       wafv1beta1.WAFSpec{},
	}
	// Many directives so joined size >> 50.
	dirs := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		dirs = append(dirs, fmt.Sprintf(`SecRule ARGS "@rx attack" "id:%d,phase:2,pass"`, 100000+i))
	}
	plugin := buildWAFPluginJSON(waf, dirs, nil, 0, TelemetryDefaults{})
	if plugin["directives_encoding"] != DirectivesEncodingGzipBase64 {
		t.Fatalf("encoding=%v plugin=%v", plugin["directives_encoding"], plugin)
	}
	dm, ok := plugin["directives_map"].(map[string]any)
	if !ok {
		t.Fatalf("directives_map type %T", plugin["directives_map"])
	}
	enc, ok := dm["default"].(string)
	if !ok || enc == "" {
		t.Fatalf("default should be base64 string, got %T %v", dm["default"], dm["default"])
	}
	// Round-trip
	plain, err := DecompressDirectivesGzipBase64(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, "SecRule ARGS") {
		t.Fatalf("decompressed missing rules:\n%s", plain)
	}
	stats, ok := plugin["directives_stats"].(map[string]any)
	if !ok || stats["raw_bytes"] == nil {
		t.Fatalf("missing directives_stats: %v", plugin["directives_stats"])
	}
}

func TestBuildWAFPluginJSON_SmallModSecurityPlain(t *testing.T) {
	old := DirectivesCompressThreshold
	DirectivesCompressThreshold = 4 * 1024
	t.Cleanup(func() { DirectivesCompressThreshold = old })

	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w", Namespace: "ns"},
		Spec:       wafv1beta1.WAFSpec{},
	}
	dirs := []string{"Include @kubewaf-defaults", "SecRuleEngine On"}
	plugin := buildWAFPluginJSON(waf, dirs, nil, 0, TelemetryDefaults{})
	if plugin["directives_encoding"] != nil {
		t.Fatalf("small config should stay plain: %v", plugin)
	}
}
