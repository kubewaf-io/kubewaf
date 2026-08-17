package waf

import (
	"strings"
	"testing"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

func TestEffectiveMode(t *testing.T) {
	if effectiveMode("") != wafv1beta1.WAFModeBlocking {
		t.Fatal("empty -> Blocking")
	}
	if effectiveMode(wafv1beta1.WAFModeDetectionOnly) != wafv1beta1.WAFModeDetectionOnly {
		t.Fatal("DetectionOnly")
	}
}

func TestRenderDirectivesForStatus_Truncate(t *testing.T) {
	// Build a payload larger than the cap.
	line := strings.Repeat("a", 1000)
	dirs := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		dirs = append(dirs, line)
	}
	text, trunc := renderDirectivesForStatus(dirs)
	if !trunc {
		t.Fatal("expected truncation")
	}
	if len(text) > maxRenderedDirectivesBytes+80 {
		t.Fatalf("still too large: %d", len(text))
	}
	if !strings.Contains(text, "truncated") {
		t.Fatalf("missing marker: %q", text[len(text)-80:])
	}

	small, trunc := renderDirectivesForStatus([]string{"SecRuleEngine On"})
	if trunc || small != "SecRuleEngine On" {
		t.Fatalf("small=%q trunc=%v", small, trunc)
	}
}
