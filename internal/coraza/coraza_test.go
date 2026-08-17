package coraza

import (
	"strings"
	"testing"

	"github.com/coreruleset/crslang/types"
	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
)

func TestLoadAndValidateSeclangDirectives_Empty(t *testing.T) {
	if _, err := LoadAndValidateSeclangDirectives(nil); err == nil {
		t.Fatal("expected error for nil directives")
	}
	if _, err := LoadAndValidateSeclangDirectives([]types.SeclangDirective{}); err == nil {
		t.Fatal("expected error for empty slice")
	}
}

func TestLoadAndValidateSeclangDirectives_ValidRule(t *testing.T) {
	sr := seclangv1beta1.SecRule{
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                100001,
			},
			Match: []seclangv1beta1.Match{{AlwaysMatch: true}},
			Actions: &seclangv1beta1.SecRuleActions{
				DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Pass},
				NonDisruptive: []seclangv1beta1.NonDisruptiveAction{
					{Type: seclangv1beta1.NoLog},
				},
			},
		},
	}
	dirs, err := convert.ConvertSecRule(sr)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	waf, err := LoadAndValidateSeclangDirectives(dirs)
	if err != nil {
		t.Fatalf("validate: %v\nseclang=%s", err, convert.ConvertToSecLangString(dirs))
	}
	if waf == nil {
		t.Fatal("expected non-nil WAF")
	}
}

func TestLoadAndValidateSeclangDirectives_PmFromFileCRS(t *testing.T) {
	// Stock CRS phrase list must resolve via go:embed + WithRootFS.
	sr := seclangv1beta1.SecRule{
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                913100,
			},
			Match: []seclangv1beta1.Match{{
				Collections: []seclangv1beta1.Collection{{
					Name:      seclangv1beta1.REQUEST_HEADERS,
					Arguments: []string{"User-Agent"},
				}},
				Operator: seclangv1beta1.Operator{
					Name:  seclangv1beta1.PmFromFile,
					Value: "scanners-user-agents.data",
				},
			}},
			Actions: &seclangv1beta1.SecRuleActions{
				DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Pass},
				NonDisruptive: []seclangv1beta1.NonDisruptiveAction{
					{Type: seclangv1beta1.NoLog},
				},
			},
		},
	}
	dirs, err := convert.ConvertSecRule(sr)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	out := convert.ConvertToSecLangString(dirs)
	if !strings.Contains(out, "pmFromFile") || !strings.Contains(out, "scanners-user-agents.data") {
		t.Fatalf("unexpected seclang: %s", out)
	}
	waf, err := LoadAndValidateSeclangDirectives(dirs)
	if err != nil {
		t.Fatalf("validate with CRS embed failed: %v\nseclang=%s", err, out)
	}
	if waf == nil {
		t.Fatal("expected non-nil WAF")
	}
}
