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

package convert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	types "github.com/coreruleset/crslang/types"
	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"sigs.k8s.io/yaml"
)

// FromFile operators are the SecLang contract for PhraseList / IPList basenames:
//   @pmFromFile / @pmf              → PhraseList.spec.fileName
//   @ipMatchFromFile / @ipMatchF    → IPList.spec.fileName
//
// The converter must preserve operator name + basename value end-to-end so
// dataplane ScanPmFromFileBasenames / data_files inject keeps working.

func TestOperatorMapper_FromFileEnums(t *testing.T) {
	fwd := OperatorMapperImpl{}
	rev := OperatorReverseMapperImpl{}

	pairs := []struct {
		api v1beta1.OperatorType
		crs types.OperatorType
	}{
		{v1beta1.PmFromFile, types.PmFromFile},
		{v1beta1.Pmf, types.Pmf},
		{v1beta1.IpMatchFromFile, types.IpMatchFromFile},
		{v1beta1.IpMatchF, types.IpMatchF},
	}
	for _, tc := range pairs {
		t.Run(string(tc.api), func(t *testing.T) {
			got := fwd.Convert(tc.api)
			if got != tc.crs {
				t.Fatalf("API→CRS: got %v want %v", got, tc.crs)
			}
			back := rev.Convert(tc.crs)
			if back != tc.api {
				t.Fatalf("CRS→API: got %v want %v", back, tc.api)
			}
		})
	}
}

func TestConvertSecRule_FromFileOperators_RenderAndRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		op    v1beta1.OperatorType
		value string
		// Exactly one of collection or variable is set.
		collection v1beta1.CollectionName
		arg        string
		variable   v1beta1.VariableName
		// Substrings that must appear in rendered SecLang.
		wantOps []string
	}{
		{
			name:       "pmFromFile-phrase-list",
			op:         v1beta1.PmFromFile,
			value:      "team-scanners.data",
			collection: v1beta1.REQUEST_HEADERS,
			arg:        "User-Agent",
			wantOps:    []string{`@pmFromFile team-scanners.data`, "REQUEST_HEADERS:User-Agent"},
		},
		{
			name:       "pmf-short-alias",
			op:         v1beta1.Pmf,
			value:      "custom-scanners.data",
			collection: v1beta1.REQUEST_HEADERS,
			arg:        "User-Agent",
			// crslang may expand short alias to long form or keep pmf — accept either.
			wantOps: []string{"custom-scanners.data"},
		},
		{
			name:     "ipMatchFromFile-ip-list",
			op:       v1beta1.IpMatchFromFile,
			value:    "edge-ip-blocklist.data",
			variable: v1beta1.REMOTE_ADDR,
			wantOps:  []string{`@ipMatchFromFile edge-ip-blocklist.data`, "REMOTE_ADDR"},
		},
		{
			name:     "ipMatchF-short-alias",
			op:       v1beta1.IpMatchF,
			value:    "allowlist.data",
			variable: v1beta1.REMOTE_ADDR,
			wantOps:  []string{"allowlist.data"},
		},
		{
			name:       "pmFromFile-stock-crs-basename",
			op:         v1beta1.PmFromFile,
			value:      "scanners-user-agents.data",
			collection: v1beta1.REQUEST_HEADERS,
			arg:        "User-Agent",
			wantOps:    []string{`@pmFromFile scanners-user-agents.data`},
		},
		{
			name:       "pmFromFile-negate",
			op:         v1beta1.PmFromFile,
			value:      "lfi-os-files.data",
			collection: v1beta1.ARGS,
			wantOps:    []string{"lfi-os-files.data"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			match := v1beta1.Match{
				Operator: v1beta1.Operator{
					Name:   tc.op,
					Value:  tc.value,
					Negate: strings.Contains(tc.name, "negate"),
				},
			}
			if tc.variable != "" {
				match.Variables = []v1beta1.Variable{{Name: tc.variable}}
			}
			if tc.collection != "" {
				col := v1beta1.Collection{Name: tc.collection}
				if tc.arg != "" {
					col.Arguments = []string{tc.arg}
				}
				match.Collections = []v1beta1.Collection{col}
			}
			sr := v1beta1.SecRule{
				Spec: v1beta1.SecRuleSpec{
					Metadata: &v1beta1.SecRuleMetadata{
						OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
						Id:                100100,
						Msg:               "fromfile test",
					},
					Match: []v1beta1.Match{match},
					Actions: &v1beta1.SecRuleActions{
						DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Deny},
					},
				},
			}

			dirs, err := ConvertSecRule(sr)
			if err != nil {
				t.Fatalf("ConvertSecRule: %v", err)
			}
			if len(dirs) == 0 {
				t.Fatal("no directives")
			}

			// Inspect structured operator on the first RuleWithCondition.
			rwc, ok := dirs[0].(*types.RuleWithCondition)
			if !ok {
				t.Fatalf("want *RuleWithCondition, got %T", dirs[0])
			}
			if len(rwc.Conditions) != 1 {
				t.Fatalf("conditions=%d", len(rwc.Conditions))
			}
			op := rwc.Conditions[0].Operator
			if op.Value != tc.value {
				t.Fatalf("operator value: got %q want %q", op.Value, tc.value)
			}
			// Forward map must not fall through to Eq.
			if op.Name == types.Eq || op.Name == types.UnknownOperator {
				t.Fatalf("operator name collapsed to %v (mapping bug)", op.Name)
			}
			// Round-trip name through reverse mapper should recover API enum.
			gotAPI := operatorMapper.Convert(op.Name)
			if gotAPI != tc.op {
				// Short aliases: crslang may normalize pmf→pmFromFile etc.
				// Accept long-form equivalents for short aliases.
				if !fromFileAliasOK(tc.op, gotAPI) {
					t.Fatalf("operator name round-trip: got API %q want %q (crs=%v)", gotAPI, tc.op, op.Name)
				}
			}
			if strings.Contains(tc.name, "negate") && !op.Negate {
				t.Fatal("expected Negate=true")
			}

			out := ConvertToSecLangString(dirs)
			if out == "" {
				t.Fatal("empty SecLang")
			}
			if strings.Contains(out, "t:unknown") || strings.Contains(out, "@eq ") {
				// @eq with a .data value would mean operator mapping fell to Eq.
				if strings.Contains(out, "@eq ") && strings.Contains(out, ".data") {
					t.Fatalf("operator degraded to @eq:\n%s", out)
				}
			}
			for _, want := range tc.wantOps {
				if !strings.Contains(out, want) {
					t.Fatalf("missing %q in SecLang:\n%s", want, out)
				}
			}
			// Basename must appear for data_files discovery.
			if !strings.Contains(out, tc.value) {
				t.Fatalf("basename %q missing from SecLang:\n%s", tc.value, out)
			}

			// Reverse path: CRS RuleWithCondition → API SecLangSecRule keeps op+value.
			legacy, err := ConvertCrsRule(*rwc, "")
			if err != nil {
				t.Fatalf("ConvertCrsRule: %v", err)
			}
			if len(legacy.Conditions) != 1 {
				t.Fatalf("legacy conditions=%d", len(legacy.Conditions))
			}
			lop := legacy.Conditions[0].Operator
			if lop.Value != tc.value {
				t.Fatalf("ConvertCrsRule value: got %q want %q", lop.Value, tc.value)
			}
			if lop.Name != tc.op && !fromFileAliasOK(tc.op, lop.Name) {
				t.Fatalf("ConvertCrsRule name: got %q want %q", lop.Name, tc.op)
			}
		})
	}
}

func fromFileAliasOK(want, got v1beta1.OperatorType) bool {
	switch want {
	case v1beta1.Pmf:
		return got == v1beta1.PmFromFile || got == v1beta1.Pmf
	case v1beta1.PmFromFile:
		return got == v1beta1.PmFromFile || got == v1beta1.Pmf
	case v1beta1.IpMatchF:
		return got == v1beta1.IpMatchFromFile || got == v1beta1.IpMatchF
	case v1beta1.IpMatchFromFile:
		return got == v1beta1.IpMatchFromFile || got == v1beta1.IpMatchF
	default:
		return false
	}
}

func TestConvertCrsRule_FromFileOperators_CRSToAPI(t *testing.T) {
	cases := []struct {
		name  string
		crsOp types.OperatorType
		value string
		want  v1beta1.OperatorType
	}{
		{"PmFromFile", types.PmFromFile, "scanners-user-agents.data", v1beta1.PmFromFile},
		{"Pmf", types.Pmf, "team-scanners.data", v1beta1.Pmf},
		{"IpMatchFromFile", types.IpMatchFromFile, "edge-ip-blocklist.data", v1beta1.IpMatchFromFile},
		{"IpMatchF", types.IpMatchF, "allowlist.data", v1beta1.IpMatchF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := types.RuleWithCondition{
				Kind: types.RuleKind,
				Metadata: types.SecRuleMetadata{
					OnlyPhaseMetadata: types.OnlyPhaseMetadata{Phase: "1"},
					Id:                913100,
					Msg:               "crs fromfile",
				},
				Conditions: []types.Condition{{
					Collections: []types.Collection{{Name: types.REQUEST_HEADERS, Arguments: []string{"User-Agent"}}},
					Operator: types.Operator{
						Name:  tc.crsOp,
						Value: tc.value,
					},
				}},
			}
			legacy, err := ConvertCrsRule(src, "")
			if err != nil {
				t.Fatalf("ConvertCrsRule: %v", err)
			}
			op := legacy.Conditions[0].Operator
			if op.Name != tc.want {
				t.Fatalf("name: got %q want %q", op.Name, tc.want)
			}
			if op.Value != tc.value {
				t.Fatalf("value: got %q want %q", op.Value, tc.value)
			}

			spec, err := ConvertCrsRuleToSingleForm(src, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(spec.Match) != 1 {
				t.Fatalf("match len=%d", len(spec.Match))
			}
			if spec.Match[0].Operator.Name != tc.want || spec.Match[0].Operator.Value != tc.value {
				t.Fatalf("single form op=%+v", spec.Match[0].Operator)
			}

			// Full loop: CRS → single form → SecLang must keep basename + operator family.
			sr := v1beta1.SecRule{Spec: spec}
			// Single form needs actions for a valid deny path; attach minimal.
			if sr.Spec.Actions == nil {
				sr.Spec.Actions = &v1beta1.SecRuleActions{
					DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
				}
			}
			dirs, err := ConvertSecRule(sr)
			if err != nil {
				t.Fatalf("ConvertSecRule: %v", err)
			}
			out := ConvertToSecLangString(dirs)
			if !strings.Contains(out, tc.value) {
				t.Fatalf("basename lost after full loop:\n%s", out)
			}
			// Must not degrade to @eq.
			if strings.Contains(out, "@eq "+tc.value) || strings.Contains(out, `@eq "`+tc.value) {
				t.Fatalf("degraded to @eq:\n%s", out)
			}
		})
	}
}

func TestConvertSecRule_SamplePhraseListAndIPListYAML(t *testing.T) {
	// Samples are multi-doc YAML (PhraseList/IPList + SecRule). Convert only SecRule docs.
	roots := []string{
		filepath.Join("..", "..", "..", "..", "config", "samples", "phraselist", "team-scanners.yaml"),
		filepath.Join("..", "..", "..", "..", "config", "samples", "iplist", "ip-blocklist.yaml"),
	}
	// Also try absolute from module root via walk-up if relative fails.
	for i, p := range roots {
		if _, err := os.Stat(p); err != nil {
			// From package dir api/seclang/v1beta1/convert → repo root is 4 levels up; already.
			// Try cwd-relative (go test runs with package dir as cwd sometimes, or module root).
			alt := filepath.Join("config", "samples", filepath.Base(filepath.Dir(p)), filepath.Base(p))
			if _, err2 := os.Stat(alt); err2 == nil {
				roots[i] = alt
			}
		}
	}

	want := map[string]struct {
		op    string
		value string
	}{
		"team-scanners.yaml": {op: "pmFromFile", value: "team-scanners.data"},
		"ip-blocklist.yaml":  {op: "ipMatchFromFile", value: "edge-ip-blocklist.data"},
	}

	for _, path := range roots {
		base := filepath.Base(path)
		tc, ok := want[base]
		if !ok {
			continue
		}
		t.Run(base, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				// Last resort: known absolute layout under /data
				raw, err = os.ReadFile(filepath.Join("/data/config/samples",
					map[string]string{
						"team-scanners.yaml": "phraselist/team-scanners.yaml",
						"ip-blocklist.yaml":  "iplist/ip-blocklist.yaml",
					}[base]))
				if err != nil {
					t.Skipf("sample not found: %v", err)
				}
			}
			// Split multi-doc; convert each SecRule.
			docs := splitYAMLDocs(string(raw))
			found := false
			for _, doc := range docs {
				if !strings.Contains(doc, "kind: SecRule") {
					continue
				}
				var sr v1beta1.SecRule
				if err := yaml.Unmarshal([]byte(doc), &sr); err != nil {
					t.Fatalf("unmarshal SecRule: %v\n%s", err, doc)
				}
				if sr.Kind != "" && sr.Kind != "SecRule" {
					continue
				}
				// yaml.v3 may leave Kind empty when TypeMeta not fully set; detect via Spec.
				if sr.Spec.Metadata == nil && len(sr.Spec.Match) == 0 {
					continue
				}
				found = true
				dirs, err := ConvertSecRule(sr)
				if err != nil {
					t.Fatalf("ConvertSecRule: %v", err)
				}
				out := ConvertToSecLangString(dirs)
				if !strings.Contains(out, tc.value) {
					t.Fatalf("missing basename %q:\n%s", tc.value, out)
				}
				// Operator long form should appear for samples.
				if !strings.Contains(strings.ToLower(out), strings.ToLower(tc.op)) {
					t.Fatalf("missing operator %q:\n%s", tc.op, out)
				}
				// Match form operator fields.
				if len(sr.Spec.Match) == 0 {
					t.Fatal("sample SecRule has empty match[]")
				}
				if string(sr.Spec.Match[0].Operator.Name) != tc.op {
					t.Fatalf("sample op name=%q want %q", sr.Spec.Match[0].Operator.Name, tc.op)
				}
				if sr.Spec.Match[0].Operator.Value != tc.value {
					t.Fatalf("sample op value=%q want %q", sr.Spec.Match[0].Operator.Value, tc.value)
				}
			}
			if !found {
				t.Fatal("no SecRule document found in sample")
			}
		})
	}
}

func splitYAMLDocs(s string) []string {
	parts := strings.Split(s, "\n---")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") && !strings.Contains(p, "\nkind:") {
			// keep if it has kind after comments
			if !strings.Contains(p, "kind:") {
				continue
			}
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func TestConvertSecRule_FromFileLegacyBagForm(t *testing.T) {
	// CRS bulk samples use secLangRules[] — must preserve FromFile there too.
	sr := v1beta1.SecRule{
		Spec: v1beta1.SecRuleSpec{
			SecRules: []v1beta1.SecLangSecRule{{
				Metadata: &v1beta1.SecRuleMetadata{
					OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
					Id:                100200,
				},
				Conditions: []v1beta1.Condition{{
					Variables: []v1beta1.Variable{{Name: v1beta1.REMOTE_ADDR}},
					Operator: v1beta1.Operator{
						Name:  v1beta1.IpMatchFromFile,
						Value: "edge-ip-blocklist.data",
					},
				}},
				Actions: &v1beta1.SecRuleActions{
					DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Deny},
				},
			}},
		},
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	if !strings.Contains(out, "edge-ip-blocklist.data") {
		t.Fatalf("legacy bag lost basename:\n%s", out)
	}
	if !strings.Contains(out, "ipMatchFromFile") && !strings.Contains(out, "ipMatchF") {
		t.Fatalf("legacy bag lost ipMatchFromFile:\n%s", out)
	}
}
