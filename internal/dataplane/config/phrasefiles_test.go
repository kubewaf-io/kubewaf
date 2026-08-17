/*
Copyright 2025 Buzz-IT GmbH.
*/

package config

import (
	"strings"
	"testing"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
)

func TestScanPmFromFileBasenames(t *testing.T) {
	dirs := []string{
		`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners-user-agents.data" "id:1,phase:1,pass"`,
		`SecRule ARGS "@pmf custom-scanners.data extra.data" "id:2,phase:2,pass"`,
		`SecRule REMOTE_ADDR "@ipMatchFromFile blocklist.data" "id:3,phase:1,deny"`,
		`SecRule REMOTE_ADDR "@ipMatchF allowlist.data" "id:4,phase:1,pass"`,
		`# SecRule ARGS "@pmFromFile ignored.data" "id:5"`,
		`SecRule ARGS "@rx foo" "id:6,phase:2,pass"`,
	}
	got := ScanPmFromFileBasenames(dirs)
	want := map[string]bool{
		"scanners-user-agents.data": true,
		"custom-scanners.data":      true,
		"extra.data":                true,
		"blocklist.data":            true,
		"allowlist.data":            true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %d basenames", got, len(want))
	}
	for _, b := range got {
		if !want[b] {
			t.Errorf("unexpected basename %q", b)
		}
	}
}

func TestDropSecLangLinesWithBasenames(t *testing.T) {
	dirs := []string{
		`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile team-scanners.data" "id:1,phase:1,deny"`,
		`SecRule ARGS "@rx x" "id:2,phase:2,pass"`,
		`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners-user-agents.data" "id:3,phase:1,pass"`,
	}
	out := DropSecLangLinesWithBasenames(dirs, map[string]struct{}{"team-scanners.data": {}})
	if len(out) != 2 {
		t.Fatalf("expected 2 lines remaining, got %d: %v", len(out), out)
	}
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "team-scanners.data") {
		t.Fatal("dropped basename still present")
	}
	if !strings.Contains(joined, "scanners-user-agents.data") {
		t.Fatal("stock CRS line was incorrectly stripped")
	}
}

func TestHashPhraseFilesStable(t *testing.T) {
	a := hashPhraseFiles(map[string][]byte{"b.data": []byte("b"), "a.data": []byte("a")})
	b := hashPhraseFiles(map[string][]byte{"a.data": []byte("a"), "b.data": []byte("b")})
	if a == "" || a != b {
		t.Fatalf("hash not stable: %q vs %q", a, b)
	}
}

func TestStockCRSPhraseListLabelConstant(t *testing.T) {
	// Pack CRs use seclang.kubewaf.io/crs-data=true (see generate-crs-phraselists.py).
	// Keep the API constant aligned so inject accepts pack lists without allow-crs-override.
	const want = "seclang.kubewaf.io/crs-data"
	if seclangv1beta1.LabelCRSData != want {
		t.Fatalf("LabelCRSData = %q, want %q", seclangv1beta1.LabelCRSData, want)
	}
}

func TestScanPmFromFileBasenames_FromConverterOutput(t *testing.T) {
	// Converter must emit SecLang that the inject scanner can discover for
	// PhraseList (@pmFromFile) and IPList (@ipMatchFromFile) basenames.
	rules := []seclangv1beta1.SecRule{
		{
			Spec: seclangv1beta1.SecRuleSpec{
				Metadata: &seclangv1beta1.SecRuleMetadata{
					OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
					Id:                100001,
				},
				Match: []seclangv1beta1.Match{{
					Collections: []seclangv1beta1.Collection{{
						Name:      seclangv1beta1.REQUEST_HEADERS,
						Arguments: []string{"User-Agent"},
					}},
					Operator: seclangv1beta1.Operator{
						Name:  seclangv1beta1.PmFromFile,
						Value: "team-scanners.data",
					},
				}},
				Actions: &seclangv1beta1.SecRuleActions{
					DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Deny},
				},
			},
		},
		{
			Spec: seclangv1beta1.SecRuleSpec{
				Metadata: &seclangv1beta1.SecRuleMetadata{
					OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
					Id:                100002,
				},
				Match: []seclangv1beta1.Match{{
					Variables: []seclangv1beta1.Variable{{Name: seclangv1beta1.REMOTE_ADDR}},
					Operator: seclangv1beta1.Operator{
						Name:  seclangv1beta1.IpMatchFromFile,
						Value: "edge-ip-blocklist.data",
					},
				}},
				Actions: &seclangv1beta1.SecRuleActions{
					DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Deny},
				},
			},
		},
		{
			Spec: seclangv1beta1.SecRuleSpec{
				Metadata: &seclangv1beta1.SecRuleMetadata{
					OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
					Id:                100003,
				},
				Match: []seclangv1beta1.Match{{
					Variables: []seclangv1beta1.Variable{{Name: seclangv1beta1.REMOTE_ADDR}},
					Operator: seclangv1beta1.Operator{
						Name:  seclangv1beta1.IpMatchF,
						Value: "allowlist.data",
					},
				}},
				Actions: &seclangv1beta1.SecRuleActions{
					DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Pass},
				},
			},
		},
	}

	lines := make([]string, 0, len(rules)*2)
	for i, sr := range rules {
		dirs, err := convert.ConvertSecRule(sr)
		if err != nil {
			t.Fatalf("rule[%d] ConvertSecRule: %v", i, err)
		}
		out := convert.ConvertToSecLangString(dirs)
		if out == "" {
			t.Fatalf("rule[%d] empty SecLang", i)
		}
		t.Logf("rule[%d]: %s", i, strings.TrimSpace(out))
		lines = append(lines, strings.Split(out, "\n")...)
	}

	got := ScanPmFromFileBasenames(lines)
	want := map[string]bool{
		"team-scanners.data":     true,
		"edge-ip-blocklist.data": true,
		"allowlist.data":         true,
	}
	for b := range want {
		found := false
		for _, g := range got {
			if g == b {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("basename %q not discovered from converter SecLang; got %v", b, got)
		}
	}
}
