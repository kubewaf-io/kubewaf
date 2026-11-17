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

package compile

import (
	"strings"
	"testing"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildOrdersIncludesAndRewritesFiles(t *testing.T) {
	rule := baseRule()
	rule.Name = "block-sqlmap"
	rule.Spec.Order = 100
	rule.Spec.Placement = seclangv1alpha1.PlacementAfterCRS
	rule.Spec.Chain[0].Operator = seclangv1alpha1.Operator{Name: seclangv1alpha1.PmFromFile, Value: "scanners.data"}
	rule.Spec.Chain[0].Actions = &seclangv1alpha1.Actions{
		Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny},
		Data:       []seclangv1alpha1.DataAction{{Type: seclangv1alpha1.Status, Value: "403"}},
	}

	setup := &seclangv1alpha1.SecAction{
		ObjectMeta: metav1.ObjectMeta{Name: "paranoia"},
		Spec: seclangv1alpha1.SecActionSpec{
			Order: 10, Placement: seclangv1alpha1.PlacementBeforeCRS,
			Metadata: seclangv1alpha1.Metadata{ID: 900990, Phase: 1},
			Actions: &seclangv1alpha1.Actions{
				Disruptive:    &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Pass},
				NonDisruptive: []seclangv1alpha1.NonDisruptiveAction{{Type: seclangv1alpha1.Nolog}},
			},
		},
	}
	portable, err := EmitRule(&rule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(portable, "scanners.data") || strings.Contains(portable, MountDir) {
		t.Fatalf("status text keeps the basename: %s", portable)
	}

	b, err := Build(Input{
		Policy: seclangv1alpha1.SecPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "default"},
			Spec: seclangv1alpha1.SecPolicySpec{
				Engine: "On", Inspection: "RequestOnly", ModuleName: "composer",
				DefaultActions: []seclangv1alpha1.DefaultAction{{Phase: 1, Actions: "log,auditlog,deny,status:403"}},
				PostDirectives: []string{"SecRuleRemoveById 942100"},
				DataFiles:      []seclangv1alpha1.DataFile{{Name: "scanners.data", Content: "sqlmap\n"}},
			},
		},
		Rules:   []seclangv1alpha1.SecRule{rule},
		Actions: []seclangv1alpha1.SecAction{*setup},
		Includes: []IncludeInput{
			{Include: seclangv1alpha1.Include{ObjectMeta: metav1.ObjectMeta{Name: "crs-setup"}, Spec: seclangv1alpha1.IncludeSpec{Order: 20, Placement: seclangv1alpha1.PlacementBeforeCRS, VirtualPath: "@crs-setup.conf"}}},
			{Include: seclangv1alpha1.Include{ObjectMeta: metav1.ObjectMeta{Name: "owasp"}, Spec: seclangv1alpha1.IncludeSpec{Order: 10, Placement: seclangv1alpha1.PlacementAfterCRS, VirtualPath: "@owasp_crs/*.conf"}}},
			{Include: seclangv1alpha1.Include{ObjectMeta: metav1.ObjectMeta{Name: "extra"}, Spec: seclangv1alpha1.IncludeSpec{Order: 50, Placement: seclangv1alpha1.PlacementAfterCRS, ConfigMapRef: &seclangv1alpha1.ConfigMapKeyRef{Name: "rules", Key: "extra.conf"}}}, Content: "SecAction \"id:1,phase:1,pass,nolog\"\n"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.Marker != "KUBEWAF"+b.Hash[:16] || len(b.Hash) != 64 {
		t.Fatalf("marker %s hash %s", b.Marker, b.Hash)
	}
	if b.Inspection != "REQUEST_ONLY" || !b.RequestBodyAccess || b.ResponseBodyAccess {
		t.Fatalf("inspection defaults: %+v", b)
	}
	before := b.Before
	after := b.After
	if !strings.HasPrefix(before, "SecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\n") {
		t.Fatalf("before start:\n%s", before)
	}
	if !strings.Contains(before, "SecAction ") || !strings.Contains(before, "Include @crs-setup.conf") {
		t.Fatalf("before:\n%s", before)
	}
	if strings.Index(before, "id:900990") > strings.Index(before, "Include @crs-setup.conf") {
		t.Fatalf("setup action should sort before the crs include:\n%s", before)
	}
	if !strings.Contains(after, "Include @owasp_crs/*.conf") || !strings.Contains(after, "SecRuleRemoveById 942100") {
		t.Fatalf("after:\n%s", after)
	}
	if !strings.Contains(after, "@pmFromFile /etc/kubewaf/seclang/default_edge_scanners.data") {
		t.Fatalf("rewritten file:\n%s", after)
	}
	if b.Files["default_edge_scanners.data"] != "sqlmap\n" {
		t.Fatal(b.Files["default_edge_scanners.data"])
	}
	if !strings.Contains(after, "SecAction \"id:1,phase:1,pass,nolog\"") {
		t.Fatalf("configmap include was not inlined:\n%s", after)
	}
	if err := ParseFiles(before+"\n"+after, b.Files); err != nil {
		t.Fatal(err)
	}

	b2, err := Build(Input{
		Policy: seclangv1alpha1.SecPolicy{ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "default"}},
		Rules:  []seclangv1alpha1.SecRule{rule},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b2.Marker == b.Marker {
		t.Fatal("hash did not change when the bundle changed")
	}
}

func TestBuildRejectsUnresolvedData(t *testing.T) {
	_, err := Build(Input{
		Policy: seclangv1alpha1.SecPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "default"},
			Spec: seclangv1alpha1.SecPolicySpec{
				DataFiles: []seclangv1alpha1.DataFile{{Name: "a.data", ConfigMapRef: &seclangv1alpha1.ConfigMapKeyRef{Name: "c", Key: "a.data"}}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected unresolved data file")
	}
}
