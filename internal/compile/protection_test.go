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
	wafv1alpha1 "github.com/kubewaf-io/kubewaf/api/waf/v1alpha1"
)

func TestBuildProtectionOrdersCRSAndExclusions(t *testing.T) {
	inbound := int32(5)
	rule := seclangv1alpha1.SecRule{Spec: seclangv1alpha1.SecRuleSpec{
		Order:    1000,
		Metadata: seclangv1alpha1.Metadata{ID: 100001, Phase: 1},
		Chain: []seclangv1alpha1.ChainLink{{
			Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "User-Agent"}},
			Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: "sqlmap"},
			Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny}},
		}},
	}}
	rule.Name = "block-sqlmap"
	bundle, err := BuildProtection(ProtectionInput{
		Namespace: "default",
		Name:      "edge",
		Spec: wafv1alpha1.ProtectionSpec{
			Mode:       "Blocking",
			Inspection: "RequestOnly",
			CRS: &wafv1alpha1.CRSSpec{
				Paranoia:                2,
				InboundAnomalyThreshold: &inbound,
				RemoveIDs:               []int32{942100},
				RemoveTags:              []string{"attack-xss"},
				UpdateTargets:           []wafv1alpha1.TargetUpdate{{ID: 942100, Remove: []string{"ARGS:password"}}},
			},
		},
		Rules: []seclangv1alpha1.SecRule{rule},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Name != "p-edge" || bundle.Engine != "On" {
		t.Fatalf("bundle %+v", bundle)
	}
	before := bundle.Before
	after := bundle.After
	if !strings.Contains(before, "Include @crs-setup.conf") || !strings.Contains(before, "id:900991") {
		t.Fatalf("before\n%s", before)
	}
	setup := strings.Index(before, "Include @crs-setup.conf")
	action := strings.Index(before, "id:900991")
	if setup < 0 || action < setup {
		t.Fatalf("paranoia action must follow crs-setup\n%s", before)
	}
	if !strings.Contains(before, "tx.blocking_paranoia_level=2") || !strings.Contains(before, "tx.inbound_anomaly_score_threshold=5") {
		t.Fatalf("setvar missing\n%s", before)
	}
	owasp := strings.Index(after, "Include @owasp_crs/*.conf")
	custom := strings.Index(after, "id:100001")
	remove := strings.Index(after, "SecRuleRemoveById 942100")
	tag := strings.Index(after, "SecRuleRemoveByTag attack-xss")
	update := strings.Index(after, `SecRuleUpdateTargetById 942100 "!ARGS:password"`)
	if owasp < 0 || custom < owasp || update < custom || remove < update || tag < remove {
		t.Fatalf("after order\n%s", after)
	}
	if err := ParseProtection(bundle); err != nil {
		t.Fatal(err)
	}
}

func TestCustomRuleWithCRSOrderStillFollowsTheInclude(t *testing.T) {
	rule := seclangv1alpha1.SecRule{Spec: seclangv1alpha1.SecRuleSpec{
		Order:    10,
		Metadata: seclangv1alpha1.Metadata{ID: 100001, Phase: 1},
		Chain: []seclangv1alpha1.ChainLink{{
			Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_URI}},
			Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: "sqlmap"},
			Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny}},
		}},
	}}
	rule.Name = "block-sqlmap"
	bundle, err := BuildProtection(ProtectionInput{
		Namespace: "default", Name: "edge",
		Spec:  wafv1alpha1.ProtectionSpec{Mode: "Blocking"},
		Rules: []seclangv1alpha1.SecRule{rule},
	})
	if err != nil {
		t.Fatal(err)
	}
	owasp := strings.Index(bundle.After, "Include @owasp_crs/*.conf")
	custom := strings.Index(bundle.After, "id:100001")
	if owasp < 0 || custom < owasp {
		t.Fatalf("custom rule sorted before CRS include\n%s", bundle.After)
	}
}

func TestUpdateAfterRemoveIsRejected(t *testing.T) {
	_, err := BuildProtection(ProtectionInput{
		Namespace: "default", Name: "edge",
		Spec: wafv1alpha1.ProtectionSpec{
			PostDirectives: []string{
				"SecRuleRemoveById 942100",
				`SecRuleUpdateTargetById 942100 "!ARGS:password"`,
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "follows SecRuleRemoveById") {
		t.Fatal(err)
	}
}
