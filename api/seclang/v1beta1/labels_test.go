/*
Copyright 2025 Buzz-IT GmbH.
*/
package v1beta1

import "testing"

func TestTagToLabelKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"OWASP_CRS", LabelTagPrefix + "owasp_crs"},
		{"attack-xss", LabelTagPrefix + "attack-xss"},
		{"OWASP_CRS/ATTACK-XSS", LabelTagPrefix + "owasp_crs.attack-xss"},
		{"paranoia-level/1", LabelTagPrefix + "paranoia-level.1"},
		{"", ""},
	}
	for _, tc := range cases {
		got := TagToLabelKey(tc.in)
		if got != tc.want {
			t.Errorf("TagToLabelKey(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestCollectTagsFromSecRule(t *testing.T) {
	sr := &SecRule{
		Spec: SecRuleSpec{
			SecRules: []SecLangSecRule{
				{Metadata: &SecRuleMetadata{Tags: []string{"OWASP_CRS", "attack-xss"}}},
				{Metadata: &SecRuleMetadata{Tags: []string{"OWASP_CRS", "paranoia-level/1"}}},
			},
		},
	}
	tags := CollectTagsFromSecRule(sr)
	if len(tags) != 3 {
		t.Fatalf("tags=%v", tags)
	}
}
