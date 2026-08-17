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

package probeassemble

import (
	"errors"
	"testing"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

func TestApplyAssignedIDsAndEnsure(t *testing.T) {
	sr := &seclangv1beta1.SecRule{
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{},
			Match:    []seclangv1beta1.Match{{AlwaysMatch: true}},
			Actions: &seclangv1beta1.SecRuleActions{
				DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Pass},
			},
		},
	}
	// No ids → unresolved
	if err := EnsureRuleIDs(sr); !errors.Is(err, ErrRuleIDsUnresolved) {
		t.Fatalf("expected unresolved, got %v", err)
	}
	sr.Status.AssignedIDs = []int{100001}
	with := ApplyAssignedIDs(sr, nil)
	if with.Spec.Metadata.Id != 100001 {
		t.Fatalf("id=%d", with.Spec.Metadata.Id)
	}
	if err := EnsureRuleIDs(with); err != nil {
		t.Fatalf("ensure: %v", err)
	}
}

func TestAssembleSecRule(t *testing.T) {
	sr := &seclangv1beta1.SecRule{
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "2"},
				Id:                100001,
			},
			Match: []seclangv1beta1.Match{{
				Collections: []seclangv1beta1.Collection{{
					Name: seclangv1beta1.ARGS,
				}},
				Operator: seclangv1beta1.Operator{
					Name:  seclangv1beta1.Rx,
					Value: "attack",
				},
			}},
			Actions: &seclangv1beta1.SecRuleActions{
				DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Deny},
			},
		},
	}
	asm, err := AssembleSecRule(sr)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if asm.Directives == "" {
		t.Fatal("empty directives")
	}
	if asm.RulesLoaded < 1 {
		t.Fatalf("rulesLoaded=%d", asm.RulesLoaded)
	}
}
