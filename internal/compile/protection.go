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
	"fmt"
	"strings"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	wafv1alpha1 "github.com/kubewaf-io/kubewaf/api/waf/v1alpha1"
)

// ProtectionInput is a Protection plus the custom objects the caller resolved.
// The compiler does not read the API server.
type ProtectionInput struct {
	Namespace string
	Name      string
	Spec      wafv1alpha1.ProtectionSpec
	Rules     []seclangv1alpha1.SecRule
	Actions   []seclangv1alpha1.SecAction
	Includes  []IncludeInput
}

// BuildProtection compiles a Protection to the same bundle shape SecPolicy uses.
// CRS includes are always present. The bundle name is waf.ObjectName so the
// extension policy does not collide with a SecPolicy of the same metadata name.
func BuildProtection(in ProtectionInput) (Bundle, error) {
	if in.Namespace == "" || in.Name == "" {
		return Bundle{}, fmt.Errorf("protection namespace and name are required")
	}
	lines, err := protectionLines(in.Spec.CRS, in.Spec.PostDirectives)
	if err != nil {
		return Bundle{}, err
	}
	engine := "On"
	if orString(in.Spec.Mode, "Blocking") == "DetectionOnly" {
		engine = "DetectionOnly"
	} else if orString(in.Spec.Mode, "Blocking") != "Blocking" {
		return Bundle{}, fmt.Errorf("mode must be Blocking or DetectionOnly")
	}
	action, err := paranoiaAction(in.Spec.CRS)
	if err != nil {
		return Bundle{}, err
	}
	includes := make([]IncludeInput, 0, 2+len(in.Includes))
	includes = append(includes,
		IncludeInput{Include: virtualInclude("crs-setup", 20, seclangv1alpha1.PlacementBeforeCRS, "@crs-setup.conf")},
		IncludeInput{Include: virtualInclude("owasp", 10, seclangv1alpha1.PlacementAfterCRS, "@owasp_crs/*.conf")},
	)
	includes = append(includes, in.Includes...)
	actions := append([]seclangv1alpha1.SecAction{action}, in.Actions...)
	return Build(Input{
		Policy: seclangv1alpha1.SecPolicy{Spec: seclangv1alpha1.SecPolicySpec{
			Engine:             engine,
			Inspection:         orString(in.Spec.Inspection, "RequestOnly"),
			RequestBodyAccess:  in.Spec.RequestBodyAccess,
			ResponseBodyAccess: in.Spec.ResponseBodyAccess,
			PostDirectives:     lines,
			ModuleName:         in.Spec.ModuleName,
		},
		},
		Rules:    in.Rules,
		Actions:  actions,
		Includes: includes,
	}.withIdentity(in.Namespace, wafv1alpha1.ObjectName(in.Name)))
}

func (in Input) withIdentity(namespace, name string) Input {
	in.Policy.Namespace = namespace
	in.Policy.Name = name
	return in
}

func virtualInclude(name string, order int32, placement seclangv1alpha1.Placement, path string) seclangv1alpha1.Include {
	inc := seclangv1alpha1.Include{Spec: seclangv1alpha1.IncludeSpec{
		Order:       order,
		Placement:   placement,
		VirtualPath: path,
	}}
	inc.Name = name
	return inc
}

func paranoiaAction(crs *wafv1alpha1.CRSSpec) (seclangv1alpha1.SecAction, error) {
	level := int32(1)
	var inbound, outbound *int32
	if crs != nil {
		if crs.Paranoia != 0 {
			level = crs.Paranoia
		}
		inbound = crs.InboundAnomalyThreshold
		outbound = crs.OutboundAnomalyThreshold
	}
	if level < 1 || level > 4 {
		return seclangv1alpha1.SecAction{}, fmt.Errorf("crs.paranoia must be 1 through 4")
	}
	sets := []seclangv1alpha1.NonDisruptiveAction{
		{Type: seclangv1alpha1.Nolog},
		{Type: seclangv1alpha1.Setvar, Value: fmt.Sprintf("tx.blocking_paranoia_level=%d", level)},
		{Type: seclangv1alpha1.Setvar, Value: fmt.Sprintf("tx.detection_paranoia_level=%d", level)},
	}
	if inbound != nil {
		sets = append(sets, seclangv1alpha1.NonDisruptiveAction{
			Type: seclangv1alpha1.Setvar, Value: fmt.Sprintf("tx.inbound_anomaly_score_threshold=%d", *inbound),
		})
	}
	if outbound != nil {
		sets = append(sets, seclangv1alpha1.NonDisruptiveAction{
			Type: seclangv1alpha1.Setvar, Value: fmt.Sprintf("tx.outbound_anomaly_score_threshold=%d", *outbound),
		})
	}
	action := seclangv1alpha1.SecAction{Spec: seclangv1alpha1.SecActionSpec{
		Order:     30,
		Placement: seclangv1alpha1.PlacementBeforeCRS,
		// 900990 is the id inside @crs-setup.conf. Repeating it makes Coraza reject the
		// filter. 900991 runs after that include and overwrites the same tx variables.
		Metadata: seclangv1alpha1.Metadata{ID: 900991, Phase: 1},
		Actions: &seclangv1alpha1.Actions{
			Disruptive:    &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Pass},
			NonDisruptive: sets,
		},
	}}
	action.Name = "crs-setup"
	return action, nil
}

// ParseProtection checks the before file and each after-file line.
// SecRuleRemove* and SecRuleUpdate* are not given to Coraza: those directives
// look up a CRS rule id, and the webhook and the operator do not load CRS.
func ParseProtection(bundle Bundle) error {
	if err := ParseFiles(bundle.Before, bundle.Files); err != nil {
		return err
	}
	for _, line := range strings.Split(bundle.After, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "SecRuleRemove") || strings.HasPrefix(line, "SecRuleUpdate") {
			continue
		}
		if err := ParseFiles(line, bundle.Files); err != nil {
			return err
		}
	}
	return nil
}

// ProtectionLines returns the SecLang lines a Protection emits besides selected objects.
// The webhook parses the setup action and postDirectives. Removal lines are
// checked for shape here; Coraza cannot resolve them without the CRS loaded.
func ProtectionLines(spec wafv1alpha1.ProtectionSpec) ([]string, error) {
	action, err := paranoiaAction(spec.CRS)
	if err != nil {
		return nil, err
	}
	text, err := EmitAction(&action)
	if err != nil {
		return nil, err
	}
	lines, err := protectionLines(spec.CRS, spec.PostDirectives)
	if err != nil {
		return nil, err
	}
	return append([]string{text}, lines...), nil
}

func protectionLines(crs *wafv1alpha1.CRSSpec, extra []string) ([]string, error) {
	var lines []string
	if crs != nil {
		for _, id := range crs.RemoveIDs {
			if id < 1 {
				return nil, fmt.Errorf("removeIds must be positive")
			}
			lines = append(lines, fmt.Sprintf("SecRuleRemoveById %d", id))
		}
		for _, tag := range crs.RemoveTags {
			if !safeToken(tag) {
				return nil, fmt.Errorf("removeTags entry %q is not a single token", tag)
			}
			lines = append(lines, "SecRuleRemoveByTag "+tag)
		}
		for _, update := range crs.UpdateTargets {
			if update.ID < 1 {
				return nil, fmt.Errorf("updateTargets.id must be positive")
			}
			for _, target := range update.Remove {
				if !safeToken(target) {
					return nil, fmt.Errorf("updateTargets remove %q is not a single token", target)
				}
				lines = append(lines, fmt.Sprintf("SecRuleUpdateTargetById %d \"!%s\"", update.ID, target))
			}
		}
	}
	for _, line := range extra {
		if strings.TrimSpace(line) == "" || strings.ContainsAny(line, "\n\r") {
			return nil, fmt.Errorf("postDirectives entries must be single lines")
		}
		lines = append(lines, line)
	}
	if len(lines) > 64 {
		return nil, fmt.Errorf("protection emits more than 64 exclusion lines")
	}
	return lines, nil
}

func safeToken(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\n\r\"'") {
		return false
	}
	return true
}
