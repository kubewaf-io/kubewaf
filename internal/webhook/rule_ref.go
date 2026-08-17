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

package webhook

import (
	"fmt"
	"strings"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// allowedRuleRefKinds are kinds RuleSet may reference.
var allowedRuleRefKinds = map[string]struct{}{
	"":          {}, // defaulted at resolve time
	"SecRule":   {},
	"SecAction": {},
	"RuleSet":   {},
	"ConfigMap": {},
}

// allowedWAFRefKinds are kinds a WAF may reference (RuleSet only).
var allowedWAFRefKinds = map[string]struct{}{
	"":        {},
	"RuleSet": {},
}

// ValidateRuleRef checks a single RuleRef structural constraints.
// ownerKind is "RuleSet" or "WAF" and selects allowed target kinds.
func ValidateRuleRef(ref wafv1beta1.RuleRef, ownerKind string, index int) error {
	prefix := fmt.Sprintf("spec.ruleRefs[%d]", index)

	hasName := strings.TrimSpace(ref.Name) != ""
	hasSelector := ref.Selector != nil
	if hasName == hasSelector {
		// both or neither
		if !hasName && !hasSelector {
			return fmt.Errorf("%s: name or selector is required", prefix)
		}
		return fmt.Errorf("%s: name and selector are mutually exclusive", prefix)
	}

	kind := strings.TrimSpace(ref.Kind)
	switch ownerKind {
	case "WAF":
		if _, ok := allowedWAFRefKinds[kind]; !ok {
			return fmt.Errorf("%s: WAF may only reference kind RuleSet (got %q)", prefix, kind)
		}
	default: // RuleSet
		if _, ok := allowedRuleRefKinds[kind]; !ok {
			return fmt.Errorf("%s: unsupported kind %q (want SecRule, SecAction, RuleSet, or ConfigMap)", prefix, kind)
		}
	}
	return nil
}

// ValidateRuleRefs validates a slice of RuleRefs.
func ValidateRuleRefs(refs []wafv1beta1.RuleRef, ownerKind string) error {
	for i, ref := range refs {
		if err := ValidateRuleRef(ref, ownerKind, i); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAllowedRules validates RuleSet.spec.allowedRules.
func ValidateAllowedRules(a wafv1beta1.RuleNamespaces) error {
	if a.From == nil {
		return nil
	}
	from := *a.From
	switch from {
	case gatewayv1.NamespacesFromAll, gatewayv1.NamespacesFromSame, "":
		return nil
	case gatewayv1.NamespacesFromSelector:
		if a.Selector == nil {
			return fmt.Errorf("spec.allowedRules.selector is required when from=Selector")
		}
		return nil
	case gatewayv1.NamespacesFromNone:
		// Allowed by Gateway API enum; treat as Same-like deny-all cross-ns at runtime.
		return nil
	default:
		return fmt.Errorf("spec.allowedRules.from: unsupported value %q", from)
	}
}
