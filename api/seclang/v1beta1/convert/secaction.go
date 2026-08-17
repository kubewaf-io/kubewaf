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
	types "github.com/coreruleset/crslang/types"
	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

// ConvertSecAction maps a SecAction CR to crslang directives.
// Rendered SecLang is `SecAction "id:…,phase:…,pass,setvar:…"`.
func ConvertSecAction(source v1beta1.SecAction) ([]types.SeclangDirective, error) {
	actions := source.Spec.SecRuleActions
	m := v1beta1.Match{
		AlwaysMatch:     true,
		Transformations: source.Spec.Transformations,
	}
	// Route through single-rule form so always-match becomes a real SecAction.
	sr := v1beta1.SecRule{
		ObjectMeta: source.ObjectMeta,
		Spec: v1beta1.SecRuleSpec{
			Metadata: source.Spec.Metadata,
			Match:    []v1beta1.Match{m},
			Actions:  &actions,
		},
	}
	return ConvertSecRule(sr)
}

// ConvertSecActionToString is a convenience for status / tests.
func ConvertSecActionToString(source v1beta1.SecAction) (string, error) {
	dirs, err := ConvertSecAction(source)
	if err != nil {
		return "", err
	}
	return ConvertToSecLangString(dirs), nil
}
