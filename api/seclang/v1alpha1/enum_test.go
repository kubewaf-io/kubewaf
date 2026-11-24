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

package v1alpha1

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestEnumMarkerListsEveryConstant(t *testing.T) {
	b, err := os.ReadFile("tokens.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	re := regexp.MustCompile(`(?m)^\t\w+\s+(VariableName|OperatorName|Transformation|DisruptiveActionType|FlowActionType|DataActionType|NonDisruptiveActionType)\s+=\s+"([^"]+)"`)
	byType := map[string][]string{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		byType[m[1]] = append(byType[m[1]], m[2])
	}
	markers := regexp.MustCompile(`\+kubebuilder:validation:Enum=([^\n]+)\ntype (VariableName|OperatorName|Transformation|DisruptiveActionType|FlowActionType|DataActionType|NonDisruptiveActionType) `)
	found := map[string]string{}
	for _, m := range markers.FindAllStringSubmatch(src, -1) {
		found[m[2]] = m[1]
	}
	for typ, consts := range byType {
		got := strings.Split(found[typ], ";")
		if strings.Join(got, ";") != strings.Join(consts, ";") {
			t.Fatalf("%s enum marker does not match the constants", typ)
		}
	}
}
