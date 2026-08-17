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
	"strings"
	"testing"

	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"sigs.k8s.io/yaml"
)

func TestCollapseSecLangLineContinuations(t *testing.T) {
	in := "SecRule ARGS \"@rx x\" \\\n    \"id:100001,\\\n    phase:1,\\\n    deny\"\n\n"
	got := collapseSecLangLineContinuations(in)
	if strings.Contains(got, "\\\n") || strings.Contains(got, "\\\r\n") {
		t.Fatalf("still has line continuations: %q", got)
	}
	if !strings.Contains(got, `SecRule ARGS "@rx x" "id:100001,phase:1,deny"`) {
		t.Fatalf("unexpected collapsed form: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("expected trailing newline: %q", got)
	}
}

func TestConvertToSecLangString_IsSingleLineSecRule(t *testing.T) {
	raw := []byte(`
apiVersion: seclang.kubewaf.io/v1beta1
kind: SecRule
metadata:
  name: block-bad-user-agent
spec:
  secLangRules:
  - actions:
      data:
      - dataActionType: status
        value: "403"
      disruptive:
        disruptiveActionType: deny
    conditions:
    - collections:
      - arguments:
        - User-Agent
        name: REQUEST_HEADERS
      operator:
        name: rx
        value: (?:nikto|sqlmap|nessus|openvas)
    metadata:
      id: 100001
      message: Malicious scanner detected
      phase: "1"
      severity: ERROR
      tags:
      - attack-generic
      - e2e
`)
	var sr v1beta1.SecRule
	if err := yaml.Unmarshal(raw, &sr); err != nil {
		t.Fatal(err)
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	if out == "" {
		t.Fatal("empty SecLang")
	}
	if strings.Contains(out, "\\\n") || strings.Contains(out, "\\\r\n") {
		t.Fatalf("line continuations remain:\n%s", out)
	}
	nonEmpty := 0
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			nonEmpty++
		}
	}
	if nonEmpty != 1 {
		t.Fatalf("expected single non-empty line, got %d:\n%s", nonEmpty, out)
	}
	if !strings.Contains(out, "id:100001") || !strings.Contains(out, "REQUEST_HEADERS") {
		t.Fatalf("missing expected content:\n%s", out)
	}
}
