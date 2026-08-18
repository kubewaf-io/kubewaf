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
	"strings"
	"testing"
)

func TestPreamble(t *testing.T) {
	lines := Preamble()
	if len(lines) != 3 {
		t.Fatalf("len=%d", len(lines))
	}
	if lines[0] != "SecRuleEngine On" {
		t.Fatalf("line0=%q", lines[0])
	}
	if lines[1] != "SecRequestBodyAccess On" {
		t.Fatalf("line1=%q", lines[1])
	}
	if lines[2] != "SecResponseBodyAccess Off" {
		t.Fatalf("line2=%q", lines[2])
	}
	// Must never include wasm virtuals.
	s := PreambleString()
	for _, bad := range []string{"@kubewaf-defaults", "@crs-setup-conf", "@owasp_crs", "@ftw-conf"} {
		if strings.Contains(s, bad) {
			t.Fatalf("preamble contains wasm virtual %s", bad)
		}
	}
}

func TestStampOnly900990(t *testing.T) {
	s := StampOnly900990()
	if !strings.Contains(s, "id:900990") {
		t.Fatalf("missing id: %s", s)
	}
	if !strings.Contains(s, "crs_setup_version=427") {
		t.Fatalf("missing version: %s", s)
	}
}

func TestScanPmFromFileBasenames_CommentPrefixedCRSBlob(t *testing.T) {
	blob := `# -=[ Restricted File Access ]=-
#
SecRule REQUEST_FILENAME "@pmFromFile restricted-files.data" "id:930130,phase:1,block"`
	got := ScanPmFromFileBasenames([]string{blob})
	if len(got) != 1 || got[0] != "restricted-files.data" {
		t.Fatalf("comment-prefixed CRS blob: got %v, want [restricted-files.data]", got)
	}
}

func TestScanPmFromFileBasenames(t *testing.T) {
	dirs := []string{
		`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners-user-agents.data" "id:1,phase:1,pass"`,
		`SecRule REMOTE_ADDR "@ipMatchFromFile blocklist.data" "id:2,phase:1,deny"`,
		`# comment @pmFromFile ignored.data`,
		`SecRule ARGS "@rx test" "id:3,phase:2,pass"`,
	}
	got := ScanPmFromFileBasenames(dirs)
	want := map[string]bool{"scanners-user-agents.data": true, "blocklist.data": true}
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected %s", g)
		}
	}
}

func TestJoinDocument(t *testing.T) {
	doc := JoinDocument(Preamble(), []string{`SecRule ARGS "@rx x" "id:1,phase:2,deny,status:403"`})
	if !strings.HasPrefix(doc, "SecRuleEngine On") {
		t.Fatalf("doc=%s", doc)
	}
	if CountNonEmptyLines(doc) < 4 {
		t.Fatalf("count=%d", CountNonEmptyLines(doc))
	}
}
