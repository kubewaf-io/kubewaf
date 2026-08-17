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
)

func TestCollapseEmptyLines_MaxTwo(t *testing.T) {
	in := "a\n\n\n\nb\n\n\nc\n"
	got := CollapseEmptyLines(in, MaxYAMLEmptyLines)
	// At most 2 consecutive blank lines between a and b.
	if strings.Contains(got, "\n\n\n\n") {
		t.Fatalf("still has 3+ consecutive empty lines: %q", got)
	}
	// Exactly two blanks between a and b is OK (a\n\n\nb).
	if !strings.Contains(got, "a\n\n\nb") {
		t.Fatalf("expected two blanks between a and b, got %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("expected trailing newline, got %q", got)
	}
	if strings.HasSuffix(got, "\n\n") {
		t.Fatalf("expected no trailing blank line, got %q", got)
	}
}

func TestCollapseEmptyLines_Zero(t *testing.T) {
	got := CollapseEmptyLines("a\n\n\nb\n", 0)
	if got != "a\nb\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeRuleComment_CRSStyle(t *testing.T) {
	// Mirrors CRS rule 932239 comment ending with 3 blank lines before
	// "Regular expression generated from regex-assembly/...".
	in := strings.Join([]string{
		"[ Unix command injection ]",
		"",
		"body",
		"",
		"",
		"",
		"Regular expression generated from regex-assembly/932239.ra.",
		"",
		"",
	}, "\n")
	got := SanitizeRuleComment(in)
	assertMaxEmptyRun(t, got, MaxYAMLEmptyLines)
	if !strings.Contains(got, "Regular expression generated") {
		t.Fatalf("lost content: %q", got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatalf("comment should not end with newline (YAML | chomping): %q", got)
	}
	// 3 blanks between body and Regular → collapsed to 2.
	if !strings.Contains(got, "body\n\n\nRegular") {
		t.Fatalf("expected two blank lines between body and Regular, got %q", got)
	}
}

func TestSanitizeRuleComment_ThreeBlanksBecomesTwo(t *testing.T) {
	// "head\n\n\n\ntail" = head + 3 empty lines + tail → head + 2 empty + tail.
	got := SanitizeRuleComment("head\n\n\n\ntail")
	if got != "head\n\n\ntail" {
		t.Fatalf("got %q want %q", got, "head\n\n\ntail")
	}
}

func assertMaxEmptyRun(t *testing.T, s string, max int) {
	t.Helper()
	run := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) == "" {
			run++
			if run > max {
				t.Fatalf("run of %d empty lines > max %d in %q", run, max, s)
			}
			continue
		}
		run = 0
	}
}
