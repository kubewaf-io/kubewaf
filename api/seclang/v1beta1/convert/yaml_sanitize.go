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

import "strings"

// MaxYAMLEmptyLines matches yamllint empty-lines.max in
// .github/configs/lintconf.yaml. Generated CRS YAML must not emit more than
// this many consecutive blank lines (including inside multi-line comment: | blocks).
const MaxYAMLEmptyLines = 2

// CollapseEmptyLines reduces runs of blank (empty or whitespace-only) lines to
// at most maxEmpty consecutive blanks. Trailing blank lines are stripped; if
// the result is non-empty it ends with a single newline (new-line-at-end-of-file).
//
// Pass maxEmpty <= 0 to remove all blank lines between content.
func CollapseEmptyLines(s string, maxEmpty int) string {
	if maxEmpty < 0 {
		maxEmpty = 0
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	emptyRun := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			emptyRun++
			if emptyRun <= maxEmpty {
				out = append(out, "")
			}
			continue
		}
		emptyRun = 0
		out = append(out, line)
	}
	// yamllint empty-lines.max-end: 0 — no trailing blank lines.
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// SanitizeRuleComment cleans CRS comment text before it is stored on SecRule
// metadata. Upstream CRS conf comments often contain 3+ consecutive blank
// lines, which yamllint rejects even inside YAML literal blocks.
func SanitizeRuleComment(s string) string {
	if s == "" {
		return ""
	}
	// Reuse collapse logic without forcing a file-style trailing newline.
	collapsed := CollapseEmptyLines(s, MaxYAMLEmptyLines)
	return strings.TrimRight(collapsed, "\n")
}
