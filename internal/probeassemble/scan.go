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
	"path"
	"regexp"
	"sort"
	"strings"
)

// MaxPhraseFilesRawBytes is the unified data-file inject budget (2 MiB).
// Redeclared here so probeassemble does not import dataplane/config (K29).
const MaxPhraseFilesRawBytes = 2 * 1024 * 1024

// fromFileRe matches @pmFromFile / @pmf / @ipMatchFromFile / @ipMatchF operators.
// Copied from internal/dataplane/config/phrasefiles.go.
var fromFileRe = regexp.MustCompile(`(?i)@(?:pmFromFile|pmf|ipMatchFromFile|ipMatchF)\s+([^\s"']+(?:\s+[^\s"']+)*)`)

// ScanPmFromFileBasenames returns unique basenames referenced by @pmFromFile/@pmf
// and @ipMatchFromFile/@ipMatchF in SecLang lines.
// Copied from internal/dataplane/config — do not import that package (K23/K29).
func ScanPmFromFileBasenames(directives []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, line := range directives {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		for _, m := range fromFileRe.FindAllStringSubmatch(line, -1) {
			if len(m) < 2 {
				continue
			}
			for _, tok := range strings.Fields(m[1]) {
				base := path.Base(strings.Trim(tok, `"'`))
				if base == "" || base == "." {
					continue
				}
				if _, ok := seen[base]; ok {
					continue
				}
				seen[base] = struct{}{}
				out = append(out, base)
			}
		}
	}
	sort.Strings(out)
	return out
}

// DropSecLangLinesWithBasenames removes lines that reference any of the given basenames.
func DropSecLangLinesWithBasenames(directives []string, basenames map[string]struct{}) []string {
	if len(basenames) == 0 {
		return directives
	}
	out := make([]string, 0, len(directives))
	for _, line := range directives {
		if lineReferencesFromFileBasename(line, basenames) {
			continue
		}
		out = append(out, line)
	}
	return out
}

func lineReferencesFromFileBasename(line string, basenames map[string]struct{}) bool {
	for _, m := range fromFileRe.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		for _, tok := range strings.Fields(m[1]) {
			base := path.Base(strings.Trim(tok, `"'`))
			if _, ok := basenames[base]; ok {
				return true
			}
		}
	}
	return false
}
