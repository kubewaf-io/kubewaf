/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    10|Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package compile

import (
	"fmt"
	"regexp"
	"strings"
)

// simpleValue is an action value that SecLang can leave unquoted.
var simpleValue = regexp.MustCompile(`^[A-Za-z0-9_./+=@%{}!:-]+$`)

// quoteActionValue quotes one action value the way Coraza's action parser reads it.
// The action list itself is a double-quoted directive argument that Coraza does not
// unescape, so a double quote in a value cannot be stored (it would keep the backslash).
// Values that need quoting are wrapped in single quotes. An apostrophe toggles that
// quoting, and a comma that falls outside it is rejected because Coraza would split the action.
func quoteActionValue(v string) (string, error) {
	if strings.ContainsAny(v, "\n\r") {
		return "", fmt.Errorf("action value contains a newline")
	}
	// The action list is a double-quoted string that Coraza does not unescape.
	// A double quote in a value would have to be written as \" and would stay that way.
	if strings.Contains(v, `"`) {
		return "", fmt.Errorf("action value %q contains a double quote, which Coraza cannot store without a leftover backslash", v)
	}
	if v == "" || simpleValue.MatchString(v) {
		return v, nil
	}
	if !actionCommasStayQuoted(v) {
		return "", fmt.Errorf("action value %q has a comma after an apostrophe, which Coraza would split", v)
	}
	return "'" + v + "'", nil
}

// actionCommasStayQuoted reports whether commas in v stay inside the single
// quotes Coraza uses for action values. An apostrophe toggles that state.
func actionCommasStayQuoted(v string) bool {
	inQuotes := true
	for i := 0; i < len(v); i++ {
		if i > 0 && v[i-1] == '\\' {
			continue
		}
		if v[i] == '\'' {
			inQuotes = !inQuotes
			continue
		}
		if v[i] == ',' && !inQuotes {
			return false
		}
	}
	return true
}

// quoteDirectiveArg wraps a whole operator or action list in one Coraza quoted string.
// Backslashes are copied through. Only a double quote is escaped, and only when the
// backslashes already in front of it are even, so the stored text matches the input.
func quoteDirectiveArg(body string) (string, error) {
	if strings.ContainsAny(body, "\n\r") {
		return "", fmt.Errorf("directive argument contains a newline")
	}
	escaped, err := escapeCorazaDoubleQuoted(body)
	if err != nil {
		return "", err
	}
	return `"` + escaped + `"`, nil
}

func escapeCorazaDoubleQuoted(v string) (string, error) {
	var b strings.Builder
	b.Grow(len(v))
	backslashes := 0
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			b.WriteByte('\\')
			backslashes++
		case '"':
			// Unescape removes exactly one backslash from \" . An even run needs
			// one added backslash so the quote does not end the string and the
			// stored run keeps its length. An odd run cannot.
			if backslashes%2 == 1 {
				return "", fmt.Errorf("value %q has a quote preceded by an odd number of backslashes, which Coraza cannot round-trip", v)
			}
			b.WriteString(`\"`)
			backslashes = 0
		default:
			b.WriteByte(v[i])
			backslashes = 0
		}
	}
	return b.String(), nil
}
