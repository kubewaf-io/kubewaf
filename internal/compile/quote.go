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
	"regexp"
	"strings"
)

// simpleValue is an action value that SecLang can leave unquoted.
var simpleValue = regexp.MustCompile(`^[A-Za-z0-9_./+=@%{}!:-]+$`)

func quoteActionValue(v string) (string, error) {
	if strings.ContainsAny(v, "\n\r") {
		return "", fmt.Errorf("action value contains a newline")
	}
	if v == "" || simpleValue.MatchString(v) {
		return v, nil
	}
	if !strings.Contains(v, "'") {
		return "'" + v + "'", nil
	}
	return `"` + escapeDQ(v) + `"`, nil
}

func escapeDQ(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return v
}

func quoteDirectiveArg(body string) string {
	return `"` + escapeDQ(body) + `"`
}
