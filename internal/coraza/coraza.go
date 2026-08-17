/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

10→Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package coraza

import (
	"fmt"
	"io/fs"

	"github.com/corazawaf/coraza/v3"
	"github.com/coreruleset/crslang/types"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
	"github.com/kubewaf-io/kubewaf/internal/coraza/crsdata"
)

// LoadAndValidateSeclangDirectives takes a slice of parsed SeclangDirective
// from the crslang/types package, converts them back to a valid SecLang string
// (using the built-in ToSeclang() method), loads them into a fresh Coraza WAF
// instance with the embedded CRS phrase-list root FS, and returns the WAF + any error.
//
// If the returned error is nil → the rules are syntactically valid and were
// successfully compiled by Coraza's SecLang parser.
func LoadAndValidateSeclangDirectives(directives []types.SeclangDirective) (coraza.WAF, error) {
	return LoadAndValidateSeclangDirectivesWithFS(directives, crsdata.MapFS(nil))
}

// LoadAndValidateSeclangDirectivesWithFS loads directives with an optional root FS
// so @pmFromFile basenames resolve via fs.Open(basename) / relative paths.
// When root is nil, Coraza uses the default (host) filesystem.
func LoadAndValidateSeclangDirectivesWithFS(directives []types.SeclangDirective, root fs.FS) (coraza.WAF, error) {
	if len(directives) == 0 {
		return nil, fmt.Errorf("no directives provided")
	}

	cfg := coraza.NewWAFConfig().WithDirectives(convert.ConvertToSecLangString(directives))
	if root != nil {
		cfg = cfg.WithRootFS(root)
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("rules are invalid: %w", err)
	}
	return waf, nil
}
