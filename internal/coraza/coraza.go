package coraza

import (
	"fmt"

	"github.com/buzz-it/kubewaf/api/seclang/v1beta1/convert"
	"github.com/corazawaf/coraza/v3"
	"github.com/coreruleset/crslang/types"
)

// LoadAndValidateSeclangDirectives takes a slice of parsed SeclangDirective
// from the crslang/types package, converts them back to a valid SecLang string
// (using the built-in ToSeclang() method), loads them into a fresh Coraza WAF
// instance, and returns the WAF + any error.
//
// If the returned error is nil → the rules are syntactically valid and were
// successfully compiled by Coraza's SecLang parser.
func LoadAndValidateSeclangDirectives(directives []types.SeclangDirective) (coraza.WAF, error) {
	if len(directives) == 0 {
		return nil, fmt.Errorf("no directives provided")
	}

	// Coraza v3 public API – the parser is invoked internally by WithDirectives
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().WithDirectives(convert.ConvertToSecLangString(directives)),
	)
	if err != nil {
		return nil, fmt.Errorf("rules are invalid: %w", err)
	}

	return waf, nil
}
