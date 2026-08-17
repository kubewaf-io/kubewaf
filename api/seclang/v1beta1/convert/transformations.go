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
	"fmt"
	"strings"

	types "github.com/coreruleset/crslang/types"
	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

// FromCRSTransformation maps a crslang transform onto the SecRule API enum.
//
// OWASP CRS uses American spellings (normalizePath / normalizePathWin). crslang
// models those as distinct enum values from the British forms (normalisePath /
// normalisePathWin). The goverter mapper only knows the British names and used
// to silently drop the American ones to "" — re-render then emitted t:unknown
// and ModSecurity-proxy-wasm trapped (unreachable) during onConfigure.
//
// American spellings are aliased to the British API constants. Truly unknown
// or unmapped transforms return an error; callers must never store empty /
// unknownTransformation on a CR.
func FromCRSTransformation(src types.Transformation) (v1beta1.Transformation, error) {
	// Prefer String() so unexported American crslang enum values still alias.
	switch src.String() {
	case "normalizePath", "normalisePath":
		return v1beta1.NormalisePath, nil
	case "normalizePathWin", "normalisePathWin":
		return v1beta1.NormalisePathWin, nil
	case "unknown", "":
		return "", fmt.Errorf("unsupported SecLang transformation %q", src.String())
	}

	got := transformationReverseMapper.Convert(src)
	if err := validateAPITransformation(got); err != nil {
		return "", fmt.Errorf("unsupported SecLang transformation %q: %w", src.String(), err)
	}
	return got, nil
}

// ToCRSTransformation maps a SecRule API transform onto crslang.
// Empty, unknownTransformation, and unmapped values error — never emit
// types.UnknownTransformation (String "unknown" → t:unknown in SecLang).
// American spellings are accepted on the API string for CRS-faithful YAML.
func ToCRSTransformation(src v1beta1.Transformation) (types.Transformation, error) {
	switch strings.TrimSpace(string(src)) {
	case "":
		return types.UnknownTransformation, fmt.Errorf("empty transformation is not allowed")
	case string(v1beta1.UnknownTransformation), "unknown":
		return types.UnknownTransformation, fmt.Errorf("unknown transformation is not allowed")
	case "normalizePath", string(v1beta1.NormalisePath):
		return types.NormalisePath, nil
	case "normalizePathWin", string(v1beta1.NormalisePathWin):
		return types.NormalisePathWin, nil
	}

	got := transformationMapper.Convert(src)
	if got == types.UnknownTransformation || got.String() == "unknown" {
		return types.UnknownTransformation, fmt.Errorf("unsupported transformation %q", src)
	}
	return got, nil
}

// ValidateAPITransformations rejects empty / unknown / unmapped transforms so
// webhooks and controllers can keep SecRule Ready=False.
func ValidateAPITransformations(ts []v1beta1.Transformation) error {
	for i, t := range ts {
		if err := validateAPITransformation(t); err != nil {
			return fmt.Errorf("transformations[%d]: %w", i, err)
		}
		// Ensure the value can actually round-trip to crslang (catches typos
		// that are non-empty but not in the enum).
		if _, err := ToCRSTransformation(t); err != nil {
			return fmt.Errorf("transformations[%d]: %w", i, err)
		}
	}
	return nil
}

func validateAPITransformation(t v1beta1.Transformation) error {
	s := strings.TrimSpace(string(t))
	switch s {
	case "":
		return fmt.Errorf("empty transformation is not allowed (CRS normalizePath must map to normalisePath)")
	case string(v1beta1.UnknownTransformation), "unknown":
		return fmt.Errorf("unknown transformation is not allowed (would render as t:unknown and trap ModSecurity wasm)")
	}
	return nil
}

// mapAPITransformations converts a CR transform list or returns a descriptive error.
func mapAPITransformations(ts []v1beta1.Transformation) ([]types.Transformation, error) {
	if len(ts) == 0 {
		return nil, nil
	}
	out := make([]types.Transformation, 0, len(ts))
	for i, t := range ts {
		got, err := ToCRSTransformation(t)
		if err != nil {
			return nil, fmt.Errorf("transformations[%d]: %w", i, err)
		}
		out = append(out, got)
	}
	return out, nil
}

// mapCRSTransformations converts crslang transforms onto API enums or errors.
func mapCRSTransformations(ts []types.Transformation) ([]v1beta1.Transformation, error) {
	if len(ts) == 0 {
		return nil, nil
	}
	out := make([]v1beta1.Transformation, 0, len(ts))
	for i, t := range ts {
		got, err := FromCRSTransformation(t)
		if err != nil {
			return nil, fmt.Errorf("transformations[%d]: %w", i, err)
		}
		out = append(out, got)
	}
	return out, nil
}
