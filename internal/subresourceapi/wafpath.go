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

package subresourceapi

import (
	"fmt"
	"strings"

	subv1alpha1 "github.com/kubewaf-io/kubewaf/api/subresources/v1alpha1"
)

// WAFSubresource is a GET-only capability on a WAF parent.
type WAFSubresource string

const (
	WAFSubresourceDirectives WAFSubresource = "directives"
	WAFSubresourceMetrics    WAFSubresource = "metrics"
	WAFSubresourceTraces     WAFSubresource = "traces"
)

// WAFRoute is a parsed object-scoped WAF subresource path.
type WAFRoute struct {
	Namespace   string
	Name        string
	Subresource WAFSubresource
	// Extra is the optional suffix after the subresource (e.g. Jaeger trace ID).
	Extra string
}

// ParseWAFSubresourcePath parses
//
//	/apis/subresources.kubewaf.io/v1alpha1/namespaces/{ns}/wafs/{name}/{directives|metrics|traces}[/{extra}]
func ParseWAFSubresourcePath(urlPath string) (*WAFRoute, error) {
	path := strings.TrimSuffix(urlPath, "/")
	const prefix = "/apis/" + subv1alpha1.Group + "/" + subv1alpha1.Version
	path = strings.TrimPrefix(path, prefix)
	parts := splitPath(path)
	if len(parts) < 5 {
		return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "path too short"}
	}
	for _, seg := range parts[:5] {
		if seg == "" {
			return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "empty path segment"}
		}
	}
	if parts[0] != "namespaces" {
		return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "expected namespaces"}
	}
	if parts[2] != subv1alpha1.ResourceWAFs {
		return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "expected wafs"}
	}
	sub := WAFSubresource(parts[4])
	switch sub {
	case WAFSubresourceDirectives, WAFSubresourceMetrics, WAFSubresourceTraces:
	default:
		return nil, &PathError{Reason: ReasonNotFound, Message: fmt.Sprintf("unknown WAF subresource %q", parts[4])}
	}
	extra := ""
	if len(parts) > 5 {
		if sub != WAFSubresourceTraces {
			return nil, &PathError{Reason: ReasonNotFound, Message: "unexpected path suffix"}
		}
		for _, seg := range parts[5:] {
			if seg == "" {
				return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "empty path segment"}
			}
		}
		extra = strings.Join(parts[5:], "/")
	}
	return &WAFRoute{
		Namespace:   parts[1],
		Name:        parts[3],
		Subresource: sub,
		Extra:       extra,
	}, nil
}
