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
	"net/http"
	"strconv"
	"strings"

	subv1alpha1 "github.com/kubewaf-io/kubewaf/api/subresources/v1alpha1"
)

// Control header names (X-KubeWAF-Probe-*).
const (
	HeaderTimeoutSeconds = "X-KubeWAF-Probe-TimeoutSeconds"
	HeaderRemoteAddr     = "X-KubeWAF-Probe-Remote-Addr"
	HeaderMode           = "X-KubeWAF-Probe-Mode"
	HeaderCrsEnable      = "X-KubeWAF-Probe-CrsEnable"
	HeaderMaxMatches     = "X-KubeWAF-Probe-Max-Matches"
	HeaderTraceID        = "X-KubeWAF-Probe-Trace-Id"
	HeaderPrefix         = "X-KubeWAF-Probe-"
)

// ParentKind identifies the parent CR kind for a probe route.
type ParentKind string

const (
	ParentSecRule ParentKind = "SecRule"
	ParentRuleSet ParentKind = "RuleSet"
	ParentWAF     ParentKind = "WAF"
)

// ProbeRoute is a parsed object-scoped probe path.
type ProbeRoute struct {
	ParentKind ParentKind
	Namespace  string
	Name       string
	// AppPath is the simulated application path (always starts with /).
	AppPath string
	// RawQuery is the client query string (without ?).
	RawQuery string
}

// AllowedMethods for pass-through probes.
var AllowedMethods = map[string]struct{}{
	http.MethodGet:    {},
	http.MethodHead:   {},
	http.MethodPost:   {},
	http.MethodPut:    {},
	http.MethodPatch:  {},
	http.MethodDelete: {},
}

// MethodToRBACVerb maps HTTP method to discovery/RBAC verb.
func MethodToRBACVerb(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead:
		return "get"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		return "delete"
	default:
		return ""
	}
}

// ParseProbePath parses an aggregated probe URL path (after host).
// Expected forms:
//
//	/apis/subresources.kubewaf.io/v1alpha1/namespaces/{ns}/{parents}/{name}/probes
//	/apis/subresources.kubewaf.io/v1alpha1/namespaces/{ns}/{parents}/{name}/probes/http/{path…}
//
// Also accepts paths without the /apis/group/version prefix (handler-relative).
// Trailing slashes on the application path suffix are preserved (e.g. /search/).
func ParseProbePath(urlPath, rawQuery string) (*ProbeRoute, error) {
	// Preserve trailing slash for the simulated AppPath only (not for routing structure).
	hadTrailingSlash := len(urlPath) > 1 && strings.HasSuffix(urlPath, "/")
	path := strings.TrimSuffix(urlPath, "/")
	// Strip API prefix if present.
	const prefix = "/apis/" + subv1alpha1.Group + "/" + subv1alpha1.Version
	path = strings.TrimPrefix(path, prefix)
	if path == "" {
		return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "empty path"}
	}
	// Expect: /namespaces/{ns}/{resource}/{name}/probes[/http/...]
	parts := splitPath(path)
	if len(parts) < 5 {
		return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "path too short"}
	}
	// Empty structural segments (//) → 400.
	for _, seg := range parts[:5] {
		if seg == "" {
			return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "empty path segment"}
		}
	}
	if parts[0] != "namespaces" {
		return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "expected namespaces"}
	}
	ns := parts[1]
	resource := parts[2]
	name := parts[3]
	if parts[4] != "probes" {
		return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "expected probes subresource"}
	}

	var kind ParentKind
	switch resource {
	case subv1alpha1.ResourceSecRules:
		kind = ParentSecRule
	case subv1alpha1.ResourceRuleSets:
		kind = ParentRuleSet
	case subv1alpha1.ResourceWAFs:
		kind = ParentWAF
	case "secactions":
		// Defensive: ParseProbePath callers may hit this if check was skipped.
		return nil, &PathError{Reason: "SecActionProbesDeferred", Message: "SecAction probes deferred to v1.1"}
	default:
		return nil, &PathError{Reason: ReasonInvalidProbePath, Message: fmt.Sprintf("unknown parent resource %q", resource)}
	}

	appPath := "/"
	if len(parts) > 5 {
		// Must be /http or /http/... — unknown suffix is NotFound (404), not 400.
		if parts[5] != "http" {
			return nil, &PathError{Reason: ReasonNotFound, Message: "only /probes/http/{path} suffix is supported"}
		}
		if len(parts) > 6 {
			// Join remaining as path; empty segments → 400 InvalidProbePath.
			for _, seg := range parts[6:] {
				if seg == "" {
					return nil, &PathError{Reason: ReasonInvalidProbePath, Message: "empty path segment"}
				}
			}
			appPath = "/" + strings.Join(parts[6:], "/")
			// Preserve trailing slash on the application path (pass-through fidelity).
			if hadTrailingSlash {
				appPath += "/"
			}
		}
	}

	return &ProbeRoute{
		ParentKind: kind,
		Namespace:  ns,
		Name:       name,
		AppPath:    appPath,
		RawQuery:   rawQuery,
	}, nil
}

// PathError is a structured path parse failure.
type PathError struct {
	Reason  string
	Message string
}

func (e *PathError) Error() string {
	return e.Message
}

func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// ControlOptions are derived from X-KubeWAF-Probe-* headers.
type ControlOptions struct {
	TimeoutSeconds int
	RemoteAddr     string
	Mode           subv1alpha1.ProbeRequestedMode
	CrsEnable      *bool
	MaxMatches     int
	TraceID        string
}

// ParseControlHeaders extracts probe control options from request headers.
func ParseControlHeaders(h http.Header) (ControlOptions, error) {
	opt := ControlOptions{
		TimeoutSeconds: 5,
		Mode:           subv1alpha1.ProbeModeDetectionOnly,
		MaxMatches:     50,
	}
	if v := h.Get(HeaderTimeoutSeconds); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 30 {
			return opt, fmt.Errorf("invalid %s", HeaderTimeoutSeconds)
		}
		opt.TimeoutSeconds = n
	}
	if v := h.Get(HeaderRemoteAddr); v != "" {
		opt.RemoteAddr = v
	}
	if v := h.Get(HeaderMode); v != "" {
		switch v {
		case string(subv1alpha1.ProbeModeDetectionOnly), string(subv1alpha1.ProbeModeBlocking):
			opt.Mode = subv1alpha1.ProbeRequestedMode(v)
		default:
			return opt, fmt.Errorf("invalid %s", HeaderMode)
		}
	}
	if v := h.Get(HeaderCrsEnable); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return opt, fmt.Errorf("invalid %s", HeaderCrsEnable)
		}
		opt.CrsEnable = &b
	}
	if v := h.Get(HeaderMaxMatches); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			return opt, fmt.Errorf("invalid %s", HeaderMaxMatches)
		}
		opt.MaxMatches = n
	}
	if v := h.Get(HeaderTraceID); v != "" {
		opt.TraceID = v
	}
	return opt, nil
}

// hopByHopHeaders are never forwarded to Coraza as app headers.
var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"transfer-encoding":   {},
	"te":                  {},
	"trailer":             {},
	"upgrade":             {},
	"proxy-authorization": {},
	"proxy-authenticate":  {},
}

// denylistExact headers (case-insensitive).
var denylistExact = map[string]struct{}{
	"authorization":  {},
	"cookie":         {},
	"x-remote-user":  {},
	"x-remote-group": {},
}

// FilterAppHeaders returns headers to forward into EvalHTTPRequest after denylist.
func FilterAppHeaders(h http.Header) map[string]string {
	out := make(map[string]string)
	for k, vals := range h {
		lk := strings.ToLower(k)
		if _, ok := denylistExact[lk]; ok {
			continue
		}
		if _, ok := hopByHopHeaders[lk]; ok {
			continue
		}
		if strings.HasPrefix(lk, "x-remote-extra-") {
			continue
		}
		if strings.HasPrefix(lk, strings.ToLower(HeaderPrefix)) {
			continue
		}
		// Join multi-value headers with comma (HTTP common case).
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

// IsDeniedHeader reports whether a header name is on the denylist (for tests).
func IsDeniedHeader(name string) bool {
	lk := strings.ToLower(name)
	if _, ok := denylistExact[lk]; ok {
		return true
	}
	if _, ok := hopByHopHeaders[lk]; ok {
		return true
	}
	if strings.HasPrefix(lk, "x-remote-extra-") {
		return true
	}
	if strings.HasPrefix(lk, strings.ToLower(HeaderPrefix)) {
		return true
	}
	return false
}
