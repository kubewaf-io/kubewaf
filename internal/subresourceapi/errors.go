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
	"encoding/json"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Aggregated error / path reason strings (goconst).
const (
	ReasonNotFound             = "NotFound"
	ReasonInvalidProbePath     = "InvalidProbePath"
	ReasonEvalEngineError      = "EvalEngineError"
	ReasonAssemblyFailed       = "AssemblyFailed"
	ReasonRuleIDsUnresolved    = "RuleIDsUnresolved"
	ReasonReferencesUnresolved = "ReferencesUnresolved"
	ReasonCRSPathA             = "CorazaCRSPathAUnsupported"
	ReasonInternalError        = "InternalError"
	ReasonBadRequest           = "BadRequest"
	ReasonMethodNotAllowed     = "MethodNotAllowed"
	ReasonTooManyRequests      = "TooManyRequests"
)

// MappedError is an aggregated API error rendered as metav1.Status (K30).
type MappedError struct {
	HTTPStatus int
	Reason     string
	Message    string
}

func (e *MappedError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// WriteStatus writes a metav1.Status JSON error body.
func WriteStatus(w http.ResponseWriter, err *MappedError) {
	if err == nil {
		err = &MappedError{HTTPStatus: 500, Reason: ReasonInternalError, Message: "internal error"}
	}
	status := metav1.Status{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Status",
			APIVersion: "v1",
		},
		Status:  metav1.StatusFailure,
		Message: err.Message,
		Reason:  metav1.StatusReason(err.Reason),
		Code:    int32(err.HTTPStatus),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	_ = json.NewEncoder(w).Encode(status)
}

// WriteMethodNotAllowed writes a 405 Status for non-GET/HEAD subresource verbs.
func WriteMethodNotAllowed(w http.ResponseWriter) {
	WriteStatus(w, &MappedError{
		HTTPStatus: http.StatusMethodNotAllowed,
		Reason:     ReasonMethodNotAllowed,
		Message:    "method not allowed",
	})
}

// MapTestServerStatus maps a raw Test Server HTTP status to aggregated error (unit-test helper).
func MapTestServerStatus(code int) *MappedError {
	switch code {
	case http.StatusOK:
		return nil
	case http.StatusBadRequest:
		return &MappedError{HTTPStatus: 400, Reason: "EvalRequestInvalid", Message: "invalid eval request"}
	case http.StatusUnauthorized:
		return &MappedError{HTTPStatus: 503, Reason: "TestServerUnauthorized", Message: "test server authentication failed"}
	case http.StatusRequestEntityTooLarge:
		return &MappedError{HTTPStatus: 400, Reason: "EvalPayloadTooLarge", Message: "eval payload too large"}
	case http.StatusTooManyRequests:
		return &MappedError{HTTPStatus: 429, Reason: "TestServerBusy", Message: "test server busy"}
	case http.StatusGatewayTimeout:
		return &MappedError{HTTPStatus: 503, Reason: "EvalTimeout", Message: "evaluation timed out"}
	case http.StatusServiceUnavailable:
		return &MappedError{HTTPStatus: 503, Reason: "TestServerUnavailable", Message: "test server unavailable"}
	case http.StatusInternalServerError:
		return &MappedError{HTTPStatus: 503, Reason: ReasonEvalEngineError, Message: "evaluation engine error"}
	default:
		return &MappedError{HTTPStatus: 503, Reason: ReasonEvalEngineError, Message: "unexpected test server status"}
	}
}
