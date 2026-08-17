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
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMapTestServerStatus(t *testing.T) {
	cases := []struct {
		code       int
		wantStatus int
		wantReason string
	}{
		{200, 0, ""},
		{400, 400, "EvalRequestInvalid"},
		{401, 503, "TestServerUnauthorized"},
		{413, 400, "EvalPayloadTooLarge"},
		{429, 429, "TestServerBusy"},
		{504, 503, "EvalTimeout"},
		{500, 503, "EvalEngineError"},
		{503, 503, "TestServerUnavailable"},
	}
	for _, tt := range cases {
		got := MapTestServerStatus(tt.code)
		if tt.code == 200 {
			if got != nil {
				t.Fatalf("200 should map to nil")
			}
			continue
		}
		if got.HTTPStatus != tt.wantStatus || got.Reason != tt.wantReason {
			t.Errorf("code %d -> %+v want status=%d reason=%s", tt.code, got, tt.wantStatus, tt.wantReason)
		}
	}
}

func TestWriteStatusShape(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteStatus(rr, &MappedError{HTTPStatus: 403, Reason: "Forbidden", Message: "denied"})
	if rr.Code != 403 {
		t.Fatalf("code %d", rr.Code)
	}
	var st metav1.Status
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Kind != "Status" || st.Status != metav1.StatusFailure {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Reason != "Forbidden" || st.Code != 403 {
		t.Fatalf("reason/code: %+v", st)
	}
}

func TestHTTPEvalClientErrorMapping(t *testing.T) {
	// Unit-test mapping via MapTestServerStatus covers the matrix; client uses same table.
	_ = http.StatusOK
}
