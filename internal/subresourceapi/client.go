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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kubewaf-io/kubewaf/internal/probetest/api"
)

// EvalClient calls the Test HTTP Server /v1/eval.
type EvalClient interface {
	Eval(ctx context.Context, req *api.EvalRequest, timeoutSeconds int) (*api.EvalResponse, *MappedError)
}

// ReadyChecker is optionally implemented by EvalClient for /readyz.
type ReadyChecker interface {
	Ready(ctx context.Context) error
}

// HTTPEvalClient is the production EvalClient.
type HTTPEvalClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	// ConnectTimeout is applied to Transport DialContext.
	ConnectTimeout time.Duration
}

// NewHTTPEvalClient builds a client with connect timeout default 2s.
// BaseURL trailing slashes are stripped.
func NewHTTPEvalClient(baseURL, token string) *HTTPEvalClient {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	connectTO := 2 * time.Second
	dialer := &net.Dialer{Timeout: connectTO}
	return &HTTPEvalClient{
		BaseURL: baseURL,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 0,
			Transport: &http.Transport{
				// Never honor HTTP_PROXY for eval hop (bearer + directives must not leave cluster path).
				Proxy: nil,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
				// Response header bound per-request via context deadline in Eval.
				ResponseHeaderTimeout: 0,
			},
		},
		ConnectTimeout: connectTO,
	}
}

// Ready GETs the Test Server /readyz.
func (c *HTTPEvalClient) Ready(ctx context.Context) error {
	if c == nil || c.BaseURL == "" {
		return fmt.Errorf("eval client not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/readyz", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("test server readyz status %d", resp.StatusCode)
	}
	return nil
}

// Eval POSTs EvalRequest and maps Test Server status codes (error matrix).
func (c *HTTPEvalClient) Eval(ctx context.Context, req *api.EvalRequest, timeoutSeconds int) (*api.EvalResponse, *MappedError) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	// API Server client timeout = eval budget + 1s skew (K25/error model).
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds+1)*time.Second)
	defer cancel()

	body, err := json.Marshal(req)
	if err != nil {
		return nil, &MappedError{HTTPStatus: 500, Reason: ReasonInternalError, Message: "encode eval request failed"}
	}
	url := c.BaseURL + "/v1/eval"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, &MappedError{HTTPStatus: 503, Reason: "TestServerUnreachable", Message: "build request failed"}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &MappedError{HTTPStatus: 503, Reason: "EvalTimeout", Message: "evaluation timed out"}
		}
		return nil, &MappedError{HTTPStatus: 503, Reason: "TestServerUnreachable", Message: "test server unreachable"}
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))

	if resp.StatusCode == http.StatusOK {
		var er api.EvalResponse
		if err := json.Unmarshal(respBody, &er); err != nil {
			return nil, &MappedError{HTTPStatus: 503, Reason: ReasonEvalEngineError, Message: "invalid eval response"}
		}
		return &er, nil
	}

	// Prefer machine-readable class when present (e.g. compile_failed → 422).
	var eb api.ErrorBody
	_ = json.Unmarshal(respBody, &eb)
	if eb.Class == api.ErrClassCompileFailed {
		return nil, &MappedError{HTTPStatus: 422, Reason: "EvalCompileFailed", Message: "rule compile failed"}
	}

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return nil, &MappedError{HTTPStatus: 400, Reason: "EvalRequestInvalid", Message: "invalid eval request"}
	case http.StatusUnauthorized:
		return nil, &MappedError{HTTPStatus: 503, Reason: "TestServerUnauthorized", Message: "test server authentication failed"}
	case http.StatusRequestEntityTooLarge:
		return nil, &MappedError{HTTPStatus: 400, Reason: "EvalPayloadTooLarge", Message: "eval payload too large"}
	case http.StatusTooManyRequests:
		return nil, &MappedError{HTTPStatus: 429, Reason: "TestServerBusy", Message: "test server busy"}
	case http.StatusGatewayTimeout:
		return nil, &MappedError{HTTPStatus: 503, Reason: "EvalTimeout", Message: "evaluation timed out"}
	case http.StatusServiceUnavailable:
		return nil, &MappedError{HTTPStatus: 503, Reason: "TestServerUnavailable", Message: "test server unavailable"}
	case http.StatusUnprocessableEntity:
		return nil, &MappedError{HTTPStatus: 422, Reason: "EvalCompileFailed", Message: "rule compile failed"}
	case http.StatusInternalServerError:
		return nil, &MappedError{HTTPStatus: 503, Reason: ReasonEvalEngineError, Message: "evaluation engine error"}
	default:
		return nil, &MappedError{
			HTTPStatus: 503,
			Reason:     ReasonEvalEngineError,
			Message:    fmt.Sprintf("unexpected test server status %d", resp.StatusCode),
		}
	}
}

// StubEvalClient is a test double for EvalClient.
type StubEvalClient struct {
	// Fn is called for each Eval; if nil, returns a simple non-disrupted response.
	Fn func(ctx context.Context, req *api.EvalRequest, timeoutSeconds int) (*api.EvalResponse, *MappedError)
	// ReadyErr when set makes Ready fail (for readyz tests).
	ReadyErr error
}

// Eval implements EvalClient.
func (s *StubEvalClient) Eval(ctx context.Context, req *api.EvalRequest, timeoutSeconds int) (*api.EvalResponse, *MappedError) {
	if s.Fn != nil {
		return s.Fn(ctx, req, timeoutSeconds)
	}
	return &api.EvalResponse{
		Engine:        "coraza-go",
		EngineVersion: "coraza/v3.7.0",
		RulesLoaded:   1,
		Interruption:  &api.EvalInterrupt{Disrupted: false, Action: "pass"},
		HTTP:          api.EvalHTTPView{WouldStatus: 200},
	}, nil
}

// Ready implements ReadyChecker for tests.
func (s *StubEvalClient) Ready(context.Context) error {
	return s.ReadyErr
}
