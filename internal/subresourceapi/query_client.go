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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxQueryResponseBytes = 8 * 1024 * 1024
	defaultQueryTimeout   = 20 * time.Second
)

// QueryBackend is the in-cluster Prom/Jaeger client (operator / subresource-api only).
type QueryBackend struct {
	MetricsURL string
	TracesURL  string
	HTTPClient *http.Client
}

// NewQueryBackend builds a ClusterIP HTTP client. Proxy env is ignored.
func NewQueryBackend(metricsURL, tracesURL string) *QueryBackend {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &QueryBackend{
		MetricsURL: strings.TrimRight(strings.TrimSpace(metricsURL), "/"),
		TracesURL:  strings.TrimRight(strings.TrimSpace(tracesURL), "/"),
		HTTPClient: &http.Client{
			Timeout: defaultQueryTimeout,
			Transport: &http.Transport{
				Proxy: nil,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
			},
		},
	}
}

func (q *QueryBackend) metricsConfigured() bool {
	return q != nil && q.MetricsURL != ""
}

func (q *QueryBackend) tracesConfigured() bool {
	return q != nil && q.TracesURL != ""
}

func (q *QueryBackend) instantQuery(ctx context.Context, promql string) ([]byte, string, *MappedError) {
	if !q.metricsConfigured() {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: "NoMetricsBackend", Message: "metrics backend is not configured"}
	}
	u, err := url.Parse(q.MetricsURL + "/api/v1/query")
	if err != nil {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "invalid metrics backend URL"}
	}
	qs := u.Query()
	qs.Set("query", promql)
	u.RawQuery = qs.Encode()
	return q.get(ctx, u.String())
}

func (q *QueryBackend) rangeQuery(ctx context.Context, promql, start, end, step string) ([]byte, string, *MappedError) {
	if !q.metricsConfigured() {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: "NoMetricsBackend", Message: "metrics backend is not configured"}
	}
	u, err := url.Parse(q.MetricsURL + "/api/v1/query_range")
	if err != nil {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "invalid metrics backend URL"}
	}
	qs := u.Query()
	qs.Set("query", promql)
	qs.Set("start", start)
	qs.Set("end", end)
	qs.Set("step", step)
	u.RawQuery = qs.Encode()
	return q.get(ctx, u.String())
}

func (q *QueryBackend) jaegerTraces(ctx context.Context, tagsJSON string, startUs, endUs int64, limit int) ([]byte, string, *MappedError) {
	if !q.tracesConfigured() {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: "NoTracesBackend", Message: "traces backend is not configured"}
	}
	u, err := url.Parse(q.TracesURL + "/select/jaeger/api/traces")
	if err != nil {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "invalid traces backend URL"}
	}
	qs := u.Query()
	qs.Set("service", "kubewaf")
	qs.Set("operation", "waf.eval")
	qs.Set("tags", tagsJSON)
	qs.Set("limit", fmt.Sprintf("%d", limit))
	if startUs > 0 {
		qs.Set("start", fmt.Sprintf("%d", startUs))
	}
	if endUs > 0 {
		qs.Set("end", fmt.Sprintf("%d", endUs))
	}
	u.RawQuery = qs.Encode()
	return q.get(ctx, u.String())
}

func (q *QueryBackend) jaegerTraceByID(ctx context.Context, traceID string) ([]byte, string, *MappedError) {
	if !q.tracesConfigured() {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: "NoTracesBackend", Message: "traces backend is not configured"}
	}
	if traceID == "" || strings.Contains(traceID, "/") || strings.Contains(traceID, "..") {
		return nil, "", &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: "invalid trace id"}
	}
	u := strings.TrimRight(q.TracesURL, "/") + "/select/jaeger/api/traces/" + url.PathEscape(traceID)
	return q.get(ctx, u)
}

func (q *QueryBackend) get(ctx context.Context, rawURL string) ([]byte, string, *MappedError) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "failed to build backend request"}
	}
	resp, err := q.HTTPClient.Do(req)
	if err != nil {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: "BackendUnreachable", Message: "query backend unreachable"}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxQueryResponseBytes+1))
	if err != nil {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: "BackendUnreachable", Message: "failed to read backend response"}
	}
	if len(body) > maxQueryResponseBytes {
		return nil, "", &MappedError{HTTPStatus: 413, Reason: "RequestEntityTooLarge", Message: "backend response exceeds 8 MiB"}
	}
	if resp.StatusCode >= 400 {
		return nil, "", &MappedError{
			HTTPStatus: 502,
			Reason:     "BackendError",
			Message:    fmt.Sprintf("query backend returned %d", resp.StatusCode),
		}
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	return body, ct, nil
}
