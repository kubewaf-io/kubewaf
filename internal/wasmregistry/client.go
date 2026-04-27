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

package wasmregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Client is a simple HTTP client for the coraza-wasm-registry service.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// CreateRequest matches the expected payload for POST /api/v1beta1/coraza.
type CreateRequest struct {
	Name    string                      `json:"name"`
	Objects []unstructured.Unstructured `json:"objects,omitempty"`
}

// Response is a generic response from the registry API.
type Response struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// NewClient creates a new registry client. baseURL defaults to http://localhost:3000.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:3000"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second, // WASM build can take time
		},
	}
}

// Create ensures a WASM module is built and registered for the given name and objects.
// It sends the objects (typically resolved CRs/rules) to the registry.
func (c *Client) Create(ctx context.Context, namespace, name, version string, objects []unstructured.Unstructured) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}

	reqBody := CreateRequest{
		Name:    generateName(namespace, name, version),
		Objects: objects,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.baseURL + "/api/v1beta1/coraza"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("POST %s failed: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		var apiErr Response
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		return fmt.Errorf("registry create failed (status %d): %s", resp.StatusCode, apiErr.Error)
	}

	return nil
}

// GetURL returns the HTTP URL where the WASM can be fetched (for Envoy Wasm config).
func (c *Client) GetURL(namespace, name, version string) string {

	return fmt.Sprintf("%s/api/v1beta1/coraza/%s", c.baseURL, generateName(namespace, name, version))
}

// Download fetches the raw WASM bytes (useful for caching or debugging).
func (c *Client) Download(ctx context.Context, namespace, name, version string) ([]byte, error) {
	url := c.GetURL(namespace, name, version)
	if url == "" {
		return nil, fmt.Errorf("invalid name")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var apiErr Response
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		return nil, fmt.Errorf("download failed (status %d): %s", resp.StatusCode, apiErr.Error)
	}

	return io.ReadAll(resp.Body)
}

func generateName(namespace, name, version string) string {
	return fmt.Sprintf("%s_%s_%s", namespace, name, version)
}
