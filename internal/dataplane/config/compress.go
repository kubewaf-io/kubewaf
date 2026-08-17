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

package config

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// DirectivesEncodingGzipBase64 is the plugin JSON encoding for compressed SecLang.
// Operator emits base64(gzip(joined lines with "\n")). Wasm inflates then splits on newlines.
const DirectivesEncodingGzipBase64 = "gzip+base64"

// DirectivesCompressThreshold is the minimum joined SecLang size (bytes) that triggers
// compression for modsecurity-proxy-wasm. Below this, plain []string is used (easier debug).
// Set to 0 to always compress. Tests may override.
var DirectivesCompressThreshold = 4 * 1024

// DirectivesMaxInflatedBytes is the max allowed size after gunzip (zip-bomb guard).
// Mirrored in modsecurity-proxy-wasm waf_config.cc.
const DirectivesMaxInflatedBytes = 32 * 1024 * 1024

// CompressDirectivesGzipBase64 joins directive lines with "\n", gzip-compresses, and base64-encodes.
func CompressDirectivesGzipBase64(directives []string) (encoded string, rawBytes, compressedBytes int, err error) {
	joined := strings.Join(directives, "\n")
	if joined != "" && !strings.HasSuffix(joined, "\n") {
		joined += "\n"
	}
	rawBytes = len(joined)
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", rawBytes, 0, err
	}
	if _, err := zw.Write([]byte(joined)); err != nil {
		_ = zw.Close()
		return "", rawBytes, 0, err
	}
	if err := zw.Close(); err != nil {
		return "", rawBytes, 0, err
	}
	compressedBytes = buf.Len()
	encoded = base64.StdEncoding.EncodeToString(buf.Bytes())
	return encoded, rawBytes, compressedBytes, nil
}

// CompressBytesGzipBase64 gzip-compresses then base64-encodes raw bytes (data_files bodies).
func CompressBytesGzipBase64(raw []byte) (encoded string, rawBytes, compressedBytes int, err error) {
	rawBytes = len(raw)
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", rawBytes, 0, err
	}
	if _, err := zw.Write(raw); err != nil {
		_ = zw.Close()
		return "", rawBytes, 0, err
	}
	if err := zw.Close(); err != nil {
		return "", rawBytes, 0, err
	}
	compressedBytes = buf.Len()
	encoded = base64.StdEncoding.EncodeToString(buf.Bytes())
	return encoded, rawBytes, compressedBytes, nil
}

// ShouldCompressDirectives reports whether directives should be gzip+base64 encoded.
func ShouldCompressDirectives(directives []string) bool {
	if DirectivesCompressThreshold <= 0 {
		return len(directives) > 0
	}
	n := 0
	for i, d := range directives {
		n += len(d)
		if i > 0 {
			n++ // newline
		}
		if n >= DirectivesCompressThreshold {
			return true
		}
	}
	return false
}

// DecompressDirectivesGzipBase64 inflates a gzip+base64 blob (tests / operator tooling).
func DecompressDirectivesGzipBase64(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = zr.Close() }()
	limited := io.LimitReader(zr, DirectivesMaxInflatedBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("gzip read: %w", err)
	}
	if len(body) > DirectivesMaxInflatedBytes {
		return "", fmt.Errorf("inflated directives exceed max size (%d)", DirectivesMaxInflatedBytes)
	}
	return string(body), nil
}
