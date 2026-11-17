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

package compile

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
)

const parsePreamble = "SecRuleEngine On\nSecRequestBodyAccess On\n"

// Parse asks Coraza to compile one directive, or several lines.
// Virtual includes and mount paths that are not in files are empty files:
// the operator does not ship the module's embedded CRS, and a glob with no
// matches is a Coraza warning rather than a parse error.
func Parse(directive string) error {
	return ParseFiles(directive, nil)
}

// ParseFiles is Parse with extra file bodies keyed by the path Coraza will open.
func ParseFiles(directive string, files map[string]string) error {
	if strings.TrimSpace(directive) == "" {
		return fmt.Errorf("empty directive")
	}
	cfg := coraza.NewWAFConfig().
		WithRootFS(ruleFS{files: files}).
		WithDirectives(parsePreamble + directive + "\n")
	if _, err := coraza.NewWAF(cfg); err != nil {
		return err
	}
	return nil
}

// ruleFS serves known files and empty bodies for @ paths and the mount dir.
type ruleFS struct {
	files map[string]string
}

func (r ruleFS) Open(name string) (fs.File, error) {
	if c, ok := r.lookup(name); ok {
		return newMemFile(name, c), nil
	}
	if c, ok := r.lookup(path.Base(name)); ok {
		return newMemFile(name, c), nil
	}
	if strings.HasPrefix(name, "@") || strings.HasPrefix(strings.TrimPrefix(name, "/"), "@") || strings.Contains(name, "kubewaf/seclang/") {
		return newMemFile(name, ""), nil
	}
	return nil, fs.ErrNotExist
}

func (r ruleFS) lookup(name string) (string, bool) {
	if r.files == nil {
		return "", false
	}
	if c, ok := r.files[name]; ok {
		return c, true
	}
	if c, ok := r.files["/"+name]; ok {
		return c, true
	}
	return "", false
}

func (r ruleFS) Glob(pattern string) ([]string, error) {
	var matched []string
	for k := range r.files {
		ok, err := path.Match(pattern, strings.TrimPrefix(k, "/"))
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, strings.TrimPrefix(k, "/"))
		}
	}
	if len(matched) == 0 && strings.Contains(pattern, "*") {
		return []string{strings.ReplaceAll(pattern, "*", "stub")}, nil
	}
	return matched, nil
}

type memFile struct {
	name string
	r    *bytes.Reader
}

func newMemFile(name, content string) *memFile {
	return &memFile{name: name, r: bytes.NewReader([]byte(content))}
}

func (m *memFile) Stat() (fs.FileInfo, error) {
	return memInfo{name: m.name, size: m.r.Size()}, nil
}
func (m *memFile) Read(p []byte) (int, error) { return m.r.Read(p) }
func (m *memFile) Close() error               { return nil }

type memInfo struct {
	name string
	size int64
}

func (m memInfo) Name() string       { return path.Base(m.name) }
func (m memInfo) Size() int64        { return m.size }
func (m memInfo) Mode() fs.FileMode  { return 0o644 }
func (m memInfo) ModTime() time.Time { return time.Time{} }
func (m memInfo) IsDir() bool        { return false }
func (m memInfo) Sys() any           { return nil }
