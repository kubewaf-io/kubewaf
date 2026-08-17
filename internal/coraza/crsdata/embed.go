/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

10→Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package crsdata embeds stock OWASP CRS *.data phrase lists used by
// @pmFromFile for operator-side Coraza validation (WithRootFS).
// Keep in sync with modsecurity-proxy-wasm @crs-data catalog assets.
package crsdata

import (
	"embed"
	"io/fs"
	"path"
	"testing/fstest"
)

//go:embed *.data
var files embed.FS

// AnnotationAllowCRSOverride must be set to "true" on a PhraseList whose
// fileName is a stock CRS basename before the dataplane will inject an override.
const AnnotationAllowCRSOverride = "seclang.kubewaf.io/allow-crs-override"

// Known basenames (21 catalog assets). Keep sorted.
var Basenames = []string{
	"ai-critical-artifacts.data",
	"asp-dotnet-errors.data",
	"iis-errors.data",
	"java-classes.data",
	"lfi-os-files.data",
	"php-errors.data",
	"php-function-names-933150.data",
	"php-variables.data",
	"restricted-files.data",
	"restricted-upload.data",
	"ruby-errors.data",
	"scanners-user-agents.data",
	"sql-errors.data",
	"ssrf-no-scheme.data",
	"ssrf.data",
	"unix-shell-aliases.data",
	"unix-shell-builtins.data",
	"unix-shell.data",
	"web-shells-asp.data",
	"web-shells-php.data",
	"windows-powershell-commands.data",
}

var basenameSet map[string]struct{}

func init() {
	basenameSet = make(map[string]struct{}, len(Basenames))
	for _, b := range Basenames {
		basenameSet[b] = struct{}{}
	}
}

// IsKnown reports whether name is a stock CRS @pmFromFile data file basename.
func IsKnown(name string) bool {
	_, ok := basenameSet[path.Base(name)]
	return ok
}

// Available reports whether the embed pack loaded at least one .data file.
func Available() bool {
	entries, err := fs.ReadDir(files, ".")
	return err == nil && len(entries) > 0
}

// MapFS returns an fstest.MapFS with all embedded CRS data files keyed by basename.
// Optional overrides (basename → body) replace or add entries (PhraseList merge).
func MapFS(overrides map[string][]byte) fstest.MapFS {
	m := make(fstest.MapFS)
	_ = fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		base := path.Base(p)
		if path.Ext(base) != ".data" {
			return nil
		}
		b, rerr := files.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		// Copy so callers can mutate overrides without touching embed.
		cp := make([]byte, len(b))
		copy(cp, b)
		m[base] = &fstest.MapFile{Data: cp}
		return nil
	})
	for k, v := range overrides {
		base := path.Base(k)
		if base == "" || base == "." {
			continue
		}
		cp := make([]byte, len(v))
		copy(cp, v)
		m[base] = &fstest.MapFile{Data: cp}
	}
	return m
}

// Read returns the embedded body for a known basename, or nil if missing.
func Read(basename string) ([]byte, error) {
	base := path.Base(basename)
	return files.ReadFile(base)
}
