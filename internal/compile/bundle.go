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
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
)

// MountDir is the directory the platform mounts kubewaf-seclang on.
const MountDir = "/etc/kubewaf/seclang"

// ConfigMapName is the one ConfigMap kubeWAF writes in the proxy namespace.
const ConfigMapName = "kubewaf-seclang"

// VersionKey is the ConfigMap key whose value is the JSON map of policy -> bundle hash.
// The projection agent reads this file from the mounted volume and reports it.
const VersionKey = "kubewaf-version"

// SeenConfigMapName records the version file contents each node has projected.
const SeenConfigMapName = "kubewaf-seclang-seen"

// IncludeInput is one Include plus ConfigMap content the caller already fetched.
// Content is ignored for virtual paths.
type IncludeInput struct {
	Include seclangv1alpha1.Include
	Content string
}

// DataInput is one data file body. Content is set when the caller resolved a ConfigMap.
type DataInput struct {
	File    seclangv1alpha1.DataFile
	Content string
}

// Input is everything the compiler needs. It does not read the API server.
type Input struct {
	Policy   seclangv1alpha1.SecPolicy
	Rules    []seclangv1alpha1.SecRule
	Actions  []seclangv1alpha1.SecAction
	Includes []IncludeInput
	Data     []DataInput
}

// Bundle is the provider-neutral result.
// The Envoy Gateway provider turns it into filter directives. This package does not.
type Bundle struct {
	Namespace string
	Name      string
	// Hash is the hex sha256 of the file map. Marker is KUBEWAF plus the first 16 hex chars.
	Hash   string
	Marker string

	Engine             string
	RequestBodyAccess  bool
	ResponseBodyAccess bool
	// Inspection is REQUEST_ONLY or FULL.
	Inspection string
	ModuleName string

	Before string
	After  string
	Files  map[string]string
}

type piece struct {
	order     int32
	name      string
	kind      string
	placement seclangv1alpha1.Placement
	text      string
}

// Build writes the before and after documents, data files, and the SecMarker hash.
// Include lines are sorted with rules by order, then name, then kind.
// @crs-setup.conf and @owasp_crs globs are ordinary Include lines. There is no crs.bundle flag.
func Build(in Input) (Bundle, error) {
	if in.Policy.Namespace == "" || in.Policy.Name == "" {
		return Bundle{}, fmt.Errorf("policy namespace and name are required")
	}
	b := Bundle{
		Namespace:          in.Policy.Namespace,
		Name:               in.Policy.Name,
		Engine:             orString(in.Policy.Spec.Engine, "On"),
		RequestBodyAccess:  boolOr(in.Policy.Spec.RequestBodyAccess, true),
		ResponseBodyAccess: boolOr(in.Policy.Spec.ResponseBodyAccess, false),
		Inspection:         inspectionToken(orString(in.Policy.Spec.Inspection, "RequestOnly")),
		ModuleName:         orString(in.Policy.Spec.ModuleName, "composer"),
		Files:              map[string]string{},
	}
	if b.Inspection == "" {
		return Bundle{}, fmt.Errorf("inspection must be RequestOnly or Full")
	}
	switch b.Engine {
	case "On", "DetectionOnly", "Off":
	default:
		return Bundle{}, fmt.Errorf("engine must be On, DetectionOnly, or Off")
	}

	dataPaths, err := dataFiles(&b, in)
	if err != nil {
		return Bundle{}, err
	}

	var pieces []piece
	for i := range in.Rules {
		rule := in.Rules[i]
		text, err := emitRule(&rule, dataPaths)
		if err != nil {
			return Bundle{}, fmt.Errorf("SecRule %s: %w", rule.Name, err)
		}
		pieces = append(pieces, piece{rule.Spec.Order, rule.Name, "rule", place(rule.Spec.Placement), text})
	}
	for i := range in.Actions {
		action := in.Actions[i]
		text, err := EmitAction(&action)
		if err != nil {
			return Bundle{}, fmt.Errorf("SecAction %s: %w", action.Name, err)
		}
		pieces = append(pieces, piece{action.Spec.Order, action.Name, "action", place(action.Spec.Placement), text})
	}
	for _, inc := range in.Includes {
		key := includeKey(b.Namespace, b.Name, inc.Include.Name)
		abs := MountDir + "/" + key
		path, err := includePath(&inc.Include, "")
		if err != nil {
			return Bundle{}, fmt.Errorf("include %s: %w", inc.Include.Name, err)
		}
		if inc.Include.Spec.ConfigMapRef != nil {
			if inc.Content == "" && inc.Include.Spec.ConfigMapRef != nil {
				return Bundle{}, fmt.Errorf("include %s: configMap content is not resolved", inc.Include.Name)
			}
			if _, exists := b.Files[key]; exists {
				return Bundle{}, fmt.Errorf("include file key %s collides", key)
			}
			b.Files[key] = inc.Content
			path = abs
		}
		if err := checkMarker(inc.Include.Spec.MarkerAfter); err != nil {
			return Bundle{}, err
		}
		text := withMarker("Include "+path, inc.Include.Spec.MarkerAfter)
		pieces = append(pieces, piece{inc.Include.Spec.Order, inc.Include.Name, "include", place(inc.Include.Spec.Placement), text})
	}

	slices.SortStableFunc(pieces, func(a, c piece) int {
		if a.order != c.order {
			return cmp.Compare(a.order, c.order)
		}
		if a.name != c.name {
			return cmp.Compare(a.name, c.name)
		}
		return cmp.Compare(a.kind, c.kind)
	})

	var before, after []string
	seenPhase := map[int]struct{}{}
	for _, d := range in.Policy.Spec.DefaultActions {
		if _, ok := seenPhase[d.Phase]; ok {
			return Bundle{}, fmt.Errorf("default action phase %d is repeated", d.Phase)
		}
		seenPhase[d.Phase] = struct{}{}
		if d.Phase < 1 || d.Phase > 5 {
			return Bundle{}, fmt.Errorf("default action phase %d is out of range", d.Phase)
		}
		if strings.TrimSpace(d.Actions) == "" || strings.ContainsAny(d.Actions, "\n\r\"") {
			return Bundle{}, fmt.Errorf("default action for phase %d must be a single raw action list", d.Phase)
		}
		before = append(before, fmt.Sprintf("SecDefaultAction \"phase:%d,%s\"", d.Phase, d.Actions))
	}
	for _, p := range pieces {
		if p.placement == seclangv1alpha1.PlacementBeforeCRS {
			before = append(before, p.text)
		} else {
			after = append(after, p.text)
		}
	}
	for _, line := range in.Policy.Spec.PostDirectives {
		if strings.TrimSpace(line) == "" || strings.ContainsAny(line, "\n\r") {
			return Bundle{}, fmt.Errorf("postDirectives entries must be single lines")
		}
		after = append(after, line)
	}

	b.Before = strings.Join(before, "\n")
	b.After = strings.Join(after, "\n")
	beforeKey := fileKey(b.Namespace, b.Name, "before")
	afterKey := fileKey(b.Namespace, b.Name, "after")
	b.Files[beforeKey] = fileBody(b.Before)
	b.Files[afterKey] = fileBody(b.After)
	sum := hashFiles(b.Files)
	b.Hash = sum
	b.Marker = "KUBEWAF" + sum[:16]
	return b, nil
}

func dataFiles(b *Bundle, in Input) (map[string]string, error) {
	paths := map[string]string{}
	seen := map[string]struct{}{}
	files := in.Data
	if len(files) == 0 {
		for _, f := range in.Policy.Spec.DataFiles {
			files = append(files, DataInput{File: f, Content: f.Content})
		}
	}
	for _, d := range files {
		name := d.File.Name
		if name == "" {
			return nil, fmt.Errorf("data file name is empty")
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("duplicate data file %s", name)
		}
		seen[name] = struct{}{}
		content := d.Content
		if content == "" {
			content = d.File.Content
		}
		if content == "" {
			return nil, fmt.Errorf("data file %s content is not resolved", name)
		}
		if d.File.Content != "" && d.File.ConfigMapRef != nil {
			return nil, fmt.Errorf("data file %s sets content and configMapRef", name)
		}
		key := fmt.Sprintf("%s_%s_%s", b.Namespace, b.Name, name)
		b.Files[key] = content
		paths[name] = MountDir + "/" + key
	}
	return paths, nil
}

func fileKey(ns, name, which string) string {
	return fmt.Sprintf("%s_%s-%s.conf", ns, name, which)
}

func includeKey(ns, policy, includeName string) string {
	return fmt.Sprintf("%s_%s_%s.conf", ns, policy, includeName)
}

func fileBody(text string) string {
	if text == "" {
		return ""
	}
	if strings.HasSuffix(text, "\n") {
		return text
	}
	return text + "\n"
}

func hashFiles(files map[string]string) string {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(files[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func place(p seclangv1alpha1.Placement) seclangv1alpha1.Placement {
	if p == seclangv1alpha1.PlacementBeforeCRS {
		return p
	}
	return seclangv1alpha1.PlacementAfterCRS
}

func orString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func inspectionToken(v string) string {
	switch v {
	case "RequestOnly":
		return "REQUEST_ONLY"
	case "Full":
		return "FULL"
	default:
		return ""
	}
}

// BeforeKey and AfterKey are the ConfigMap keys for the two documents.
func BeforeKey(namespace, name string) string { return fileKey(namespace, name, "before") }
func AfterKey(namespace, name string) string  { return fileKey(namespace, name, "after") }
