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

package probeassemble

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

// PhraseListPolicy mirrors waf.PhraseListPolicy without importing waf types into
// every call site (string constants only for slim assembly).
type PhraseListPolicy string

const (
	// PhraseListPolicyFailClosed refuses when a custom list is missing/not Ready.
	PhraseListPolicyFailClosed PhraseListPolicy = "FailClosed"
	// PhraseListPolicyIgnoreUnknown drops lines for unresolved basenames.
	PhraseListPolicyIgnoreUnknown PhraseListPolicy = "IgnoreUnknown"
)

// DataFilesResult is the outcome of ResolveDataFiles.
type DataFilesResult struct {
	Files            map[string][]byte
	DroppedBasenames []string
	RawBytes         int64
	// EffectiveLines is directiveLines after IgnoreUnknown drops (SecLang rewrite).
	// When nothing is dropped this equals the input lines.
	EffectiveLines []string
}

// ListBodyProvider looks up PhraseList/IPList bodies by basename in a namespace.
// Tests can stub this without a full kube client.
type ListBodyProvider interface {
	// Lookup returns body, ready, found for a basename.
	Lookup(ctx context.Context, namespace, basename string) (body []byte, ready bool, found bool, err error)
}

// ClientListProvider implements ListBodyProvider via controller-runtime client.
type ClientListProvider struct {
	Client client.Client
}

// Lookup finds a PhraseList or IPList by spec.fileName in the namespace.
// Ready lists win when several share a basename. Bodies come from content,
// configMapRef, or parts (same composition as operator inject). An empty or
// unreadable composed body is treated as found-but-not-ready so probes do
// not inject "".
func (p *ClientListProvider) Lookup(ctx context.Context, namespace, basename string) ([]byte, bool, bool, error) {
	if p == nil || p.Client == nil {
		return nil, false, false, fmt.Errorf("nil client")
	}
	var plList seclangv1beta1.PhraseListList
	if err := p.Client.List(ctx, &plList, client.InNamespace(namespace)); err != nil {
		return nil, false, false, err
	}
	if pl, found, ready, err := pickReadyPhraseList(plList.Items, namespace, basename); err != nil {
		return nil, false, false, err
	} else if found {
		if !ready {
			return nil, false, true, nil
		}
		body, berr := resolvePhraseListBody(ctx, p.Client, pl)
		if berr != nil || len(body) == 0 {
			// Compose failure / empty file: do not inject "".
			if berr != nil {
				return nil, false, true, berr
			}
			return nil, false, true, nil
		}
		return body, true, true, nil
	}

	var ipList seclangv1beta1.IPListList
	if err := p.Client.List(ctx, &ipList, client.InNamespace(namespace)); err != nil {
		return nil, false, false, err
	}
	if ipl, found, ready, err := pickReadyIPList(ipList.Items, namespace, basename); err != nil {
		return nil, false, false, err
	} else if found {
		if !ready {
			return nil, false, true, nil
		}
		body, berr := resolveIPListBody(ctx, p.Client, ipl)
		if berr != nil || len(body) == 0 {
			if berr != nil {
				return nil, false, true, berr
			}
			return nil, false, true, nil
		}
		return body, true, true, nil
	}
	return nil, false, false, nil
}

func listFileName(spec, status string) string {
	if spec != "" {
		return spec
	}
	return status
}

func pickReadyPhraseList(items []seclangv1beta1.PhraseList, ns, basename string) (*seclangv1beta1.PhraseList, bool, bool, error) {
	var (
		readyMatch *seclangv1beta1.PhraseList
		anyMatch   bool
	)
	for i := range items {
		pl := &items[i]
		if listFileName(pl.Spec.FileName, pl.Status.FileName) != basename {
			continue
		}
		anyMatch = true
		if !meta.IsStatusConditionTrue(pl.Status.Conditions, "Ready") {
			continue
		}
		if readyMatch != nil {
			return nil, false, false, fmt.Errorf("FileNameConflict: multiple Ready PhraseLists for %s/%s", ns, basename)
		}
		readyMatch = pl
	}
	if readyMatch != nil {
		return readyMatch, true, true, nil
	}
	if anyMatch {
		return nil, true, false, nil
	}
	return nil, false, false, nil
}

func pickReadyIPList(items []seclangv1beta1.IPList, ns, basename string) (*seclangv1beta1.IPList, bool, bool, error) {
	var (
		readyMatch *seclangv1beta1.IPList
		anyMatch   bool
	)
	for i := range items {
		ipl := &items[i]
		if listFileName(ipl.Spec.FileName, ipl.Status.FileName) != basename {
			continue
		}
		anyMatch = true
		if !meta.IsStatusConditionTrue(ipl.Status.Conditions, "Ready") {
			continue
		}
		if readyMatch != nil {
			return nil, false, false, fmt.Errorf("FileNameConflict: multiple Ready IPLists for %s/%s", ns, basename)
		}
		readyMatch = ipl
	}
	if readyMatch != nil {
		return readyMatch, true, true, nil
	}
	if anyMatch {
		return nil, true, false, nil
	}
	return nil, false, false, nil
}

// resolvePhraseListBody matches dataplane/config.ResolvePhraseListBody without
// importing that package (K29).
func resolvePhraseListBody(ctx context.Context, c client.Client, pl *seclangv1beta1.PhraseList) ([]byte, error) {
	if pl == nil {
		return nil, fmt.Errorf("phraselist is nil")
	}
	if pl.Spec.Content != "" {
		return []byte(pl.Spec.Content), nil
	}
	if pl.Spec.ConfigMapRef != nil {
		return readConfigMapKey(ctx, c, pl.Namespace, pl.Spec.ConfigMapRef.Name, pl.Spec.ConfigMapRef.Key)
	}
	if len(pl.Spec.Parts) > 0 {
		var buf []byte
		for _, part := range pl.Spec.Parts {
			b, err := readConfigMapKey(ctx, c, pl.Namespace, part.ConfigMapRef.Name, part.ConfigMapRef.Key)
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
			if len(buf) > 0 && buf[len(buf)-1] != '\n' {
				buf = append(buf, '\n')
			}
		}
		return buf, nil
	}
	return nil, fmt.Errorf("PhraseList %s/%s has no content source", pl.Namespace, pl.Name)
}

// resolveIPListBody matches dataplane/config.ResolveIPListBody without importing that package (K29).
func resolveIPListBody(ctx context.Context, c client.Client, ipl *seclangv1beta1.IPList) ([]byte, error) {
	if ipl == nil {
		return nil, fmt.Errorf("iplist is nil")
	}
	if ipl.Spec.Content != "" {
		return []byte(ipl.Spec.Content), nil
	}
	if ipl.Spec.ConfigMapRef != nil {
		return readConfigMapKey(ctx, c, ipl.Namespace, ipl.Spec.ConfigMapRef.Name, ipl.Spec.ConfigMapRef.Key)
	}
	if len(ipl.Spec.Parts) > 0 {
		var buf []byte
		for _, part := range ipl.Spec.Parts {
			b, err := readConfigMapKey(ctx, c, ipl.Namespace, part.ConfigMapRef.Name, part.ConfigMapRef.Key)
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
			if len(buf) > 0 && buf[len(buf)-1] != '\n' {
				buf = append(buf, '\n')
			}
		}
		return buf, nil
	}
	return nil, fmt.Errorf("IPList %s/%s has no content source", ipl.Namespace, ipl.Name)
}

func readConfigMapKey(ctx context.Context, c client.Client, ns, name, key string) ([]byte, error) {
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &cm); err != nil {
		return nil, fmt.Errorf("configmap %s/%s: %w", ns, name, err)
	}
	if v, ok := cm.Data[key]; ok {
		return []byte(v), nil
	}
	if v, ok := cm.BinaryData[key]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("configmap %s/%s missing key %q", ns, name, key)
}

// MapProvider is a test/simple ListBodyProvider from an in-memory map.
type MapProvider struct {
	// Files maps namespace/basename → body.
	Files map[string][]byte
	// Ready maps namespace/basename → ready (default true if missing and file present).
	Ready map[string]bool
}

// Lookup implements ListBodyProvider.
func (m *MapProvider) Lookup(_ context.Context, namespace, basename string) ([]byte, bool, bool, error) {
	key := namespace + "/" + basename
	body, ok := m.Files[key]
	if !ok {
		// also try basename-only keys for simple tests
		body, ok = m.Files[basename]
		if !ok {
			return nil, false, false, nil
		}
	}
	ready := true
	if m.Ready != nil {
		if r, exists := m.Ready[key]; exists {
			ready = r
		} else if r, exists := m.Ready[basename]; exists {
			ready = r
		}
	}
	return body, ready, true, nil
}

// ResolveDataFiles builds MapFS bodies for @pmFromFile / @ipMatchFromFile basenames.
// overrides are merged last (highest precedence).
// When provider is nil, only overrides are used; missing basenames follow policy.
func ResolveDataFiles(
	ctx context.Context,
	provider ListBodyProvider,
	namespace string,
	policy PhraseListPolicy,
	directiveLines []string,
	overrides map[string][]byte,
) (*DataFilesResult, error) {
	if policy == "" {
		policy = PhraseListPolicyFailClosed
	}
	basenames := ScanPmFromFileBasenames(directiveLines)
	files := make(map[string][]byte)
	var dropped []string
	var raw int64

	for _, base := range basenames {
		if body, ok := overrides[base]; ok {
			files[base] = body
			raw += int64(len(body))
			continue
		}
		if provider == nil {
			if policy == PhraseListPolicyIgnoreUnknown {
				dropped = append(dropped, base)
				continue
			}
			return nil, fmt.Errorf("DataFileUnresolved: %s", base)
		}
		body, ready, found, err := provider.Lookup(ctx, namespace, base)
		if err != nil {
			return nil, err
		}
		if !found || !ready {
			if policy == PhraseListPolicyIgnoreUnknown {
				dropped = append(dropped, base)
				continue
			}
			if !found {
				return nil, fmt.Errorf("DataFileUnresolved: %s", base)
			}
			return nil, fmt.Errorf("PhraseListNotReady: %s", base)
		}
		files[base] = body
		raw += int64(len(body))
	}
	// Always allow override-only extras not referenced (harmless).
	for k, v := range overrides {
		if _, ok := files[k]; !ok {
			files[k] = v
			raw += int64(len(v))
		}
	}
	if raw > MaxPhraseFilesRawBytes {
		return nil, fmt.Errorf("PhraseFilesTooLarge: injected raw size %d exceeds %d", raw, MaxPhraseFilesRawBytes)
	}
	// Rewrite SecLang so dropped basenames are not referenced (IgnoreUnknown policy).
	effective := directiveLines
	if len(dropped) > 0 {
		dropSet := make(map[string]struct{}, len(dropped))
		for _, b := range dropped {
			dropSet[b] = struct{}{}
		}
		effective = DropSecLangLinesWithBasenames(directiveLines, dropSet)
	}
	return &DataFilesResult{
		Files:            files,
		DroppedBasenames: dropped,
		RawBytes:         raw,
		EffectiveLines:   effective,
	}, nil
}

// ReadyConditionTrue is a small helper for tests.
func ReadyConditionTrue() metav1.Condition {
	return metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready", Message: "ready"}
}
