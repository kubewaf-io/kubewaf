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

package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/coraza/crsdata"
)

// MaxPhraseFilesRawBytes is the unified Ready/inject budget (2 MiB).
const MaxPhraseFilesRawBytes = 2 * 1024 * 1024

// MaxPluginJSONHardFailBytes refuses publish when compressed plugin payload exceeds this.
const MaxPluginJSONHardFailBytes = 1536 * 1024 // 1.5 MiB

// SoftPluginJSONWarnBytes is a soft warn threshold for total plugin JSON size.
const SoftPluginJSONWarnBytes = 512 * 1024

// PhraseListIndexField is the field indexer key for PhraseList by namespace/fileName.
const PhraseListIndexField = "phraselist.spec.fileName"

// IPListIndexField is the field indexer key for IPList by namespace/fileName.
const IPListIndexField = "iplist.spec.fileName"

// PhraseFilesResult is the outcome of DiscoverAndResolvePhraseFiles.
type PhraseFilesResult struct {
	// Files is basename → body for plugin data_files inject.
	Files map[string][]byte
	// Directives is SecLang after IgnoreUnknown rewrite (may equal input).
	Directives []string
	// DroppedBasenames lists custom basenames stripped under IgnoreUnknown.
	DroppedBasenames []string
	// OverrideCRSCount is how many CRS basenames were injected as overrides.
	OverrideCRSCount int
	// RawBytes is total uncompressed inject size.
	RawBytes int64
	// ContentHash fingerprints injected files.
	ContentHash string
	// ConditionReason / Message for PhraseListsResolved.
	ConditionReason  string
	ConditionMessage string
	// Ready is false when publish must be refused (FailClosed / CRS override / size).
	Ready bool
	// Error is a hard failure (also Ready=false).
	Error error
}

// fromFileRe matches @pmFromFile / @pmf / @ipMatchFromFile / @ipMatchF operators
// with one or more file tokens (shared data_files inject path).
var fromFileRe = regexp.MustCompile(`(?i)@(?:pmFromFile|pmf|ipMatchFromFile|ipMatchF)\s+([^\s"']+(?:\s+[^\s"']+)*)`)

// ScanPmFromFileBasenames returns unique basenames referenced by @pmFromFile/@pmf
// and @ipMatchFromFile/@ipMatchF in SecLang lines (shared data_files inject set).
func ScanPmFromFileBasenames(directives []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range directives {
		// Flatten multi-line SecLang blobs. GetSecLang / BuildDirectives pass
		// one ConvertToSecLangString per SecRule; CRS metadata.comment prefixes
		// that blob with "# ...". Skipping the whole blob hid @pmFromFile
		// (juice-shop 930130 / restricted-files.data) and Envoy fail-closed.
		for _, line := range strings.Split(raw, "\n") {
			trim := strings.TrimSpace(line)
			if trim == "" || strings.HasPrefix(trim, "#") {
				continue
			}
			for _, m := range fromFileRe.FindAllStringSubmatch(line, -1) {
				if len(m) < 2 {
					continue
				}
				for _, tok := range strings.Fields(m[1]) {
					base := path.Base(strings.Trim(tok, `"'`))
					if base == "" || base == "." {
						continue
					}
					if _, ok := seen[base]; ok {
						continue
					}
					seen[base] = struct{}{}
					out = append(out, base)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// DropSecLangLinesWithBasenames removes SecLang lines that reference any of the given basenames
// via @pmFromFile/@pmf/@ipMatchFromFile/@ipMatchF (IgnoreUnknown safe degrade).
func DropSecLangLinesWithBasenames(directives []string, basenames map[string]struct{}) []string {
	if len(basenames) == 0 {
		return directives
	}
	out := make([]string, 0, len(directives))
	for _, line := range directives {
		if lineReferencesFromFileBasename(line, basenames) {
			continue
		}
		out = append(out, line)
	}
	return out
}

func lineReferencesFromFileBasename(line string, basenames map[string]struct{}) bool {
	for _, m := range fromFileRe.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		for _, tok := range strings.Fields(m[1]) {
			base := path.Base(strings.Trim(tok, `"'`))
			if _, ok := basenames[base]; ok {
				return true
			}
		}
	}
	return false
}

// PhraseListFileNameIndexKey builds the field index value for PhraseList and IPList.
func PhraseListFileNameIndexKey(namespace, fileName string) string {
	return namespace + "/" + fileName
}

// IndexPhraseListByFileName is a controller-runtime IndexerFunc for *PhraseList.
func IndexPhraseListByFileName(obj client.Object) []string {
	pl, ok := obj.(*seclangv1beta1.PhraseList)
	if !ok || pl == nil {
		return nil
	}
	fn := pl.Spec.FileName
	if fn == "" {
		fn = pl.Status.FileName
	}
	if fn == "" {
		return nil
	}
	return []string{PhraseListFileNameIndexKey(pl.Namespace, fn)}
}

// IndexIPListByFileName is a controller-runtime IndexerFunc for *IPList.
func IndexIPListByFileName(obj client.Object) []string {
	ipl, ok := obj.(*seclangv1beta1.IPList)
	if !ok || ipl == nil {
		return nil
	}
	fn := ipl.Spec.FileName
	if fn == "" {
		fn = ipl.Status.FileName
	}
	if fn == "" {
		return nil
	}
	return []string{PhraseListFileNameIndexKey(ipl.Namespace, fn)}
}

// DiscoverAndResolvePhraseFiles implements three-way resolution for @pmFromFile /
// @ipMatchFromFile basenames: stock CRS pack, Ready PhraseList, or Ready IPList.
// Always injects data files for ModSecurity Path B.
func DiscoverAndResolvePhraseFiles(
	ctx context.Context,
	c client.Client,
	waf *wafv1beta1.WAF,
	directives []string,
	resolved []unstructured.Unstructured,
) *PhraseFilesResult {
	res := &PhraseFilesResult{
		Files:            map[string][]byte{},
		Directives:       directives,
		Ready:            true,
		ConditionReason:  "PhraseListsResolved",
		ConditionMessage: "no phrase files to inject",
	}
	if waf == nil {
		res.Ready = false
		res.Error = fmt.Errorf("waf is nil")
		return res
	}

	policy := waf.Spec.PhraseListPolicy
	if policy == "" {
		policy = wafv1beta1.PhraseListPolicyFailClosed
	}

	// Packaging presence checks for RuleSet phraseListRefs / ipListRefs.
	if err := checkPhraseListRefs(ctx, c, waf.Namespace, resolved); err != nil {
		res.Ready = false
		res.Error = err
		res.ConditionReason = "PhraseListRefNotReady"
		res.ConditionMessage = err.Error()
		return res
	}
	if err := checkIPListRefs(ctx, c, waf.Namespace, resolved); err != nil {
		res.Ready = false
		res.Error = err
		res.ConditionReason = "IPListRefNotReady"
		res.ConditionMessage = err.Error()
		return res
	}

	basenames := ScanPmFromFileBasenames(directives)
	if len(basenames) == 0 {
		res.ConditionMessage = "no @pmFromFile/@ipMatchFromFile basenames in assembled SecLang"
		return res
	}

	var (
		missingCustom []string
		dropped       = map[string]struct{}{}
	)

	for _, base := range basenames {
		isCRS := crsdata.IsKnown(base)

		// Stock CRS basenames (Path B / ModSecurity):
		//  1. Ready PhraseList labeled seclang.kubewaf.io/crs-data=true → stock pack CR (preferred)
		//  2. Ready PhraseList with allow-crs-override=true → intentional user override
		//  3. Else inject from operator go:embed pack (internal/coraza/crsdata)
		// Unannotated non-pack PhraseLists that reuse a CRS basename are refused.
		if isCRS {
			pl, found, err := lookupReadyPhraseList(ctx, c, waf.Namespace, base)
			if err != nil {
				res.Ready = false
				res.Error = err
				res.ConditionReason = "PhraseListLookupFailed"
				res.ConditionMessage = err.Error()
				return res
			}
			if found {
				isStockPack := pl.Labels[seclangv1beta1.LabelCRSData] == "true" ||
					pl.Labels["seclang.kubewaf.io/crs-data"] == "true"
				allowOverride := pl.Annotations[seclangv1beta1.AnnotationAllowCRSOverride] == "true" ||
					pl.Annotations[crsdata.AnnotationAllowCRSOverride] == "true"
				if !isStockPack && !allowOverride {
					res.Ready = false
					res.Error = fmt.Errorf("CRSOverrideNotAllowed: PhraseList %q would override stock CRS basename %q; use a pack PhraseList (label %s=true) or set annotation %s=true",
						pl.Name, base, seclangv1beta1.LabelCRSData, seclangv1beta1.AnnotationAllowCRSOverride)
					res.ConditionReason = "CRSOverrideNotAllowed"
					res.ConditionMessage = res.Error.Error()
					return res
				}
				body, berr := resolvePhraseListBody(ctx, c, pl)
				if berr != nil {
					res.Ready = false
					res.Error = berr
					res.ConditionReason = "PhraseListBodyFailed"
					res.ConditionMessage = berr.Error()
					return res
				}
				res.Files[base] = body
				if !isStockPack {
					res.OverrideCRSCount++
				}
				continue
			}
			body, rerr := crsdata.Read(base)
			if rerr != nil || len(body) == 0 {
				res.Ready = false
				res.Error = fmt.Errorf("stock CRS data file %q missing from operator pack: %v", base, rerr)
				res.ConditionReason = "CRSDataPackMissing"
				res.ConditionMessage = res.Error.Error()
				return res
			}
			res.Files[base] = body
			continue
		}

		// Custom basenames: Ready PhraseList or IPList in the WAF namespace.
		body, kind, found, err := lookupReadyDataFileBody(ctx, c, waf.Namespace, base)
		if err != nil {
			res.Ready = false
			res.Error = err
			res.ConditionReason = "DataFileLookupFailed"
			res.ConditionMessage = err.Error()
			return res
		}
		if found {
			res.Files[base] = body
			_ = kind
			continue
		}
		missingCustom = append(missingCustom, base)
	}

	if len(missingCustom) > 0 {
		if policy == wafv1beta1.PhraseListPolicyIgnoreUnknown {
			for _, b := range missingCustom {
				dropped[b] = struct{}{}
				res.DroppedBasenames = append(res.DroppedBasenames, b)
			}
			res.Directives = DropSecLangLinesWithBasenames(directives, dropped)
			res.ConditionReason = "IgnoredUnknownPhraseLists"
			res.ConditionMessage = fmt.Sprintf("dropped SecLang lines referencing unresolved basenames: %s",
				strings.Join(res.DroppedBasenames, ", "))
			res.Ready = true
		} else {
			res.Ready = false
			res.Error = fmt.Errorf("DataFileNotFound: basename %q is not a stock CRS data file and no Ready PhraseList or IPList was found in namespace %q",
				missingCustom[0], waf.Namespace)
			res.ConditionReason = "DataFileNotFound"
			res.ConditionMessage = res.Error.Error()
			return res
		}
	}

	var raw int64
	for _, body := range res.Files {
		raw += int64(len(body))
	}
	res.RawBytes = raw
	if raw > MaxPhraseFilesRawBytes {
		res.Ready = false
		res.Error = fmt.Errorf("PhraseFilesTooLarge: injected raw size %d exceeds %d", raw, MaxPhraseFilesRawBytes)
		res.ConditionReason = "PhraseFilesTooLarge"
		res.ConditionMessage = res.Error.Error()
		res.Files = nil
		return res
	}

	res.ContentHash = hashPhraseFiles(res.Files)
	if res.ConditionReason == "PhraseListsResolved" || res.ConditionReason == "" {
		res.ConditionReason = "PhraseListsResolved"
		res.ConditionMessage = fmt.Sprintf("injected %d data files (%d bytes)", len(res.Files), raw)
	}
	return res
}

func checkPhraseListRefs(ctx context.Context, c client.Client, ns string, resolved []unstructured.Unstructured) error {
	names := collectRuleSetLocalRefs(resolved, "phraseListRefs")
	for name := range names {
		var pl seclangv1beta1.PhraseList
		if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &pl); err != nil {
			return fmt.Errorf("phraseListRefs %q: %w", name, err)
		}
		if !meta.IsStatusConditionTrue(pl.Status.Conditions, controller.ConditionTypeReady) {
			return fmt.Errorf("phraseListRefs %q: PhraseList is not Ready", name)
		}
	}
	return nil
}

func checkIPListRefs(ctx context.Context, c client.Client, ns string, resolved []unstructured.Unstructured) error {
	names := collectRuleSetLocalRefs(resolved, "ipListRefs")
	for name := range names {
		var ipl seclangv1beta1.IPList
		if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &ipl); err != nil {
			return fmt.Errorf("ipListRefs %q: %w", name, err)
		}
		if !meta.IsStatusConditionTrue(ipl.Status.Conditions, controller.ConditionTypeReady) {
			return fmt.Errorf("ipListRefs %q: IPList is not Ready", name)
		}
	}
	return nil
}

func collectRuleSetLocalRefs(resolved []unstructured.Unstructured, field string) map[string]struct{} {
	names := map[string]struct{}{}
	for i := range resolved {
		u := &resolved[i]
		if u.GetKind() != "RuleSet" {
			continue
		}
		refs, found, err := unstructured.NestedSlice(u.Object, "spec", field)
		if err != nil || !found {
			continue
		}
		for _, r := range refs {
			m, ok := r.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			if name != "" {
				names[name] = struct{}{}
			}
		}
	}
	return names
}

// lookupReadyDataFileBody finds a Ready PhraseList or IPList body for basename.
// Returns kind "PhraseList" or "IPList".
func lookupReadyDataFileBody(ctx context.Context, c client.Client, ns, fileName string) (body []byte, kind string, found bool, err error) {
	pl, ok, err := lookupReadyPhraseList(ctx, c, ns, fileName)
	if err != nil {
		return nil, "", false, err
	}
	if ok {
		b, berr := resolvePhraseListBody(ctx, c, pl)
		if berr != nil {
			return nil, "", false, berr
		}
		return b, "PhraseList", true, nil
	}
	ipl, ok, err := lookupReadyIPList(ctx, c, ns, fileName)
	if err != nil {
		return nil, "", false, err
	}
	if ok {
		b, berr := resolveIPListBody(ctx, c, ipl)
		if berr != nil {
			return nil, "", false, berr
		}
		return b, "IPList", true, nil
	}
	return nil, "", false, nil
}

func lookupReadyPhraseList(ctx context.Context, c client.Client, ns, fileName string) (*seclangv1beta1.PhraseList, bool, error) {
	key := PhraseListFileNameIndexKey(ns, fileName)
	var list seclangv1beta1.PhraseListList
	if err := c.List(ctx, &list, client.InNamespace(ns), client.MatchingFields{PhraseListIndexField: key}); err != nil {
		// Index may be missing in unit tests — fall back to full ns list.
		if err2 := c.List(ctx, &list, client.InNamespace(ns)); err2 != nil {
			return nil, false, err2
		}
		var match *seclangv1beta1.PhraseList
		for i := range list.Items {
			pl := &list.Items[i]
			if pl.Spec.FileName != fileName {
				continue
			}
			if !meta.IsStatusConditionTrue(pl.Status.Conditions, controller.ConditionTypeReady) {
				continue
			}
			if match != nil {
				return nil, false, fmt.Errorf("FileNameConflict: multiple Ready PhraseLists for %s/%s", ns, fileName)
			}
			match = pl
		}
		if match == nil {
			return nil, false, nil
		}
		return match, true, nil
	}
	var match *seclangv1beta1.PhraseList
	for i := range list.Items {
		pl := &list.Items[i]
		if pl.Spec.FileName != fileName {
			continue
		}
		if !meta.IsStatusConditionTrue(pl.Status.Conditions, controller.ConditionTypeReady) {
			continue
		}
		if match != nil {
			return nil, false, fmt.Errorf("FileNameConflict: multiple Ready PhraseLists for %s/%s", ns, fileName)
		}
		match = pl
	}
	if match == nil {
		return nil, false, nil
	}
	return match, true, nil
}

// ResolvePhraseListBody returns composed content for a PhraseList (exported for SecRule controller).
func ResolvePhraseListBody(ctx context.Context, c client.Client, pl *seclangv1beta1.PhraseList) ([]byte, error) {
	return resolvePhraseListBody(ctx, c, pl)
}

// ResolveIPListBody returns composed content for an IPList (exported for SecRule controller).
func ResolveIPListBody(ctx context.Context, c client.Client, ipl *seclangv1beta1.IPList) ([]byte, error) {
	return resolveIPListBody(ctx, c, ipl)
}

func resolvePhraseListBody(ctx context.Context, c client.Client, pl *seclangv1beta1.PhraseList) ([]byte, error) {
	if pl == nil {
		return nil, fmt.Errorf("phraselist is nil")
	}
	// Prefer status-cached body via content when inline; otherwise re-read sources.
	if pl.Spec.Content != "" {
		return []byte(pl.Spec.Content), nil
	}
	if pl.Spec.ConfigMapRef != nil {
		return readConfigMapKey(ctx, c, pl.Namespace, pl.Spec.ConfigMapRef.Name, pl.Spec.ConfigMapRef.Key)
	}
	if len(pl.Spec.Parts) > 0 {
		var buf []byte
		for _, p := range pl.Spec.Parts {
			b, err := readConfigMapKey(ctx, c, pl.Namespace, p.ConfigMapRef.Name, p.ConfigMapRef.Key)
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
		for _, p := range ipl.Spec.Parts {
			b, err := readConfigMapKey(ctx, c, ipl.Namespace, p.ConfigMapRef.Name, p.ConfigMapRef.Key)
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

func lookupReadyIPList(ctx context.Context, c client.Client, ns, fileName string) (*seclangv1beta1.IPList, bool, error) {
	key := PhraseListFileNameIndexKey(ns, fileName)
	var list seclangv1beta1.IPListList
	if err := c.List(ctx, &list, client.InNamespace(ns), client.MatchingFields{IPListIndexField: key}); err != nil {
		if err2 := c.List(ctx, &list, client.InNamespace(ns)); err2 != nil {
			return nil, false, err2
		}
	}
	var match *seclangv1beta1.IPList
	for i := range list.Items {
		ipl := &list.Items[i]
		if ipl.Spec.FileName != fileName {
			continue
		}
		if !meta.IsStatusConditionTrue(ipl.Status.Conditions, controller.ConditionTypeReady) {
			continue
		}
		if match != nil {
			return nil, false, fmt.Errorf("FileNameConflict: multiple Ready IPLists for %s/%s", ns, fileName)
		}
		match = ipl
	}
	if match == nil {
		return nil, false, nil
	}
	return match, true, nil
}

func readConfigMapKey(ctx context.Context, c client.Client, ns, name, key string) ([]byte, error) {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("v1")
	u.SetKind("ConfigMap")
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, u); err != nil {
		return nil, fmt.Errorf("configmap %s/%s: %w", ns, name, err)
	}
	if data, found, _ := unstructured.NestedStringMap(u.Object, "data"); found {
		if v, ok := data[key]; ok {
			return []byte(v), nil
		}
	}
	if bdata, found, _ := unstructured.NestedStringMap(u.Object, "binaryData"); found {
		// binaryData in unstructured from API is base64-decoded by client into string sometimes;
		// handle raw if present.
		if v, ok := bdata[key]; ok {
			return []byte(v), nil
		}
	}
	// binaryData as []byte via NestedFieldNoCopy
	if raw, found, _ := unstructured.NestedFieldNoCopy(u.Object, "binaryData", key); found {
		switch t := raw.(type) {
		case []byte:
			return t, nil
		case string:
			return []byte(t), nil
		}
	}
	return nil, fmt.Errorf("configmap %s/%s missing key %q", ns, name, key)
}

func hashPhraseFiles(files map[string][]byte) string {
	if len(files) == 0 {
		return ""
	}
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(files[k])
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
