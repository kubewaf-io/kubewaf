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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

func listProviderScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := seclangv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func readyPhraseList(name, ns, fileName, content string) *seclangv1beta1.PhraseList {
	pl := &seclangv1beta1.PhraseList{
		TypeMeta:   metav1.TypeMeta{APIVersion: "seclang.kubewaf.io/v1beta1", Kind: "PhraseList"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: seclangv1beta1.PhraseListSpec{
			FileName: fileName,
			Content:  content,
		},
	}
	pl.Status.Conditions = []metav1.Condition{ReadyConditionTrue()}
	pl.Status.FileName = fileName
	return pl
}

func TestClientListProviderLookup_ConfigMapRef(t *testing.T) {
	scheme := listProviderScheme(t)
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: "phrases", Namespace: "ns"},
		Data:       map[string]string{"list.data": "from-configmap\n"},
	}
	pl := &seclangv1beta1.PhraseList{
		TypeMeta:   metav1.TypeMeta{APIVersion: "seclang.kubewaf.io/v1beta1", Kind: "PhraseList"},
		ObjectMeta: metav1.ObjectMeta{Name: "cm-list", Namespace: "ns"},
		Spec: seclangv1beta1.PhraseListSpec{
			FileName: "custom.data",
			ConfigMapRef: &seclangv1beta1.PhraseListConfigMapRef{
				Name: "phrases",
				Key:  "list.data",
			},
		},
	}
	pl.Status.Conditions = []metav1.Condition{ReadyConditionTrue()}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm, pl).Build()
	p := &ClientListProvider{Client: c}

	body, ready, found, err := p.Lookup(context.Background(), "ns", "custom.data")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !ready {
		t.Fatalf("found=%v ready=%v", found, ready)
	}
	if string(body) != "from-configmap\n" {
		t.Fatalf("body=%q", body)
	}
}

func TestClientListProviderLookup_Parts(t *testing.T) {
	scheme := listProviderScheme(t)
	a := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "part-a", Namespace: "ns"},
		Data:       map[string]string{"k": "one"},
	}
	b := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "part-b", Namespace: "ns"},
		Data:       map[string]string{"k": "two"},
	}
	pl := &seclangv1beta1.PhraseList{
		ObjectMeta: metav1.ObjectMeta{Name: "parts", Namespace: "ns"},
		Spec: seclangv1beta1.PhraseListSpec{
			FileName: "parts.data",
			Parts: []seclangv1beta1.PhraseListPart{
				{ConfigMapRef: seclangv1beta1.PhraseListConfigMapRef{Name: "part-a", Key: "k"}},
				{ConfigMapRef: seclangv1beta1.PhraseListConfigMapRef{Name: "part-b", Key: "k"}},
			},
		},
	}
	pl.Status.Conditions = []metav1.Condition{ReadyConditionTrue()}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(a, b, pl).Build()
	p := &ClientListProvider{Client: c}

	body, ready, found, err := p.Lookup(context.Background(), "ns", "parts.data")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !ready {
		t.Fatalf("found=%v ready=%v", found, ready)
	}
	if string(body) != "one\ntwo\n" {
		t.Fatalf("body=%q", body)
	}
}

func TestClientListProviderLookup_PrefersReady(t *testing.T) {
	scheme := listProviderScheme(t)
	stale := &seclangv1beta1.PhraseList{
		ObjectMeta: metav1.ObjectMeta{Name: "stale", Namespace: "ns"},
		Spec: seclangv1beta1.PhraseListSpec{
			FileName: "shared.data",
			Content:  "stale-body\n",
		},
	}
	ready := readyPhraseList("live", "ns", "shared.data", "ready-body\n")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stale, ready).Build()
	p := &ClientListProvider{Client: c}

	body, isReady, found, err := p.Lookup(context.Background(), "ns", "shared.data")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !isReady {
		t.Fatalf("found=%v ready=%v", found, isReady)
	}
	if string(body) != "ready-body\n" {
		t.Fatalf("body=%q (must not return first-match stale content)", body)
	}
}

func TestClientListProviderLookup_IPListConfigMapRef(t *testing.T) {
	scheme := listProviderScheme(t)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "ips", Namespace: "ns"},
		Data:       map[string]string{"block": "203.0.113.10\n"},
	}
	ipl := &seclangv1beta1.IPList{
		ObjectMeta: metav1.ObjectMeta{Name: "blocklist", Namespace: "ns"},
		Spec: seclangv1beta1.IPListSpec{
			FileName:     "block.data",
			ConfigMapRef: &seclangv1beta1.IPListConfigMapRef{Name: "ips", Key: "block"},
		},
	}
	ipl.Status.Conditions = []metav1.Condition{ReadyConditionTrue()}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm, ipl).Build()
	p := &ClientListProvider{Client: c}

	body, ready, found, err := p.Lookup(context.Background(), "ns", "block.data")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !ready {
		t.Fatalf("found=%v ready=%v", found, ready)
	}
	if string(body) != "203.0.113.10\n" {
		t.Fatalf("body=%q", body)
	}
}

func TestClientListProviderLookup_EmptyBodyNotInjected(t *testing.T) {
	scheme := listProviderScheme(t)
	pl := &seclangv1beta1.PhraseList{
		ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "ns"},
		Spec: seclangv1beta1.PhraseListSpec{
			FileName: "empty.data",
			// ConfigMapRef with missing key → compose error / empty, must not inject "".
			ConfigMapRef: &seclangv1beta1.PhraseListConfigMapRef{Name: "missing", Key: "k"},
		},
	}
	pl.Status.Conditions = []metav1.Condition{ReadyConditionTrue()}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pl).Build()
	p := &ClientListProvider{Client: c}

	body, ready, found, err := p.Lookup(context.Background(), "ns", "empty.data")
	if err == nil && ready {
		t.Fatalf("empty/unreadable body must not be ready, body=%q", body)
	}
	if !found {
		t.Fatal("list exists so found must be true")
	}
	if len(body) != 0 {
		t.Fatalf("must not inject composed empty/error body, got %q", body)
	}
}

func TestResolveDataFilesIgnoreUnknownRewritesSecLang(t *testing.T) {
	lines := []string{
		`SecRule ARGS "@pmFromFile missing.data" "id:1,phase:2,deny,status:403"`,
		`SecRule ARGS "@rx ok" "id:2,phase:2,pass"`,
	}
	df, err := ResolveDataFiles(context.Background(), nil, "ns", PhraseListPolicyIgnoreUnknown, lines, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(df.DroppedBasenames) != 1 || df.DroppedBasenames[0] != "missing.data" {
		t.Fatalf("dropped=%v", df.DroppedBasenames)
	}
	joined := strings.Join(df.EffectiveLines, "\n")
	if strings.Contains(joined, "missing.data") {
		t.Fatalf("expected SecLang rewrite to drop missing.data lines, got %q", joined)
	}
	if !strings.Contains(joined, "@rx ok") {
		t.Fatalf("expected remaining rule preserved: %q", joined)
	}
	if len(df.Files) != 0 {
		t.Fatalf("files=%v", df.Files)
	}
}

func TestResolveDataFilesFailClosed(t *testing.T) {
	lines := []string{
		`SecRule ARGS "@pmFromFile missing.data" "id:1,phase:2,deny"`,
	}
	_, err := ResolveDataFiles(context.Background(), nil, "ns", PhraseListPolicyFailClosed, lines, nil)
	if err == nil || !strings.Contains(err.Error(), "DataFileUnresolved") {
		t.Fatalf("want DataFileUnresolved, got %v", err)
	}
}
