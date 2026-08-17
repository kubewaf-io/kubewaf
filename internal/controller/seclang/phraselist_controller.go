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

package seclang

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
)

// MaxPhraseListBytes is the composed body budget (aligned with inject budget).
const MaxPhraseListBytes = config.MaxPhraseFilesRawBytes

// PhraseListReconciler reconciles PhraseList objects.
type PhraseListReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=phraselists,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=phraselists/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=phraselists/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile resolves content, enforces size/conflicts, and updates Ready status.
func (r *PhraseListReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)
	pl := &seclangv1beta1.PhraseList{}
	if err := r.Get(ctx, req.NamespacedName, pl); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	body, err := r.resolveBody(ctx, pl)
	if err != nil {
		return r.fail(ctx, pl, "ContentUnresolved", err.Error())
	}
	if int64(len(body)) > MaxPhraseListBytes {
		return r.fail(ctx, pl, "ContentTooLarge",
			fmt.Sprintf("composed body %d bytes exceeds max %d", len(body), MaxPhraseListBytes))
	}
	if conflict, cerr := r.fileNameConflict(ctx, pl); cerr != nil {
		return ctrl.Result{}, cerr
	} else if conflict != "" {
		return r.fail(ctx, pl, "FileNameConflict", conflict)
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])

	// Optional convenience labels.
	if pl.Labels == nil {
		pl.Labels = map[string]string{}
	}
	needUpdate := false
	if pl.Labels[seclangv1beta1.LabelPhraseList] != "true" {
		pl.Labels[seclangv1beta1.LabelPhraseList] = "true"
		needUpdate = true
	}
	if fn := pl.Spec.FileName; len(fn) <= 63 && isLabelSafe(fn) {
		if pl.Labels[seclangv1beta1.LabelFileName] != fn {
			pl.Labels[seclangv1beta1.LabelFileName] = fn
			needUpdate = true
		}
	}
	if needUpdate {
		if err := r.Update(ctx, pl); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Get(ctx, req.NamespacedName, pl); err != nil {
			return ctrl.Result{}, err
		}
	}

	meta.SetStatusCondition(&pl.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             "ContentReady",
		Message:            fmt.Sprintf("fileName=%s size=%d", pl.Spec.FileName, len(body)),
		ObservedGeneration: pl.Generation,
	})
	pl.Status.SizeBytes = int64(len(body))
	pl.Status.ContentHash = hash
	pl.Status.FileName = pl.Spec.FileName
	if err := r.Status().Update(ctx, pl); err != nil {
		return ctrl.Result{}, err
	}
	l.V(1).Info("PhraseList ready", "fileName", pl.Spec.FileName, "size", len(body))
	return ctrl.Result{}, nil
}

func (r *PhraseListReconciler) fail(ctx context.Context, pl *seclangv1beta1.PhraseList, reason, msg string) (ctrl.Result, error) {
	meta.SetStatusCondition(&pl.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: pl.Generation,
	})
	pl.Status.FileName = pl.Spec.FileName
	_ = r.Status().Update(ctx, pl)
	return ctrl.Result{}, nil
}

func (r *PhraseListReconciler) resolveBody(ctx context.Context, pl *seclangv1beta1.PhraseList) ([]byte, error) {
	sources := 0
	if pl.Spec.Content != "" {
		sources++
	}
	if pl.Spec.ConfigMapRef != nil {
		sources++
	}
	if len(pl.Spec.Parts) > 0 {
		sources++
	}
	if sources != 1 {
		return nil, fmt.Errorf("exactly one of content, configMapRef, or parts is required")
	}
	if pl.Spec.Content != "" {
		return []byte(pl.Spec.Content), nil
	}
	if pl.Spec.ConfigMapRef != nil {
		return r.readCM(ctx, pl.Namespace, pl.Spec.ConfigMapRef.Name, pl.Spec.ConfigMapRef.Key)
	}
	var buf []byte
	for _, p := range pl.Spec.Parts {
		b, err := r.readCM(ctx, pl.Namespace, p.ConfigMapRef.Name, p.ConfigMapRef.Key)
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

func (r *PhraseListReconciler) readCM(ctx context.Context, ns, name, key string) ([]byte, error) {
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &cm); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("configmap %s/%s not found", ns, name)
		}
		return nil, err
	}
	if v, ok := cm.Data[key]; ok {
		return []byte(v), nil
	}
	if v, ok := cm.BinaryData[key]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("configmap %s/%s missing key %q", ns, name, key)
}

func (r *PhraseListReconciler) fileNameConflict(ctx context.Context, pl *seclangv1beta1.PhraseList) (string, error) {
	var list seclangv1beta1.PhraseListList
	if err := r.List(ctx, &list, client.InNamespace(pl.Namespace)); err != nil {
		return "", err
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name == pl.Name {
			continue
		}
		if other.Spec.FileName != pl.Spec.FileName {
			continue
		}
		if meta.IsStatusConditionTrue(other.Status.Conditions, controller.ConditionTypeReady) {
			return fmt.Sprintf("another Ready PhraseList %q already owns fileName %q", other.Name, pl.Spec.FileName), nil
		}
	}
	// Cross-kind: IPList must not own the same basename.
	var ipList seclangv1beta1.IPListList
	if err := r.List(ctx, &ipList, client.InNamespace(pl.Namespace)); err != nil {
		if meta.IsNoMatchError(err) {
			return "", nil
		}
		return "", err
	}
	for i := range ipList.Items {
		ipl := &ipList.Items[i]
		if ipl.Spec.FileName != pl.Spec.FileName {
			continue
		}
		if meta.IsStatusConditionTrue(ipl.Status.Conditions, controller.ConditionTypeReady) {
			return fmt.Sprintf("Ready IPList %q already owns fileName %q (use a distinct basename)", ipl.Name, pl.Spec.FileName), nil
		}
	}
	return "", nil
}

func isLabelSafe(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

// SetupWithManager registers the PhraseList controller and field index.
func (r *PhraseListReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &seclangv1beta1.PhraseList{},
		config.PhraseListIndexField, config.IndexPhraseListByFileName); err != nil {
		return fmt.Errorf("index PhraseList by fileName: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&seclangv1beta1.PhraseList{}).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.mapConfigMapToPhraseLists)).
		Named("phraselist").
		Complete(r)
}

func (r *PhraseListReconciler) mapConfigMapToPhraseLists(ctx context.Context, obj client.Object) []reconcile.Request {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm == nil {
		return nil
	}
	var list seclangv1beta1.PhraseListList
	if err := r.List(ctx, &list, client.InNamespace(cm.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		pl := &list.Items[i]
		if phraseListUsesConfigMap(pl, cm.Name) {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: pl.Namespace,
				Name:      pl.Name,
			}})
		}
	}
	return reqs
}

func phraseListUsesConfigMap(pl *seclangv1beta1.PhraseList, cmName string) bool {
	if pl.Spec.ConfigMapRef != nil && pl.Spec.ConfigMapRef.Name == cmName {
		return true
	}
	for _, p := range pl.Spec.Parts {
		if p.ConfigMapRef.Name == cmName {
			return true
		}
	}
	return false
}
