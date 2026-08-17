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

// MaxIPListBytes is the composed body budget (aligned with inject budget).
const MaxIPListBytes = config.MaxPhraseFilesRawBytes

// IPListReconciler reconciles IPList objects.
type IPListReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=iplists,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=iplists/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=iplists/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile resolves content, enforces size/conflicts, and updates Ready status.
func (r *IPListReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)
	ipl := &seclangv1beta1.IPList{}
	if err := r.Get(ctx, req.NamespacedName, ipl); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	body, err := r.resolveBody(ctx, ipl)
	if err != nil {
		return r.fail(ctx, ipl, "ContentUnresolved", err.Error())
	}
	if int64(len(body)) > MaxIPListBytes {
		return r.fail(ctx, ipl, "ContentTooLarge",
			fmt.Sprintf("composed body %d bytes exceeds max %d", len(body), MaxIPListBytes))
	}
	if conflict, cerr := r.fileNameConflict(ctx, ipl); cerr != nil {
		return ctrl.Result{}, cerr
	} else if conflict != "" {
		return r.fail(ctx, ipl, "FileNameConflict", conflict)
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])

	// Optional convenience labels.
	if ipl.Labels == nil {
		ipl.Labels = map[string]string{}
	}
	needUpdate := false
	if ipl.Labels[seclangv1beta1.LabelIPList] != "true" {
		ipl.Labels[seclangv1beta1.LabelIPList] = "true"
		needUpdate = true
	}
	if fn := ipl.Spec.FileName; len(fn) <= 63 && isLabelSafe(fn) {
		if ipl.Labels[seclangv1beta1.LabelFileName] != fn {
			ipl.Labels[seclangv1beta1.LabelFileName] = fn
			needUpdate = true
		}
	}
	if needUpdate {
		if err := r.Update(ctx, ipl); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Get(ctx, req.NamespacedName, ipl); err != nil {
			return ctrl.Result{}, err
		}
	}

	meta.SetStatusCondition(&ipl.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             "ContentReady",
		Message:            fmt.Sprintf("fileName=%s size=%d", ipl.Spec.FileName, len(body)),
		ObservedGeneration: ipl.Generation,
	})
	ipl.Status.SizeBytes = int64(len(body))
	ipl.Status.ContentHash = hash
	ipl.Status.FileName = ipl.Spec.FileName
	if err := r.Status().Update(ctx, ipl); err != nil {
		return ctrl.Result{}, err
	}
	l.V(1).Info("IPList ready", "fileName", ipl.Spec.FileName, "size", len(body))
	return ctrl.Result{}, nil
}

func (r *IPListReconciler) fail(ctx context.Context, ipl *seclangv1beta1.IPList, reason, msg string) (ctrl.Result, error) {
	meta.SetStatusCondition(&ipl.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ipl.Generation,
	})
	ipl.Status.FileName = ipl.Spec.FileName
	_ = r.Status().Update(ctx, ipl)
	return ctrl.Result{}, nil
}

func (r *IPListReconciler) resolveBody(ctx context.Context, ipl *seclangv1beta1.IPList) ([]byte, error) {
	sources := 0
	if ipl.Spec.Content != "" {
		sources++
	}
	if ipl.Spec.ConfigMapRef != nil {
		sources++
	}
	if len(ipl.Spec.Parts) > 0 {
		sources++
	}
	if sources != 1 {
		return nil, fmt.Errorf("exactly one of content, configMapRef, or parts is required")
	}
	if ipl.Spec.Content != "" {
		return []byte(ipl.Spec.Content), nil
	}
	if ipl.Spec.ConfigMapRef != nil {
		return r.readCM(ctx, ipl.Namespace, ipl.Spec.ConfigMapRef.Name, ipl.Spec.ConfigMapRef.Key)
	}
	var buf []byte
	for _, p := range ipl.Spec.Parts {
		b, err := r.readCM(ctx, ipl.Namespace, p.ConfigMapRef.Name, p.ConfigMapRef.Key)
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

func (r *IPListReconciler) readCM(ctx context.Context, ns, name, key string) ([]byte, error) {
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

func (r *IPListReconciler) fileNameConflict(ctx context.Context, ipl *seclangv1beta1.IPList) (string, error) {
	var list seclangv1beta1.IPListList
	if err := r.List(ctx, &list, client.InNamespace(ipl.Namespace)); err != nil {
		return "", err
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name == ipl.Name {
			continue
		}
		if other.Spec.FileName != ipl.Spec.FileName {
			continue
		}
		if meta.IsStatusConditionTrue(other.Status.Conditions, controller.ConditionTypeReady) {
			return fmt.Sprintf("another Ready IPList %q already owns fileName %q", other.Name, ipl.Spec.FileName), nil
		}
	}
	// Cross-kind: PhraseList must not own the same basename.
	var plList seclangv1beta1.PhraseListList
	if err := r.List(ctx, &plList, client.InNamespace(ipl.Namespace)); err != nil {
		if meta.IsNoMatchError(err) {
			return "", nil
		}
		return "", err
	}
	for i := range plList.Items {
		pl := &plList.Items[i]
		if pl.Spec.FileName != ipl.Spec.FileName {
			continue
		}
		if meta.IsStatusConditionTrue(pl.Status.Conditions, controller.ConditionTypeReady) {
			return fmt.Sprintf("Ready PhraseList %q already owns fileName %q (use a distinct basename)", pl.Name, ipl.Spec.FileName), nil
		}
	}
	return "", nil
}

// SetupWithManager registers the IPList controller and field index.
func (r *IPListReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &seclangv1beta1.IPList{},
		config.IPListIndexField, config.IndexIPListByFileName); err != nil {
		return fmt.Errorf("index IPList by fileName: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&seclangv1beta1.IPList{}).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.mapConfigMapToIPLists)).
		Named("iplist").
		Complete(r)
}

func (r *IPListReconciler) mapConfigMapToIPLists(ctx context.Context, obj client.Object) []reconcile.Request {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm == nil {
		return nil
	}
	var list seclangv1beta1.IPListList
	if err := r.List(ctx, &list, client.InNamespace(cm.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		ipl := &list.Items[i]
		if ipListUsesConfigMap(ipl, cm.Name) {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: ipl.Namespace,
				Name:      ipl.Name,
			}})
		}
	}
	return reqs
}

func ipListUsesConfigMap(ipl *seclangv1beta1.IPList, cmName string) bool {
	if ipl.Spec.ConfigMapRef != nil && ipl.Spec.ConfigMapRef.Name == cmName {
		return true
	}
	for _, p := range ipl.Spec.Parts {
		if p.ConfigMapRef.Name == cmName {
			return true
		}
	}
	return false
}
