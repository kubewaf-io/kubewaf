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

package controller

import (
	"context"
	"fmt"
	"strings"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const Finalizer = "finalizer.kubewaf.io"
const RuleSetRefFinalizer = "ruleSetRef.kubewaf.io"

func InitHandler(ctx context.Context, req ctrl.Request, obj client.Object, c client.Client) (bool, error) {
	if err := c.Get(ctx, req.NamespacedName, obj); err != nil {
		return false, err
	}

	updated := controllerutil.AddFinalizer(obj, Finalizer)
	return updated, nil
}

// CleanupBackReferences removes this owner from SecRule/SecAction status.RuleSetRefs
// and drops ruleSetRef.kubewaf.io when no back-references remain.
// Called when a RuleSet (or other owner) is being deleted.
func CleanupBackReferences(ctx context.Context, c client.Client, owner client.Object) error {
	log := logf.FromContext(ctx)
	ownerKind := ownerKindOf(owner)
	ownerName := owner.GetName()
	ownerNS := owner.GetNamespace()

	var rules seclangv1beta1.SecRuleList
	if err := c.List(ctx, &rules); err != nil {
		// Unit tests / EG-only installs may not register seclang types; skip cleanup.
		if !isUnregisteredKind(err) {
			return fmt.Errorf("list secrules for back-ref cleanup: %w", err)
		}
		log.V(1).Info("skip secrule back-ref cleanup (kind not registered)")
	} else {
		for i := range rules.Items {
			if err := stripSecRuleBackRef(ctx, c, &rules.Items[i], ownerKind, ownerName, ownerNS); err != nil {
				return err
			}
		}
	}

	var actions seclangv1beta1.SecActionList
	if err := c.List(ctx, &actions); err != nil {
		if !isUnregisteredKind(err) {
			return fmt.Errorf("list secactions for back-ref cleanup: %w", err)
		}
		log.V(1).Info("skip secaction back-ref cleanup (kind not registered)")
	} else {
		for i := range actions.Items {
			if err := stripSecActionBackRef(ctx, c, &actions.Items[i], ownerKind, ownerName, ownerNS); err != nil {
				return err
			}
		}
	}

	log.V(1).Info("cleaned back-references", "ownerKind", ownerKind, "owner", ownerNS+"/"+ownerName)
	return nil
}

// isUnregisteredKind reports scheme/CRD absence (safe to skip optional cleanup).
func isUnregisteredKind(err error) bool {
	if err == nil {
		return false
	}
	if meta.IsNoMatchError(err) {
		return true
	}
	// client-go fake / incomplete schemes: "no kind is registered for the type ..."
	msg := err.Error()
	return strings.Contains(msg, "no kind is registered") || strings.Contains(msg, "no matches for kind")
}

func ownerKindOf(owner client.Object) string {
	if k := owner.GetObjectKind().GroupVersionKind().Kind; k != "" {
		return k
	}
	// client.Get often leaves TypeMeta empty; infer from concrete Go type.
	t := fmt.Sprintf("%T", owner)
	switch {
	case strings.HasSuffix(t, ".RuleSet") || strings.HasSuffix(t, "*RuleSet"):
		return "RuleSet"
	case strings.Contains(t, ".WAF") && !strings.Contains(t, "WAFList"):
		return "WAF"
	default:
		return ""
	}
}

func matchesOwner(ref seclangv1beta1.RuleSetRef, ownerKind, ownerName, ownerNS string) bool {
	if ref.Name != ownerName || ref.Namespace != ownerNS {
		return false
	}
	// Kind empty on either side: match by name+namespace only.
	if ownerKind == "" || ref.Kind == "" {
		return true
	}
	return ref.Kind == ownerKind
}

func stripSecRuleBackRef(ctx context.Context, c client.Client, sr *seclangv1beta1.SecRule, ownerKind, ownerName, ownerNS string) error {
	filtered, removed := filterRefs(sr.Status.RuleSetRefs, ownerKind, ownerName, ownerNS)
	if !removed {
		return nil
	}
	sr.Status.RuleSetRefs = filtered
	if err := c.Status().Update(ctx, sr); err != nil {
		return fmt.Errorf("update SecRule status back-refs %s/%s: %w", sr.Namespace, sr.Name, err)
	}
	if len(filtered) > 0 {
		return nil
	}
	// Re-fetch for finalizer removal (fresh resourceVersion).
	key := client.ObjectKeyFromObject(sr)
	fresh := &seclangv1beta1.SecRule{}
	if err := c.Get(ctx, key, fresh); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if controllerutil.RemoveFinalizer(fresh, RuleSetRefFinalizer) {
		if err := c.Update(ctx, fresh); err != nil {
			return fmt.Errorf("remove RuleSetRef finalizer from SecRule %s/%s: %w", fresh.Namespace, fresh.Name, err)
		}
	}
	return nil
}

func stripSecActionBackRef(ctx context.Context, c client.Client, sa *seclangv1beta1.SecAction, ownerKind, ownerName, ownerNS string) error {
	filtered, removed := filterRefs(sa.Status.RuleSetRefs, ownerKind, ownerName, ownerNS)
	if !removed {
		return nil
	}
	sa.Status.RuleSetRefs = filtered
	if err := c.Status().Update(ctx, sa); err != nil {
		return fmt.Errorf("update SecAction status back-refs %s/%s: %w", sa.Namespace, sa.Name, err)
	}
	if len(filtered) > 0 {
		return nil
	}
	key := client.ObjectKeyFromObject(sa)
	fresh := &seclangv1beta1.SecAction{}
	if err := c.Get(ctx, key, fresh); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if controllerutil.RemoveFinalizer(fresh, RuleSetRefFinalizer) {
		if err := c.Update(ctx, fresh); err != nil {
			return fmt.Errorf("remove RuleSetRef finalizer from SecAction %s/%s: %w", fresh.Namespace, fresh.Name, err)
		}
	}
	return nil
}

func filterRefs(refs []seclangv1beta1.RuleSetRef, ownerKind, ownerName, ownerNS string) ([]seclangv1beta1.RuleSetRef, bool) {
	if len(refs) == 0 {
		return refs, false
	}
	out := make([]seclangv1beta1.RuleSetRef, 0, len(refs))
	removed := false
	for _, ref := range refs {
		if matchesOwner(ref, ownerKind, ownerName, ownerNS) {
			removed = true
			continue
		}
		out = append(out, ref)
	}
	return out, removed
}
