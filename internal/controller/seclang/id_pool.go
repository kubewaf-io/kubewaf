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
	"fmt"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

// ensureClusterIDPool creates the singleton pool if missing.
func ensureClusterIDPool(ctx context.Context, c client.Client) (*seclangv1beta1.SecRuleIDPool, error) {
	pool := &seclangv1beta1.SecRuleIDPool{}
	key := types.NamespacedName{Name: seclangv1beta1.DefaultIDPoolName}
	err := c.Get(ctx, key, pool)
	if err == nil {
		return pool, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}
	pool = &seclangv1beta1.SecRuleIDPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: seclangv1beta1.DefaultIDPoolName,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "kubewaf",
				"app.kubernetes.io/name":       "secrule-id-pool",
			},
		},
		Spec: seclangv1beta1.SecRuleIDPoolSpec{
			MinID: seclangv1beta1.DefaultIDPoolMin,
			MaxID: seclangv1beta1.DefaultIDPoolMax,
		},
	}
	if err := c.Create(ctx, pool); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := c.Get(ctx, key, pool); err != nil {
				return nil, err
			}
			return pool, nil
		}
		return nil, err
	}
	// Initialize status.nextId
	pool.Status.NextID = pool.EffectiveMin()
	if err := c.Status().Update(ctx, pool); err != nil {
		// non-fatal: next allocate will set it
		_ = err
	}
	return pool, nil
}

// collectUsedIDs returns every rule id currently claimed cluster-wide.
func collectUsedIDs(ctx context.Context, c client.Client) (map[int]struct{}, error) {
	used := map[int]struct{}{}
	var list seclangv1beta1.SecRuleList
	if err := c.List(ctx, &list); err != nil {
		return nil, err
	}
	for i := range list.Items {
		sr := &list.Items[i]
		for _, id := range sr.Status.AssignedIDs {
			if id > 0 {
				used[id] = struct{}{}
			}
		}
		if sr.Status.RuleID > 0 {
			used[sr.Status.RuleID] = struct{}{}
		}
		// Also treat explicit metadata ids as used.
		if sr.Spec.Metadata != nil && sr.Spec.Metadata.Id > 0 {
			used[sr.Spec.Metadata.Id] = struct{}{}
		}
		for _, rule := range sr.Spec.SecRules {
			if rule.Metadata != nil && rule.Metadata.Id > 0 {
				used[rule.Metadata.Id] = struct{}{}
			}
		}
		if ann := sr.Annotations[seclangv1beta1.AnnotationAssignedID]; ann != "" {
			if id, err := strconv.Atoi(ann); err == nil && id > 0 {
				used[id] = struct{}{}
			}
		}
	}
	return used, nil
}

// freeSelfClaims removes this SecRule's previous claims from used so reallocate can reuse them.
func freeSelfClaims(sr *seclangv1beta1.SecRule, used map[int]struct{}) {
	if sr == nil {
		return
	}
	for _, id := range sr.Status.AssignedIDs {
		delete(used, id)
	}
	if sr.Status.RuleID > 0 {
		delete(used, sr.Status.RuleID)
	}
	if ann := sr.Annotations[seclangv1beta1.AnnotationAssignedID]; ann != "" {
		if id, err := strconv.Atoi(ann); err == nil {
			delete(used, id)
		}
	}
}

// allocateIDs fills AssignedIDs for the CR.
// Single-rule form (metadata/match): one id. Legacy bag: one id per secLangRules[i].
// Fixed metadata.id values are preserved; missing ids are allocated from the pool.
// used is mutated to include newly allocated ids.
func allocateIDs(
	ctx context.Context,
	c client.Client,
	sr *seclangv1beta1.SecRule,
	used map[int]struct{},
) (assigned []int, primary int, idSource string, err error) {
	freeSelfClaims(sr, used)

	// Canonical one-rule-per-CR form.
	if sr.Spec.IsSingleRuleForm() {
		metaID := 0
		if sr.Spec.Metadata != nil {
			metaID = sr.Spec.Metadata.Id
		}
		id, src, aerr := resolveOneID(ctx, c, sr, metaID, 0, used)
		if aerr != nil {
			return nil, 0, "", aerr
		}
		return []int{id}, id, src, nil
	}

	n := len(sr.Spec.SecRules)
	if n == 0 {
		return nil, 0, "", nil
	}

	assigned = make([]int, n)
	autoCount, specCount := 0, 0

	for i := range sr.Spec.SecRules {
		metaID := 0
		if sr.Spec.SecRules[i].Metadata != nil {
			metaID = sr.Spec.SecRules[i].Metadata.Id
		}
		id, src, aerr := resolveOneID(ctx, c, sr, metaID, i, used)
		if aerr != nil {
			return nil, 0, "", aerr
		}
		assigned[i] = id
		if src == seclangv1beta1.IDSourceSpec {
			specCount++
		} else {
			autoCount++
		}
	}

	primary = assigned[0]
	switch {
	case autoCount > 0 && specCount > 0:
		idSource = seclangv1beta1.IDSourceMixed
	case autoCount > 0:
		idSource = seclangv1beta1.IDSourceAuto
	default:
		idSource = seclangv1beta1.IDSourceSpec
	}
	return assigned, primary, idSource, nil
}

// resolveOneID picks Spec id, sticky status/annotation, or pool allocation.
func resolveOneID(
	ctx context.Context,
	c client.Client,
	sr *seclangv1beta1.SecRule,
	metaID int,
	index int,
	used map[int]struct{},
) (id int, idSource string, err error) {
	if metaID > 0 {
		used[metaID] = struct{}{}
		return metaID, seclangv1beta1.IDSourceSpec, nil
	}
	// Reuse previous assignment for this index.
	if index < len(sr.Status.AssignedIDs) && sr.Status.AssignedIDs[index] > 0 {
		id = sr.Status.AssignedIDs[index]
		used[id] = struct{}{}
		return id, seclangv1beta1.IDSourceAuto, nil
	}
	// Sticky annotation only for primary (index 0).
	if index == 0 {
		if ann := sr.Annotations[seclangv1beta1.AnnotationAssignedID]; ann != "" {
			if parsed, aerr := strconv.Atoi(ann); aerr == nil && parsed > 0 {
				used[parsed] = struct{}{}
				return parsed, seclangv1beta1.IDSourceAuto, nil
			}
		}
	}
	id, err = allocateOne(ctx, c, used)
	if err != nil {
		return 0, "", err
	}
	used[id] = struct{}{}
	return id, seclangv1beta1.IDSourceAuto, nil
}

func allocateOne(ctx context.Context, c client.Client, used map[int]struct{}) (int, error) {
	const maxAttempts = 32
	for attempt := 0; attempt < maxAttempts; attempt++ {
		pool, err := ensureClusterIDPool(ctx, c)
		if err != nil {
			return 0, err
		}
		minID := pool.EffectiveMin()
		maxID := pool.EffectiveMax()
		if maxID < minID {
			return 0, fmt.Errorf("SecRuleIDPool %q has maxId < minId", pool.Name)
		}
		next := pool.Status.NextID
		if next < minID {
			next = minID
		}
		// Find free id in [next, max] then wrap [min, next).
		id, ok := findFree(next, maxID, used)
		if !ok {
			id, ok = findFree(minID, next-1, used)
		}
		if !ok {
			return 0, fmt.Errorf("SecRuleIDPool %q exhausted (%d–%d)", pool.Name, minID, maxID)
		}

		// Advance pool status (optimistic).
		pool.Status.NextID = id + 1
		if pool.Status.NextID > maxID {
			pool.Status.NextID = minID
		}
		pool.Status.LastAllocatedID = id
		pool.Status.AllocatedCount++
		if err := c.Status().Update(ctx, pool); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return 0, err
		}
		return id, nil
	}
	return 0, fmt.Errorf("SecRuleIDPool allocate: too many conflicts")
}

func findFree(from, to int, used map[int]struct{}) (int, bool) {
	if to < from {
		return 0, false
	}
	for id := from; id <= to; id++ {
		if _, taken := used[id]; !taken {
			return id, true
		}
	}
	return 0, false
}
