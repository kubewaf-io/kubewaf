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

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const Finalizer = "finalizer.kubewaf.io"
const RuleSetRefFinalizer = "ruleSetRef.kubewaf.io"

var WasmRegistry = "http://172.17.0.1:3000"

func InitHandler(ctx context.Context, req ctrl.Request, obj client.Object, client client.Client) (bool, error) {
	if err := client.Get(ctx, req.NamespacedName, obj); err != nil {
		return false, err
	}

	updated := controllerutil.AddFinalizer(obj, Finalizer)
	return updated, nil
}

// CleanupBackReferences removes references to the owner from target SecLang objects'
// status.RuleSetRefs and removes the RuleSetRefFinalizer when the owner is being deleted.
// This is called from Reconcile when deletionTimestamp is set. Full implementation may
// require additional RBAC and indexing for efficiency.
func CleanupBackReferences(ctx context.Context, c client.Client, owner client.Object) error {
	// TODO: List SecRule and SecAction resources that reference this owner in their
	// status.RuleSetRefs, remove the matching entry, update status, and remove finalizer
	// if no other references remain. The current resolver adds the back-refs; this
	// cleans them up.
	// For a simple start, we rely on finalizer on owner to prevent premature deletion.
	return nil
}
