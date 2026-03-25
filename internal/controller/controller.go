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

const finalizer = "finalizer.kubewaf.io"

func InitHandler(ctx context.Context, req ctrl.Request, obj client.Object, client client.Client) (bool, error) {
	if err := client.Get(ctx, req.NamespacedName, obj); err != nil {
		return false, err
	}

	updated := controllerutil.AddFinalizer(obj, finalizer)
	return updated, nil
}
