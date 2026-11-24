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

package v1alpha1

import (
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

// ReferenceGrantV1Served reports whether gateway.networking.k8s.io/v1
// referencegrants is in the apiserver's discovery document. Gateway API 1.5
// and later serve that version. A cluster that only serves v1beta1 is treated
// as not served: cross-namespace refs stay denied and the operator still starts.
// The operator does not install the CRD.
func ReferenceGrantV1Served(cfg *rest.Config) (bool, error) {
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return false, err
	}
	list, err := dc.ServerResourcesForGroupVersion("gateway.networking.k8s.io/v1")
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		var groupErr *discovery.ErrGroupDiscoveryFailed
		if errors.As(err, &groupErr) {
			return false, nil
		}
		return false, err
	}
	for _, resource := range list.APIResources {
		if resource.Name == "referencegrants" {
			return true, nil
		}
	}
	return false, nil
}
