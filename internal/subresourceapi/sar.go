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

package subresourceapi

import (
	"context"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DenyAllSAR fails closed when authorization is not configured.
type DenyAllSAR struct{}

// CanGetParent always denies.
func (DenyAllSAR) CanGetParent(context.Context, string, []string, ParentKind, string, string) *MappedError {
	return &MappedError{HTTPStatus: 403, Reason: "Forbidden", Message: "authorization not configured"}
}

// SubjectAccessReviewSAR checks parent get via Kubernetes SubjectAccessReview (K9).
type SubjectAccessReviewSAR struct {
	Client kubernetes.Interface
}

// CanGetParent creates a SubjectAccessReview for get on the storage-group parent.
func (s *SubjectAccessReviewSAR) CanGetParent(ctx context.Context, user string, groups []string, kind ParentKind, namespace, name string) *MappedError {
	if s == nil || s.Client == nil {
		return &MappedError{HTTPStatus: 403, Reason: "Forbidden", Message: "authorization not configured"}
	}
	group, resource := parentStorageGVR(kind)
	if group == "" || resource == "" {
		return &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: "unknown parent kind"}
	}
	sar := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			User:   user,
			Groups: groups,
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      "get",
				Group:     group,
				Resource:  resource,
				Name:      name,
			},
		},
	}
	res, err := s.Client.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "authorization check failed"}
	}
	if !res.Status.Allowed {
		msg := "not authorized to get parent object"
		if res.Status.Reason != "" {
			msg = res.Status.Reason
		}
		return &MappedError{HTTPStatus: 403, Reason: "Forbidden", Message: msg}
	}
	return nil
}

// parentStorageGVR maps probe parent kinds to CRD storage group/resource.
func parentStorageGVR(kind ParentKind) (group, resource string) {
	switch kind {
	case ParentSecRule:
		return "seclang.kubewaf.io", "secrules"
	case ParentRuleSet:
		return "waf.kubewaf.io", "rulesets"
	case ParentWAF:
		return "waf.kubewaf.io", "wafs"
	default:
		return "", ""
	}
}
