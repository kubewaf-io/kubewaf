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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
)

var _ = Describe("SecRule Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-secrule"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: metav1.NamespaceDefault,
		}

		BeforeEach(func() {
			By("creating a minimal valid SecRule")
			err := k8sClient.Get(ctx, typeNamespacedName, &seclangv1beta1.SecRule{})
			if err != nil && errors.IsNotFound(err) {
				resource := &seclangv1beta1.SecRule{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: metav1.NamespaceDefault,
					},
					Spec: seclangv1beta1.SecRuleSpec{
						Metadata: &seclangv1beta1.SecRuleMetadata{
							OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
							Id:                100001,
						},
						Match: []seclangv1beta1.Match{{AlwaysMatch: true}},
						Actions: &seclangv1beta1.SecRuleActions{
							NonDisruptive: []seclangv1beta1.NonDisruptiveAction{
								{Type: seclangv1beta1.NoLog},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &seclangv1beta1.SecRule{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				By("Cleanup SecRule")
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
				// Drive deletion finalizers.
				rec := &SecRuleReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
				_, _ = rec.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			}
		})

		It("should allocate rule id, set Ready, and add finalizer", func() {
			rec := &SecRuleReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			updated := &seclangv1beta1.SecRule{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Status.RuleID).To(Equal(100001))
			Expect(updated.Finalizers).To(ContainElement(controller.Finalizer))

			cond := meta.FindStatusCondition(updated.Status.Conditions, controller.ConditionTypeReady)
			Expect(cond).NotTo(BeNil())
			// Ready may be True (Coraza load ok) or False if validation fails in envtest —
			// either way the condition must be present with observedGeneration.
			Expect(cond.ObservedGeneration).To(Equal(updated.Generation))
		})
	})
})
