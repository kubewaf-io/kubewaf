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

package waf

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
)

var _ = Describe("RuleSet Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-ruleset"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: metav1.NamespaceDefault,
		}

		It("should set ReferencesResolved and finalizer", func() {
			resource := &wafv1beta1.RuleSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: metav1.NamespaceDefault,
				},
				Spec: wafv1beta1.RuleSetSpec{},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			rec := &RuleSetReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			updated := &wafv1beta1.RuleSet{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Finalizers).To(ContainElement(controller.Finalizer))

			cond := meta.FindStatusCondition(updated.Status.Conditions, controller.ConditionTypeReferencesResolved)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(updated.Status.RulesLoaded).To(Equal(int32(0)))

			// Cleanup
			Expect(k8sClient.Delete(ctx, updated)).To(Succeed())
			_, _ = rec.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
		})
	})
})
