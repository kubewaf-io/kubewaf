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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wafv1beta1 "github.com/buzz-it/kubewaf/api/waf/v1beta1"
)

// WAFInstanceReconciler reconciles a WAFInstance object
type WAFInstanceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafinstances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafinstances/finalizers,verbs=update
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules;secactions;rulesets,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules/status;secactions/status,verbs=update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=autoscaling,resources=horizontalpodautoscalers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps;secrets;services,verbs=get;list;watch;create;update;patch;delete

// Reconcile reconciles a WAFInstance by resolving its RuleSetRefs (only RuleSets
// allowed per resolver policy) using the shared RuleRefResolver.
func (r *WAFInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// l := logf.FromContext(ctx)
	// wafInstance := wafv1beta1.WAFInstance{}

	// updated, err := controller.InitHandler(ctx, req, &wafInstance, r.Client)
	// if err != nil {
	// 	if errors.IsNotFound(err) {
	// 		l.V(1).Info("WAFInstance not found, skipping")
	// 		return ctrl.Result{}, nil
	// 	}
	// 	return ctrl.Result{}, err
	// }
	// if updated {
	// 	// Finalizer was added, requeue to process
	// 	return ctrl.Result{Requeue: true}, nil
	// }

	// // Handle deletion
	// if !wafInstance.DeletionTimestamp.IsZero() {
	// 	if err := controller.CleanupBackReferences(ctx, r.Client, &wafInstance); err != nil {
	// 		return ctrl.Result{}, err
	// 	}
	// 	if controllerutil.RemoveFinalizer(&wafInstance, controller.Finalizer) {
	// 		if err := r.Update(ctx, &wafInstance); err != nil {
	// 			return ctrl.Result{}, err
	// 		}
	// 	}
	// 	return ctrl.Result{}, nil
	// }

	// // Resolve references using the shared reusable resolver (handles recursion, backrefs, conditions)
	// resolver := references2.NewRuleRefResolver(r.Client, r.Scheme)
	// resolved, errs, err := resolver.AddUpdateReconcile(ctx, wafInstance.Spec.RuleSetRefs, &wafInstance)
	// if err != nil {
	// 	return ctrl.Result{}, err
	// }
	// if len(errs) > 0 {
	// 	l.Error(fmt.Errorf("%v", errs), "Reference resolution had errors")
	// }

	// // Handle workload configuration (e.g. create/update Deployment/StatefulSet with WAF sidecar,
	// // generate ConfigMaps from resolved rules, set owner refs, update conditions)
	// if _, err = r.workloadHandler(ctx, &wafInstance, resolved); err != nil {
	// 	return ctrl.Result{}, err
	// }

	// if err := r.Status().Update(ctx, &wafInstance); err != nil {
	// 	return ctrl.Result{}, err
	// }

	return ctrl.Result{}, nil
}

// workloadHandler handles the workload stuff from WAFInstance.Spec.Workload.
// It switches on the workload type, reconciles the corresponding Kubernetes resource
// (Deployment, StatefulSet, DaemonSet or HPA), integrates the resolved rules (e.g. by
// creating a ConfigMap with Coraza/ModSecurity config derived from resolved RuleSets),
// sets appropriate owner references, and updates the status conditions.
//
// Yes, we can (and do) overwrite specific pod template fields here. The user's
// provided template (via Workload.Deployment etc.) is used as a base, but the
// operator *always* merges/overwrites key pod spec elements (sidecar container,
// volumes for rules, labels, securityContext, etc.) to enforce WAF behavior. This
// is done via direct mutation before CreateOrUpdate (strategic merge or mergo lib
// could be used for more complex cases).
func (r *WAFInstanceReconciler) workloadHandler(ctx context.Context, wafInstance *wafv1beta1.WAFInstance, resolved []client.Object) (bool, error) {
	_ = logf.FromContext(ctx)
	// var updated bool

	// if wafInstance.Spec.Workload.Type == "" {
	// 	l.Info("No workload.type specified in WAFInstance, skipping workload reconciliation")
	// 	// Still set a condition
	// 	newCondition := metav1.Condition{
	// 		Type:               "WorkloadConfigured",
	// 		Status:             metav1.ConditionFalse,
	// 		ObservedGeneration: wafInstance.Generation,
	// 		Reason:             "NoWorkloadSpecified",
	// 		Message:            "Workload field not configured in spec",
	// 	}
	// 	updated = meta.SetStatusCondition(&wafInstance.Status.Conditions, newCondition)
	// 	return updated, nil
	// }

	// l.Info("Handling workload for WAFInstance", "workloadType", wafInstance.Spec.Workload.Type, "name", wafInstance.Name)

	// // Example: always create a rules ConfigMap (placeholder for now; in full impl use
	// // internal/coraza to flatten resolved rules into valid seclang string).
	// cm := &corev1.ConfigMap{
	// 	ObjectMeta: metav1.ObjectMeta{
	// 		Name:      wafInstance.Name + "-rules",
	// 		Namespace: wafInstance.Namespace,
	// 	},
	// 	Data: map[string]string{
	// 		"waf.conf": "# Generated from " + fmt.Sprintf("%d", len(resolved)) + " resolved RuleSets\nSecRuleEngine On\n",
	// 	},
	// }
	// if err := controllerutil.SetControllerReference(wafInstance, cm, r.Scheme); err != nil {
	// 	return false, err
	// }
	// // Reconcile the ConfigMap (standard pattern; overwrites if exists via controller ref)
	// if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
	// 	// CM data already set above; could merge more fields here if needed
	// 	return nil
	// }); err != nil {
	// 	return false, fmt.Errorf("failed to reconcile rules ConfigMap: %w", err)
	// }

	// switch wafInstance.Spec.Workload.Type {
	// case wafv1beta1.WorkloadTypeDeployment:
	// 	deploy := &appsv1.Deployment{
	// 		ObjectMeta: metav1.ObjectMeta{
	// 			Name:      wafInstance.Name + "-deployment",
	// 			Namespace: wafInstance.Namespace,
	// 			Labels:    map[string]string{"app": "kubewaf"},
	// 		},
	// 	}
	// 	// Base from user template (overwrites most of spec)
	// 	if wafInstance.Spec.Workload.Deployment != nil {
	// 		if wafInstance.Spec.Workload.Deployment.DeploymentSpec != nil {
	// 			deploy.Spec = *wafInstance.Spec.Workload.Deployment.DeploymentSpec
	// 		}
	// 	}

	// 	// Overwrite pod template stuff (this is the key part answering the query).
	// 	// User's pod spec is respected where possible, but we mutate to inject WAF.
	// 	if len(deploy.Spec.Template.Spec.Containers) == 0 {
	// 		deploy.Spec.Template.Spec.Containers = []corev1.Container{}
	// 	}
	// 	podSpec := &deploy.Spec.Template.Spec

	// 	// Example overwrite: ensure WAF sidecar container (appends if missing; could replace image etc.)
	// 	wafContainer := corev1.Container{
	// 		Name:  "waf-sidecar",
	// 		Image: "ghcr.io/corazawaf/coraza-proxy:0.0.1", // example; make configurable
	// 		Ports: []corev1.ContainerPort{{ContainerPort: 8080}},
	// 		VolumeMounts: []corev1.VolumeMount{
	// 			{Name: "waf-rules", MountPath: "/etc/coraza/rules"},
	// 		},
	// 		// Could overwrite securityContext, resources, env from template too
	// 	}
	// 	overwrote := false
	// 	for i, c := range podSpec.Containers {
	// 		if c.Name == "waf-sidecar" {
	// 			podSpec.Containers[i] = wafContainer // full overwrite of our container
	// 			overwrote = true
	// 			break
	// 		}
	// 	}
	// 	if !overwrote {
	// 		podSpec.Containers = append(podSpec.Containers, wafContainer)
	// 	}

	// 	// Overwrite/add volume for the rules ConfigMap (always ensures this pod config)
	// 	volume := corev1.Volume{
	// 		Name: "waf-rules",
	// 		VolumeSource: corev1.VolumeSource{
	// 			ConfigMap: &corev1.ConfigMapVolumeSource{
	// 				LocalObjectReference: corev1.LocalObjectReference{Name: cm.Name},
	// 			},
	// 		},
	// 	}
	// 	volOverwrote := false
	// 	for i, v := range podSpec.Volumes {
	// 		if v.Name == "waf-rules" {
	// 			podSpec.Volumes[i] = volume
	// 			volOverwrote = true
	// 			break
	// 		}
	// 	}
	// 	if !volOverwrote {
	// 		podSpec.Volumes = append(podSpec.Volumes, volume)
	// 	}

	// 	// Additional pod overwrites: labels, annotations for WAF/gateway, securityContext, etc.
	// 	if deploy.Spec.Template.Labels == nil {
	// 		deploy.Spec.Template.Labels = map[string]string{}
	// 	}
	// 	deploy.Spec.Template.Labels["kubewaf.io/injected"] = "true"

	// 	if err := controllerutil.SetControllerReference(wafInstance, deploy, r.Scheme); err != nil {
	// 		return false, err
	// 	}
	// 	// Reconcile the Deployment (user template base + our pod overwrites)
	// 	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, deploy, func() error {
	// 		// Pod template already mutated above; further mutations could go in this func
	// 		return nil
	// 	}); err != nil {
	// 		return false, fmt.Errorf("failed to reconcile Deployment: %w", err)
	// 	}
	// 	l.Info("Overwrote pod template in Deployment with WAF sidecar + rules volume")

	// case wafv1beta1.WorkloadTypeStatefulSet:
	// 	// Similar pattern: base from template + overwrite podSpec.Containers/Volumes
	// 	l.Info("StatefulSet workload handling not fully implemented yet")
	// case wafv1beta1.WorkloadTypeDaemonSet:
	// 	l.Info("DaemonSet workload handling not fully implemented yet")
	// case wafv1beta1.WorkloadTypeHPA:
	// 	l.Info("HPA workload handling not fully implemented yet")
	// default:
	// 	return false, fmt.Errorf("unsupported workload type: %s", wafInstance.Spec.Workload.Type)
	// }

	// // Set status condition for workload
	// newCondition := metav1.Condition{
	// 	Type:               "WorkloadConfigured",
	// 	Status:             metav1.ConditionTrue,
	// 	ObservedGeneration: wafInstance.Generation,
	// 	Reason:             "WorkloadReconciled",
	// 	Message:            fmt.Sprintf("Successfully reconciled %s workload with %d resolved references", wafInstance.Spec.Workload.Type, len(resolved)),
	// }
	// updated = meta.SetStatusCondition(&wafInstance.Status.Conditions, newCondition)

	return false, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WAFInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.WAFInstance{}).
		Named("waf-wafinstance").
		Complete(r)
}
