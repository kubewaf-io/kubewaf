package v1beta1

import (
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
)

// WorkloadType is the discriminator
type WorkloadType string

const (
	WorkloadTypeDeployment  WorkloadType = "Deployment"
	WorkloadTypeStatefulSet WorkloadType = "StatefulSet"
	WorkloadTypeDaemonSet   WorkloadType = "DaemonSet"
	WorkloadTypeHPA         WorkloadType = "HPA"
)

// WorkloadTemplate lets the user choose exactly one workload kind
type WorkloadTemplate struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Deployment;StatefulSet;DaemonSet;HPA
	Type WorkloadType `json:"type"`

	// Exactly one of the following must be set
	Deployment  *DeploymentTemplate  `json:"deployment,omitempty"`
	StatefulSet *StatefulSetTemplate `json:"statefulSet,omitempty"`
	DaemonSet   *DaemonSetTemplate   `json:"daemonSet,omitempty"`
	HPA         *HPATemplate         `json:"hpa,omitempty"`
}

// Lightweight wrappers (you can embed the real spec or cherry-pick fields)
type DeploymentTemplate struct {
	*appsv1.DeploymentSpec `json:",inline"`
}

type StatefulSetTemplate struct {
	*appsv1.StatefulSetSpec `json:",inline"`
}

type DaemonSetTemplate struct {
	*appsv1.DaemonSetSpec `json:",inline"`
}

type HPATemplate struct {
	*autoscalingv2.HorizontalPodAutoscalerSpec `json:",inline"`
}
