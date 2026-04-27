package v1beta1

// CrossNamespaceObject can be used across namespace
// these objects are protected using RuleNamespaces
// +kubebuilder:object:generate=false
type CrossNamespaceObject interface {
	GetRuleNamespaces() RuleNamespaces
}
