package controller

const (
	// ConditionTypeValid indicates the SecRule is syntactically valid and can be rendered.
	ConditionTypeValid = "Valid"
	// ConditionTypeRendered means the SecLang string was successfully generated.
	ConditionTypeRendered = "Rendered"
	// ConditionTypeReferencesResolved means all referenced rules/actions are valid.
	ConditionTypeReferencesResolved = "ReferencesResolved"
	// ConditionTypeReady is the overall readiness of the rule.
	ConditionTypeReady = "Ready"
)
