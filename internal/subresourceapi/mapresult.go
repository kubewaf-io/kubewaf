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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	subv1alpha1 "github.com/kubewaf-io/kubewaf/api/subresources/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/probeassemble"
	"github.com/kubewaf-io/kubewaf/internal/probetest/api"
)

// MapEvalToProbe builds the user-facing Probe result from EvalResponse + assembly context.
func MapEvalToProbe(
	route *ProbeRoute,
	ctrl ControlOptions,
	assembly *probeassemble.AssemblyResult,
	dataFilesCount int,
	dropped []string,
	eval *api.EvalResponse,
	parentUID string,
) *subv1alpha1.Probe {
	now := metav1.NewTime(time.Now().UTC())
	p := &subv1alpha1.Probe{
		TypeMeta: metav1.TypeMeta{
			APIVersion: subv1alpha1.Group + "/" + subv1alpha1.Version,
			Kind:       "Probe",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              ctrl.TraceID,
			Namespace:         route.Namespace,
			CreationTimestamp: now,
		},
		Status: subv1alpha1.ProbeStatus{
			Phase:         subv1alpha1.ProbePhaseComplete,
			Engine:        "Coraza",
			EngineVersion: eval.EngineVersion,
			RequestedMode: ctrl.Mode,
			Target: &subv1alpha1.ProbeTarget{
				Kind:      string(route.ParentKind),
				Name:      route.Name,
				Namespace: route.Namespace,
				Group:     parentGroup(route.ParentKind),
				UID:       parentUID,
			},
			RequestEcho: &subv1alpha1.ProbeRequestEcho{
				Method:   "", // filled by caller if desired
				Path:     route.AppPath,
				RawQuery: route.RawQuery,
			},
			Conditions: engineConditions(now),
		},
	}
	if assembly != nil {
		p.Status.Assembly = &subv1alpha1.ProbeAssembly{
			RulesLoaded:      assembly.RulesLoaded,
			ActionsLoaded:    assembly.ActionsLoaded,
			DirectivesCount:  assembly.DirectivesCount,
			DataFilesCount:   dataFilesCount,
			DroppedDataFiles: dropped,
		}
		if eval.RulesLoaded > 0 {
			p.Status.Assembly.RulesLoaded = eval.RulesLoaded
		}
	}
	if eval.Interruption != nil {
		p.Status.Interruption = &subv1alpha1.ProbeInterruption{
			Disrupted: eval.Interruption.Disrupted,
			Action:    eval.Interruption.Action,
			Status:    eval.Interruption.Status,
			RuleID:    eval.Interruption.RuleID,
		}
	}
	if eval.Anomaly != nil {
		p.Status.Anomaly = &subv1alpha1.ProbeAnomaly{
			Inbound:  eval.Anomaly.Inbound,
			Outbound: eval.Anomaly.Outbound,
		}
	}
	if len(eval.Matches) > 0 {
		p.Status.Matches = make([]subv1alpha1.ProbeMatch, len(eval.Matches))
		for i, m := range eval.Matches {
			p.Status.Matches[i] = subv1alpha1.ProbeMatch{
				RuleID:      m.RuleID,
				Msg:         m.Msg,
				Phase:       m.Phase,
				Severity:    m.Severity,
				Tags:        m.Tags,
				MatchedData: m.MatchedData,
				Variable:    m.Variable,
			}
		}
	}
	p.Status.HTTP = &subv1alpha1.ProbeHTTPView{
		WouldStatus: eval.HTTP.WouldStatus,
		WouldBody:   eval.HTTP.WouldBody,
	}
	if eval.EngineVersion == "" {
		p.Status.EngineVersion = eval.Engine
	}
	return p
}

func parentGroup(k ParentKind) string {
	switch k {
	case ParentSecRule:
		return "seclang.kubewaf.io"
	case ParentRuleSet, ParentWAF:
		return "waf.kubewaf.io"
	default:
		return ""
	}
}

func engineConditions(now metav1.Time) []metav1.Condition {
	return []metav1.Condition{
		{
			Type:               subv1alpha1.ConditionAssembled,
			Status:             metav1.ConditionTrue,
			Reason:             subv1alpha1.ReasonRulesResolved,
			LastTransitionTime: now,
		},
		{
			Type:               subv1alpha1.ConditionEvaluated,
			Status:             metav1.ConditionTrue,
			Reason:             subv1alpha1.ReasonComplete,
			LastTransitionTime: now,
		},
		{
			Type:               subv1alpha1.ConditionEvalEngineMode,
			Status:             metav1.ConditionTrue,
			Reason:             subv1alpha1.ReasonSecRuleEngineOn,
			Message:            "evaluation always uses SecRuleEngine On (would-block); see status.requestedMode",
			LastTransitionTime: now,
		},
		{
			Type:               subv1alpha1.ConditionEngineParity,
			Status:             metav1.ConditionFalse,
			Reason:             subv1alpha1.ReasonCorazaNotModSecurity,
			Message:            "probe evaluation uses go-coraza in the Test HTTP Server; production dataplane is modsecurity-proxy-wasm — not a Coraza engine in kubeWAF",
			LastTransitionTime: now,
		},
	}
}
