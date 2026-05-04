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

package convert

import (
	"fmt"
	"strings"

	types "github.com/coreruleset/crslang/types"
	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

var (
	dataActionMapper          = DataActionTypeMapperImpl{}
	disruptiveActionMapper    = DisruptiveActionMapperImpl{}
	flowActionMapper          = FlowActionTypeMapperImpl{}
	nonDisruptiveActionMapper = NonDisruptiveActionTypeMapperImpl{}
)

func FlowActionToAPI(source types.Action) v1beta1.FlowAction {
	target := v1beta1.FlowAction{}

	target.Type = v1beta1.FlowActionType(source.GetKey())

	switch target.Type {
	case v1beta1.Skip, v1beta1.SkipAfter:
		target.Value = strings.Trim(strings.TrimPrefix(source.ToString(), source.GetKey()+":"), "'")
	default:
	}

	return target

}

func DataActionToAPI(source types.Action) v1beta1.DataAction {
	target := v1beta1.DataAction{}

	target.Type = v1beta1.DataActionType(source.GetKey())

	// Extract value from ToString() output, trimming outer single quotes added by the library
	s := source.ToString()
	if idx := strings.Index(s, ":"); idx != -1 {
		target.Value = strings.Trim(strings.TrimSpace(s[idx+1:]), "'")
	} else if len(s) > len(source.GetKey()) {
		target.Value = strings.Trim(strings.TrimSpace(strings.TrimPrefix(s, source.GetKey())), "'")
	}

	return target
}

func NonDisruptiveActionToAPI(source types.Action) []v1beta1.NonDisruptiveAction {
	target := v1beta1.NonDisruptiveAction{}

	target.Type = v1beta1.NonDisruptiveActionType(source.GetKey())

	switch source := source.(type) {
	case types.SetvarAction:
		results := make([]v1beta1.NonDisruptiveAction, 0, len(source.Assignments))

		for _, asg := range source.Assignments {
			result := v1beta1.NonDisruptiveAction{
				Value: source.Collection.String() + "." + asg.Variable + source.Operation.String() + asg.Value,
				Type:  v1beta1.SetVar,
			}
			results = append(results, result)
		}

		return results
	default:
		switch target.Type {
		case v1beta1.Ctl, v1beta1.Exec, v1beta1.ExpireVar, v1beta1.InitCol, v1beta1.LogData, v1beta1.SetEnv, v1beta1.SetVar, v1beta1.SetRsc, v1beta1.SetSid, v1beta1.SetUid:
			target.Value = strings.Trim(strings.TrimPrefix(source.ToString(), source.GetKey()+":"), "'")
		default:
		}

	}

	return []v1beta1.NonDisruptiveAction{target}

}

func DisruptiveActionToAPI(source types.Action) v1beta1.DisruptiveAction {
	target := v1beta1.DisruptiveAction{}

	target.Type = v1beta1.DisruptiveActionType(source.GetKey())

	switch target.Type {
	case v1beta1.Redirect:
		target.Value = strings.Trim(strings.TrimPrefix(source.ToString(), source.GetKey()+":"), "'")
	default:
	}

	return target

}

func ActionToCSR(source v1beta1.SecLangActions) (types.Action, error) {
	targetKind := source.GetKind()

	switch targetKind {
	case "DataAction":
		if a, ok := source.(v1beta1.DataAction); ok {
			return actionToCSR(dataActionMapper.Convert(a.Type), a.Value)
		} else if a, ok := source.(*v1beta1.DataAction); ok {
			return actionToCSR(dataActionMapper.Convert(a.Type), a.Value)
		}
		return nil, fmt.Errorf("could not translate data action obj=%v", source)
	case "FlowAction":
		if a, ok := source.(v1beta1.FlowAction); ok {
			return actionToCSR(flowActionMapper.Convert(a.Type), a.Value)
		} else if a, ok := source.(*v1beta1.FlowAction); ok {
			return actionToCSR(flowActionMapper.Convert(a.Type), a.Value)
		}
		return nil, fmt.Errorf("could not translate flow action obj=%v", source)
	case "NonDisruptiveAction":
		if a, ok := source.(v1beta1.NonDisruptiveAction); ok {
			return actionToCSR(nonDisruptiveActionMapper.Convert(a.Type), a.Value)
		} else if a, ok := source.(*v1beta1.NonDisruptiveAction); ok {
			return actionToCSR(nonDisruptiveActionMapper.Convert(a.Type), a.Value)
		}
		return nil, fmt.Errorf("could not translate NonDisruptiveAction obj=%v", source)
	case "DisruptiveAction":
		if a, ok := source.(v1beta1.DisruptiveAction); ok {
			return actionToCSR(disruptiveActionMapper.Convert(a.Type), a.Value)
		} else if a, ok := source.(*v1beta1.DisruptiveAction); ok {
			return actionToCSR(disruptiveActionMapper.Convert(a.Type), a.Value)
		}
		return nil, fmt.Errorf("could not translate DisruptiveAction obj=%v", source)
	default:
		return nil, fmt.Errorf("could not translate action obj=%v", source)
	}

}

func actionToCSR[T types.ActionType](targetType T, value string) (types.Action, error) {
	if value == "" {
		target, err := types.NewActionOnly(targetType)
		if err != nil {
			return target, err
		}
		return target, nil
	} else {
		target, err := types.NewActionWithParam(targetType, value)
		if err != nil {
			return target, err
		}
		return target, nil
	}
}

func SecActionToCSR(source v1beta1.SecRuleActions) (types.SeclangActions, error) {
	target := types.SeclangActions{}
	var err error
	if len(source.Data) > 0 {
		for _, data := range source.Data {
			dataAction, err := ActionToCSR(data)
			if err != nil {
				return target, err
			}
			target.DataActions = append(target.DataActions, dataAction)
		}
	}
	if source.DisruptiveAction != nil {
		target.DisruptiveAction, err = ActionToCSR(*source.DisruptiveAction)
		if err != nil {
			return target, err
		}
	} else {
		// Default to 'pass' for rules without explicit disruptive action (common in CRS setup rules).
		// This prevents nil pointer in crslang's sortActions/ToSeclang.
		defaultAction, _ := types.NewActionOnly(types.Pass)
		target.DisruptiveAction = defaultAction
	}

	if len(source.Flow) > 0 {
		for _, flow := range source.Flow {
			flowAction, err := ActionToCSR(flow)
			if err != nil {
				return target, err
			}
			target.FlowActions = append(target.FlowActions, flowAction)
		}
	}

	if len(source.NonDisruptive) > 0 {
		for _, da := range source.NonDisruptive {
			daAction, err := ActionToCSR(da)
			if err != nil {
				return target, err
			}
			target.NonDisruptiveActions = append(target.NonDisruptiveActions, daAction)
		}
	}

	return target, nil

}

func SecActionToAPI(source types.SeclangActions) v1beta1.SecRuleActions {
	target := v1beta1.SecRuleActions{}

	if len(source.DataActions) > 0 {
		for _, action := range source.DataActions {
			target.Data = append(target.Data, DataActionToAPI(action))
		}
	}

	if len(source.FlowActions) > 0 {
		for _, action := range source.FlowActions {
			target.Flow = append(target.Flow, FlowActionToAPI(action))
		}
	}

	if len(source.NonDisruptiveActions) > 0 {
		for _, action := range source.NonDisruptiveActions {
			target.NonDisruptive = append(target.NonDisruptive, NonDisruptiveActionToAPI(action)...)
		}
	}

	if source.DisruptiveAction != nil {
		action := DisruptiveActionToAPI(source.DisruptiveAction)
		target.DisruptiveAction = &action
	}

	return target
}
