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
	v1beta1 "github.com/buzz-it/kubewaf/api/seclang/v1beta1"
	types "github.com/coreruleset/crslang/types"
	"github.com/jinzhu/copier"
)

var (
	variableReverseMapper   = VariableReverseMapperImpl{}
	variableMapper          = VariableMapperImpl{}
	operatorMapper          = OperatorReverseMapperImpl{}
	operatorForwardMapper   = OperatorMapperImpl{}
	collectionReverseMapper = CollectionReverseMapperImpl{}
	collectionMapper        = CollectionMapperImpl{}
	transformationMapper    = TransformationMapperImpl{}
)

func ConvertSecRule(source v1beta1.SecRule) ([]types.SeclangDirective, error) {
	target := []types.SeclangDirective{}

	// Manual index to properly consume chained rules (skip next entry after attaching ChainedRule)
	for i := 0; i < len(source.Spec.SecRules); i++ {
		secRule := source.Spec.SecRules[i]
		sds, err := secLangSecRuleToRuleWithCondition(secRule)
		if err != nil {
			return target, err
		}

		for _, r := range sds {
			switch rwc := r.(type) {
			case *types.RuleWithCondition:
				if hasChainInFlow(secRule) && i+1 < len(source.Spec.SecRules) {
					// Consume the next rule as chained (do not add it as top-level)
					i++
					nextSecRule := source.Spec.SecRules[i]
					nextSds, err := secLangSecRuleToRuleWithCondition(nextSecRule)
					if err != nil {
						return target, err
					}
					for _, nextR := range nextSds {
						if nextRwc, ok := nextR.(*types.RuleWithCondition); ok {
							removeChainFromFlowActions(nextRwc)
							rwc.ChainedRule = nextRwc
							break
						}
					}
					// chained rules should not have the chain action themselves
				}
				target = append(target, rwc)

			default:
				target = append(target, rwc)
			}
		}
	}

	return target, nil
}

func secLangSecRuleToRuleWithCondition(secRule v1beta1.SecLangSecRule) ([]types.SeclangDirective, error) {

	var sds []types.SeclangDirective
	var secMarker types.ConfigurationDirective

	rwc := types.RuleWithCondition{
		Kind: types.RuleKind,
	}

	if secRule.Metadata != nil {
		if err := copier.Copy(&rwc.Metadata, secRule.Metadata); err != nil {
			return sds, err
		}
	}

	if secRule.SecMarker != "" {
		secMarker = types.ConfigurationDirective{
			Kind:      types.ConfigurationKind,
			Name:      types.SecMarker,
			Parameter: secRule.SecMarker,
			Metadata:  &types.CommentMetadata{Comment: "bla"},
		}
		sds = append(sds, secMarker)
	}

	for _, cond := range secRule.Conditions {
		condition := types.Condition{
			AlwaysMatch: cond.AlwaysMatch,
			Script:      cond.Script,
		}

		if len(cond.Variables) > 0 {
			for _, variable := range cond.Variables {
				condition.Variables = append(condition.Variables, types.Variable{
					Name:     variableMapper.Convert(variable.Name),
					Excluded: variable.Excluded,
				})
			}
		}

		for _, collection := range cond.Collections {
			condition.Collections = append(condition.Collections, types.Collection{
				Arguments: collection.Arguments,
				Excluded:  collection.Excluded,
				Count:     collection.Count,
				Name:      collectionMapper.Convert(collection.Name),
			})

		}
		condition.Operator = types.Operator{
			Negate: cond.Operator.Negate,
			Value:  cond.Operator.Value,
		}
		if string(cond.Operator.Name) != "" {
			condition.Operator.Name = operatorForwardMapper.Convert(cond.Operator.Name)
		}
		if err := copier.Copy(&condition.Transformations, cond.Transformations); err != nil {
			return sds, err
		}

		rwc.Conditions = append(rwc.Conditions, condition)
	}

	if secRule.Actions != nil {
		actions, err := SecActionToCSR(*secRule.Actions)
		if err != nil {
			return sds, err
		}
		rwc.Actions = actions
	}
	sds = append(sds, &rwc)
	return sds, nil
}

func hasChainInFlow(secRule v1beta1.SecLangSecRule) bool {
	if secRule.Actions == nil || len(secRule.Actions.Flow) == 0 {
		return false
	}
	for _, flow := range secRule.Actions.Flow {
		if flow.Type == v1beta1.Chain {
			return true
		}
	}
	return false
}

func removeChainFromFlowActions(rwc *types.RuleWithCondition) {
	if len(rwc.Actions.FlowActions) == 0 {
		return
	}
	newFlow := []types.Action{}
	for _, fa := range rwc.Actions.FlowActions {
		if fa.GetKey() != "chain" {
			newFlow = append(newFlow, fa)
		}
	}
	rwc.Actions.FlowActions = newFlow
}
func ConvertCrsRule(source types.RuleWithCondition, secMarker string) (v1beta1.SecLangSecRule, error) {
	target := v1beta1.SecLangSecRule{}
	targetMetdata := v1beta1.SecRuleMetadata{}

	err := copier.Copy(&targetMetdata, source.Metadata)
	if err != nil {
		return target, err
	}
	target.Metadata = &targetMetdata
	if len(source.Conditions) > 0 {
		for _, condition := range source.Conditions {
			targetCondition := v1beta1.Condition{}
			targetCondition.AlwaysMatch = condition.AlwaysMatch
			targetCondition.Script = condition.Script

			if len(condition.Variables) > 0 {
				for _, variable := range condition.Variables {
					targetVariable := v1beta1.Variable{
						Excluded: variable.Excluded,
						Name:     variableReverseMapper.Convert(variable.Name),
					}
					targetCondition.Variables = append(targetCondition.Variables, targetVariable)
				}
			}
			if len(condition.Collections) > 0 {

				for _, collection := range condition.Collections {
					targetCollection := v1beta1.Collection{
						Arguments: collection.Arguments,
						Excluded:  collection.Excluded,
						Count:     collection.Count,
						Name:      collectionReverseMapper.Convert(collection.Name),
					}
					targetCondition.Collections = append(targetCondition.Collections, targetCollection)
				}

			}
			targetCondition.Operator = v1beta1.Operator{
				Negate: condition.Operator.Negate,
				Value:  condition.Operator.Value,
				Name:   operatorMapper.Convert(condition.Operator.Name),
			}

			target.Conditions = append(target.Conditions, targetCondition)
		}
	}
	// Action
	actions := SecActionToAPI(source.Actions)
	target.Actions = &actions
	target.SecMarker = secMarker
	return target, nil
}

func ConvertToSecLangString(rules []types.SeclangDirective) string {
	configList := types.ConfigurationList{
		DirectiveList: []types.DirectiveList{{
			Directives: rules,
		}},
	}

	unformatted := types.FromCRSLangToUnformattedDirectives(configList)
	return unformatted.DirectiveList[0].ToSeclang()
}
