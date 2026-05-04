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
	"reflect"
	"testing"

	v1beta1 "github.com/buzz-it/kubewaf/api/seclang/v1beta1"
	"github.com/coreruleset/crslang/types"
)

func TestFlowActionToAPI(t *testing.T) {
	tests := []struct {
		name   string
		source types.Action
		want   v1beta1.FlowAction
	}{
		{
			name: "skip action",
			source: func() types.Action {
				fa := flowActionMapper.Convert(v1beta1.Skip)
				a, _ := types.NewActionWithParam(fa, "5")
				return a
			}(),
			want: v1beta1.FlowAction{
				Type:  v1beta1.Skip,
				Value: "5",
			},
		},
		{
			name: "skipafter action",
			source: func() types.Action {
				fa := flowActionMapper.Convert(v1beta1.SkipAfter)
				a, _ := types.NewActionWithParam(fa, "10")
				return a
			}(),
			want: v1beta1.FlowAction{
				Type:  v1beta1.SkipAfter,
				Value: "10",
			},
		},
		{
			name: "chain action",
			source: func() types.Action {
				fa := flowActionMapper.Convert(v1beta1.Chain)
				a, _ := types.NewActionOnly(fa)
				return a
			}(),
			want: v1beta1.FlowAction{
				Type:  v1beta1.Chain,
				Value: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FlowActionToAPI(tt.source)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FlowActionToAPI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDataActionToAPI(t *testing.T) {
	tests := []struct {
		name   string
		source types.Action
		want   v1beta1.DataAction
	}{
		{
			name: "status action with value",
			source: func() types.Action {
				da := dataActionMapper.Convert(v1beta1.Status)
				a, _ := types.NewActionWithParam(da, "403")
				return a
			}(),
			want: v1beta1.DataAction{
				Type:  v1beta1.Status,
				Value: "403",
			},
		},
		{
			name: "xmlns action with value",
			source: func() types.Action {
				da := dataActionMapper.Convert(v1beta1.XLMNS)
				a, _ := types.NewActionWithParam(da, "soap='http://...'")
				return a
			}(),
			want: v1beta1.DataAction{
				Type:  v1beta1.XLMNS,
				Value: "soap='http://...",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DataActionToAPI(tt.source)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DataActionToAPI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNonDisruptiveActionToAPI(t *testing.T) {
	tests := []struct {
		name   string
		source types.Action
		want   []v1beta1.NonDisruptiveAction
	}{
		// Actions without parameters
		{
			name: "append action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.Append)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.Append,
				Value: "",
			}},
		},
		{
			name: "auditlog action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.AuditLog)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.AuditLog,
				Value: "",
			}},
		},
		{
			name: "capture action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.Capture)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.Capture,
				Value: "",
			}},
		},
		{
			name: "deprecatevar action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.DeprecateVar)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.DeprecateVar,
				Value: "",
			}},
		},
		{
			name: "log action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.Log)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.Log,
				Value: "",
			}},
		},
		{
			name: "multimatch action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.MultiMatch)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.MultiMatch,
				Value: "",
			}},
		},
		{
			name: "noauditlog action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.NoAuditLog)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.NoAuditLog,
				Value: "",
			}},
		},
		{
			name: "nolog action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.NoLog)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.NoLog,
				Value: "",
			}},
		},
		{
			name: "sanitiseArg action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SanitiseArg)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SanitiseArg,
				Value: "",
			}},
		},
		{
			name: "sanitiseMatched action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SanitiseMatched)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SanitiseMatched,
				Value: "",
			}},
		},
		{
			name: "sanitiseMatchedBytes action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SanitiseMatchedBytes)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SanitiseMatchedBytes,
				Value: "",
			}},
		},
		{
			name: "sanitiseRequestHeader action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SanitiseRequestHeader)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SanitiseRequestHeader,
				Value: "",
			}},
		},
		{
			name: "sanitiseResponseHeader action",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SanitiseResponseHeader)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SanitiseResponseHeader,
				Value: "",
			}},
		},
		// Actions with parameters
		{
			name: "ctl action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.Ctl)
				a, _ := types.NewActionWithParam(nda, "ruleRemoveById=123")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.Ctl,
				Value: "ruleRemoveById=123",
			}},
		},
		{
			name: "exec action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.Exec)
				a, _ := types.NewActionWithParam(nda, "/path/to/script")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.Exec,
				Value: "/path/to/script",
			}},
		},
		{
			name: "expirevar action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.ExpireVar)
				a, _ := types.NewActionWithParam(nda, "TX.test=10")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.ExpireVar,
				Value: "TX.test=10",
			}},
		},
		{
			name: "initcol action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.InitCol)
				a, _ := types.NewActionWithParam(nda, "RESOURCE=10")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.InitCol,
				Value: "RESOURCE=10",
			}},
		},
		{
			name: "logdata action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.LogData)
				a, _ := types.NewActionWithParam(nda, "Logged data")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.LogData,
				Value: "Logged data",
			}},
		},
		{
			name: "setenv action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SetEnv)
				a, _ := types.NewActionWithParam(nda, "VAR=value")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SetEnv,
				Value: "VAR=value",
			}},
		},
		{
			name: "setrsc action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SetRsc)
				a, _ := types.NewActionWithParam(nda, "5")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SetRsc,
				Value: "5",
			}},
		},
		{
			name: "setsid action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SetSid)
				a, _ := types.NewActionWithParam(nda, "12345")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SetSid,
				Value: "12345",
			}},
		},
		{
			name: "setuid action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SetUid)
				a, _ := types.NewActionWithParam(nda, "user123")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SetUid,
				Value: "user123",
			}},
		},
		{
			name: "setvar action with value",
			source: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SetVar)
				a, _ := types.NewActionWithParam(nda, "TX.test=1")
				return a
			}(),
			want: []v1beta1.NonDisruptiveAction{{
				Type:  v1beta1.SetVar,
				Value: "TX.test=1",
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NonDisruptiveActionToAPI(tt.source)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NonDisruptiveActionToAPI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDisruptiveActionToAPI(t *testing.T) {
	tests := []struct {
		name   string
		source types.Action
		want   v1beta1.DisruptiveAction
	}{
		// Actions without parameters
		{
			name: "allow action",
			source: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Allow)
				a, _ := types.NewActionOnly(da)
				return a
			}(),
			want: v1beta1.DisruptiveAction{
				Type:  v1beta1.Allow,
				Value: "",
			},
		},
		{
			name: "block action",
			source: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Block)
				a, _ := types.NewActionOnly(da)
				return a
			}(),
			want: v1beta1.DisruptiveAction{
				Type:  v1beta1.Block,
				Value: "",
			},
		},
		{
			name: "deny action",
			source: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Deny)
				a, _ := types.NewActionOnly(da)
				return a
			}(),
			want: v1beta1.DisruptiveAction{
				Type:  v1beta1.Deny,
				Value: "",
			},
		},
		{
			name: "drop action",
			source: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Drop)
				a, _ := types.NewActionOnly(da)
				return a
			}(),
			want: v1beta1.DisruptiveAction{
				Type:  v1beta1.Drop,
				Value: "",
			},
		},
		{
			name: "pass action",
			source: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Pass)
				a, _ := types.NewActionOnly(da)
				return a
			}(),
			want: v1beta1.DisruptiveAction{
				Type:  v1beta1.Pass,
				Value: "",
			},
		},
		{
			name: "pause action",
			source: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Pause)
				a, _ := types.NewActionOnly(da)
				return a
			}(),
			want: v1beta1.DisruptiveAction{
				Type:  v1beta1.Pause,
				Value: "",
			},
		},
		{
			name: "proxy action",
			source: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Proxy)
				a, _ := types.NewActionOnly(da)
				return a
			}(),
			want: v1beta1.DisruptiveAction{
				Type:  v1beta1.Proxy,
				Value: "",
			},
		},
		// Action with parameter
		{
			name: "redirect action with value",
			source: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Redirect)
				a, _ := types.NewActionWithParam(da, "http://example.com")
				return a
			}(),
			want: v1beta1.DisruptiveAction{
				Type:  v1beta1.Redirect,
				Value: "http://example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DisruptiveActionToAPI(tt.source)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DisruptiveActionToAPI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActionToCSR(t *testing.T) {
	tests := []struct {
		name    string
		source  v1beta1.SecLangActions
		want    types.Action
		wantErr bool
	}{
		// DataAction
		{
			name: "data action status with value",
			source: &v1beta1.DataAction{
				Type:  v1beta1.Status,
				Value: "403",
			},
			want: func() types.Action {
				da := dataActionMapper.Convert(v1beta1.Status)
				a, _ := types.NewActionWithParam(da, "403")
				return a
			}(),
			wantErr: false,
		},
		{
			name: "data action xlmns with value",
			source: &v1beta1.DataAction{
				Type:  v1beta1.XLMNS,
				Value: "soap='http://...'",
			},
			want: func() types.Action {
				da := dataActionMapper.Convert(v1beta1.XLMNS)
				a, _ := types.NewActionWithParam(da, "soap='http://...'")
				return a
			}(),
			wantErr: false,
		},
		// FlowAction
		{
			name: "flow action skip with value",
			source: &v1beta1.FlowAction{
				Type:  v1beta1.Skip,
				Value: "5",
			},
			want: func() types.Action {
				fa := flowActionMapper.Convert(v1beta1.Skip)
				a, _ := types.NewActionWithParam(fa, "5")
				return a
			}(),
			wantErr: false,
		},
		{
			name: "flow action skipafter with value",
			source: &v1beta1.FlowAction{
				Type:  v1beta1.SkipAfter,
				Value: "marker",
			},
			want: func() types.Action {
				fa := flowActionMapper.Convert(v1beta1.SkipAfter)
				a, _ := types.NewActionWithParam(fa, "marker")
				return a
			}(),
			wantErr: false,
		},
		{
			name: "flow action chain without value",
			source: &v1beta1.FlowAction{
				Type:  v1beta1.Chain,
				Value: "",
			},
			want: func() types.Action {
				fa := flowActionMapper.Convert(v1beta1.Chain)
				a, _ := types.NewActionOnly(fa)
				return a
			}(),
			wantErr: false,
		},
		// NonDisruptiveAction
		{
			name: "non disruptive action log without value",
			source: &v1beta1.NonDisruptiveAction{
				Type:  v1beta1.Log,
				Value: "",
			},
			want: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.Log)
				a, _ := types.NewActionOnly(nda)
				return a
			}(),
			wantErr: false,
		},
		{
			name: "non disruptive action setvar with value",
			source: &v1beta1.NonDisruptiveAction{
				Type:  v1beta1.SetVar,
				Value: "TX.test=1",
			},
			want: func() types.Action {
				nda := nonDisruptiveActionMapper.Convert(v1beta1.SetVar)
				a, _ := types.NewActionWithParam(nda, "TX.test=1")
				return a
			}(),
			wantErr: false,
		},
		// DisruptiveAction
		{
			name: "disruptive action deny without value",
			source: &v1beta1.DisruptiveAction{
				Type:  v1beta1.Deny,
				Value: "",
			},
			want: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Deny)
				a, _ := types.NewActionOnly(da)
				return a
			}(),
			wantErr: false,
		},
		{
			name: "disruptive action redirect with value",
			source: &v1beta1.DisruptiveAction{
				Type:  v1beta1.Redirect,
				Value: "http://example.com",
			},
			want: func() types.Action {
				da := disruptiveActionMapper.Convert(v1beta1.Redirect)
				a, _ := types.NewActionWithParam(da, "http://example.com")
				return a
			}(),
			wantErr: false,
		},
		// Error case: unknown kind
		{
			name:    "unknown kind",
			source:  &mockSecLangActions{kind: "Unknown"},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ActionToCSR(tt.source)
			if (err != nil) != tt.wantErr {
				t.Errorf("ActionToCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ActionToCSR() = %v, want %v", got, tt.want)
			}
		})
	}
}

// mockSecLangActions for testing unknown kind
type mockSecLangActions struct {
	kind string
}

func (m *mockSecLangActions) GetType() string  { return "" }
func (m *mockSecLangActions) GetValue() string { return "" }
func (m *mockSecLangActions) GetKind() string  { return m.kind }
