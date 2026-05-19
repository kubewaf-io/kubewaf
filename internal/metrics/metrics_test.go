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

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsCanBeUpdated(t *testing.T) {
	// Basic smoke test: the metrics should be registered at init time
	// and we should be able to update and read them.

	WAFReady.WithLabelValues("default", "test-policy").Set(1)
	RulesLoaded.WithLabelValues("default", "test-policy", "waf").Set(42)

	if v := testutil.ToFloat64(WAFReady.WithLabelValues("default", "test-policy")); v != 1 {
		t.Errorf("expected 1, got %v", v)
	}
	if v := testutil.ToFloat64(RulesLoaded.WithLabelValues("default", "test-policy", "waf")); v != 42 {
		t.Errorf("expected 42, got %v", v)
	}
}

func TestInventoryGauges(t *testing.T) {
	SecRuleTotal.WithLabelValues("default").Set(15)
	RuleSetTotal.WithLabelValues("default").Set(3)

	if v := testutil.ToFloat64(SecRuleTotal.WithLabelValues("default")); v != 15 {
		t.Errorf("expected 15 secrules, got %v", v)
	}
	if v := testutil.ToFloat64(RuleSetTotal.WithLabelValues("default")); v != 3 {
		t.Errorf("expected 3 rulesets, got %v", v)
	}
}
