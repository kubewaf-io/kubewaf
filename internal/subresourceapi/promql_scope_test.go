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
	"strconv"
	"strings"
	"testing"
)

func TestScopePromQLInjectsIdentity(t *testing.T) {
	q := `sum(increase({__name__=~"kubewaf_waf_tx_interruptions(_total)?"}[5m]))`
	got, err := ScopePromQL(q, "shop", "shop-waf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `waf_namespace="shop"`) || !strings.Contains(got, `waf_name="shop-waf"`) {
		t.Fatalf("identity missing: %s", got)
	}
	if strings.Count(got, "waf_namespace") != 1 {
		t.Fatalf("unexpected rewrite: %s", got)
	}
}

func TestScopePromQLRejectsForeignIdentity(t *testing.T) {
	_, err := ScopePromQL(`{__name__=~"x",waf_namespace="other",waf_name="x"}`, "shop", "shop-waf")
	if err == nil {
		t.Fatal("expected reject")
	}
}

func TestScopePromQLAcceptsMatchingIdentity(t *testing.T) {
	got, err := ScopePromQL(`{__name__=~"x",waf_namespace="shop",waf_name="shop-waf"}`, "shop", "shop-waf")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, `waf_namespace="shop"`) != 1 {
		t.Fatalf("duplicated identity: %s", got)
	}
}

func TestScopePromQLToWAFsUnions(t *testing.T) {
	got, err := ScopePromQLToWAFs(`sum(increase({__name__=~"kubewaf_waf_tx_total(_total)?"}[5m]))`, []WAFIdentity{
		{Namespace: "a", Name: "one"},
		{Namespace: "b", Name: "two"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `waf_namespace="a"`) || !strings.Contains(got, `waf_namespace="b"`) {
		t.Fatalf("union missing: %s", got)
	}
	if !strings.Contains(got, " or ") {
		t.Fatalf("expected or-union: %s", got)
	}
}

func TestScopePromQLToWAFsEmpty(t *testing.T) {
	got, err := ScopePromQLToWAFs(`sum(up)`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "vector(0)" {
		t.Fatalf("got %s", got)
	}
}

func TestScopePromQLNamedMetric(t *testing.T) {
	got, err := ScopePromQL(`up`, "shop", "shop-waf")
	if err != nil {
		t.Fatal(err)
	}
	if got != `up{waf_namespace="shop",waf_name="shop-waf"}` {
		t.Fatalf("got %s", got)
	}
}

func TestScopePromQLProductQueries(t *testing.T) {
	cases := []struct {
		name  string
		q     string
		sels  int
		check func(t *testing.T, got string)
	}{
		{
			name: "interrupt ratio 1e-9",
			q:    `sum(increase({__name__=~"kubewaf_waf_tx_interruptions(_total)?"}[5m])) / clamp_min(sum(increase({__name__=~"kubewaf_waf_tx_total(_total)?"}[5m])), 1e-9)`,
			sels: 2,
			check: func(t *testing.T, got string) {
				if !strings.Contains(got, "1e-9") || strings.Contains(got, "1e{") {
					t.Fatalf("scientific notation broken: %s", got)
				}
			},
		},
		{
			name: "sum by phase severity",
			q:    `sum by (phase, severity) (increase({__name__=~"kubewaf_waf_rule_matches_by_phase(_total)?"}[5m]))`,
			sels: 1,
			check: func(t *testing.T, got string) {
				if !strings.Contains(got, "sum by (phase, severity)") {
					t.Fatalf("grouping rewritten: %s", got)
				}
				if strings.Contains(got, "phase{") || strings.Contains(got, "severity{") {
					t.Fatalf("label names treated as metrics: %s", got)
				}
			},
		},
		{
			name: "sum by rule_id phase",
			q:    `sum by (rule_id, phase) (increase({__name__=~"kubewaf_waf_rule_matches_by_rule(_total)?"}[5m]))`,
			sels: 1,
			check: func(t *testing.T, got string) {
				if !strings.Contains(got, "sum by (rule_id, phase)") {
					t.Fatalf("grouping rewritten: %s", got)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ScopePromQL(tc.q, "shop", "shop-waf")
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(got, `waf_namespace="shop"`); n != tc.sels {
				t.Fatalf("waf_namespace count=%d want %d: %s", n, tc.sels, got)
			}
			if n := strings.Count(got, `waf_name="shop-waf"`); n != tc.sels {
				t.Fatalf("waf_name count=%d want %d: %s", n, tc.sels, got)
			}
			tc.check(t, got)
		})
	}
}

func TestScopePromQLRejectsNonEqualityIdentity(t *testing.T) {
	for _, q := range []string{
		`{waf_namespace=~".*"}`,
		`{waf_name=~"a|b"}`,
		`{waf_namespace!="x"}`,
		`{__name__=~"x",waf_namespace="other"}`,
	} {
		if _, err := ScopePromQL(q, "shop", "shop-waf"); err == nil {
			t.Fatalf("expected reject for %s", q)
		}
	}
}

func TestScopePromQLToWAFsAttachesRangePerSelector(t *testing.T) {
	got, err := ScopePromQLToWAFs(
		`sum(increase({__name__=~"kubewaf_waf_tx_interruptions(_total)?"}[5m])) / clamp_min(sum(increase({__name__=~"kubewaf_waf_tx_total(_total)?"}[5m])), 1e-9)`,
		[]WAFIdentity{{Namespace: "a", Name: "one"}, {Namespace: "b", Name: "two"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, ")[5m]") {
		t.Fatalf("range applied to parenthesized or: %s", got)
	}
	if increaseArgsContainOr(got) {
		t.Fatalf("or inside increase(: %s", got)
	}
	if strings.Count(got, "increase(") != 4 {
		t.Fatalf("expected increase distributed per identity: %s", got)
	}
	if strings.Count(got, `waf_name="one"`) != 2 || strings.Count(got, `waf_name="two"`) != 2 {
		t.Fatalf("identity count: %s", got)
	}
}

func TestScopePromQLToWAFsDistributesIncrease(t *testing.T) {
	got, err := ScopePromQLToWAFs(`increase({__name__=~"x"}[5m])`, []WAFIdentity{
		{Namespace: "a", Name: "one"},
		{Namespace: "b", Name: "two"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if increaseArgsContainOr(got) {
		t.Fatalf("or inside increase(: %s", got)
	}
	if strings.Count(got, "increase(") != 2 {
		t.Fatalf("expected two increase() calls: %s", got)
	}
	if !strings.Contains(got, `waf_namespace="a"`) || !strings.Contains(got, `waf_name="one"`) {
		t.Fatalf("missing first identity: %s", got)
	}
	if !strings.Contains(got, `waf_namespace="b"`) || !strings.Contains(got, `waf_name="two"`) {
		t.Fatalf("missing second identity: %s", got)
	}
	if !strings.Contains(got, " or ") {
		t.Fatalf("expected or-union of increases: %s", got)
	}
	if !strings.Contains(got, `[5m]`) {
		t.Fatalf("range missing: %s", got)
	}
}

func TestScopePromQLToWAFsCapsAt256(t *testing.T) {
	ids := make([]WAFIdentity, 257)
	for i := range ids {
		ids[i] = WAFIdentity{Namespace: "ns", Name: "w" + strconv.Itoa(i)}
	}
	got, err := ScopePromQLToWAFs("up", ids)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, `waf_name="w256"`) {
		t.Fatalf("257th identity leaked: %s", got)
	}
	if !strings.Contains(got, `waf_name="w255"`) {
		t.Fatalf("256th identity missing: %s", got)
	}
	if strings.Count(got, `waf_name=`) != 256 {
		t.Fatalf("want 256 identities, got %d: %s", strings.Count(got, `waf_name=`), got)
	}
}

func increaseArgsContainOr(q string) bool {
	for i := 0; i < len(q); {
		j := strings.Index(q[i:], "increase(")
		if j < 0 {
			return false
		}
		start := i + j + len("increase")
		end, err := skipParen(q, start)
		if err != nil {
			return true
		}
		if strings.Contains(q[start:end], " or ") {
			return true
		}
		i = end
	}
	return false
}
