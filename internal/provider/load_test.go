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

package provider

import "testing"

func TestObserveLoad(t *testing.T) {
	rejected := `
[warning][dynamic_modules] Dynamic module ABI version v0.1.0 is deprecated.
Failed to load configuration: failed to create WAF from directives: invalid WAF config from string: failed to readfile: open /etc/kubewaf/seclang/default_edge-before.conf: no such file or directory
config rejected: Failed to initialize dynamic module
`
	state, msg := ObserveLoad(nil, rejected)
	if state != LoadRejected || msg == "" {
		t.Fatalf("rejected log: %s %q", state, msg)
	}

	loaded := rejected + "\n[warning][dynamic_modules] Dynamic module ABI version v0.1.0 is deprecated.\n"
	state, _ = ObserveLoad(nil, loaded)
	if state != LoadCandidate {
		t.Fatalf("load after rejection: %s", state)
	}

	state, msg = ObserveLoad([]string{"failed to readfile: /etc/kubewaf/seclang/a.conf"}, "")
	if state != LoadRejected {
		t.Fatalf("status rejection: %s %q", state, msg)
	}

	state, _ = ObserveLoad(nil, "")
	if state != LoadUnknown {
		t.Fatalf("empty: %s", state)
	}
}

func TestMarkerWithGeneration(t *testing.T) {
	if got := MarkerWithGeneration("KUBEWAFabcd", 0); got != "KUBEWAFabcd" {
		t.Fatal(got)
	}
	if got := MarkerWithGeneration("KUBEWAFabcd", 2); got != "KUBEWAFabcdr2" {
		t.Fatal(got)
	}
}
