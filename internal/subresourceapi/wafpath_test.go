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

import "testing"

func TestParseWAFSubresourcePath(t *testing.T) {
	r, err := ParseWAFSubresourcePath("/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if r.Namespace != "shop" || r.Name != "shop-waf" || r.Subresource != WAFSubresourceMetrics {
		t.Fatalf("%+v", r)
	}
	r, err = ParseWAFSubresourcePath("/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/traces/abc")
	if err != nil || r.Extra != "abc" {
		t.Fatalf("traces extra: %+v err=%v", r, err)
	}
	if _, err = ParseWAFSubresourcePath("/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/nope"); err == nil {
		t.Fatal("expected unknown subresource")
	}
}
