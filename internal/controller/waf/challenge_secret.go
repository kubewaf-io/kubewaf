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

package waf

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/challenge"
)

// Re-export challenge helpers for controller call sites and existing tests.
// Canonical implementation lives in internal/dataplane/challenge so dataplane
// sync does not import the WAF controller package.

const ChallengeHMACKey = challenge.ChallengeHMACKey

// ChallengeHMACResult is the resolved HMAC material for a WAF challenge filter.
type ChallengeHMACResult = challenge.ChallengeHMACResult

// ChallengeEnabled reports whether the WAF installs the challenge filter.
func ChallengeEnabled(ch *wafv1beta1.ChallengeSpec) bool {
	return challenge.ChallengeEnabled(ch)
}

// ManagedChallengeSecretName returns the DNS-1123 name for the operator-managed Secret.
func ManagedChallengeSecretName(wafName string) string {
	return challenge.ManagedChallengeSecretName(wafName)
}

// ResolveChallengeHMAC returns the HMAC string for plugin config.
// Leader path: ensures managed Secrets when needed.
func ResolveChallengeHMAC(ctx context.Context, c client.Client, scheme *runtime.Scheme, waf *wafv1beta1.WAF) (ChallengeHMACResult, error) {
	return challenge.ResolveChallengeHMAC(ctx, c, scheme, waf, challenge.ResolveOptions{EnsureManaged: true})
}
