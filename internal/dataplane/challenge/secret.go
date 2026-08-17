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

package challenge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
)

const (
	// ChallengeHMACKey is the data key inside the operator-managed Secret.
	ChallengeHMACKey = "hmac"

	// challengeHMACBytes is the raw entropy for a new HMAC secret.
	challengeHMACBytes = 32

	// managedChallengeSecretSuffix is appended to the WAF name for the managed Secret.
	managedChallengeSecretSuffix = "-challenge-hmac"

	labelManagedBy    = "app.kubernetes.io/managed-by"
	labelManagedByVal = "kubewaf"
	labelWAFName      = "kubewaf.io/waf"
	labelComponent    = "kubewaf.io/component"
	labelComponentVal = "challenge-hmac"
)

// ChallengeHMACResult is the resolved HMAC material for a WAF challenge filter.
type ChallengeHMACResult struct {
	// Value is the secret string injected into the pow-proxy-wasm plugin config.
	Value string
	// SecretName is the Kubernetes Secret that holds the key (empty for inline Spec.Secret).
	SecretName string
	// Managed is true when the operator owns the Secret.
	Managed bool
}

// ChallengeEnabled reports whether the WAF installs the challenge filter.
func ChallengeEnabled(ch *wafv1beta1.ChallengeSpec) bool {
	return config.ChallengeEnabled(ch)
}

// ManagedChallengeSecretName returns the DNS-1123 name for the operator-managed Secret.
func ManagedChallengeSecretName(wafName string) string {
	const maxLen = 63
	if len(wafName)+len(managedChallengeSecretSuffix) <= maxLen {
		return wafName + managedChallengeSecretSuffix
	}
	keep := maxLen - len(managedChallengeSecretSuffix)
	if keep < 1 {
		return "challenge-hmac"
	}
	return wafName[:keep] + managedChallengeSecretSuffix
}

// ResolveOptions controls whether managed Secrets may be created/adopted.
type ResolveOptions struct {
	// EnsureManaged creates or adopts the operator-managed HMAC Secret.
	// Leader WAF reconciler sets this true; non-leader dataplane sync leaves it false
	// (read-only: wait until the Secret exists).
	EnsureManaged bool
}

// ResolveChallengeHMAC returns the HMAC string for plugin config.
//
// Priority:
//  1. Spec.Challenge.Secret (plaintext override)
//  2. Spec.Challenge.SecretRef (user-managed Secret)
//  3. Operator-managed Secret (create if missing when opts.EnsureManaged, else read-only)
func ResolveChallengeHMAC(ctx context.Context, c client.Client, scheme *runtime.Scheme, waf *wafv1beta1.WAF, opts ResolveOptions) (ChallengeHMACResult, error) {
	if waf == nil || !ChallengeEnabled(waf.Spec.Challenge) {
		return ChallengeHMACResult{}, nil
	}
	ch := waf.Spec.Challenge

	if ch.Secret != "" {
		if len(ch.Secret) < 32 {
			return ChallengeHMACResult{}, fmt.Errorf("challenge.spec.secret must be at least 32 bytes (got %d)", len(ch.Secret))
		}
		return ChallengeHMACResult{Value: ch.Secret}, nil
	}

	if ch.SecretRef != nil {
		if ch.SecretRef.Name == "" || ch.SecretRef.Key == "" {
			return ChallengeHMACResult{}, fmt.Errorf("challenge.secretRef requires name and key")
		}
		var sec corev1.Secret
		key := types.NamespacedName{Namespace: waf.Namespace, Name: ch.SecretRef.Name}
		if err := c.Get(ctx, key, &sec); err != nil {
			return ChallengeHMACResult{}, fmt.Errorf("challenge secretRef %s/%s: %w", waf.Namespace, ch.SecretRef.Name, err)
		}
		raw, ok := sec.Data[ch.SecretRef.Key]
		if !ok || len(raw) == 0 {
			return ChallengeHMACResult{}, fmt.Errorf("challenge secretRef %s/%s missing key %q",
				waf.Namespace, ch.SecretRef.Name, ch.SecretRef.Key)
		}
		if len(raw) < 32 {
			return ChallengeHMACResult{}, fmt.Errorf("challenge secretRef key %q must be at least 32 bytes (got %d)",
				ch.SecretRef.Key, len(raw))
		}
		return ChallengeHMACResult{
			Value:      string(raw),
			SecretName: ch.SecretRef.Name,
			Managed:    false,
		}, nil
	}

	if opts.EnsureManaged {
		return ensureManagedChallengeSecret(ctx, c, scheme, waf)
	}
	return readManagedChallengeSecret(ctx, c, waf)
}

// readManagedChallengeSecret loads an existing managed Secret without creating it.
func readManagedChallengeSecret(ctx context.Context, c client.Client, waf *wafv1beta1.WAF) (ChallengeHMACResult, error) {
	name := ManagedChallengeSecretName(waf.Name)
	nn := types.NamespacedName{Namespace: waf.Namespace, Name: name}
	var existing corev1.Secret
	if err := c.Get(ctx, nn, &existing); err != nil {
		return ChallengeHMACResult{}, fmt.Errorf("managed challenge secret %s/%s: %w", waf.Namespace, name, err)
	}
	if v, ok := secretHMACValue(&existing); ok {
		return ChallengeHMACResult{Value: v, SecretName: name, Managed: true}, nil
	}
	return ChallengeHMACResult{}, fmt.Errorf("managed challenge secret %s/%s has no usable hmac key", waf.Namespace, name)
}

// ensureManagedChallengeSecret creates or reuses <waf-name>-challenge-hmac.
func ensureManagedChallengeSecret(ctx context.Context, c client.Client, scheme *runtime.Scheme, waf *wafv1beta1.WAF) (ChallengeHMACResult, error) {
	name := ManagedChallengeSecretName(waf.Name)
	nn := types.NamespacedName{Namespace: waf.Namespace, Name: name}

	var existing corev1.Secret
	err := c.Get(ctx, nn, &existing)
	if err == nil {
		if v, ok := secretHMACValue(&existing); ok {
			if err := adoptManagedSecretIfNeeded(ctx, c, scheme, waf, &existing); err != nil {
				return ChallengeHMACResult{}, err
			}
			return ChallengeHMACResult{Value: v, SecretName: name, Managed: true}, nil
		}
		// Secret exists but has no usable key — refill.
		val, genErr := generateChallengeHMAC()
		if genErr != nil {
			return ChallengeHMACResult{}, genErr
		}
		if existing.Data == nil {
			existing.Data = map[string][]byte{}
		}
		existing.Data[ChallengeHMACKey] = []byte(val)
		setManagedSecretLabels(&existing, waf.Name)
		if scheme != nil {
			if err := controllerutil.SetControllerReference(waf, &existing, scheme); err != nil {
				return ChallengeHMACResult{}, fmt.Errorf("set owner on challenge secret: %w", err)
			}
		}
		if err := c.Update(ctx, &existing); err != nil {
			return ChallengeHMACResult{}, fmt.Errorf("update managed challenge secret %s/%s: %w", waf.Namespace, name, err)
		}
		return ChallengeHMACResult{Value: val, SecretName: name, Managed: true}, nil
	}
	if !apierrors.IsNotFound(err) {
		return ChallengeHMACResult{}, fmt.Errorf("get managed challenge secret %s/%s: %w", waf.Namespace, name, err)
	}

	val, genErr := generateChallengeHMAC()
	if genErr != nil {
		return ChallengeHMACResult{}, genErr
	}

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: waf.Namespace,
			Labels: map[string]string{
				labelManagedBy: labelManagedByVal,
				labelWAFName:   waf.Name,
				labelComponent: labelComponentVal,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			ChallengeHMACKey: []byte(val),
		},
	}
	if scheme != nil {
		if err := controllerutil.SetControllerReference(waf, sec, scheme); err != nil {
			return ChallengeHMACResult{}, fmt.Errorf("set owner on challenge secret: %w", err)
		}
	}
	if err := c.Create(ctx, sec); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if getErr := c.Get(ctx, nn, &existing); getErr != nil {
				return ChallengeHMACResult{}, fmt.Errorf("re-get challenge secret after race: %w", getErr)
			}
			if v, ok := secretHMACValue(&existing); ok {
				return ChallengeHMACResult{Value: v, SecretName: name, Managed: true}, nil
			}
			return ChallengeHMACResult{}, fmt.Errorf("challenge secret %s/%s exists but has no usable hmac key", waf.Namespace, name)
		}
		return ChallengeHMACResult{}, fmt.Errorf("create managed challenge secret %s/%s: %w", waf.Namespace, name, err)
	}
	return ChallengeHMACResult{Value: val, SecretName: name, Managed: true}, nil
}

// adoptManagedSecretIfNeeded sets owner + labels when missing (no-op if already correct).
func adoptManagedSecretIfNeeded(ctx context.Context, c client.Client, scheme *runtime.Scheme, waf *wafv1beta1.WAF, sec *corev1.Secret) error {
	needsUpdate := false
	if sec.Labels == nil {
		sec.Labels = map[string]string{}
		needsUpdate = true
	}
	if sec.Labels[labelManagedBy] != labelManagedByVal ||
		sec.Labels[labelWAFName] != waf.Name ||
		sec.Labels[labelComponent] != labelComponentVal {
		setManagedSecretLabels(sec, waf.Name)
		needsUpdate = true
	}
	hasOwner := false
	for _, o := range sec.OwnerReferences {
		if o.UID == waf.UID && o.Controller != nil && *o.Controller {
			hasOwner = true
			break
		}
	}
	if !hasOwner && scheme != nil {
		if err := controllerutil.SetControllerReference(waf, sec, scheme); err != nil {
			return fmt.Errorf("set owner on challenge secret: %w", err)
		}
		needsUpdate = true
	}
	if !needsUpdate {
		return nil
	}
	if err := c.Update(ctx, sec); err != nil {
		return fmt.Errorf("adopt managed challenge secret %s/%s: %w", sec.Namespace, sec.Name, err)
	}
	return nil
}

func setManagedSecretLabels(sec *corev1.Secret, wafName string) {
	if sec.Labels == nil {
		sec.Labels = map[string]string{}
	}
	sec.Labels[labelManagedBy] = labelManagedByVal
	sec.Labels[labelWAFName] = wafName
	sec.Labels[labelComponent] = labelComponentVal
}

func secretHMACValue(sec *corev1.Secret) (string, bool) {
	if sec == nil || sec.Data == nil {
		return "", false
	}
	if v, ok := sec.Data[ChallengeHMACKey]; ok && len(v) >= 32 {
		return string(v), true
	}
	// Accept alternate key name for resilience.
	if v, ok := sec.Data["secret"]; ok && len(v) >= 32 {
		return string(v), true
	}
	return "", false
}

func generateChallengeHMAC() (string, error) {
	raw := make([]byte, challengeHMACBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate challenge hmac: %w", err)
	}
	// URL-safe base64 without padding → 43 chars for 32 bytes (≥ 32 min length).
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
