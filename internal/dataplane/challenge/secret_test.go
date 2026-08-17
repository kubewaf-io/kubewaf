package challenge

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := wafv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestManagedChallengeSecretName(t *testing.T) {
	if got := ManagedChallengeSecretName("shop"); got != "shop-challenge-hmac" {
		t.Fatalf("got %q", got)
	}
	long := make([]byte, 60)
	for i := range long {
		long[i] = 'a'
	}
	got := ManagedChallengeSecretName(string(long))
	if len(got) > 63 {
		t.Fatalf("name too long: %d %q", len(got), got)
	}
	if got[len(got)-len("-challenge-hmac"):] != "-challenge-hmac" {
		t.Fatalf("missing suffix: %q", got)
	}
}

func TestResolveChallengeHMAC_ManagedCreateAndReuse(t *testing.T) {
	scheme := testScheme(t)
	ctx := context.Background()
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shop",
			Namespace: "ns1",
			UID:       "uid-shop-1",
		},
		Spec: wafv1beta1.WAFSpec{
			Challenge: &wafv1beta1.ChallengeSpec{
				Enabled: ptr.To(true),
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()

	r1, err := ResolveChallengeHMAC(ctx, c, scheme, waf, ResolveOptions{EnsureManaged: true})
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Managed || r1.SecretName != "shop-challenge-hmac" {
		t.Fatalf("unexpected result: %+v", r1)
	}
	if len(r1.Value) < 32 {
		t.Fatalf("hmac too short: %d", len(r1.Value))
	}

	// Second resolve reuses the same material.
	r2, err := ResolveChallengeHMAC(ctx, c, scheme, waf, ResolveOptions{EnsureManaged: true})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Value != r1.Value {
		t.Fatalf("hmac rotated unexpectedly")
	}

	var sec corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns1", Name: "shop-challenge-hmac"}, &sec); err != nil {
		t.Fatal(err)
	}
	if string(sec.Data[ChallengeHMACKey]) != r1.Value {
		t.Fatalf("secret data mismatch")
	}
	if sec.Labels[labelComponent] != labelComponentVal {
		t.Fatalf("labels: %v", sec.Labels)
	}
}

func TestResolveChallengeHMAC_InlineSecret(t *testing.T) {
	scheme := testScheme(t)
	ctx := context.Background()
	secret := "0123456789abcdef0123456789abcdef" // 32
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Challenge: &wafv1beta1.ChallengeSpec{
				Enabled: ptr.To(true),
				Secret:  secret,
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r, err := ResolveChallengeHMAC(ctx, c, scheme, waf, ResolveOptions{EnsureManaged: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Value != secret || r.Managed || r.SecretName != "" {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestResolveChallengeHMAC_SecretRef(t *testing.T) {
	scheme := testScheme(t)
	ctx := context.Background()
	val := "abcdefghijklmnopqrstuvwxyz012345" // 32
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-hmac", Namespace: "ns1"},
		Data:       map[string][]byte{"key": []byte(val)},
	}
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Challenge: &wafv1beta1.ChallengeSpec{
				Enabled: ptr.To(true),
				SecretRef: &wafv1beta1.SecretKeyRef{
					Name: "my-hmac",
					Key:  "key",
				},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sec).Build()
	r, err := ResolveChallengeHMAC(ctx, c, scheme, waf, ResolveOptions{EnsureManaged: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Value != val || r.SecretName != "my-hmac" || r.Managed {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestGenerateChallengeHMACLength(t *testing.T) {
	v, err := generateChallengeHMAC()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) < 32 {
		t.Fatalf("len=%d", len(v))
	}
}
