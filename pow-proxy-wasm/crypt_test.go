package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"
)

func solveChallenge(t *testing.T, ch SignedChallenge, diff uint) Solution {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	var nonce uint64
	for {
		nb := make([]byte, 8)
		binary.BigEndian.PutUint64(nb, nonce)
		data := make([]byte, len(raw)+8)
		copy(data, raw)
		copy(data[len(raw):], nb)
		sum := sha256.Sum256(data)
		if hasLeadingZeroBits(sum[:], diff) {
			return Solution{SignedChallenge: ch, Nonce: nonce}
		}
		nonce++
		if nonce > 1<<20 {
			t.Fatal("could not solve low difficulty")
		}
	}
}

func TestGenerateAndVerifySolution(t *testing.T) {
	secret := SecretKey("0123456789abcdef0123456789abcdef")
	client := ClientContext{IP: "1.2.3.4", ConnID: "99"}
	ch, err := GenerateChallenge(secret, 8, client)
	if err != nil {
		t.Fatal(err)
	}
	sol := solveChallenge(t, ch, 8)

	if err := VerifySolution(secret, sol, client); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifySolution(secret, sol, ClientContext{IP: "9.9.9.9", ConnID: "99"}); err != ErrContextMismatch {
		t.Fatalf("want IP mismatch, got %v", err)
	}
	if err := VerifySolution(secret, sol, ClientContext{IP: "1.2.3.4", ConnID: "100"}); err != ErrContextMismatch {
		t.Fatalf("want connection.id mismatch, got %v", err)
	}
	// Missing ConnID on verifier side: skip CID check (property unavailable).
	if err := VerifySolution(secret, sol, ClientContext{IP: "1.2.3.4"}); err != nil {
		t.Fatalf("empty expected ConnID should skip cid check: %v", err)
	}
}

func TestMatchChallengeContext(t *testing.T) {
	if err := matchChallengeContext("1.1.1.1", "7", ClientContext{IP: "1.1.1.1", ConnID: "7"}); err != nil {
		t.Fatal(err)
	}
	if err := matchChallengeContext("1.1.1.1", "7", ClientContext{IP: "1.1.1.1", ConnID: "8"}); err != ErrContextMismatch {
		t.Fatalf("want cid mismatch, got %v", err)
	}
	if err := matchChallengeContext("1.1.1.1", "7", ClientContext{IP: "2.2.2.2", ConnID: "7"}); err != ErrContextMismatch {
		t.Fatalf("want ip mismatch, got %v", err)
	}
	// No expected IP → do not require token IP
	if err := matchChallengeContext("1.1.1.1", "7", ClientContext{ConnID: "7"}); err != nil {
		t.Fatal(err)
	}
}

func TestClearance(t *testing.T) {
	secret := SecretKey("0123456789abcdef0123456789abcdef")
	tok, err := GenerateClearance(secret, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyClearance(secret, tok, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyClearance(secret, tok, "10.0.0.2"); err != ErrContextMismatch {
		t.Fatalf("want mismatch got %v", err)
	}
}

func TestClearanceBindIgnoresConnID(t *testing.T) {
	c := ClientContext{IP: "10.0.0.1", ConnID: "42"}
	if c.ClearanceBind() != "10.0.0.1" {
		t.Fatalf("clearance must be IP-only, got %q", c.ClearanceBind())
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:5678":     "1.2.3.4",
		"[2001:db8::1]:80": "2001:db8::1",
		"  8.8.8.8  ":      "8.8.8.8",
		"not-an-ip":        "",
	}
	for in, want := range cases {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q)=%q want %q", in, got, want)
		}
	}
	if got := firstForwardedIP("203.0.113.1, 10.0.0.1"); got != "203.0.113.1" {
		t.Errorf("xff got %q", got)
	}
}

func TestTimersAligned(t *testing.T) {
	if ChallengeCookieMaxAge() != int(ChallengeLifetime/time.Second) {
		t.Fatal("challenge cookie max-age != ChallengeLifetime")
	}
	if ChallengeCookieMaxAge() != 60 {
		t.Fatalf("expected 60s challenge window, got %d", ChallengeCookieMaxAge())
	}
	if ClearanceCookieMaxAge() != int(ClearanceLifetime/time.Second) {
		t.Fatal("clearance cookie max-age != ClearanceLifetime")
	}
}

func TestClientContextString(t *testing.T) {
	if got := (ClientContext{IP: "1.2.3.4", ConnID: "9"}).String(); got != "1.2.3.4;cid=9" {
		t.Fatalf("got %q", got)
	}
}
