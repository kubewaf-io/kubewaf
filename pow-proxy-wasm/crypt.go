package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	// DefaultDifficulty is used when no difficulty is configured.
	DefaultDifficulty = 18

	// ChallengeLifetime is how long a PoW challenge remains valid to solve.
	// Cookie Max-Age for challenge/challenge-sig/challenge-nonce must match this.
	ChallengeLifetime = 60 * time.Second

	// ClearanceLifetime is how long a successful solve grants access without re-solving.
	// Implemented as a separate signed clearance cookie (HttpOnly).
	ClearanceLifetime = 30 * time.Minute

	// MinSecretLen is the minimum accepted HMAC secret length.
	MinSecretLen = 32
)

// SecretKey should be 32+ random bytes, loaded from env/config once at startup.
type SecretKey []byte

// ClientContext is the request identity used for token binding.
//
// Challenge tokens bind IP + Envoy connection.id (same downstream connection).
// Clearance tokens bind IP only so they survive reloads / new connections after a solve.
type ClientContext struct {
	// IP is the normalized client address (may be empty if unknown).
	IP string
	// ConnID is Envoy's downstream connection.id (stable for one TCP/TLS connection).
	// Empty when the property is unavailable (e.g. unit tests, some runtimes).
	ConnID string
}

// ClearanceBind returns the long-lived clearance context (IP only).
func (c ClientContext) ClearanceBind() string {
	return c.IP
}

// String is a compact log form.
func (c ClientContext) String() string {
	if c.IP == "" && c.ConnID == "" {
		return ""
	}
	if c.ConnID == "" {
		return c.IP
	}
	if c.IP == "" {
		return "cid=" + c.ConnID
	}
	return c.IP + ";cid=" + c.ConnID
}

type ChallengePayload struct {
	Timestamp  int64  `json:"ts"`            // unix seconds
	Expiry     int64  `json:"exp"`           // unix seconds
	Difficulty uint   `json:"diff"`          // leading zero bits
	Salt       string `json:"salt"`          // base64url random bytes
	Context    string `json:"ctx,omitempty"` // client IP
	// ConnID is Envoy downstream connection.id at challenge issue time.
	// Verified strictly when both issue and verify see a non-empty id.
	ConnID string `json:"cid,omitempty"`
}

type SignedChallenge struct {
	Challenge string `json:"c"` // base64url(JSON payload)
	Signature string `json:"s"` // base64url(HMAC-SHA256)
}

type Solution struct {
	SignedChallenge
	Nonce uint64 `json:"n"`
}

// ClearancePayload is issued after a successful PoW solve. Subsequent requests
// present this instead of replaying the raw challenge solution.
// Bound to client IP only (not connection.id) so navigation/reloads keep working.
type ClearancePayload struct {
	Issued  int64  `json:"iat"`
	Expiry  int64  `json:"exp"`
	Context string `json:"ctx,omitempty"` // client IP
	// Salt makes each clearance unique (limits bulk cookie minting usefulness).
	Salt string `json:"salt"`
}

// GenerateChallenge returns a signed challenge ready to send to the client.
// client binds IP and, when available, Envoy connection.id.
func GenerateChallenge(secret SecretKey, difficulty uint, client ClientContext) (SignedChallenge, error) {
	if difficulty < 1 {
		difficulty = DefaultDifficulty
	}

	now := time.Now()
	payload := ChallengePayload{
		Timestamp:  now.Unix(),
		Expiry:     now.Add(ChallengeLifetime).Unix(),
		Difficulty: difficulty,
		Context:    client.IP,
		ConnID:     client.ConnID,
	}

	salt, err := randomBytes(32)
	if err != nil {
		return SignedChallenge{}, err
	}
	payload.Salt = base64.RawURLEncoding.EncodeToString(salt)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return SignedChallenge{}, err
	}

	challenge := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Sign the challenge token (not the raw JSON) → easy for any client language
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(challenge))
	sig := h.Sum(nil)

	return SignedChallenge{
		Challenge: challenge,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// GenerateClearance returns a signed clearance token cookie value:
// base64url(JSON) + "." + base64url(HMAC-SHA256 over the payload segment).
func GenerateClearance(secret SecretKey, context string) (string, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	now := time.Now()
	payload := ClearancePayload{
		Issued:  now.Unix(),
		Expiry:  now.Add(ClearanceLifetime).Unix(),
		Context: context,
		Salt:    base64.RawURLEncoding.EncodeToString(salt),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payloadBytes)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return body + "." + sig, nil
}

// randomBytes returns cryptographically secure random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

var (
	ErrInvalidToken    = errors.New("invalid token format")
	ErrExpired         = errors.New("challenge expired")
	ErrBadSignature    = errors.New("bad signature")
	ErrBadPoW          = errors.New("invalid proof of work")
	ErrContextMismatch = errors.New("context mismatch")
)

// hasLeadingZeroBits reports whether the hash has at least `bits` leading zero bits.
// Matches the JS implementation in challenge.html.
func hasLeadingZeroBits(hash []byte, bits uint) bool {
	if bits == 0 {
		return true
	}
	for i := uint(0); i < bits; i++ {
		byteIdx := i / 8
		if byteIdx >= uint(len(hash)) {
			return false
		}
		bitIdx := 7 - (i % 8)
		if (hash[byteIdx] & (1 << bitIdx)) != 0 {
			return false
		}
	}
	return true
}

// VerifySolution validates a client-submitted Solution sent via cookies or challenge-token header.
// - Recomputes and checks HMAC signature over the challenge (c)
// - Validates PoW using the provided nonce
// - Checks expiry
// - Enforces IP binding and, when both sides have it, Envoy connection.id
func VerifySolution(secret SecretKey, sol Solution, expected ClientContext) error {
	if sol.Challenge == "" || sol.Signature == "" {
		return ErrInvalidToken
	}

	// Decode the challenge (base64url of JSON payload)
	chBytes, err := base64.RawURLEncoding.DecodeString(sol.Challenge)
	if err != nil {
		return ErrInvalidToken
	}

	var payload ChallengePayload
	if err := json.Unmarshal(chBytes, &payload); err != nil {
		return ErrInvalidToken
	}

	// Expiry check
	if time.Now().Unix() > payload.Expiry {
		return ErrExpired
	}

	// Signature check (HMAC over the *challenge string* b64, not the JSON)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(sol.Challenge))
	expectedSig := h.Sum(nil)

	sigBytes, err := base64.RawURLEncoding.DecodeString(sol.Signature)
	if err != nil {
		return ErrBadSignature
	}
	if subtle.ConstantTimeCompare(expectedSig, sigBytes) != 1 {
		return ErrBadSignature
	}

	// PoW check
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, sol.Nonce)

	data := make([]byte, len(chBytes)+8)
	copy(data, chBytes)
	copy(data[len(chBytes):], nonceBytes)

	hash := sha256.Sum256(data)
	if !hasLeadingZeroBits(hash[:], payload.Difficulty) {
		return ErrBadPoW
	}

	if err := matchChallengeContext(payload.Context, payload.ConnID, expected); err != nil {
		return err
	}

	return nil
}

// matchChallengeContext enforces IP and connection.id binding for a PoW solution.
//
// IP: when the verifier knows the client IP, the token must carry the same IP.
// ConnID: when both the token and the current request have a connection.id, they
// must match (same downstream connection). If either side lacks ConnID, the check
// is skipped so environments without the property still work.
//
// Note: a full page navigation often opens a new connection. The challenge page
// uses fetch() before reload so the solve can complete on the original connection;
// clearance is then IP-only and survives later connections.
func matchChallengeContext(tokenIP, tokenCID string, expected ClientContext) error {
	if expected.IP != "" {
		if tokenIP == "" || tokenIP != expected.IP {
			return ErrContextMismatch
		}
	}
	if tokenCID != "" && expected.ConnID != "" && tokenCID != expected.ConnID {
		return ErrContextMismatch
	}
	return nil
}

// VerifyClearance validates a challenge-clearance cookie value.
// expectedIP is the current client IP (clearance is not bound to connection.id).
func VerifyClearance(secret SecretKey, token string, expectedIP string) error {
	body, sig, ok := strings.Cut(token, ".")
	if !ok || body == "" || sig == "" {
		return ErrInvalidToken
	}

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(body))
	expectedSig := h.Sum(nil)

	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return ErrBadSignature
	}
	if subtle.ConstantTimeCompare(expectedSig, sigBytes) != 1 {
		return ErrBadSignature
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return ErrInvalidToken
	}
	var payload ClearancePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return ErrInvalidToken
	}

	if time.Now().Unix() > payload.Expiry {
		return ErrExpired
	}

	if expectedIP != "" {
		if payload.Context == "" || payload.Context != expectedIP {
			return ErrContextMismatch
		}
	}

	return nil
}

// ChallengeCookieMaxAge returns Max-Age seconds for challenge cookies (aligned with ChallengeLifetime).
func ChallengeCookieMaxAge() int {
	return int(ChallengeLifetime.Seconds())
}

// ClearanceCookieMaxAge returns Max-Age seconds for the clearance cookie.
func ClearanceCookieMaxAge() int {
	return int(ClearanceLifetime.Seconds())
}
