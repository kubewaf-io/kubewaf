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
	"time"
)

const (
	DefaultDifficulty = 18
	ChallengeLifetime = 1 * time.Minute
)

// SecretKey should be 32+ random bytes, loaded from env/config once at startup.
type SecretKey []byte

type ChallengePayload struct {
	Timestamp  int64  `json:"ts"`            // unix seconds
	Expiry     int64  `json:"exp"`           // unix seconds
	Difficulty uint   `json:"diff"`          // leading zero bits
	Salt       string `json:"salt"`          // base64url random bytes
	Context    string `json:"ctx,omitempty"` // optional: IP, path hash, session ID, etc.
}

type SignedChallenge struct {
	Challenge string `json:"c"` // base64url(JSON payload)
	Signature string `json:"s"` // base64url(HMAC-SHA256)
}

type Solution struct {
	SignedChallenge
	Nonce uint64 `json:"n"`
}

// GenerateChallenge returns a signed challenge ready to send to the client.
// context can be r.RemoteAddr, a hash of the request, etc.
func GenerateChallenge(secret SecretKey, difficulty uint, context string) (SignedChallenge, error) {
	if difficulty < 1 {
		difficulty = DefaultDifficulty
	}

	payload := ChallengePayload{
		Timestamp:  time.Now().Unix(),
		Expiry:     time.Now().Add(ChallengeLifetime).Unix(),
		Difficulty: difficulty,
		Context:    context,
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

// VerifySolution validates a client-submitted Solution sent via challenge-token header.
// - Recomputes and checks HMAC signature over the challenge (c)
// - Validates PoW using the provided nonce
// - Checks expiry
// - Optionally enforces context (e.g. client IP) match if expectedContext is non-empty
func VerifySolution(secret SecretKey, sol Solution, expectedContext string) error {
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

	// Context / IP binding (if server provides expectedContext and challenge recorded one)
	if expectedContext != "" && payload.Context != expectedContext {
		return ErrContextMismatch
	}

	return nil
}
