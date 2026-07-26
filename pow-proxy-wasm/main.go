// Copyright 2020-2024 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strconv"
	"strings"

	_ "embed" // blank import required for //go:embed

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

func main() {}
func init() {
	proxywasm.SetVMContext(&vmContext{})
}

//go:embed challenge.html
var content string // file content becomes this string at compile time

// vmContext implements types.VMContext.
type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}

// NewPluginContext implements types.VMContext.
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

// pluginContext implements types.PluginContext.
type pluginContext struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultPluginContext

	// headerName and headerValue are the header to be added to response. They are configured via
	// plugin configuration during OnPluginStart. Optional.
	headerName  string
	headerValue string

	secret []byte

	// Difficulty configuration (static defaults + bounds)
	baseDifficulty uint
	minDifficulty  uint
	maxDifficulty  uint

	// Local counters for pressure tracking (avoid per-request shared data host calls)
	challengeCounter uint64
	currentDiff      uint
}

// NewHttpContext implements types.PluginContext.
func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpHeaders{
		contextID:   contextID,
		headerName:  p.headerName,
		headerValue: p.headerValue,
		plugin:      p,
	}
}

// OnPluginStart implements types.PluginContext.
func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	proxywasm.LogDebug("loading plugin config")
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil {
		proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	if data == nil || len(data) == 0 {
		proxywasm.LogCritical(`plugin configuration required; expected JSON with at least {"secret":"<32+ bytes>"}`)
		return types.OnPluginStartStatusFailed
	}

	if !gjson.ValidBytes(data) {
		proxywasm.LogCritical(`invalid configuration format; expected JSON object`)
		return types.OnPluginStartStatusFailed
	}

	// Secret is mandatory — refuse to start with a hardcoded default.
	secretStr := strings.TrimSpace(gjson.GetBytes(data, "secret").Str)
	if secretStr == "" {
		proxywasm.LogCritical("secret is required in plugin configuration (no default)")
		return types.OnPluginStartStatusFailed
	}
	if len(secretStr) < MinSecretLen {
		proxywasm.LogCriticalf("secret must be at least %d bytes (got %d)", MinSecretLen, len(secretStr))
		return types.OnPluginStartStatusFailed
	}
	p.secret = []byte(secretStr)

	// Optional response header injection
	p.headerName = strings.TrimSpace(gjson.GetBytes(data, "header").Str)
	p.headerValue = strings.TrimSpace(gjson.GetBytes(data, "value").Str)

	// Parse difficulty configuration with sensible defaults
	p.baseDifficulty = uint(gjson.GetBytes(data, "base_difficulty").Uint())
	p.minDifficulty = uint(gjson.GetBytes(data, "min_difficulty").Uint())
	p.maxDifficulty = uint(gjson.GetBytes(data, "max_difficulty").Uint())

	if p.baseDifficulty < 1 {
		p.baseDifficulty = DefaultDifficulty
	}
	if p.minDifficulty < 1 {
		p.minDifficulty = 12
	}
	if p.maxDifficulty < 1 || p.maxDifficulty < p.minDifficulty {
		p.maxDifficulty = 26
	}
	if p.baseDifficulty < p.minDifficulty {
		p.baseDifficulty = p.minDifficulty
	}
	if p.baseDifficulty > p.maxDifficulty {
		p.baseDifficulty = p.maxDifficulty
	}

	if p.headerName != "" {
		proxywasm.LogInfof("response header from config: %s = %s", p.headerName, p.headerValue)
	}
	proxywasm.LogInfof("difficulty config: base=%d min=%d max=%d", p.baseDifficulty, p.minDifficulty, p.maxDifficulty)
	proxywasm.LogInfof("secret configured: len=%d", len(p.secret))
	proxywasm.LogInfof("timers: challenge=%ds clearance=%ds", ChallengeCookieMaxAge(), ClearanceCookieMaxAge())

	// Enable self-contained dynamic difficulty tracking (lower freq for less cpu)
	if err := proxywasm.SetTickPeriodMilliSeconds(5000); err != nil {
		proxywasm.LogWarnf("failed to set tick period for dynamic difficulty: %v", err)
	} else {
		proxywasm.LogInfo("dynamic difficulty tracking enabled (tick every 5000ms)")
	}

	return types.OnPluginStartStatusOK
}

// httpHeaders implements types.HttpContext.
type httpHeaders struct {
	// Embed the default http context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultHttpContext
	contextID   uint32
	headerName  string
	headerValue string

	// plugin holds reference to static config (base/min/max difficulty)
	plugin *pluginContext

	// issueClearance is set when a fresh PoW solution was accepted; OnHttpResponseHeaders
	// mints the longer-lived clearance cookie and drops one-shot challenge cookies.
	issueClearance bool
	client         ClientContext
	secureCookie   bool
}

// OnHttpRequestHeaders implements types.HttpContext.
func (ctx *httpHeaders) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	client := resolveClientContext()
	ctx.client = client
	ctx.secureCookie = requestIsHTTPS()

	secret := ctx.plugin.secret

	cookieHeader, _ := proxywasm.GetHttpRequestHeader("cookie")

	// 1) Long-lived clearance (preferred after a successful solve) — IP-only bind
	if cl := getCookie(cookieHeader, "challenge-clearance"); cl != "" {
		if err := VerifyClearance(secret, cl, client.ClearanceBind()); err == nil {
			proxywasm.LogDebugf("challenge: verified clearance (ctx=%s)", client.ClearanceBind())
			return types.ActionContinue
		} else {
			proxywasm.LogInfof("challenge: clearance verification failed: %v", err)
		}
	}

	// 2) One-shot PoW solution via cookies (valid only within ChallengeLifetime)
	//    Bound to IP + connection.id when available (same downstream connection).
	ckChallenge := getCookie(cookieHeader, "challenge")
	ckSignature := getCookie(cookieHeader, "challenge-sig")
	ckNonceStr := getCookie(cookieHeader, "challenge-nonce")

	if ckChallenge != "" && ckSignature != "" && ckNonceStr != "" {
		if nonce, parseErr := strconv.ParseUint(ckNonceStr, 10, 64); parseErr == nil {
			sol := Solution{
				SignedChallenge: SignedChallenge{Challenge: ckChallenge, Signature: ckSignature},
				Nonce:           nonce,
			}
			if verifyErr := VerifySolution(secret, sol, client); verifyErr == nil {
				proxywasm.LogDebugf("challenge: verified PoW solution from cookies (nonce=%d, ctx=%s)", sol.Nonce, client)
				// Promote to clearance on the way out; challenge cookies stay short-lived.
				ctx.issueClearance = true
				return types.ActionContinue
			} else {
				proxywasm.LogInfof("challenge: cookie solution verification failed: %v", verifyErr)
			}
		} else {
			proxywasm.LogInfof("challenge: invalid nonce cookie: %v", parseErr)
		}
	}

	// 3) Fallback: challenge-token header JSON (API / non-browser clients)
	token, err := proxywasm.GetHttpRequestHeader("challenge-token")
	if err == nil && token != "" {
		var sol Solution
		if jsonErr := json.Unmarshal([]byte(token), &sol); jsonErr == nil {
			if verifyErr := VerifySolution(secret, sol, client); verifyErr == nil {
				proxywasm.LogDebugf("challenge: verified PoW solution from token (nonce=%d, ctx=%s)", sol.Nonce, client)
				ctx.issueClearance = true
				return types.ActionContinue
			} else {
				proxywasm.LogInfof("challenge: token verification failed: %v", verifyErr)
			}
		} else {
			proxywasm.LogInfof("challenge: invalid token json: %v", jsonErr)
		}
	}

	// No valid proof → issue a fresh signed challenge
	overrideHeader, _ := proxywasm.GetHttpRequestHeader("x-challenge-difficulty")
	difficulty, source := ctx.plugin.getEffectiveDifficulty(overrideHeader)

	challenge, err := GenerateChallenge(secret, difficulty, client)
	if err != nil {
		proxywasm.LogErrorf("failed to generate challenge: %v", err)
		// Fail open to not break traffic if crypto/RNG fails
		return types.ActionContinue
	}

	ctx.plugin.recordChallengeIssued()
	proxywasm.LogDebugf("challenge: issuing challenge (diff=%d, source=%s, ctx=%s)", difficulty, source, client)

	maxAge := ChallengeCookieMaxAge()
	respHeaders := [][2]string{
		{"content-type", "text/html; charset=utf-8"},
		{"Set-Cookie", setCookie("challenge", challenge.Challenge, maxAge, false, ctx.secureCookie)},
		{"Set-Cookie", setCookie("challenge-sig", challenge.Signature, maxAge, false, ctx.secureCookie)},
		// Clear any stale nonce / clearance when issuing a fresh challenge
		{"Set-Cookie", clearCookie("challenge-nonce", ctx.secureCookie)},
		{"Set-Cookie", clearCookie("challenge-clearance", ctx.secureCookie)},
		// Also expose signature via header (useful for non-cookie clients)
		{"challenge-sig", challenge.Signature},
	}

	proxywasm.SendHttpResponse(403, respHeaders, []byte(content), 0)
	return types.ActionPause
}

// OnHttpResponseHeaders implements types.HttpContext.
func (ctx *httpHeaders) OnHttpResponseHeaders(_ int, _ bool) types.Action {
	// After a successful one-shot PoW, mint clearance and drop challenge cookies so the
	// raw solution is not relied on for the full access window (reduces replay surface).
	if ctx.issueClearance {
		// Clearance is IP-only so later requests on new connections still pass.
		if token, err := GenerateClearance(ctx.plugin.secret, ctx.client.ClearanceBind()); err != nil {
			proxywasm.LogErrorf("failed to generate clearance: %v", err)
		} else {
			_ = proxywasm.AddHttpResponseHeader("Set-Cookie",
				setCookie("challenge-clearance", token, ClearanceCookieMaxAge(), true, ctx.secureCookie))
			// Drop short-lived solve cookies; clearance is the access credential now.
			_ = proxywasm.AddHttpResponseHeader("Set-Cookie", clearCookie("challenge", ctx.secureCookie))
			_ = proxywasm.AddHttpResponseHeader("Set-Cookie", clearCookie("challenge-sig", ctx.secureCookie))
			_ = proxywasm.AddHttpResponseHeader("Set-Cookie", clearCookie("challenge-nonce", ctx.secureCookie))
			proxywasm.LogDebugf("challenge: issued clearance (ctx=%s, max-age=%d)", ctx.client.ClearanceBind(), ClearanceCookieMaxAge())
		}
	}

	// Optional: inject configured response header from plugin config
	if ctx.headerName != "" {
		if err := proxywasm.AddHttpResponseHeader(ctx.headerName, ctx.headerValue); err != nil {
			proxywasm.LogCriticalf("failed to set response header: %v", err)
		}
	}
	return types.ActionContinue
}

// OnHttpStreamDone implements types.HttpContext.
func (ctx *httpHeaders) OnHttpStreamDone() {
	// no-op to reduce logging overhead
}

// =============================================================================
// Client identity (IP + connection.id binding)
// =============================================================================

// resolveClientContext builds the binding identity for challenge / clearance tokens.
func resolveClientContext() ClientContext {
	return ClientContext{
		IP:     resolveClientIP(),
		ConnID: resolveConnectionID(),
	}
}

// resolveClientIP picks the best available client address for context binding.
// Priority:
//  1. Envoy downstream source.address (TCP peer — best when filter is at the edge)
//  2. Left-most X-Forwarded-For hop (original client when trusted proxies append)
//  3. X-Real-IP
//
// Returns "" when unknown (challenge is issued without IP binding rather than
// forging 127.0.0.1 for every client).
func resolveClientIP() string {
	// 1) Direct connection peer from Envoy
	if raw, err := proxywasm.GetProperty([]string{"source", "address"}); err == nil {
		if ip := normalizeIP(string(raw)); ip != "" {
			return ip
		}
	}

	// 2) X-Forwarded-For: left-most is typically the original client when each hop appends.
	//    Operators must strip/overwrite untrusted XFF at the edge for this to be safe.
	if xff, err := proxywasm.GetHttpRequestHeader("x-forwarded-for"); err == nil && xff != "" {
		if ip := firstForwardedIP(xff); ip != "" {
			return ip
		}
	}

	// 3) Common single-hop header
	if rip, err := proxywasm.GetHttpRequestHeader("x-real-ip"); err == nil && rip != "" {
		if ip := normalizeIP(rip); ip != "" {
			return ip
		}
	}

	return ""
}

// resolveConnectionID returns Envoy's downstream connection.id as a decimal string.
// The Wasm ABI exposes uint attributes as little-endian 8-byte buffers.
// Empty when unavailable.
func resolveConnectionID() string {
	raw, err := proxywasm.GetProperty([]string{"connection", "id"})
	if err != nil || len(raw) == 0 {
		return ""
	}
	if len(raw) >= 8 {
		return strconv.FormatUint(binary.LittleEndian.Uint64(raw[:8]), 10)
	}
	// Some hosts may return a textual form.
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "0" {
		return ""
	}
	return s
}

// firstForwardedIP returns the left-most usable address from an XFF header value.
func firstForwardedIP(xff string) string {
	for _, part := range strings.Split(xff, ",") {
		if ip := normalizeIP(part); ip != "" {
			return ip
		}
	}
	return ""
}

// normalizeIP trims space, strips :port / [ipv6]:port, and validates the result.
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// host:port or [ipv6]:port
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	} else {
		// bare [ipv6]
		s = strings.TrimPrefix(s, "[")
		s = strings.TrimSuffix(s, "]")
	}

	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Reject obviously non-IP tokens; keep the string form Envoy gave us when ParseIP works.
	if parsed := net.ParseIP(s); parsed != nil {
		return parsed.String()
	}
	return ""
}

func requestIsHTTPS() bool {
	if scheme, err := proxywasm.GetHttpRequestHeader(":scheme"); err == nil {
		return strings.EqualFold(scheme, "https")
	}
	if raw, err := proxywasm.GetProperty([]string{"request", "scheme"}); err == nil {
		return strings.EqualFold(string(raw), "https")
	}
	return false
}

// =============================================================================
// Cookie helpers
// =============================================================================

func setCookie(name, value string, maxAge int, httpOnly, secure bool) string {
	// concat faster than fmt, fewer allocs
	b := name + "=" + value + "; Path=/; Max-Age=" + strconv.Itoa(maxAge) + "; SameSite=Lax"
	if httpOnly {
		b += "; HttpOnly"
	}
	if secure {
		b += "; Secure"
	}
	return b
}

func clearCookie(name string, secure bool) string {
	// Max-Age=0 deletes; keep Path/SameSite/Secure consistent so browsers drop the right cookie.
	b := name + "=; Path=/; Max-Age=0; SameSite=Lax"
	if secure {
		b += "; Secure"
	}
	// HttpOnly clearance must be cleared with HttpOnly as well for some browsers
	if name == "challenge-clearance" {
		b += "; HttpOnly"
	}
	return b
}

// getCookie parses a Cookie header value and returns the value for the given name.
// Index based to avoid split allocs.
func getCookie(cookieHeader, name string) string {
	if cookieHeader == "" {
		return ""
	}
	prefix := name + "="
	// handle possible start without leading ;
	if strings.HasPrefix(cookieHeader, prefix) {
		rest := cookieHeader[len(prefix):]
		if idx := strings.IndexByte(rest, ';'); idx >= 0 {
			return strings.TrimSpace(rest[:idx])
		}
		return strings.TrimSpace(rest)
	}
	search := "; " + prefix
	if idx := strings.Index(cookieHeader, search); idx != -1 {
		start := idx + len(search)
		if end := strings.IndexByte(cookieHeader[start:], ';'); end != -1 {
			return strings.TrimSpace(cookieHeader[start : start+end])
		}
		return strings.TrimSpace(cookieHeader[start:])
	}
	// fallback tolerant for single space or no space after ;
	search2 := ";" + prefix
	if idx := strings.Index(cookieHeader, search2); idx != -1 {
		start := idx + len(search2)
		if end := strings.IndexByte(cookieHeader[start:], ';'); end != -1 {
			return strings.TrimSpace(cookieHeader[start : start+end])
		}
		return strings.TrimSpace(cookieHeader[start:])
	}
	return ""
}

// =============================================================================
// Dynamic Difficulty System (based on traffic pressure)
// Optimized: local counters to avoid per-request shared data costs (CPU+mem).
// =============================================================================

const (
	sharedKeyCurrentDifficulty = "challenge:current_difficulty"
)

// difficultySource describes where the difficulty value came from (for logging).
type difficultySource string

const (
	diffSourceConfig  difficultySource = "config"
	diffSourceHeader  difficultySource = "header"
	diffSourceDynamic difficultySource = "dynamic"
)

// getEffectiveDifficulty resolves the difficulty to use for a new challenge.
// Priority: per-request header override > current dynamic value (local preferred) > base config.
// It always respects min/max bounds. Uses local cache to reduce GetSharedData calls.
func (p *pluginContext) getEffectiveDifficulty(headerOverride string) (uint, difficultySource) {
	minD := p.minDifficulty
	maxD := p.maxDifficulty
	base := p.baseDifficulty

	// 1. Per-request header override (highest priority)
	if headerOverride != "" {
		if v, err := strconv.ParseUint(headerOverride, 10, 32); err == nil && v > 0 {
			d := clampDifficulty(uint(v), minD, maxD)
			return d, diffSourceHeader
		}
	}

	// 2. Dynamic from local (updated by OnTick, zero host call in req path)
	if p.currentDiff > 0 {
		d := clampDifficulty(p.currentDiff, minD, maxD)
		return d, diffSourceDynamic
	}

	// 3. Fallback: read shared (e.g. after restart or multi vm)
	if data, _, err := proxywasm.GetSharedData(sharedKeyCurrentDifficulty); err == nil && len(data) > 0 {
		if v, err := strconv.ParseUint(string(data), 10, 32); err == nil && v > 0 {
			d := clampDifficulty(uint(v), minD, maxD)
			p.currentDiff = d // cache
			return d, diffSourceDynamic
		}
	}

	// 4. Static base from config
	return clampDifficulty(base, minD, maxD), diffSourceConfig
}

// clampDifficulty ensures d is within [min, max].
func clampDifficulty(d, minD, maxD uint) uint {
	if d < minD {
		return minD
	}
	if d > maxD {
		return maxD
	}
	return d
}

// recordChallengeIssued increments local counter only (cheap, no host allocs/locks per request).
// Pressure is observed in OnTick which publishes approx difficulty.
func (p *pluginContext) recordChallengeIssued() {
	p.challengeCounter++
}

// OnTick is called periodically. It computes a new "current difficulty"
// based on recent challenge issuance rate (simple pressure heuristic). Low freq.
func (p *pluginContext) OnTick() {
	recent := p.challengeCounter
	p.challengeCounter = 0

	// Simple pressure → difficulty mapping.
	// These numbers are starting heuristics; tune in production.
	newDiff := p.baseDifficulty

	switch {
	case recent >= 800:
		newDiff = p.baseDifficulty + 6
	case recent >= 400:
		newDiff = p.baseDifficulty + 4
	case recent >= 180:
		newDiff = p.baseDifficulty + 3
	case recent >= 80:
		newDiff = p.baseDifficulty + 2
	case recent >= 35:
		newDiff = p.baseDifficulty + 1
	}

	newDiff = clampDifficulty(newDiff, p.minDifficulty, p.maxDifficulty)
	p.currentDiff = newDiff

	// Publish (approx ok, cas=0)
	_ = proxywasm.SetSharedData(sharedKeyCurrentDifficulty, []byte(strconv.FormatUint(uint64(newDiff), 10)), 0)

	// Light observability
	if recent > 0 {
		proxywasm.LogDebugf("dynamic difficulty tick: recent_challenges=%d → diff=%d (base=%d)", recent, newDiff, p.baseDifficulty)
	}
}
