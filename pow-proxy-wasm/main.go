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
	"encoding/json"
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
	// plugin configuration during OnPluginStart.
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

// difficultyConfig holds the parsed difficulty settings from plugin config.
type difficultyConfig struct {
	Base uint `json:"base_difficulty"`
	Min  uint `json:"min_difficulty"`
	Max  uint `json:"max_difficulty"`
}

// NewHttpContext implements types.PluginContext.
func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpHeaders{
		contextID:      contextID,
		headerName:     p.headerName,
		headerValue:    p.headerValue,
		plugin:         p,
	}
}

// OnPluginStart implements types.PluginContext.
func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	proxywasm.LogDebug("loading plugin config")
	data, err := proxywasm.GetPluginConfiguration()
	if data == nil {
		// defaults
		if len(p.secret) == 0 {
			p.secret = []byte("change-this-secret-in-production-32bytes!!")
		}
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
		return types.OnPluginStartStatusOK
	}

	if err != nil {
		proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	if !gjson.ValidBytes(data) {
		proxywasm.LogCritical(`invalid configuration format; expected {"header": "<header name>", "value": "<header value>"}`)
		return types.OnPluginStartStatusFailed
	}

	p.headerName = strings.TrimSpace(gjson.GetBytes(data, "header").Str)
	p.headerValue = strings.TrimSpace(gjson.GetBytes(data, "value").Str)

	secretStr := strings.TrimSpace(gjson.GetBytes(data, "secret").Str)
	if secretStr != "" {
		p.secret = []byte(secretStr)
	} else if len(p.secret) == 0 {
		p.secret = []byte("change-this-secret-in-production-32bytes!!")
	}

	// Parse difficulty configuration with sensible defaults
	diffCfg := difficultyConfig{
		Base: uint(gjson.GetBytes(data, "base_difficulty").Uint()),
		Min:  uint(gjson.GetBytes(data, "min_difficulty").Uint()),
		Max:  uint(gjson.GetBytes(data, "max_difficulty").Uint()),
	}
	p.baseDifficulty = diffCfg.Base
	p.minDifficulty = diffCfg.Min
	p.maxDifficulty = diffCfg.Max

	// Apply defaults if not provided or invalid
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

	if p.headerName == "" || p.headerValue == "" {
		proxywasm.LogCritical(`invalid configuration format; expected {"header": "<header name>", "value": "<header value>"}`)
		return types.OnPluginStartStatusFailed
	}

	proxywasm.LogInfof("header from config: %s = %s", p.headerName, p.headerValue)
	proxywasm.LogInfof("difficulty config: base=%d min=%d max=%d", p.baseDifficulty, p.minDifficulty, p.maxDifficulty)
	proxywasm.LogInfof("secret configured: len=%d", len(p.secret))

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
}

// OnHttpRequestHeaders implements types.HttpContext.
func (ctx *httpHeaders) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Extract client IP for context binding (prefer X-Forwarded-For)
	xIP, err := proxywasm.GetHttpRequestHeader("x-forwarded-for")
	if err != nil || xIP == "" {
		xIP = "127.0.0.1"
	}

	secret := ctx.plugin.secret
	if len(secret) == 0 {
		secret = []byte("change-this-secret-in-production-32bytes!!")
	}

	// Prefer reading challenge, signature and nonce from cookies (set by client JS)
	cookieHeader, _ := proxywasm.GetHttpRequestHeader("cookie")
	ckChallenge := getCookie(cookieHeader, "challenge")
	ckSignature := getCookie(cookieHeader, "challenge-sig")
	ckNonceStr := getCookie(cookieHeader, "challenge-nonce")

	if ckChallenge != "" && ckSignature != "" && ckNonceStr != "" {
		if nonce, parseErr := strconv.ParseUint(ckNonceStr, 10, 64); parseErr == nil {
			sol := Solution{
				SignedChallenge: SignedChallenge{Challenge: ckChallenge, Signature: ckSignature},
				Nonce:           nonce,
			}
			if verifyErr := VerifySolution(secret, sol, xIP); verifyErr == nil {
				proxywasm.LogDebugf("challenge: verified solution from cookies (nonce=%d, ctx=%s)", sol.Nonce, xIP)
				return types.ActionContinue
			} else {
				proxywasm.LogInfof("challenge: cookie solution verification failed: %v", verifyErr)
			}
		} else {
			proxywasm.LogInfof("challenge: invalid nonce cookie: %v", parseErr)
		}
	}

	// Fallback: Check for solution token sent by the client verifier (challenge-token header)
	token, err := proxywasm.GetHttpRequestHeader("challenge-token")
	if err == nil && token != "" {
		var sol Solution
		if jsonErr := json.Unmarshal([]byte(token), &sol); jsonErr == nil {
			if verifyErr := VerifySolution(secret, sol, xIP); verifyErr == nil {
				proxywasm.LogDebugf("challenge: verified solution (nonce=%d, ctx=%s)", sol.Nonce, xIP)
				return types.ActionContinue
			} else {
				proxywasm.LogInfof("challenge: token verification failed: %v", verifyErr)
			}
		} else {
			proxywasm.LogInfof("challenge: invalid token json: %v", jsonErr)
		}
	}

	// No valid token present → issue a fresh signed challenge
	// Resolve difficulty with full priority: header > dynamic pressure > config base
	overrideHeader, _ := proxywasm.GetHttpRequestHeader("x-challenge-difficulty")
	difficulty, source := ctx.plugin.getEffectiveDifficulty(overrideHeader)

	challenge, err := GenerateChallenge(secret, difficulty, xIP)
	if err != nil {
		proxywasm.LogErrorf("failed to generate challenge: %v", err)
		// Fail open to not break traffic
		return types.ActionContinue
	}

	// Record pressure signal (local counter, cheap, no host call)
	ctx.plugin.recordChallengeIssued()

	proxywasm.LogDebugf("challenge: issuing challenge (diff=%d, source=%s, ctx=%s)", difficulty, source, xIP)

	respHeaders := [][2]string{
		{"content-type", "text/html; charset=utf-8"},
		{"Set-Cookie", setCookie("challenge", challenge.Challenge)},
		{"Set-Cookie", setCookie("challenge-sig", challenge.Signature)},
		// Clear any stale nonce cookie when issuing a fresh challenge
		{"Set-Cookie", "challenge-nonce=; Path=/; Max-Age=0; SameSite=Lax"},
		// Also expose signature via header (useful for non-cookie clients)
		{"challenge-sig", challenge.Signature},
	}

	proxywasm.SendHttpResponse(403, respHeaders, []byte(content), 0)
	return types.ActionPause
}

// OnHttpResponseHeaders implements types.HttpContext.
func (ctx *httpHeaders) OnHttpResponseHeaders(_ int, _ bool) types.Action {
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

// Tiny helper - zero extra dependencies, low alloc
func setCookie(name, value string) string {
	// concat faster than fmt, fewer allocs
	return name + "=" + value + "; Path=/; Max-Age=300; SameSite=Lax"
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

// (removed extractDifficultyFromSolution - was only for verbose logs; saves code size + allocs on verify path)
