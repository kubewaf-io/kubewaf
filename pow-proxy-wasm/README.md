# challenge-proxy-wasm

A lightweight, stateless browser challenge (Proof-of-Work) Proxy-WASM filter for Envoy / Istio / etc.

**Full documentation (kubeWAF docs site):** [pow-proxy-wasm](https://kubewaf.io/docs/pow-proxy-wasm) · source MDX: [`website/content/docs/pow-proxy-wasm/`](../website/content/docs/pow-proxy-wasm/)

**Language: Go** (using `proxy-wasm-go-sdk`, `GOOS=wasip1`). Builds to a small stripped WASM module.

## Features

- Configurable + **dynamic** PoW challenge (difficulty = leading zero bits in SHA-256)
  - Static config: `base_difficulty` / `min_difficulty` / `max_difficulty`
  - Per-request override via `x-challenge-difficulty` header
  - Self-contained adaptive difficulty based on traffic pressure (local counter + periodic tick, low overhead)
- Fully stateless using HMAC-SHA256 (configurable secret)
- Self-contained challenge page (single-file HTML/JS, no external deps)
- Cookie-based solution (no extra POST/roundtrip)
- Optional extra response header injection via config
- Designed to run after rate limiting, before WAFs / auth

## Code quality & efficiency

- Minimized allocations and host calls in hot paths (cookie parsing, difficulty tracking uses local counters, shared data only on tick)
- Stripped WASM builds (`-ldflags=-s -w -trimpath`)
- Challenge page is aggressively optimized: pure-JS sync SHA-256 (no per-hash async overhead), minimal DOM/CSS, system dark/light theme
- Logging reduced in success paths (debug level for common verify)

## Configuration (plugin config JSON)

```json
{
  "header": "x-wasm-header",
  "value": "demo",
  "secret": "your-32+-byte-or-longer-hmac-secret-here-please-change",
  "base_difficulty": 18,
  "min_difficulty": 12,
  "max_difficulty": 26
}
```

- `secret`: used for HMAC; **required**, ≥ 32 bytes, **must be the same across all replicas**. Plugin **fails to start** if missing or too short (no hardcoded default).
- `header` / `value`: optional response header injection.
- Difficulty bounds respected; dynamic pressure can bump up to +6 under load.

Headers / cookies used (no "kubewaf" branding):
- Solve cookies (60s, aligned with challenge expiry): `challenge`, `challenge-sig`, `challenge-nonce`
- Access cookie (30 min, HttpOnly): `challenge-clearance`
- Fallback token header: `challenge-token`
- Override: `x-challenge-difficulty`

## Build

Requires Go 1.23+.

```bash
make build
# or manually:
# GOOS=wasip1 GOARCH=wasm go build -ldflags="-s -w" -trimpath -o build/main.wasm .
```

Output: `build/main.wasm`

Other targets:
- `make oci` — build WASM + produce `build/challenge-proxy-wasm.tar` (image tarball)
- `make oci-build` — build local Docker image (default: ghcr.io/chifu/...)
- `make publish` — build image and `docker push` (set IMAGE=... first; requires registry login)

See `make help`.

## Quick Verification

```bash
make build
cd example/envoy
docker compose down -v && docker compose up
```

Open http://localhost:8080 (or curl it).

- First hit (no cookie): returns the self-contained waiting/verification page (PoW auto-solved by browser JS using system theme).
- After solve + reload: passes through to backend.
- Subsequent: cookie validated, direct pass (stateless).

Inspect cookies in DevTools for `challenge*`.

See [example/envoy/README.md](example/envoy/README.md) for more.

## How it works (Signed Proof)

1. Request without valid proof → WASM issues 403 + signed challenge (HMAC) + HTML/JS page.
2. Browser JS solves PoW (sync SHA-256 loop, very fast) using difficulty from challenge.
3. On solve: sets `challenge-nonce` cookie, reloads.
4. WASM sees valid cookies (or `challenge-token` JSON) → verifies HMAC + PoW + expiry + IP context → issues `challenge-clearance` (30 min) and clears one-shot solve cookies → `ActionContinue`.
5. Later requests use clearance only (PoW solution is not the long-lived credential).
6. Dynamic difficulty: pressure tracked locally per filter, published on tick (5s), read with low overhead.

## Timers

| Credential | Lifetime | Notes |
|------------|----------|--------|
| Challenge + solve cookies | **60s** | Must match; cookie Max-Age == `ChallengeLifetime` |
| Clearance cookie | **30 min** | Issued after successful solve; HttpOnly; IP-bound |

## Client binding (IP + connection.id)

| Token | Bound to | Why |
|-------|----------|-----|
| Challenge / PoW solve | **IP** + Envoy **`connection.id`** (when available) | Same downstream connection as issue time |
| Clearance | **IP only** | Survives reload / new connections after a successful solve |

IP resolution order: Envoy `source.address` → left-most `X-Forwarded-For` → `X-Real-IP`. If unknown, IP context is empty (no forged `127.0.0.1`). Strip untrusted XFF at the edge.

`connection.id` is Envoy’s downstream connection identifier (not the TLS protocol session id — that attribute is not exposed to Wasm). The challenge page uses `fetch()` before reload so the solve can complete on the original connection; clearance then carries only the IP.

## Dark / Light theme

The waiting page automatically follows `prefers-color-scheme` (system / browser setting). No JS theme toggle needed. Clean, minimal, no fonts or external resources.

## Security notes

- `secret` is mandatory (≥ 32 bytes); never ship a shared default.
- Challenge/solve window is short (60s); access continues via clearance (30 min).
- Clearance is still a bearer cookie (shareable). IP binding reduces cross-client reuse; true one-time nonces would need shared state.
- Context binding uses connection peer / trusted XFF — configure Envoy hop trust correctly.
- This is a layer-7 challenge; combine with rate-limit, WAF, mTLS etc.

## Status

Production-usable for many use-cases. Optimized for low memory/CPU in the proxy path and tiny client payload.

Contributions / tuning of pressure heuristics welcome.
