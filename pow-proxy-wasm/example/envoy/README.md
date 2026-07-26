# Basic Envoy Example (Verification) - Signed Proof Mode

Uses the signed proof design (no POST/verify endpoint required).

## How it works

1. Browser visits → WASM returns 403 + self-contained minimal HTML/JS page with a **signed challenge** (HMAC over challenge).
2. JS solves PoW locally (pure sync SHA-256, aggressive + fast, supports system dark/light).
3. On solve: sets `challenge-nonce` cookie + reload.
4. WASM validates cookies (or `challenge-token` header JSON):
   - HMAC signature
   - PoW (nonce + difficulty from payload)
   - Expiry (**60s**, aligned with challenge cookie Max-Age)
   - Context: client IP + Envoy `connection.id` (when known)
5. Page `fetch()`es the URL (prefer same connection) then reloads; WASM issues **`challenge-clearance`** (HttpOnly, 30 min, **IP-only**) and clears one-shot challenge cookies.
6. Later requests: clearance cookie only (no PoW replay; not bound to connection.id).

Fully stateless (shared HMAC secret across replicas), minimal overhead.

## Quick Test

```bash
make build
cd example/envoy
docker compose down -v
docker compose up
```

Open http://localhost:8080 in a browser.

- First visit: auto-solving verification page (lightweight, follows system theme).
- After solve+reload: reaches httpbin backend; DevTools shows `challenge-clearance`.
- Later visits: direct pass until clearance expires (~30 min).

## Inspect

DevTools → Application → Cookies → localhost:8080:

| Cookie | Lifetime | Purpose |
|--------|----------|---------|
| `challenge`, `challenge-sig`, `challenge-nonce` | 60s | One-shot PoW solve window |
| `challenge-clearance` | 30 min | Access after successful solve (HttpOnly) |

## Plugin configuration

`envoy.yaml` includes a required `configuration` block. The plugin **refuses to start** without a `secret` of at least 32 bytes.

```json
{
  "secret": "replace-with-strong-secret-for-hmac-32+",
  "header": "x-wasm-header",
  "value": "demo-wasm",
  "base_difficulty": 18,
  "min_difficulty": 12,
  "max_difficulty": 26
}
```

- `secret` — **required**, ≥ 32 bytes, same on every replica
- `header` / `value` — optional response header injection
- Difficulty: static bounds + dynamic pressure + per-request `x-challenge-difficulty` override

## Notes

- Client IP binding prefers Envoy `source.address`, then left-most `X-Forwarded-For`, then `X-Real-IP`.
- Edge proxies must strip/overwrite untrusted XFF (see `use_remote_address` in the example).
- The waiting page is branding-free, very small, uses only system fonts + CSS media for dark/light.
