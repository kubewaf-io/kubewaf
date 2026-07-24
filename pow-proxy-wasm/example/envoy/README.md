# Basic Envoy Example (Verification) - Signed Proof Mode

Uses the signed proof design (no POST/verify endpoint required).

## How it works

1. Browser visits → WASM returns 403 + self-contained minimal HTML/JS page with a **signed challenge** (HMAC over challenge).
2. JS solves PoW locally (pure sync SHA-256, aggressive + fast, supports system dark/light).
3. On solve: sets `challenge-nonce` cookie + reload.
4. WASM validates cookies (or `challenge-token` header JSON):
   - HMAC signature
   - PoW (nonce + difficulty from payload)
   - Expiry (~60s)
   - Optional context (IP)
5. Valid → request continues to backend. Cookie allows subsequent requests to pass for 5min.

Fully stateless, minimal overhead.

## Quick Test

```bash
make build
cd example/envoy
docker compose down -v
docker compose up
```

Open http://localhost:8080 in a browser.

- First visit: auto-solving verification page (lightweight, follows system theme).
- After solve+reload: reaches httpbin backend.
- Later visits: direct pass (valid cookie).

## Inspect

DevTools → Application → Cookies → localhost:8080 → look for `challenge`, `challenge-sig`, `challenge-nonce`.

## Notes

- Dynamic difficulty (pressure-based) + static config:
  - `base_difficulty`, `min_difficulty`, `max_difficulty` in plugin JSON config
  - Override per-request: `x-challenge-difficulty` header
  - Low-overhead local counters (no per-req shared data writes)
- See main.go + crypt.go for implementation and pressure heuristics (tunable).
- To configure secret + difficulty, edit envoy.yaml (add configuration block under wasm) or use --config-yaml etc.
- Example plugin config (add under the wasm filter "configuration"):

```json
{
  "secret": "replace-with-strong-secret-for-hmac",
  "base_difficulty": 18,
  "min_difficulty": 12,
  "max_difficulty": 26
}
```

- The waiting page is branding-free, very small, uses only system fonts + CSS media for dark/light.
