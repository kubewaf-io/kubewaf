# kubeWAF documentation site

Built with [Fumadocs](https://fumadocs.dev) (Next.js App Router + MDX).

## Develop

```bash
# from repo root
make docs-serve

# or
cd website
npm install
npm run dev
```

- Home: http://localhost:3000  
- **kubeWAF docs (default):** http://localhost:3000/docs/kubewaf  
- modsecurity-proxy-wasm: http://localhost:3000/docs/modsecurity-proxy-wasm  
- pow-proxy-wasm: http://localhost:3000/docs/pow-proxy-wasm  
- `/docs` redirects to `/docs/kubewaf`

## Three documentation roots

| Root | Content path | URL |
|------|----------------|-----|
| **kubeWAF** | `content/docs/kubewaf/` | `/docs/kubewaf` |
| **modsecurity-proxy-wasm** | `content/docs/modsecurity-proxy-wasm/` | `/docs/modsecurity-proxy-wasm` |
| **pow-proxy-wasm** | `content/docs/pow-proxy-wasm/` | `/docs/pow-proxy-wasm` |

Each folder has `meta.json` with `"root": true` so Fumadocs shows a product tab and a separate sidebar tree.

## Content layout

| Path | Purpose |
|------|---------|
| `content/docs/kubewaf/**` | Operator docs (default) |
| `content/docs/kubewaf/operator/` | Guides: rules, CRS, challenge CR, providers |
| `content/docs/modsecurity-proxy-wasm/**` | Engine project docs |
| `content/docs/pow-proxy-wasm/**` | PoW filter project docs |
| `public/` | Static assets |
| `components/mermaid.tsx` | Mermaid diagrams (fumadocs-mermaid, same as Gryt docs) |
| `app/(home)/` | Marketing landing |
| `app/docs/` | Docs layout + pages |

## Build (static export)

```bash
make docs-build
# → website/out/  and  ./site/  (Netlify publish dir)
```

## Branding

- App name / GitHub: `lib/shared.ts`
- Nav layout: `lib/layout.shared.tsx`
- Theme accents: `app/global.css`
