# Engines

Proxy-Wasm filters used by the kubeWAF operator live under this directory as
**git submodules**. The operator monorepo does not vendor engine source trees.

| Path | Upstream | Role |
|------|----------|------|
| [`modsecurity-proxy-wasm/`](modsecurity-proxy-wasm/) | [kubewaf-io/modsecurity-proxy-wasm](https://github.com/kubewaf-io/modsecurity-proxy-wasm) | Product WAF engine (SecLang; path-b injects `@pmFromFile` / `@ipMatchFromFile` bodies via plugin JSON `data_files`) |
| [`pow-proxy-wasm/`](pow-proxy-wasm/) | [kubewaf-io/pow-proxy-wasm](https://github.com/kubewaf-io/pow-proxy-wasm) | Optional PoW / challenge filter |

## Clone / update

```bash
# After cloning kubewaf
git submodule update --init --recursive

# Or via Make
make engines-submodules
```

Submodule pins are the gitlinks recorded in this monorepo (`git ls-tree HEAD engines/`).
Bump a pin after merging upstream:

```bash
cd engines/modsecurity-proxy-wasm && git fetch && git checkout <tag-or-sha>
cd ../..
git add engines/modsecurity-proxy-wasm
git commit -m "chore(engines): bump modsecurity-proxy-wasm"
```

## Build into operator image paths

Root Makefile targets:

| Target | Purpose |
|--------|---------|
| `make engines-submodules` | Init/update engine submodules |
| `make wasm-build` | Build **path-b** engines → `dist/wasm/` (default, CI) |
| `make wasm-build-full` | Build **full** catalog → `dist/wasm/*-full.wasm` (Path A, second-class) |
| `make wasm-fetch-modsecurity` | Pull pinned path-b GHCR image → `dist/wasm/` |
| `make wasm-fetch-modsecurity-full` | Pull pinned `*-full` GHCR image |
| `make wasm-stage-kodata` | Stage path-b wasm into `cmd/kodata/wasm/` for `ko` |

```bash
make wasm-build MODSECURITY_PROXY_WASM_DIR=engines/modsecurity-proxy-wasm
# Second-class Path A (embedded CRS rule confs; not used by default e2e)
make wasm-build-full
# Or in the engine tree:
make -C engines/modsecurity-proxy-wasm modsecurity-proxy-wasm.wasm CATALOG_MODE=full
make -C engines/modsecurity-proxy-wasm image-full
```

| Catalog | GHCR tags | CI / operator |
|---------|-----------|---------------|
| **path-b** (default) | `:VERSION`, `:VERSION-path-b` | All e2e, `ko` embed; CRS/`PhraseList`/`IPList` bodies via `data_files` |
| **full** (second-class) | `:VERSION-full` | Path A only; embeds `@crs-setup-conf` + `@owasp_crs` + `@crs-data` |

See `engines/modsecurity-proxy-wasm/README.md`.
