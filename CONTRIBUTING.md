# Contributing

**Canonical contributing guide:**  
[https://kubewaf.io/docs/contribute/contributing/](https://kubewaf.io/docs/contribute/contributing/)

Source for that site: [kubewaf-io/website](https://github.com/kubewaf-io/website)  
(optional local checkout path often named `website2/` — **not** tracked in this monorepo).

## Engines

Wasm engines are **git submodules** under `engines/`:

```bash
git submodule update --init --recursive
# or: make engines-submodules
```

See [engines/README.md](engines/README.md).

## Related stubs

- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
