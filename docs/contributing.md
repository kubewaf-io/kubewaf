# Contributing to kubeWAF

Thank you for your interest in improving kubeWAF!

## Ways to Contribute

- Report bugs and feature requests via [GitHub Issues](https://github.com/kubewaf-io/kubewaf/issues)
- Improve documentation (this site!)
- Add more CRS conversions or example rules
- Implement missing controller logic (especially `WAFInstance`)
- Write tests (unit + e2e)
- Review pull requests

## Development Environment

### Prerequisites

- Go 1.26+
- `make`, `docker`
- `kubectl` + a local cluster (kind, minikube, or k3d recommended)
- `helm`

### Setup

```bash
git clone https://github.com/kubewaf-io/kubewaf.git
cd kubewaf

make manifests generate fmt vet
make install          # installs CRDs into your cluster
make run              # runs the operator locally against your kubeconfig
```

### Useful Make Targets

| Target           | Description |
|------------------|-------------|
| `make test`      | Run unit tests |
| `make test-e2e`  | Run end-to-end tests (requires a real cluster) |
| `make lint-fix`  | Auto-fix lint issues |
| `make crs-converter` | Build the CRS conversion tool |
| `make docker-build` | Build the operator image |

## Documentation Contributions

The documentation site is built with **MkDocs + Material**.

To preview locally:

```bash
# Install once
pip install mkdocs mkdocs-material

# Serve
mkdocs serve
```

Then open http://localhost:8000.

When adding new pages, update `mkdocs.yml` navigation.

### Style Guidelines

- Keep examples copy-pasteable
- Prefer "real" YAML over abstract snippets
- Use admonitions (`!!! note`, `!!! warning`) for important caveats
- Link liberally to other pages

## Submitting Changes

1. Create a topic branch from `main`
2. Make focused commits with clear messages
3. Run `make lint-fix test` before pushing
4. Open a Pull Request

We use conventional commit style where possible (`feat:`, `fix:`, `docs:`, `chore:`).

## Code of Conduct

We follow the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License that covers the project.

## Recognition

All contributors are listed in Git history. Significant contributions may also be highlighted in release notes.

Thank you for helping make Kubernetes applications safer!