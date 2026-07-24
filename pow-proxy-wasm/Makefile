# challenge-proxy-wasm Makefile
# Build WASM, OCI image, and publish

WASM := build/main.wasm
IMAGE ?= ghcr.io/chifu/challenge-proxy-wasm:latest
DOCKER ?= docker

.PHONY: all build clean oci-build oci oci-tar publish help

all: build

## Build the WASM plugin (wasip1 target, stripped)
build:
	mkdir -p build
	GOOS=wasip1 GOARCH=wasm go build -ldflags="-s -w" -trimpath -o $(WASM) .
	@echo "Built $(WASM) ($$(wc -c < $(WASM)) bytes)"

## Remove build artifacts
clean:
	rm -rf build/

## Build OCI image (requires Docker/BuildKit). Depends on WASM.
oci-build: build
	$(DOCKER) build -t $(IMAGE) -f Dockerfile .

## Build and export as image tarball (portable, loadable with docker load; compatible with OCI tooling)
oci-tar: build
	$(DOCKER) build -t $(IMAGE) -f Dockerfile .
	$(DOCKER) save -o build/challenge-proxy-wasm.tar $(IMAGE)
	@echo "Image tarball: build/challenge-proxy-wasm.tar (use: docker load -i build/challenge-proxy-wasm.tar)"

## Alias for oci-tar (builds as OCI-compatible file)
oci: oci-tar

## Publish image to registry (requires login: docker login ghcr.io ...)
publish: oci-build
	$(DOCKER) push $(IMAGE)
	@echo "Published $(IMAGE)"

## Show help
help:
	@echo "Targets:"
	@echo "  make build      - compile WASM to build/main.wasm"
	@echo "  make oci        - build + export build/challenge-proxy-wasm.tar (image tarball, docker load compatible)"
	@echo "  make oci-build  - build local docker image $(IMAGE)"
	@echo "  make publish    - build and docker push $(IMAGE)"
	@echo "  make clean"
	@echo ""
	@echo "Override image: make IMAGE=myreg/foo:tag publish"
