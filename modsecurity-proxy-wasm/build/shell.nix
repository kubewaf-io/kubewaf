{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  name = "modsecurity-proxy-wasm";

  buildInputs = with pkgs; [
    # ModSecurity + dependencies
    modsecurity_standalone
    pkg-config
    gcc
    git
    autoconf
    automake
    libtool
    libxml2.dev
    curl.dev
    yajl
    pcre2.dev
    lmdb.dev

    # Proxy-Wasm C++ SDK + build tools
    cmake
    ninja
    clang
    protobuf
    # (optional but very useful)
    wasmtime
    wasm-pack
  ];

  # Keep in sync with PROXY_WASM_CPP_SDK_VERSION in Makefile (Renovate-managed).
  PROXY_WASM_CPP_SDK = pkgs.fetchFromGitHub {
    owner = "proxy-wasm";
    repo = "proxy-wasm-cpp-sdk";
    # renovate: datasource=github-tags depName=proxy-wasm/proxy-wasm-cpp-sdk versioning=git
    rev = "727de65b37507611b76123316c6832581f42d4f0";
    sha256 = "sha256-qAJ/krWyhAy6C53k8WXhlwQS4LDqmzra5ecmGzumzvg=";
  };

  shellHook = ''
    echo "🔥 ModSecurity + Proxy-Wasm C++ dev environment loaded!"

    # ModSecurity headers
    echo "ModSecurity headers → $(pkg-config --variable=includedir modsecurity)"

    # Proxy-Wasm SDK
    export PROXY_WASM_CPP_SDK_DIR="$PROXY_WASM_CPP_SDK"
    export CPATH="$PROXY_WASM_CPP_SDK/include:$CPATH"
    echo "Proxy-Wasm CPP SDK   → $PROXY_WASM_CPP_SDK_DIR"

    echo ""
    echo "✅ You can now compile with:"
    echo "   #include <proxy-wasm/proxy_wasm.h>"
    echo "   #include <modsecurity/modsecurity.h>"
    echo ""
    echo "Ready to build your modsecurity-proxy-wasm! 🚀"
  '';
}
