#!/usr/bin/env python3
"""Point proxy-wasm-cpp-sdk at modsecurity-proxy-wasm getentropy (wasi/api.h + clock_time_get)."""
from __future__ import annotations

import sys
from pathlib import Path

MARKER = "// Patch an Emscripten gap"
PATCHED = "// getentropy: src/wasm_getentropy.c"
REPLACEMENT = (
    "// getentropy: src/wasm_getentropy.c (Emscripten wasi/api.h + clock_time_get).\n"
    "extern \"C\" int getentropy(void *buffer, size_t len);\n"
)


def main() -> int:
    path = Path(sys.argv[1])
    text = path.read_text()
    if PATCHED in text:
        return 0
    if MARKER not in text:
        return 0
    start = text.index(MARKER)
    anchor = 'extern "C" int getentropy'
    fn_start = text.index(anchor, start)
    end = text.index("\n}", fn_start) + 2
    path.write_text(text[:start] + REPLACEMENT + text[end:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())