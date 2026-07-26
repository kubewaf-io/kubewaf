#!/usr/bin/env python3
"""Patch modsecurity-proxy-wasm.wat: replace env.getaddrinfo import with an in-module stub."""
import re
import sys


def remap_func_index(n: int) -> int:
    if n == 7:
        return 20
    if 8 <= n <= 20:
        return n - 1
    return n


def patch_line(line: str) -> str:
    def repl_call(m):
        return f"call {remap_func_index(int(m.group(1)))}"

    line = re.sub(r"\bcall (\d+)\b", repl_call, line)

    def repl_export_func(m):
        idx = remap_func_index(int(m.group(2)))
        return f'(export "{m.group(1)}" (func {idx}))'

    line = re.sub(
        r'\(export "([^"]+)" \(func (\d+)\)\)',
        repl_export_func,
        line,
    )
    return line


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else "/tmp/modsecurity-proxy-wasm.wat"
    dst = sys.argv[2] if len(sys.argv) > 2 else "/tmp/modsecurity-proxy-wasm-fixed.wat"

    with open(src) as f:
        lines = f.readlines()

    out = []
    inserted_stub = False
    for line in lines:
        if 'import "env" "getaddrinfo"' in line:
            continue
        if (
            not inserted_stub
            and line.strip().startswith("(func ")
            and "import" not in line
        ):
            out.append("  (func (;7;) (type 6)\n")
            out.append("    i32.const -1)\n")
            inserted_stub = True
        out.append(patch_line(line))

    with open(dst, "w") as f:
        f.writelines(out)
    print(f"Wrote {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())