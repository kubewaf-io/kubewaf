#!/usr/bin/env python3
"""Generate stock CRS PhraseList CRs from internal/coraza/crsdata/*.data.

Usage (from repo root):
  python3 hack/scripts/generate-crs-phraselists.py
  # or: make crs-phraselists

Writes:
  config/samples/crs/phraselists/crs-data-phraselists.yaml
  charts/kubewaf-crs/files/phraselists/crs-data-phraselists.yaml

Stock CRS has no @ipMatchFromFile data pack — only PhraseLists.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "internal" / "coraza" / "crsdata"
OUT_SAMPLES = REPO / "config" / "samples" / "crs" / "phraselists"
OUT_CHART = REPO / "charts" / "kubewaf-crs" / "files" / "phraselists"
VERSION = "4.27.0"


def k8s_name(basename: str) -> str:
    stem = basename[: -len(".data")] if basename.endswith(".data") else basename
    name = "crs-" + re.sub(r"[^a-z0-9-]", "-", stem.lower())
    name = re.sub(r"-+", "-", name).strip("-")
    return name[:63].rstrip("-")


def main() -> int:
    if not SRC.is_dir():
        print(f"ERROR: missing {SRC}", file=sys.stderr)
        return 1

    paths = sorted(SRC.glob("*.data"))
    if not paths:
        print(f"ERROR: no .data files in {SRC}", file=sys.stderr)
        return 1

    names: list[tuple[str, str]] = []
    docs: list[str] = []
    for path in paths:
        basename = path.name
        name = k8s_name(basename)
        names.append((name, basename))
        content = path.read_text(encoding="utf-8", errors="replace")
        indented = "\n".join(("    " + line) if line else "" for line in content.splitlines())
        docs.append(
            f"""---
apiVersion: seclang.kubewaf.io/v1beta1
kind: PhraseList
metadata:
  name: {name}
  labels:
    app.kubernetes.io/part-of: coreruleset
    app.kubernetes.io/name: kubewaf-crs
    app.kubernetes.io/component: phrase-list
    coreruleset/version: "{VERSION}"
    seclang.kubewaf.io/phrase-list: "true"
    seclang.kubewaf.io/crs-data: "true"
  annotations:
    seclang.kubewaf.io/crs-data-file: {basename}
spec:
  fileName: {basename}
  content: |
{indented}
"""
        )

    header = (
        f"# Generated CRS PhraseLists (stock @pmFromFile data files).\n"
        f"# Source: internal/coraza/crsdata/*.data (CRS {VERSION} pack).\n"
        f"# Do not edit by hand — regenerate with: make crs-phraselists\n"
        f"#\n"
        f"# Path B ModSecurity injects via basename discovery from SecRule\n"
        f"# @pmFromFile values (no RuleSet phraseListRefs required for CRS).\n"
        f"# Stock CRS has no IPList pack (@ipMatchFromFile).\n"
        f"#\n"
        f"# Names:\n"
        + "\n".join(f"#   - {n}  ({b})" for n, b in names)
        + "\n"
    )
    body = header + "\n".join(docs)

    OUT_SAMPLES.mkdir(parents=True, exist_ok=True)
    OUT_CHART.mkdir(parents=True, exist_ok=True)
    sample_path = OUT_SAMPLES / "crs-data-phraselists.yaml"
    chart_path = OUT_CHART / "crs-data-phraselists.yaml"
    sample_path.write_text(body, encoding="utf-8")
    chart_path.write_text(body, encoding="utf-8")
    print(f"Wrote {sample_path.relative_to(REPO)} ({len(names)} PhraseLists)")
    print(f"Wrote {chart_path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
