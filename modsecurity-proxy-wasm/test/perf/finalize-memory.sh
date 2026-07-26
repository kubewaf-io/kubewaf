#!/usr/bin/env bash
# Build memory-snapshot.json from envoy prometheus + optional docker stats samples.
set -euo pipefail

OUT_DIR="${1:?output dir}"
CONTAINER="${PERF_ENVOY_CONTAINER:-modsecurity-proxy-wasm-perf-envoy}"

if command -v docker >/dev/null 2>&1; then
  CTR="docker"
elif command -v podman >/dev/null 2>&1; then
  CTR="podman"
else
  CTR=""
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH="$SCRIPT_DIR" python3 - "$OUT_DIR" "$CONTAINER" "$CTR" <<'PY'
import json
import sys
from pathlib import Path

from memory import parse_modsecurity_memory, parse_prometheus_memory, peak_from_samples

out_dir = Path(sys.argv[1])
container = sys.argv[2]
ctr = sys.argv[3]

def load_envoy(label: str) -> dict:
    path = out_dir / f"memory-envoy-{label}.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return parse_prometheus_memory(out_dir / f"envoy-prometheus-{label}.txt")

peak = peak_from_samples(out_dir / "memory-samples.log")
container_after = None
if ctr:
    import subprocess

    try:
        proc = subprocess.run(
            [ctr, "stats", "--no-stream", "--format", "{{.MemUsage}}", container],
            capture_output=True,
            text=True,
            check=True,
        )
        from memory import parse_docker_mem_usage

        used, limit = parse_docker_mem_usage(proc.stdout.strip())
        if used is not None:
            container_after = {
                "container_rss_bytes": used,
                "container_limit_bytes": limit,
            }
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

modsec_after = parse_modsecurity_memory(out_dir / "envoy-prometheus-after.txt")
if not modsec_after:
    modsec_after = parse_modsecurity_memory(out_dir / "modsecurity-proxy-wasm-memory-after.txt")

snapshot = {
    "envoy_before": load_envoy("before"),
    "envoy_after": load_envoy("after"),
    "modsecurity_after": modsec_after,
    "peak_container": peak,
    "container_after": container_after or {},
}
(out_dir / "memory-snapshot.json").write_text(
    json.dumps(snapshot, indent=2) + "\n",
    encoding="utf-8",
)
PY