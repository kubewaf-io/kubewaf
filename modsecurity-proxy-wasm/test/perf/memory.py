"""Envoy and container memory helpers for perf runs."""

from __future__ import annotations

import json
import re
from pathlib import Path

PROM_MEMORY_KEYS = {
    "envoy_server_memory_allocated": "allocated_bytes",
    "envoy_server_memory_heap_size": "heap_size_bytes",
    "envoy_server_memory_physical_size": "physical_size_bytes",
}

MODSECURITY_MEMORY_KEYS = {
    "modsecurity_proxy_wasm_memory_wasm_heap_bytes": "wasm_heap_bytes",
}


def _parse_prometheus_gauges(path: Path, key_map: dict[str, str]) -> dict[str, int]:
    out: dict[str, int] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        for prom_key, field in key_map.items():
            if line.startswith(f"{prom_key}{{") or line.startswith(f"{prom_key} "):
                try:
                    out[field] = int(float(line.rsplit(" ", 1)[-1]))
                except ValueError:
                    pass
                break
    return out


def parse_prometheus_memory(path: Path) -> dict[str, int]:
    return _parse_prometheus_gauges(path, PROM_MEMORY_KEYS)


def parse_modsecurity_memory(path: Path) -> dict[str, int]:
    return _parse_prometheus_gauges(path, MODSECURITY_MEMORY_KEYS)


def parse_docker_mem_usage(value: str) -> tuple[int | None, int | None]:
    """Parse '123.4MiB / 2GiB' into (used_bytes, limit_bytes)."""
    parts = [p.strip() for p in value.split("/")]
    if len(parts) != 2:
        return None, None
    return parse_byte_quantity(parts[0]), parse_byte_quantity(parts[1])


def parse_byte_quantity(raw: str) -> int | None:
    raw = raw.strip()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?i?B)", raw, re.IGNORECASE)
    if not match:
        return None
    amount = float(match.group(1))
    unit = match.group(2).upper()
    mult = {
        "B": 1,
        "KIB": 1024,
        "MIB": 1024**2,
        "GIB": 1024**3,
        "TIB": 1024**4,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
    }.get(unit)
    if mult is None:
        return None
    return int(amount * mult)


def peak_from_samples(path: Path) -> dict[str, int | None]:
    peak_used = 0
    peak_limit: int | None = None
    if not path.is_file():
        return {"container_rss_bytes": None, "container_limit_bytes": None}
    for line in path.read_text(encoding="utf-8").splitlines():
        used, limit = parse_docker_mem_usage(line)
        if used is not None:
            peak_used = max(peak_used, used)
        if limit is not None:
            peak_limit = limit
    return {
        "container_rss_bytes": peak_used or None,
        "container_limit_bytes": peak_limit,
    }


def load_run_memory(run_dir: Path) -> dict:
    snapshot = run_dir / "memory-snapshot.json"
    if snapshot.is_file():
        with snapshot.open(encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        after_prom = run_dir / "envoy-prometheus-after.txt"
        peak = peak_from_samples(run_dir / "memory-samples.log")
        data = {
            "envoy_after": parse_prometheus_memory(after_prom),
            "peak_container": peak,
        }

    modsec_path = run_dir / "modsecurity-proxy-wasm-memory-after.txt"
    if not modsec_path.is_file():
        modsec_path = run_dir / "envoy-prometheus-after.txt"
    modsec = parse_modsecurity_memory(modsec_path)
    if modsec:
        data["modsecurity_after"] = modsec
    return data


def memory_mb(snapshot: dict) -> dict[str, float | None]:
    envoy = snapshot.get("envoy_after") or snapshot.get("after", {}).get("envoy", {})
    modsec = snapshot.get("modsecurity_after") or snapshot.get("after", {}).get("modsecurity", {})
    peak = snapshot.get("peak_container") or snapshot.get("peak", {})
    allocated = envoy.get("allocated_bytes")
    physical = envoy.get("physical_size_bytes")
    rss = peak.get("container_rss_bytes")
    wasm_heap = modsec.get("wasm_heap_bytes")
    return {
        "envoy_allocated_mb": allocated / (1024 * 1024) if allocated else None,
        "envoy_physical_mb": physical / (1024 * 1024) if physical else None,
        "container_peak_rss_mb": rss / (1024 * 1024) if rss else None,
        "modsecurity_wasm_heap_mb": wasm_heap / (1024 * 1024) if wasm_heap else None,
    }