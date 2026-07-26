#!/usr/bin/env python3
"""Print a side-by-side table from two k6 --summary-export JSON files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def metric_ms(data: dict, name: str, key: str) -> float | None:
    metrics = data.get("metrics", {})
    entry = metrics.get(name)
    if not entry or key not in entry:
        return None
    # k6 --summary-export reports durations in milliseconds.
    return float(entry[key])


def metric_rate(data: dict, name: str) -> float | None:
    metrics = data.get("metrics", {})
    entry = metrics.get(name)
    if not entry:
        return None
    if "rate" in entry:
        return float(entry["rate"])
    return None


def fmt_ms(v: float | None) -> str:
    if v is None:
        return "n/a"
    return f"{v:.2f}ms"


def fmt_rps(v: float | None) -> str:
    if v is None:
        return "n/a"
    return f"{v:.0f}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path, help="First k6-summary.json")
    parser.add_argument("right", type=Path, help="Second k6-summary.json")
    parser.add_argument("--left-label", default="left")
    parser.add_argument("--right-label", default="right")
    args = parser.parse_args()

    left = load(args.left)
    right = load(args.right)

    dur = "http_req_duration"
    rows = [
        ("p50", metric_ms(left, dur, "med"), metric_ms(right, dur, "med")),
        ("p95", metric_ms(left, dur, "p(95)"), metric_ms(right, dur, "p(95)")),
        ("p90", metric_ms(left, dur, "p(90)"), metric_ms(right, dur, "p(90)")),
        ("RPS", metric_rate(left, "http_reqs"), metric_rate(right, "http_reqs")),
    ]

    print(f"{'metric':<8} {args.left_label:<24} {args.right_label:<24} delta")
    print("-" * 72)
    for name, lv, rv in rows:
        if name == "RPS":
            delta = ""
            if lv is not None and rv is not None and lv > 0:
                pct = ((rv - lv) / lv) * 100.0
                delta = f"{pct:+.1f}%"
            print(f"{name:<8} {fmt_rps(lv):<24} {fmt_rps(rv):<24} {delta}")
        else:
            delta = ""
            if lv is not None and rv is not None:
                delta = f"{rv - lv:+.2f}ms"
            print(f"{name:<8} {fmt_ms(lv):<24} {fmt_ms(rv):<24} {delta}")

    return 0


if __name__ == "__main__":
    sys.exit(main())