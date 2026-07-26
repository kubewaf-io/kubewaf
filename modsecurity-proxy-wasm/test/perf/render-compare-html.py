#!/usr/bin/env python3
"""Write a small HTML comparison report from two k6 --summary-export JSON files."""

from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def metric_ms(data: dict, name: str, key: str) -> float | None:
    entry = data.get("metrics", {}).get(name)
    if not entry or key not in entry:
        return None
    return float(entry[key])


def metric_rate(data: dict, name: str) -> float | None:
    entry = data.get("metrics", {}).get(name)
    if not entry:
        return None
    if "rate" in entry:
        return float(entry["rate"])
    return None


def fmt_ms(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2f} ms"


def fmt_rps(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.0f}"


def delta_ms(left: float | None, right: float | None) -> str:
    if left is None or right is None:
        return "n/a"
    sign = "+" if right - left >= 0 else ""
    return f"{sign}{right - left:.2f} ms"


def delta_rps(left: float | None, right: float | None) -> str:
    if left is None or right is None or left <= 0:
        return "n/a"
    return f"{((right - left) / left) * 100.0:+.1f}%"


def render(left: dict, right: dict, left_label: str, right_label: str) -> str:
    dur = "http_req_duration"
    rows = [
        ("p50", fmt_ms(metric_ms(left, dur, "med")), fmt_ms(metric_ms(right, dur, "med")),
         delta_ms(metric_ms(left, dur, "med"), metric_ms(right, dur, "med"))),
        ("p90", fmt_ms(metric_ms(left, dur, "p(90)")), fmt_ms(metric_ms(right, dur, "p(90)")),
         delta_ms(metric_ms(left, dur, "p(90)"), metric_ms(right, dur, "p(90)"))),
        ("p95", fmt_ms(metric_ms(left, dur, "p(95)")), fmt_ms(metric_ms(right, dur, "p(95)")),
         delta_ms(metric_ms(left, dur, "p(95)"), metric_ms(right, dur, "p(95)"))),
        ("RPS", fmt_rps(metric_rate(left, "http_reqs")), fmt_rps(metric_rate(right, "http_reqs")),
         delta_rps(metric_rate(left, "http_reqs"), metric_rate(right, "http_reqs"))),
    ]
    generated = datetime.now(timezone.utc).isoformat()
    body_rows = "\n".join(
        f"<tr><td>{html.escape(name)}</td><td>{lv}</td><td>{rv}</td><td>{delta}</td></tr>"
        for name, lv, rv, delta in rows
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>k6 compare — {html.escape(left_label)} vs {html.escape(right_label)}</title>
  <style>
    body {{ margin: 0; font: 14px/1.5 system-ui, sans-serif; background: #0f1419; color: #e7ecf3; }}
    main {{ max-width: 720px; margin: 0 auto; padding: 24px 16px; }}
    h1 {{ font-size: 1.2rem; }}
    .sub {{ color: #8b9cb3; margin-bottom: 16px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #2d3a4f; }}
    th {{ color: #8b9cb3; }}
  </style>
</head>
<body>
  <main>
    <h1>{html.escape(left_label)} vs {html.escape(right_label)}</h1>
    <p class="sub">modsecurity-proxy-wasm k6 comparison · {html.escape(generated)}</p>
    <table>
      <thead><tr><th>Metric</th><th>{html.escape(left_label)}</th>
        <th>{html.escape(right_label)}</th><th>Delta</th></tr></thead>
      <tbody>
{body_rows}
      </tbody>
    </table>
  </main>
</body>
</html>"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--left-label", default="left")
    parser.add_argument("--right-label", default="right")
    args = parser.parse_args()

    args.output.write_text(
        render(load(args.left), load(args.right), args.left_label, args.right_label),
        encoding="utf-8",
    )
    print(f"==> Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())