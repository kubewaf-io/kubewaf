#!/usr/bin/env python3
"""Render small PNG charts from k6 --summary-export JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from memory import load_run_memory, memory_mb

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

VALID_PROFILES = (
    "baseline",
    "wasm-minimal",
    "modsecurity-proxy-wasm-full",
    "coraza-minimal",
    "coraza-full",
)
VALID_SCENARIOS = ("benign-get", "benign-post-1k", "block-xss", "mixed")

# Preferred legend order (CI smoke first, then extras).
TEST_ORDER = [
    ("baseline", "benign-get"),
    ("wasm-minimal", "benign-get"),
    ("coraza-minimal", "benign-get"),
    ("modsecurity-proxy-wasm-full", "benign-get"),
    ("coraza-full", "benign-get"),
    ("modsecurity-proxy-wasm-full", "benign-post-1k"),
    ("coraza-full", "benign-post-1k"),
    ("modsecurity-proxy-wasm-full", "block-xss"),
    ("coraza-full", "block-xss"),
    ("modsecurity-proxy-wasm-full", "mixed"),
    ("coraza-full", "mixed"),
]

OVERLAY_METRICS = ("p50", "p90", "p95", "p99")
OVERLAY_COLORS = (
    "#8b9cb3",
    "#3d8bfd",
    "#f0883e",
    "#2ea043",
    "#a371f7",
    "#ff7b72",
    "#79c0ff",
    "#d29922",
    "#56d364",
    "#ffa657",
    "#bc8cff",
)


def load_summary(path: Path) -> dict:
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
    if "count" in entry and "rate" not in entry:
        return None
    return None


def metric_count(data: dict, name: str) -> float | None:
    entry = data.get("metrics", {}).get(name)
    if not entry:
        return None
    if "count" in entry:
        return float(entry["count"])
    return None


def latency_stats(data: dict) -> dict[str, float | None]:
    dur = "http_req_duration"
    return {
        "p50": metric_ms(data, dur, "med"),
        "p90": metric_ms(data, dur, "p(90)"),
        "p95": metric_ms(data, dur, "p(95)"),
        "p99": metric_ms(data, dur, "p(99)"),
        "avg": metric_ms(data, dur, "avg"),
    }


def apply_style() -> None:
    plt.style.use("dark_background")
    plt.rcParams.update(
        {
            "figure.facecolor": "#0f1419",
            "axes.facecolor": "#1a2332",
            "axes.edgecolor": "#2d3a4f",
            "axes.labelcolor": "#8b9cb3",
            "text.color": "#e7ecf3",
            "xtick.color": "#8b9cb3",
            "ytick.color": "#8b9cb3",
            "grid.color": "#2d3a4f",
            "font.size": 10,
        }
    )


def render_single(summary: dict, title: str, output: Path) -> None:
    apply_style()
    lat = latency_stats(summary)
    labels = [k for k in ("p50", "p90", "p95", "p99") if lat[k] is not None]
    values = [lat[k] for k in labels]

    rps = metric_rate(summary, "http_reqs")
    reqs = metric_count(summary, "http_reqs")
    fail = metric_rate(summary, "http_req_failed")
    checks = summary.get("metrics", {}).get("checks", {}).get("value")

    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=120)
    bars = ax.bar(labels, values, color="#3d8bfd", edgecolor="#2d3a4f", linewidth=0.8)
    ax.set_ylabel("latency (ms)")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.grid(axis="y", alpha=0.35)
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{val:.2f}",
            ha="center",
            va="bottom",
            fontsize=8,
            color="#e7ecf3",
        )

    fail_pct = f"{fail * 100:.2f}%" if fail is not None else "n/a"
    checks_pct = f"{checks * 100:.1f}%" if checks is not None else "n/a"
    caption = (
        f"RPS {rps:,.0f}  ·  requests {reqs:,.0f}  ·  failed {fail_pct}  ·  checks {checks_pct}"
        if rps is not None and reqs is not None
        else "k6 summary"
    )
    fig.text(0.5, 0.02, caption, ha="center", fontsize=9, color="#8b9cb3")
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def render_overlay(
    series: list[tuple[str, dict]],
    title: str,
    output: Path,
) -> None:
    apply_style()
    x = list(range(len(OVERLAY_METRICS)))

    fig, ax = plt.subplots(figsize=(10, 6), dpi=120)
    plotted = 0
    for i, (name, summary) in enumerate(series):
        lat = latency_stats(summary)
        values = [lat[key] for key in OVERLAY_METRICS]
        if not any(v is not None for v in values):
            continue
        y = [float(v) if v is not None else 0.0 for v in values]
        color = OVERLAY_COLORS[i % len(OVERLAY_COLORS)]
        ax.plot(
            x,
            y,
            marker="o",
            label=name,
            color=color,
            linewidth=2,
            markersize=5,
            alpha=0.9,
        )
        plotted += 1

    if plotted == 0:
        raise ValueError("no latency data to plot")

    ax.set_xticks(x)
    ax.set_xticklabels(list(OVERLAY_METRICS))
    ax.set_ylabel("latency (ms)")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.legend(loc="upper left", fontsize=8, ncol=2, framealpha=0.85)
    ax.grid(axis="y", alpha=0.35)
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def render_compare(
    left: dict,
    right: dict,
    left_label: str,
    right_label: str,
    title: str,
    output: Path,
) -> None:
    apply_style()
    ll = latency_stats(left)
    rl = latency_stats(right)
    lrps = metric_rate(left, "http_reqs")
    rrps = metric_rate(right, "http_reqs")

    metrics = ["p50", "p90", "p95", "RPS"]
    left_vals = [ll["p50"], ll["p90"], ll["p95"], lrps]
    right_vals = [rl["p50"], rl["p90"], rl["p95"], rrps]

    x = range(len(metrics))
    width = 0.36
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=120)
    ax.bar([i - width / 2 for i in x], left_vals, width, label=left_label, color="#3d8bfd")
    ax.bar([i + width / 2 for i in x], right_vals, width, label=right_label, color="#f0883e")
    ax.set_xticks(list(x))
    ax.set_xticklabels(metrics)
    ax.set_ylabel("ms (RPS for last bar)")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(axis="y", alpha=0.35)
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def is_release_run(path: Path) -> bool:
    return (path / "wasm-release-tag.txt").is_file()


def parse_run_dir(path: Path) -> tuple[str, str, str] | None:
    name = path.name
    if not name.startswith("run-"):
        return None
    rest = name[4:]
    for scenario in VALID_SCENARIOS:
        suffix = f"-{scenario}"
        if not rest.endswith(suffix):
            continue
        middle = rest[: -len(suffix)]
        rel_prefix = "-rel-"
        if rel_prefix in middle:
            rel_idx = middle.index(rel_prefix)
            stamp = middle[:rel_idx]
            tail = middle[rel_idx + len(rel_prefix) :]
            for profile in VALID_PROFILES:
                profile_suffix = f"-{profile}"
                if tail.endswith(profile_suffix):
                    tag_slug = tail[: -len(profile_suffix)]
                    if stamp and tag_slug:
                        return f"{stamp}-rel-{tag_slug}", profile, scenario
            continue
        for profile in VALID_PROFILES:
            profile_suffix = f"-{profile}"
            if middle.endswith(profile_suffix):
                stamp = middle[: -len(profile_suffix)]
                if stamp:
                    return stamp, profile, scenario
    return None


def test_sort_key(profile: str, scenario: str) -> tuple[int, str, str]:
    key = (profile, scenario)
    try:
        return (TEST_ORDER.index(key), profile, scenario)
    except ValueError:
        return (len(TEST_ORDER), profile, scenario)


def test_label(profile: str, scenario: str) -> str:
    return f"{profile} / {scenario}"


def find_latest_run(results_root: Path, profile: str, scenario: str) -> Path | None:
    matches = []
    for child in results_root.iterdir():
        if not child.is_dir():
            continue
        parsed = parse_run_dir(child)
        if parsed and parsed[1] == profile and parsed[2] == scenario:
            matches.append(child)
    if not matches:
        return None
    return sorted(matches, key=lambda p: p.name, reverse=True)[0]


def collect_latest_summaries(
    results_root: Path,
    *,
    include_release_runs: bool = False,
) -> list[tuple[str, dict]]:
    latest: dict[tuple[str, str], tuple[str, dict]] = {}
    for child in results_root.iterdir():
        if not child.is_dir():
            continue
        if not include_release_runs and is_release_run(child):
            continue
        parsed = parse_run_dir(child)
        if not parsed:
            continue
        stamp, profile, scenario = parsed
        summary = child / "k6-summary.json"
        if not summary.is_file():
            continue
        key = (profile, scenario)
        prev = latest.get(key)
        if prev is None or stamp > prev[0]:
            latest[key] = (stamp, load_summary(summary))

    ordered = sorted(latest, key=lambda k: test_sort_key(k[0], k[1]))
    return [(test_label(profile, scenario), latest[(profile, scenario)][1]) for profile, scenario in ordered]


def collect_latest_memory(
    results_root: Path,
    *,
    include_release_runs: bool = False,
) -> list[tuple[str, dict[str, float | None]]]:
    latest: dict[tuple[str, str], tuple[str, Path]] = {}
    for child in results_root.iterdir():
        if not child.is_dir():
            continue
        if not include_release_runs and is_release_run(child):
            continue
        parsed = parse_run_dir(child)
        if not parsed:
            continue
        stamp, profile, scenario = parsed
        if not (child / "memory-snapshot.json").is_file() and not (
            child / "envoy-prometheus-after.txt"
        ).is_file():
            continue
        key = (profile, scenario)
        prev = latest.get(key)
        if prev is None or stamp > prev[0]:
            latest[key] = (stamp, child)

    ordered = sorted(latest, key=lambda k: test_sort_key(k[0], k[1]))
    out: list[tuple[str, dict[str, float | None]]] = []
    for profile, scenario in ordered:
        snap = memory_mb(load_run_memory(latest[(profile, scenario)][1]))
        out.append((test_label(profile, scenario), snap))
    return out


def render_memory_overlay(
    series: list[tuple[str, dict[str, float | None]]],
    title: str,
    output: Path,
) -> None:
    apply_style()
    labels = [name for name, _ in series]
    peak = [vals.get("container_peak_rss_mb") for _, vals in series]
    modsec = [vals.get("modsecurity_wasm_heap_mb") for _, vals in series]

    if not any(v is not None for v in peak + modsec):
        raise ValueError("no memory data to plot")

    x = list(range(len(labels)))
    width = 0.36
    fig, ax = plt.subplots(figsize=(11, 6), dpi=120)
    peak_vals = [float(v) if v is not None else 0.0 for v in peak]
    modsec_vals = [float(v) if v is not None else 0.0 for v in modsec]
    ax.bar(
        [i - width / 2 for i in x],
        peak_vals,
        width,
        label="Envoy container peak RSS",
        color="#f0883e",
    )
    ax.bar(
        [i + width / 2 for i in x],
        modsec_vals,
        width,
        label="modsecurity-proxy-wasm heap",
        color="#2ea043",
    )
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax.set_ylabel("memory (MiB)")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.legend(loc="upper left", fontsize=9)
    ax.grid(axis="y", alpha=0.35)
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def render_release_compare(meta_path: Path, output: Path) -> None:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    prev_tag = meta["previous_tag"]
    curr_tag = meta["current_tag"]
    scenarios = list(meta.get("scenarios", {}).keys())
    if not scenarios:
        raise ValueError("release compare metadata has no scenarios")

    left_p99: list[float | None] = []
    right_p99: list[float | None] = []
    for scenario in scenarios:
        entry = meta["scenarios"][scenario]
        left_path = entry.get("previous")
        right_path = entry.get("current")
        left = load_summary(Path(left_path) / "k6-summary.json") if left_path else {}
        right = load_summary(Path(right_path) / "k6-summary.json") if right_path else {}
        left_p99.append(metric_ms(left, "http_req_duration", "p(99)"))
        right_p99.append(metric_ms(right, "http_req_duration", "p(99)"))

    apply_style()
    x = list(range(len(scenarios)))
    width = 0.36
    fig, ax = plt.subplots(figsize=(9, 5), dpi=120)
    ax.bar(
        [i - width / 2 for i in x],
        [v if v is not None else 0.0 for v in left_p99],
        width,
        label=prev_tag,
        color="#8b9cb3",
    )
    ax.bar(
        [i + width / 2 for i in x],
        [v if v is not None else 0.0 for v in right_p99],
        width,
        label=curr_tag,
        color="#2ea043",
    )
    ax.set_xticks(x)
    ax.set_xticklabels(scenarios)
    ax.set_ylabel("p99 latency (ms)")
    ax.set_title(
        f"Release compare — {prev_tag} vs {curr_tag}",
        fontsize=12,
        fontweight="bold",
        pad=12,
    )
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(axis="y", alpha=0.35)
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def bundle(results_root: Path, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    for old in output_dir.glob("perf-*.png"):
        if old.name not in ("perf-overlay.png", "memory-overlay.png", "perf-release-compare.png"):
            old.unlink()
    written: list[Path] = []

    series = collect_latest_summaries(results_root)
    if series:
        out = output_dir / "perf-overlay.png"
        render_overlay(series, "k6 perf — all tests", out)
        print(f"==> Wrote {out} ({len(series)} series)")
        written.append(out)
    else:
        print("WARN: no k6-summary.json files found under results/", file=sys.stderr)

    memory_series = collect_latest_memory(results_root)
    if memory_series:
        mem_out = output_dir / "memory-overlay.png"
        render_memory_overlay(memory_series, "Memory — all tests", mem_out)
        print(f"==> Wrote {mem_out} ({len(memory_series)} series)")
        written.append(mem_out)
    else:
        print("WARN: no memory snapshots found under results/", file=sys.stderr)

    release_meta = results_root / "release-compare.json"
    if release_meta.is_file():
        rel_out = output_dir / "perf-release-compare.png"
        render_release_compare(release_meta, rel_out)
        print(f"==> Wrote {rel_out}")
        written.append(rel_out)

    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    single = sub.add_parser("single", help="Chart one k6-summary.json")
    single.add_argument("summary", type=Path)
    single.add_argument("-o", "--output", type=Path, required=True)
    single.add_argument("--title", default="k6 perf")

    compare = sub.add_parser("compare", help="Chart two summaries")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    compare.add_argument("-o", "--output", type=Path, required=True)
    compare.add_argument("--left-label", default="left")
    compare.add_argument("--right-label", default="right")
    compare.add_argument("--title", default="k6 compare")

    overlay_p = sub.add_parser("overlay", help="Overlay multiple k6-summary.json files")
    overlay_p.add_argument("summaries", nargs="+", type=Path)
    overlay_p.add_argument("-o", "--output", type=Path, required=True)
    overlay_p.add_argument("--title", default="k6 perf — all tests")

    bundle_p = sub.add_parser("bundle", help="Overlay chart from latest runs under results/")
    bundle_p.add_argument("results_root", type=Path)
    bundle_p.add_argument("-o", "--output", type=Path, required=True)

    memory_p = sub.add_parser("memory", help="Memory overlay from latest runs")
    memory_p.add_argument("results_root", type=Path)
    memory_p.add_argument("-o", "--output", type=Path, required=True)
    memory_p.add_argument("--title", default="Memory — all tests")

    release_p = sub.add_parser(
        "release-compare",
        help="Chart p99 latency from release-compare.json metadata",
    )
    release_p.add_argument("metadata", type=Path)
    release_p.add_argument("-o", "--output", type=Path, required=True)

    args = parser.parse_args()

    if args.cmd == "single":
        render_single(load_summary(args.summary), args.title, args.output)
        print(f"==> Wrote {args.output}")
    elif args.cmd == "compare":
        render_compare(
            load_summary(args.left),
            load_summary(args.right),
            args.left_label,
            args.right_label,
            args.title,
            args.output,
        )
        print(f"==> Wrote {args.output}")
    elif args.cmd == "overlay":
        series = []
        for path in args.summaries:
            parsed = parse_run_dir(path.parent)
            label = (
                test_label(parsed[1], parsed[2])
                if parsed
                else path.parent.name.removeprefix("run-")
            )
            series.append((label, load_summary(path)))
        render_overlay(series, args.title, args.output)
        print(f"==> Wrote {args.output}")
    elif args.cmd == "memory":
        series = collect_latest_memory(args.results_root)
        render_memory_overlay(series, args.title, args.output)
        print(f"==> Wrote {args.output}")
    elif args.cmd == "release-compare":
        render_release_compare(args.metadata, args.output)
        print(f"==> Wrote {args.output}")
    else:
        bundle(args.results_root, args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())