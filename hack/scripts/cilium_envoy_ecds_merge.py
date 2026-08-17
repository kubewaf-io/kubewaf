#!/usr/bin/env python3
"""Merge STATIC kubewaf_ecds (and optional kubewaf_otel) into a Cilium Envoy bootstrap."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from typing import Any

XDS_GRPC_CILIUM = "xds-grpc-cilium"
DEFAULT_CLUSTER = "kubewaf_ecds"
DEFAULT_OTEL_CLUSTER = "kubewaf_otel"

# Cilium's chart bootstrap (helm fromYaml|toJson) uses protojson camelCase
# (staticResources, loadAssignment, …). Writing a sibling static_resources
# key is a duplicate field in protojson and crash-loops cilium-envoy.
_CAMEL_WORD = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_ACRONYM = re.compile(r"([a-z0-9])([A-Z])")


def _camel_to_snake(name: str) -> str:
    name = _CAMEL_WORD.sub(r"\1_\2", name)
    name = _CAMEL_ACRONYM.sub(r"\1_\2", name)
    return name.lower()


def _should_snake_key(key: str) -> bool:
    if not key or key[0] == "@" or "." in key or "-" in key or "_" in key:
        return False
    return any(c.isupper() for c in key)


def _merge_normalized_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Combine two dicts that collided after camelCase→snake_case (e.g. both
    staticResources and static_resources). Cluster lists are unioned by name."""
    out = dict(left)
    for key, value in right.items():
        if key == "clusters" and isinstance(out.get(key), list) and isinstance(value, list):
            by_name: dict[str, Any] = {}
            extras: list[Any] = []
            for cluster in out[key] + value:
                if isinstance(cluster, dict) and cluster.get("name"):
                    by_name[str(cluster["name"])] = cluster
                else:
                    extras.append(cluster)
            out[key] = extras + list(by_name.values())
        elif key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _merge_normalized_dicts(out[key], value)
        else:
            out[key] = value
    return out


def normalize_bootstrap_keys(obj: Any) -> Any:
    """Rewrite protojson camelCase object keys to snake_case (Envoy accepts both).

    Leaves @type, extension-name map keys (contain '.'), and already-snake
    keys alone. Applied before merge so we never emit both staticResources
    and static_resources in the same object.
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            new_key = _camel_to_snake(key) if _should_snake_key(key) else key
            normalized = normalize_bootstrap_keys(value)
            if (
                new_key in out
                and isinstance(out[new_key], dict)
                and isinstance(normalized, dict)
            ):
                out[new_key] = _merge_normalized_dicts(out[new_key], normalized)
            else:
                out[new_key] = normalized
        return out
    if isinstance(obj, list):
        return [normalize_bootstrap_keys(item) for item in obj]
    return obj

# Keep in sync with internal/dataplane/observability/stats_tags.go
STATS_TAGS: list[dict[str, str]] = [
    {"tag_name": "tag", "regex": "(_tag=([0-9a-zA-Z.-]+))"},
    {
        "tag_name": "phase",
        "regex": "(_phase=(http_request_headers|http_request_body|http_response_headers|http_response_body|http_logging|unknown))",
    },
    {"tag_name": "rule_id", "regex": "(_ruleid=([0-9]+))"},
    {"tag_name": "severity", "regex": "(_severity=([0-9]+))"},
    {"tag_name": "waf_namespace", "regex": "(_waf_namespace=([0-9A-Za-z.-]+))"},
    {"tag_name": "waf_name", "regex": "(_waf_name=([0-9A-Za-z.-]+))"},
    {"tag_name": "engine", "regex": "(_engine=([0-9A-Za-z.-]+))"},
    {"tag_name": "owner", "regex": "(_owner=([0-9a-z.:_-]+?))(?:_|$)"},
]


def _static_http2_cluster(name: str, ip: str, port: int) -> dict[str, Any]:
    if not name or not str(name).strip():
        raise ValueError("cluster name is empty")
    if name == XDS_GRPC_CILIUM:
        raise ValueError("cluster name must not replace %r" % XDS_GRPC_CILIUM)
    addr = ipaddress.ip_address(ip)
    if port <= 0 or port > 65535:
        raise ValueError(f"invalid port {port}")
    return {
        "name": name,
        "type": "STATIC",
        "connect_timeout": "2s",
        "lb_policy": "ROUND_ROBIN",
        "typed_extension_protocol_options": {
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
                "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
                "explicit_http_config": {"http2_protocol_options": {}},
            }
        },
        "load_assignment": {
            "cluster_name": name,
            "endpoints": [
                {
                    "lb_endpoints": [
                        {
                            "endpoint": {
                                "address": {
                                    "socket_address": {
                                        "address": str(addr),
                                        "port_value": int(port),
                                    }
                                }
                            }
                        }
                    ]
                }
            ],
        },
    }


def _xds_grpc_cilium_cluster() -> dict[str, Any]:
    """STATIC pipe cluster Cilium Envoy needs for CDS/LDS (Cilium 1.19+)."""
    return {
        "name": XDS_GRPC_CILIUM,
        "type": "STATIC",
        "connect_timeout": "2s",
        "load_assignment": {
            "cluster_name": XDS_GRPC_CILIUM,
            "endpoints": [
                {
                    "lb_endpoints": [
                        {
                            "endpoint": {
                                "address": {
                                    "pipe": {
                                        "path": "/var/run/cilium/envoy/sockets/xds.sock",
                                    }
                                }
                            }
                        }
                    ]
                }
            ],
        },
        "typed_extension_protocol_options": {
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
                "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
                "explicit_http_config": {"http2_protocol_options": {}},
            }
        },
    }


def _in_place_normalize(doc: dict[str, Any]) -> None:
    normalized = normalize_bootstrap_keys(doc)
    if normalized is doc:
        return
    doc.clear()
    doc.update(normalized)


def _upsert_cluster(doc: dict[str, Any], cluster: dict[str, Any]) -> None:
    sr = doc.setdefault("static_resources", {})
    name = cluster["name"]
    clusters = [c for c in sr.get("clusters") or [] if c.get("name") != name]
    clusters.append(cluster)
    sr["clusters"] = clusters


def merge_bootstrap(
    doc: dict[str, Any],
    ip: str,
    port: int,
    cluster_name: str = DEFAULT_CLUSTER,
) -> dict[str, Any]:
    # Chart JSON is camelCase; collapse to snake_case before touching clusters.
    _in_place_normalize(doc)
    orig = [c.get("name") for c in (doc.get("static_resources") or {}).get("clusters") or []]
    if XDS_GRPC_CILIUM not in orig:
        # Incomplete dump (no chart staticResources). Inject the pipe cluster
        # Cilium's bootstrap-config.yaml uses for CDS/LDS.
        _upsert_cluster(doc, _xds_grpc_cilium_cluster())
    _upsert_cluster(doc, _static_http2_cluster(cluster_name, ip, port))
    names = [c.get("name") for c in (doc.get("static_resources") or {}).get("clusters") or []]
    if XDS_GRPC_CILIUM not in names:
        raise ValueError("merged bootstrap missing required cluster %r" % XDS_GRPC_CILIUM)
    if names.count(cluster_name) != 1:
        raise ValueError("expected exactly one %r cluster" % cluster_name)
    return doc


def merge_otel(
    doc: dict[str, Any],
    ip: str,
    port: int,
    cluster_name: str = DEFAULT_OTEL_CLUSTER,
    stats_sink: bool = False,
) -> dict[str, Any]:
    """Merge HTTP/2 STATIC kubewaf_otel (and optional stats_sinks) plus stats_tags.

    Cilium Envoy 1.36 (chart 1.19) does not register
    envoy.stat_sinks.open_telemetry — a bootstrap sink crash-loops ds/cilium-envoy.
    Keep the STATIC cluster so CEC access logs can reference it. Official Envoy
    (Istio / EG) can pass stats_sink=True.
    """
    _in_place_normalize(doc)
    _upsert_cluster(doc, _static_http2_cluster(cluster_name, ip, port))
    if stats_sink:
        merge_stats_sinks(doc, cluster_name)
    merge_stats_tags(doc)
    names = [c.get("name") for c in (doc.get("static_resources") or {}).get("clusters") or []]
    if names.count(cluster_name) != 1:
        raise ValueError("expected exactly one %r cluster" % cluster_name)
    return doc


def _stat_name_input() -> dict[str, Any]:
    return {
        "name": "envoy.matching.inputs.stat_full_name",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.matching.common_inputs.stats.v3.StatFullNameMatchInput"
        },
    }


def _conversion_action(metric_name: str) -> dict[str, Any]:
    return {
        "name": "convert",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.stat_sinks.open_telemetry.v3.SinkConfig.ConversionAction",
            "metric_name": metric_name,
        },
    }


def _drop_action() -> dict[str, Any]:
    return {
        "name": "drop",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.stat_sinks.open_telemetry.v3.SinkConfig.DropAction"
        },
    }


def custom_metric_conversions() -> dict[str, Any]:
    """Map kubewaf_waf.* → catalog names; drop dual-prefix leftovers.

    Unmatched stats pass through (Envoy default). A process-wide on_no_match
    DropAction flushed empty OTLP on Envoy 1.38: StatFullName matchers did not
    hit wasmcustom.* names, so every stat including WAF counters was dropped.
    Collector filter/waf_metrics is the membership gate. Use contains() so
    tag-extracted and full names both match.
    """
    catalog = [
        ("kubewaf_waf.tx.total", "kubewaf.waf.tx.total"),
        ("kubewaf_waf.tx.allowed", "kubewaf.waf.tx.allowed"),
        ("kubewaf_waf.tx.interruptions_ruleid=", "kubewaf.waf.tx.interruptions_by_rule"),
        ("kubewaf_waf.tx.interruptions", "kubewaf.waf.tx.interruptions"),
        ("kubewaf_waf.rule.matches_disruptive", "kubewaf.waf.rule.matches_disruptive"),
        ("kubewaf_waf.rule.matches_ruleid=", "kubewaf.waf.rule.matches_by_rule"),
        ("kubewaf_waf.rule.matches_tag=", "kubewaf.waf.rule.matches_by_tag"),
        ("kubewaf_waf.rule.matches_phase=", "kubewaf.waf.rule.matches_by_phase"),
        ("kubewaf_waf.rule.matches", "kubewaf.waf.rule.matches"),
        ("kubewaf_waf.memory.wasm_heap_bytes", "kubewaf.waf.memory.wasm_heap_bytes"),
    ]
    matchers: list[dict[str, Any]] = []
    for needle, name in catalog:
        matchers.append(
            {
                "predicate": {
                    "single_predicate": {
                        "input": _stat_name_input(),
                        "value_match": {"contains": needle},
                    }
                },
                "on_match": {"action": _conversion_action(name)},
            }
        )
    matchers.append(
        {
            "predicate": {
                "single_predicate": {
                    "input": _stat_name_input(),
                    "value_match": {"contains": "modsecurity_proxy_wasm"},
                }
            },
            "on_match": {"action": _drop_action()},
        }
    )
    return {"matcher_list": {"matchers": matchers}}


def merge_stats_sinks(doc: dict[str, Any], cluster_name: str = DEFAULT_OTEL_CLUSTER) -> dict[str, Any]:
    sink = {
        "name": "envoy.stat_sinks.open_telemetry",
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.stat_sinks.open_telemetry.v3.SinkConfig",
            "grpc_service": {"envoy_grpc": {"cluster_name": cluster_name}},
            "emit_tags_as_attributes": True,
            "use_tag_extracted_name": True,
            "prefix": "",
            # Cilium Envoy 1.36 (1.19 chart) does not register DropAction /
            # ConversionAction; a sink with those types crash-loops the DS.
            # Collector filter/waf_metrics is the membership gate.
        },
    }
    sinks = [s for s in doc.get("stats_sinks") or [] if s.get("name") != sink["name"]]
    sinks.append(sink)
    doc["stats_sinks"] = sinks
    return doc


def merge_stats_tags(doc: dict[str, Any]) -> dict[str, Any]:
    sc = doc.setdefault("stats_config", {})
    existing = list(sc.get("stats_tags") or [])
    by_name = {t.get("tag_name"): t for t in existing if isinstance(t, dict)}
    for tag in STATS_TAGS:
        by_name[tag["tag_name"]] = tag
    # Preserve non-kubeWAF tags, then pin ours.
    out = []
    seen = set()
    for t in existing:
        name = t.get("tag_name") if isinstance(t, dict) else None
        if name in by_name and name not in seen:
            out.append(by_name[name])
            seen.add(name)
        elif name not in seen:
            out.append(t)
            seen.add(name)
    for tag in STATS_TAGS:
        if tag["tag_name"] not in seen:
            out.append(tag)
            seen.add(tag["tag_name"])
    sc["stats_tags"] = out
    return doc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--ip", required=True)
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--name", default=DEFAULT_CLUSTER)
    p.add_argument("--otel-ip")
    p.add_argument("--otel-port", type=int, default=4317)
    p.add_argument("--otel-name", default=DEFAULT_OTEL_CLUSTER)
    p.add_argument(
        "--otel-stats-sink",
        action="store_true",
        help="Add envoy.stat_sinks.open_telemetry (crash-loops Cilium Envoy 1.36)",
    )
    args = p.parse_args(argv)
    with open(args.input, encoding="utf-8") as f:
        doc = json.load(f)
    merge_bootstrap(doc, args.ip, args.port, args.name)
    if args.otel_ip:
        merge_otel(
            doc,
            args.otel_ip,
            args.otel_port,
            args.otel_name,
            stats_sink=args.otel_stats_sink,
        )
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
