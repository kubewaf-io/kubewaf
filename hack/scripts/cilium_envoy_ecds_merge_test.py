#!/usr/bin/env python3
"""Fixture tests for cilium_envoy_ecds_merge.merge_bootstrap."""

import copy
import unittest

from cilium_envoy_ecds_merge import (
    DEFAULT_OTEL_CLUSTER,
    XDS_GRPC_CILIUM,
    merge_bootstrap,
    merge_otel,
    normalize_bootstrap_keys,
)


def _fixture():
    return {
        "static_resources": {
            "clusters": [
                {"name": XDS_GRPC_CILIUM, "type": "STATIC"},
                {"name": "other"},
            ]
        }
    }


class MergeBootstrapTest(unittest.TestCase):
    def test_keeps_xds_and_adds_static_ecds(self):
        out = merge_bootstrap(_fixture(), "10.96.1.2", 18001, "kubewaf_ecds")
        names = [c["name"] for c in out["static_resources"]["clusters"]]
        self.assertEqual(names.count(XDS_GRPC_CILIUM), 1)
        self.assertEqual(names.count("kubewaf_ecds"), 1)
        ecds = next(c for c in out["static_resources"]["clusters"] if c["name"] == "kubewaf_ecds")
        self.assertEqual(ecds["type"], "STATIC")
        sock = ecds["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"][
            "socket_address"
        ]
        self.assertEqual(sock["address"], "10.96.1.2")
        self.assertEqual(sock["port_value"], 18001)
        self.assertIn("other", names)
        http2 = ecds["typed_extension_protocol_options"][
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
        ]
        self.assertIn("http2_protocol_options", http2["explicit_http_config"])

    def test_idempotent_replaces_existing(self):
        first = merge_bootstrap(_fixture(), "10.96.1.2", 18001, "kubewaf_ecds")
        second = merge_bootstrap(copy.deepcopy(first), "10.96.9.9", 18001, "kubewaf_ecds")
        names = [c["name"] for c in second["static_resources"]["clusters"]]
        self.assertEqual(names.count("kubewaf_ecds"), 1)
        ecds = next(c for c in second["static_resources"]["clusters"] if c["name"] == "kubewaf_ecds")
        sock = ecds["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"][
            "socket_address"
        ]
        self.assertEqual(sock["address"], "10.96.9.9")

    def test_rejects_empty_or_none_ip(self):
        for ip in ("", "None", "not-an-ip", "kubewaf-ecds.svc"):
            with self.subTest(ip=ip):
                with self.assertRaises((ValueError, OSError)):
                    merge_bootstrap(_fixture(), ip, 18001, "kubewaf_ecds")

    def test_preserves_static_xds_when_present(self):
        out = merge_bootstrap(_fixture(), "10.96.1.2", 18001, "kubewaf_ecds")
        names = [c["name"] for c in out["static_resources"]["clusters"]]
        self.assertEqual(names.count(XDS_GRPC_CILIUM), 1)

    def test_allows_empty_static_clusters_cilium119(self):
        doc = {"static_resources": {"clusters": []}}
        out = merge_bootstrap(doc, "10.96.1.2", 18001, "kubewaf_ecds")
        names = [c["name"] for c in out["static_resources"]["clusters"]]
        self.assertIn(XDS_GRPC_CILIUM, names)
        self.assertIn("kubewaf_ecds", names)
        xds = next(c for c in out["static_resources"]["clusters"] if c["name"] == XDS_GRPC_CILIUM)
        pipe = xds["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["pipe"]
        self.assertEqual(pipe["path"], "/var/run/cilium/envoy/sockets/xds.sock")

    def test_custom_cluster_name(self):
        out = merge_bootstrap(_fixture(), "2001:db8::1", 18001, "custom_ecds")
        names = [c["name"] for c in out["static_resources"]["clusters"]]
        self.assertIn("custom_ecds", names)
        self.assertNotIn("kubewaf_ecds", names)

    def test_rejects_empty_name_and_invalid_port(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            merge_bootstrap(_fixture(), "10.96.1.2", 18001, "")
        with self.assertRaisesRegex(ValueError, "empty"):
            merge_bootstrap(_fixture(), "10.96.1.2", 18001, "  ")
        for port in (0, -1, 65536):
            with self.subTest(port=port):
                with self.assertRaisesRegex(ValueError, "invalid port"):
                    merge_bootstrap(_fixture(), "10.96.1.2", port, "kubewaf_ecds")

    def test_rejects_replacing_xds_grpc_cilium(self):
        with self.assertRaisesRegex(ValueError, XDS_GRPC_CILIUM):
            merge_bootstrap(_fixture(), "10.96.1.2", 18001, XDS_GRPC_CILIUM)

    def test_merge_otel_http2_sink_and_tags(self):
        doc = merge_bootstrap(_fixture(), "10.96.1.2", 18001, "kubewaf_ecds")
        out = merge_otel(doc, "10.96.9.9", 4317)
        names = [c["name"] for c in out["static_resources"]["clusters"]]
        self.assertEqual(names.count(XDS_GRPC_CILIUM), 1)
        self.assertEqual(names.count("kubewaf_ecds"), 1)
        self.assertEqual(names.count(DEFAULT_OTEL_CLUSTER), 1)
        otel = next(c for c in out["static_resources"]["clusters"] if c["name"] == DEFAULT_OTEL_CLUSTER)
        self.assertEqual(otel["type"], "STATIC")
        http2 = otel["typed_extension_protocol_options"][
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
        ]
        self.assertIn("http2_protocol_options", http2["explicit_http_config"])
        sock = otel["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"][
            "socket_address"
        ]
        self.assertEqual(sock["address"], "10.96.9.9")
        self.assertEqual(sock["port_value"], 4317)
        self.assertNotIn("stats_sinks", out)
        tags = [t["tag_name"] for t in out["stats_config"]["stats_tags"]]
        self.assertLess(tags.index("tag"), tags.index("phase"))
        self.assertTrue({"waf_namespace", "waf_name", "engine", "owner", "phase", "tag"} <= set(tags))

    def test_merge_otel_optional_stats_sink(self):
        out = merge_otel(merge_bootstrap(_fixture(), "10.96.1.2", 18001), "10.96.9.9", 4317, stats_sink=True)
        sinks = out["stats_sinks"]
        self.assertEqual(len(sinks), 1)
        self.assertEqual(sinks[0]["name"], "envoy.stat_sinks.open_telemetry")
        self.assertEqual(
            sinks[0]["typed_config"]["grpc_service"]["envoy_grpc"]["cluster_name"],
            DEFAULT_OTEL_CLUSTER,
        )
        self.assertNotIn("custom_metric_conversions", sinks[0]["typed_config"])

    def test_merge_otel_idempotent(self):
        first = merge_otel(merge_bootstrap(_fixture(), "10.96.1.2", 18001), "10.96.9.9", 4317)
        second = merge_otel(copy.deepcopy(first), "10.96.8.8", 4317)
        names = [c["name"] for c in second["static_resources"]["clusters"]]
        self.assertEqual(names.count(DEFAULT_OTEL_CLUSTER), 1)
        otel = next(c for c in second["static_resources"]["clusters"] if c["name"] == DEFAULT_OTEL_CLUSTER)
        sock = otel["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"][
            "socket_address"
        ]
        self.assertEqual(sock["address"], "10.96.8.8")
        self.assertNotIn("stats_sinks", second)

    def test_ecds_only_has_no_otel(self):
        out = merge_bootstrap(_fixture(), "10.96.1.2", 18001)
        names = [c["name"] for c in out["static_resources"]["clusters"]]
        self.assertNotIn(DEFAULT_OTEL_CLUSTER, names)
        self.assertNotIn("stats_sinks", out)

    def test_cilium119_camelcase_chart_bootstrap_keeps_xds_and_no_duplicate_key(self):
        # Helm fromYaml|toJson of files/cilium-envoy/configmap/bootstrap-config.yaml
        doc = {
            "node": {"id": "host~127.0.0.1~no-id~localdomain", "cluster": "ingress-cluster"},
            "staticResources": {
                "listeners": [{"name": "envoy-health-listener"}],
                "clusters": [
                    {"name": "ingress-cluster", "type": "ORIGINAL_DST"},
                    {
                        "name": XDS_GRPC_CILIUM,
                        "type": "STATIC",
                        "loadAssignment": {
                            "clusterName": XDS_GRPC_CILIUM,
                            "endpoints": [
                                {
                                    "lbEndpoints": [
                                        {
                                            "endpoint": {
                                                "address": {
                                                    "pipe": {
                                                        "path": "/var/run/cilium/envoy/sockets/xds.sock"
                                                    }
                                                }
                                            }
                                        }
                                    ]
                                }
                            ],
                        },
                    },
                    {"name": "/envoy-admin", "type": "STATIC"},
                ],
            },
            "dynamicResources": {
                "ldsConfig": {"apiConfigSource": {"apiType": "GRPC"}},
            },
        }
        out = merge_bootstrap(doc, "10.96.38.115", 18001, "kubewaf_ecds")
        self.assertNotIn("staticResources", out)
        self.assertNotIn("dynamicResources", out)
        self.assertIn("static_resources", out)
        self.assertIn("dynamic_resources", out)
        names = [c["name"] for c in out["static_resources"]["clusters"]]
        self.assertEqual(names.count(XDS_GRPC_CILIUM), 1)
        self.assertEqual(names.count("kubewaf_ecds"), 1)
        self.assertIn("ingress-cluster", names)
        self.assertIn("/envoy-admin", names)
        self.assertEqual(len(out["static_resources"]["listeners"]), 1)
        xds = next(c for c in out["static_resources"]["clusters"] if c["name"] == XDS_GRPC_CILIUM)
        self.assertEqual(
            xds["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["pipe"][
                "path"
            ],
            "/var/run/cilium/envoy/sockets/xds.sock",
        )
        ecds = next(c for c in out["static_resources"]["clusters"] if c["name"] == "kubewaf_ecds")
        sock = ecds["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"][
            "socket_address"
        ]
        self.assertEqual(sock["address"], "10.96.38.115")
        self.assertEqual(sock["port_value"], 18001)

    def test_normalize_merges_mixed_static_resources_keys(self):
        doc = {
            "staticResources": {"clusters": [{"name": XDS_GRPC_CILIUM}]},
            "static_resources": {"clusters": [{"name": "other"}]},
        }
        out = normalize_bootstrap_keys(doc)
        names = {c["name"] for c in out["static_resources"]["clusters"]}
        self.assertEqual(names, {XDS_GRPC_CILIUM, "other"})
        self.assertNotIn("staticResources", out)


if __name__ == "__main__":
    unittest.main()
