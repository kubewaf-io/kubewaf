/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package xdsutil

import (
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	otelaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/open_telemetry/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	otlpcommon "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
)

const (
	otelStringValueKey = "string_value"
	// OTelAccessLogName is the HCM access logger name (idempotent inject key).
	OTelAccessLogName = "envoy.access_loggers.open_telemetry"
	// OTelAccessLogStatPrefix is the Envoy stats prefix for the WAF access logger.
	OTelAccessLogStatPrefix = "kubewaf"
	// WasmMetadataFilter is the historical dynamic-metadata namespace. Envoy
	// 1.38 Wasm setProperty cannot write it; the live gate is CEL filter state.
	WasmMetadataFilter = "envoy.filters.http.wasm"
	// FilterStateEventKey is the Envoy-prefixed CelState key for the rollup.
	// Wasm calls setFilterState("kubewaf.event"); Envoy stores wasm.kubewaf.event.
	FilterStateEventKey = "wasm.kubewaf.event"
	// FilterStateExportKey is the Envoy-prefixed CelState export flag.
	FilterStateExportKey = "wasm.kubewaf.export"
	// CELAccessLogFilterName is the Envoy CEL access-log extension.
	CELAccessLogFilterName = "envoy.access_loggers.extension_filters.cel"
	// CELExportExpression is fail-closed: only annotated streams are logged.
	// Envoy 1.38 CEL rejects has(map[index]); compare the value instead.
	CELExportExpression = "filter_state['wasm.kubewaf.export'] == '1'"
)

// HasOTelAccessLog reports whether mgr already has the kubeWAF OTel logger.
// Platform APM loggers also use envoy.access_loggers.open_telemetry — key on stat_prefix.
func HasOTelAccessLog(mgr *hcm.HttpConnectionManager) bool {
	if mgr == nil {
		return false
	}
	for _, al := range mgr.AccessLog {
		cfg := al.GetTypedConfig()
		if cfg == nil {
			continue
		}
		var otel otelaccesslog.OpenTelemetryAccessLogConfig
		if err := cfg.UnmarshalTo(&otel); err == nil && otel.GetStatPrefix() == OTelAccessLogStatPrefix {
			return true
		}
	}
	return false
}

// AppendOTelAccessLog adds the second HCM access logger (KD-34) when missing.
func AppendOTelAccessLog(mgr *hcm.HttpConnectionManager, cluster string) error {
	if mgr == nil {
		return nil
	}
	if HasOTelAccessLog(mgr) {
		return nil
	}
	al, err := MakeOTelAccessLog(cluster)
	if err != nil {
		return err
	}
	mgr.AccessLog = append(mgr.AccessLog, al)
	return nil
}

// MakeOTelAccessLog builds envoy.access_loggers.open_telemetry filtered on Wasm export metadata.
func MakeOTelAccessLog(cluster string) (*accesslog.AccessLog, error) {
	if cluster == "" {
		cluster = config.DefaultOTelCluster
	}
	cfg := &otelaccesslog.OpenTelemetryAccessLogConfig{
		GrpcService: &core.GrpcService{
			TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: cluster},
			},
		},
		DisableBuiltinLabels: true,
		StatPrefix:           OTelAccessLogStatPrefix,
		ResourceAttributes: &otlpcommon.KeyValueList{
			Values: []*otlpcommon.KeyValue{
				strKV("service.name", "kubewaf"),
			},
		},
		Body: &otlpcommon.AnyValue{
			Value: &otlpcommon.AnyValue_StringValue{
				StringValue: "%FILTER_STATE(" + FilterStateEventKey + ":PLAIN)%",
			},
		},
		Attributes: &otlpcommon.KeyValueList{
			Values: []*otlpcommon.KeyValue{
				strKV("http.request.method", "%REQ(:METHOD)%"),
				// REQ_WITHOUT_QUERY is not in Envoy 1.38 (EG 1.8). Strip query in Collector.
				strKV("url.path", "%REQ(:PATH)%"),
				strKV("http.response.status_code", "%RESPONSE_CODE%"),
				strKV("waf.request_id", "%REQ(X-REQUEST-ID)%"),
				strKV("traceparent", "%REQ(TRACEPARENT)%"),
			},
		},
	}
	anyCfg, err := anypb.New(cfg)
	if err != nil {
		return nil, err
	}
	// No HCM filter: Envoy 1.38 Wasm cannot write dynamic metadata, and CEL
	// filter_state map-index is either rejected (has()) or does not see
	// wasm.* CelState. The logger body is %FILTER_STATE(wasm.kubewaf.event)%;
	// Collector transform/filter keeps only event JSON → waf.eval spans.
	return &accesslog.AccessLog{
		Name:       OTelAccessLogName,
		ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: anyCfg},
	}, nil
}

func strKV(key, val string) *otlpcommon.KeyValue {
	return &otlpcommon.KeyValue{
		Key: key,
		Value: &otlpcommon.AnyValue{
			Value: &otlpcommon.AnyValue_StringValue{StringValue: val},
		},
	}
}

func otelString(val string) map[string]any {
	return map[string]any{otelStringValueKey: val}
}

func otelStringKV(key, val string) map[string]any {
	return map[string]any{"key": key, "value": otelString(val)}
}

// OTelAccessLogMap is the unstructured HCM access_log entry (Istio MERGE / CEC).
func OTelAccessLogMap(cluster string) map[string]any {
	if cluster == "" {
		cluster = config.DefaultOTelCluster
	}
	return map[string]any{
		"name": OTelAccessLogName,
		"typed_config": map[string]any{
			"@type":                  "type.googleapis.com/envoy.extensions.access_loggers.open_telemetry.v3.OpenTelemetryAccessLogConfig",
			"disable_builtin_labels": true,
			"stat_prefix":            OTelAccessLogStatPrefix,
			"grpc_service": map[string]any{
				"envoy_grpc": map[string]any{
					"cluster_name": cluster,
				},
			},
			"resource_attributes": map[string]any{
				"values": []any{
					otelStringKV("service.name", "kubewaf"),
				},
			},
			"body": otelString("%FILTER_STATE(" + FilterStateEventKey + ":PLAIN)%"),
			"attributes": map[string]any{
				"values": []any{
					otelStringKV("http.request.method", "%REQ(:METHOD)%"),
					otelStringKV("url.path", "%REQ(:PATH)%"),
					otelStringKV("http.response.status_code", "%RESPONSE_CODE%"),
					otelStringKV("waf.request_id", "%REQ(X-REQUEST-ID)%"),
					otelStringKV("traceparent", "%REQ(TRACEPARENT)%"),
				},
			},
		},
	}
}

// OTelClusterMap is the unstructured CLUSTER ADD value (HTTP/2 STRICT_DNS).
func OTelClusterMap(host string, port uint32) map[string]any {
	if port == 0 {
		port = config.DefaultOTelPort
	}
	return map[string]any{
		"name":            config.DefaultOTelCluster,
		"type":            "STRICT_DNS",
		"connect_timeout": "2s",
		"lb_policy":       "ROUND_ROBIN",
		"typed_extension_protocol_options": map[string]any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				"explicit_http_config": map[string]any{
					"http2_protocol_options": map[string]any{},
				},
			},
		},
		"load_assignment": map[string]any{
			"cluster_name": config.DefaultOTelCluster,
			"endpoints": []any{
				map[string]any{
					"lb_endpoints": []any{
						map[string]any{
							"endpoint": map[string]any{
								"address": map[string]any{
									"socket_address": map[string]any{
										"address":    host,
										"port_value": int64(port),
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
