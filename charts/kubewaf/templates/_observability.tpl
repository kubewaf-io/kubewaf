{{/*
Managed observability helpers. Product path: Envoy OTLP → kubewaf_otel.
*/}}
{{- define "kubewaf.otelCollectorName" -}}
{{- printf "%s-otel-collector" (include "helm.fullname" .) -}}
{{- end -}}

{{/* Stable pod-roll hash. Bump the suffix when transform statements change. */}}
{{- define "kubewaf.otelCollectorChecksum" -}}
{{- $m := .Values.observability.managed -}}
{{- printf "%s|%s|%v|ascore-v1" ($m.profile | default "lite") (include "kubewaf.tracesExportURL" .) $m.victoriaTraces.enabled | sha256sum -}}
{{- end -}}

{{- define "kubewaf.otelHost" -}}
{{- $ep := .Values.observability.managed.otlp.endpoint | default "" -}}
{{- if $ep -}}
{{- $ep | trimPrefix "http://" | trimPrefix "https://" | trimSuffix ":4317" -}}
{{- else -}}
{{- printf "%s.%s.svc.cluster.local" (include "kubewaf.otelCollectorName" .) .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{- define "kubewaf.metricsBackendOK" -}}
{{- $m := .Values.observability.managed -}}
{{- if or $m.victoriaMetrics.enabled (and $m.victoriaMetrics.endpoint) (and $m.prometheusRemoteWrite.enabled $m.prometheusRemoteWrite.endpoint) -}}
true
{{- end -}}
{{- end -}}

{{- define "kubewaf.usePrometheusRemoteWrite" -}}
{{- $m := .Values.observability.managed -}}
{{- if and $m.prometheusRemoteWrite.enabled $m.prometheusRemoteWrite.endpoint -}}
true
{{- end -}}
{{- end -}}

{{- define "kubewaf.metricsExportURL" -}}
{{- $m := .Values.observability.managed -}}
{{- if and $m.prometheusRemoteWrite.enabled $m.prometheusRemoteWrite.endpoint -}}
{{- $m.prometheusRemoteWrite.endpoint -}}
{{- else if $m.victoriaMetrics.endpoint -}}
{{- $m.victoriaMetrics.endpoint -}}
{{- else -}}
{{- printf "http://%s-victoria-metrics.%s.svc.cluster.local:8428/api/v1/write" (include "helm.fullname" .) .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/* True when the metrics backend is Prometheus remote_write (in-cluster VM or user RW). */}}
{{- define "kubewaf.useRemoteWriteMetrics" -}}
{{- $m := .Values.observability.managed -}}
{{- if and $m.prometheusRemoteWrite.enabled $m.prometheusRemoteWrite.endpoint -}}
true
{{- else if $m.victoriaMetrics.endpoint -}}
{{- if or (contains "/api/v1/write" $m.victoriaMetrics.endpoint) (contains "remote_write" $m.victoriaMetrics.endpoint) -}}
true
{{- end -}}
{{- else if $m.victoriaMetrics.enabled -}}
true
{{- end -}}
{{- end -}}

{{- define "kubewaf.vmQueryName" -}}
{{- printf "%s-victoria-metrics" (include "helm.fullname" .) -}}
{{- end -}}

{{- define "kubewaf.vtQueryName" -}}
{{- printf "%s-victoria-traces" (include "helm.fullname" .) -}}
{{- end -}}

{{- define "kubewaf.metricsQueryURL" -}}
{{- printf "http://%s.%s.svc:%v" (include "kubewaf.vmQueryName" .) .Release.Namespace 8428 -}}
{{- end -}}

{{- define "kubewaf.tracesQueryURL" -}}
{{- printf "http://%s.%s.svc:%v" (include "kubewaf.vtQueryName" .) .Release.Namespace 10428 -}}
{{- end -}}

{{- define "kubewaf.tracesExportURL" -}}
{{- $m := .Values.observability.managed -}}
{{- if $m.victoriaTraces.endpoint -}}
{{- $m.victoriaTraces.endpoint -}}
{{- else -}}
{{- printf "http://%s-victoria-traces.%s.svc.cluster.local:10428/insert/opentelemetry/v1/traces" (include "helm.fullname" .) .Release.Namespace -}}
{{- end -}}
{{- end -}}
