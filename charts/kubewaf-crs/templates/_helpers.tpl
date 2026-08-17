{{/*
Expand the name of the chart.
*/}}
{{- define "kubewaf-crs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name.
*/}}
{{- define "kubewaf-crs.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "kubewaf-crs.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "kubewaf-crs.labels" -}}
helm.sh/chart: {{ include "kubewaf-crs.chart" . }}
{{ include "kubewaf-crs.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: coreruleset
coreruleset/version: {{ (.Values.crs.version | default "4.27.0") | quote }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "kubewaf-crs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubewaf-crs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Inject release namespace into a multi-doc YAML blob of namespaced CRs.
Also stamps helm labels under metadata.labels when possible via string form.
*/}}
{{- define "kubewaf-crs.injectNamespace" -}}
{{- $ns := .namespace -}}
{{- $raw := .content -}}
{{- /* Normalize document separators */ -}}
{{- $raw = $raw | replace "\r\n" "\n" -}}
{{- $docs := splitList "\n---" $raw -}}
{{- range $i, $doc := $docs -}}
{{- $doc = trim $doc -}}
{{- if $doc -}}
{{- /* Skip pure comment blocks without apiVersion */ -}}
{{- if contains "apiVersion:" $doc -}}
{{- if contains "\n  namespace:" $doc -}}
{{- $doc = regexReplaceAll "(?m)^  namespace:.*$" (printf "  namespace: %s" $ns) $doc -}}
{{- else if contains "\nmetadata:\n" $doc -}}
{{- $doc = regexReplaceAll "(?m)^(metadata:\n)" (printf "metadata:\n  namespace: %s\n" $ns) $doc -}}
{{- end -}}
---
{{ $doc }}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
SecRule file → coreruleset/file label mapping for includeFiles filter.
Filename pattern: crs-request-913-scanner-detection.yaml → REQUEST-913-SCANNER-DETECTION.conf
*/}}
{{- define "kubewaf-crs.fileKeyFromPath" -}}
{{- $base := base . -}}
{{- $base = trimSuffix ".yaml" $base -}}
{{- /* crs-request-913-scanner-detection → REQUEST-913-SCANNER-DETECTION.conf */ -}}
{{- if hasPrefix "crs-request-" $base -}}
{{- $rest := trimPrefix "crs-request-" $base | upper | replace "-" "-" -}}
{{- printf "REQUEST-%s.conf" ($rest | replace "_" "-") -}}
{{- else if hasPrefix "crs-response-" $base -}}
{{- $rest := trimPrefix "crs-response-" $base | upper -}}
{{- printf "RESPONSE-%s.conf" $rest -}}
{{- else -}}
{{- $base -}}
{{- end -}}
{{- end }}
