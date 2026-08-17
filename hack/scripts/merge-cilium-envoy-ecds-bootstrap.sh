#!/usr/bin/env bash
# Merge STATIC kubewaf_ecds into cilium-envoy bootstrap.
#
# Cilium xDS has no ECDS. A CEC-defined cluster is not bootstrap-static, so Envoy
# rejects: ApiConfigSource must have a statically defined non-EDS cluster: 'kubewaf_ecds'
#
# Cilium 1.19 chart JSON is protojson camelCase (staticResources). The merge
# rewrites those keys to snake_case before adding clusters — a sibling
# static_resources key is a duplicate field and crash-loops cilium-envoy.
#
# Usage:
#   merge-cilium-envoy-ecds-bootstrap.sh [--apply] [--helm-upgrade]
#     [--ecds-namespace kubewaf-system] [--ecds-service kubewaf-ecds]
#     [--cm-namespace kube-system] [--cm-name cilium-envoy-bootstrap-kubewaf]
#     [--ecds-cluster-ip IP] [--ecds-port PORT] [--ecds-cluster-name kubewaf_ecds]
#     [--otel-service NAME] [--otel-namespace NS] [--otel-cluster-ip IP]
#     [--otel-port PORT] [--otel-cluster-name kubewaf_otel]
#
# --apply writes the ConfigMap and restarts ds/cilium-envoy when that CM is
# already Cilium's envoy.bootstrapConfigMap (ClusterIP churn). --helm-upgrade
# also sets envoy.bootstrapConfigMap using the *installed* Cilium chart version
# (--set-string). Never restarts ds/cilium.
#
# ClusterIP MUST be the kubeWAF ECDS Service (hostNetwork cannot use *.svc DNS).
# STATIC pin: if the Service is deleted, that IP can be reused by another
# Service — re-merge or revert the bootstrap cluster. This script does not
# configure TLS on ECDS.
#
# Uninstall / revert:
#   helm upgrade <cilium-release> <same-chart> -n kube-system --reuse-values \
#     --version <installed> --set-string envoy.bootstrapConfigMap=""
#   kubectl -n kube-system delete cm cilium-envoy-bootstrap-kubewaf
#   kubectl -n kube-system rollout restart ds/cilium-envoy
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APPLY=0
HELM_UPGRADE=0
ECDS_NS="${KUBEWAF_ECDS_NAMESPACE:-kubewaf-system}"
ECDS_SVC="${KUBEWAF_ECDS_SERVICE:-kubewaf-ecds}"
CM_NS="${KUBEWAF_CILIUM_CM_NAMESPACE:-kube-system}"
CM_NAME="${KUBEWAF_CILIUM_CM_NAME:-cilium-envoy-bootstrap-kubewaf}"
ECDS_IP="${KUBEWAF_ECDS_CLUSTER_IP:-}"
ECDS_PORT="${KUBEWAF_ECDS_PORT:-}"
ECDS_CLUSTER_NAME="${KUBEWAF_ECDS_CLUSTER_NAME:-kubewaf_ecds}"
OTEL_NS="${KUBEWAF_OTEL_NAMESPACE:-}"
OTEL_SVC="${KUBEWAF_OTEL_SERVICE:-}"
OTEL_IP="${KUBEWAF_OTEL_CLUSTER_IP:-}"
OTEL_PORT="${KUBEWAF_OTEL_PORT:-}"
OTEL_CLUSTER_NAME="${KUBEWAF_OTEL_CLUSTER_NAME:-kubewaf_otel}"
OTEL_STATUS_NS="${KUBEWAF_OTEL_STATUS_NAMESPACE:-}"
CILIUM_NS="${KUBEWAF_CILIUM_NAMESPACE:-kube-system}"
CILIUM_RELEASE="${KUBEWAF_CILIUM_RELEASE:-cilium}"
CILIUM_CHART="${KUBEWAF_CILIUM_CHART:-cilium/cilium}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --helm-upgrade) APPLY=1; HELM_UPGRADE=1; shift ;;
    --ecds-namespace) ECDS_NS="$2"; shift 2 ;;
    --ecds-service) ECDS_SVC="$2"; shift 2 ;;
    --cm-namespace) CM_NS="$2"; shift 2 ;;
    --cm-name) CM_NAME="$2"; shift 2 ;;
    --ecds-cluster-ip) ECDS_IP="$2"; shift 2 ;;
    --ecds-port) ECDS_PORT="$2"; shift 2 ;;
    --ecds-cluster-name) ECDS_CLUSTER_NAME="$2"; shift 2 ;;
    --otel-namespace) OTEL_NS="$2"; shift 2 ;;
    --otel-service) OTEL_SVC="$2"; shift 2 ;;
    --otel-cluster-ip) OTEL_IP="$2"; shift 2 ;;
    --otel-port) OTEL_PORT="$2"; shift 2 ;;
    --otel-cluster-name) OTEL_CLUSTER_NAME="$2"; shift 2 ;;
    --otel-status-namespace) OTEL_STATUS_NS="$2"; shift 2 ;;
    --cilium-namespace) CILIUM_NS="$2"; shift 2 ;;
    --cilium-release) CILIUM_RELEASE="$2"; shift 2 ;;
    --cilium-chart) CILIUM_CHART="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,28p' "$0"
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "need $1" >&2; exit 1; }; }
need kubectl
need python3

dns1123() {
  local s="$1" what="$2"
  if [[ -z "$s" || ${#s} -gt 63 || ! "$s" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    echo "invalid ${what}: ${s@Q} (need DNS-1123 label)" >&2
    exit 1
  fi
}

envoy_name() {
  local s="$1"
  if [[ -z "$s" || ! "$s" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
    echo "invalid Envoy cluster name: ${s@Q}" >&2
    exit 1
  fi
  if [[ "$s" == "xds-grpc-cilium" ]]; then
    echo "ECDS cluster name must not replace xds-grpc-cilium" >&2
    exit 1
  fi
}

chart_ref() {
  local s="$1"
  if [[ -z "$s" || "$s" == -* ]]; then
    echo "invalid Cilium chart ref: ${s@Q}" >&2
    exit 1
  fi
  if [[ "$s" == oci://* ]]; then
    return 0
  fi
  if [[ "$s" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    return 0
  fi
  echo "Cilium chart must be repo/name or oci://... (got ${s@Q})" >&2
  exit 1
}

dns1123 "$ECDS_NS" "ECDS namespace"
dns1123 "$ECDS_SVC" "ECDS Service"
dns1123 "$CM_NS" "bootstrap ConfigMap namespace"
dns1123 "$CM_NAME" "bootstrap ConfigMap name"
dns1123 "$CILIUM_NS" "Cilium namespace"
dns1123 "$CILIUM_RELEASE" "Cilium Helm release"
envoy_name "$ECDS_CLUSTER_NAME"
envoy_name "$OTEL_CLUSTER_NAME"
chart_ref "$CILIUM_CHART"
OTEL_NS="${OTEL_NS:-$ECDS_NS}"
OTEL_STATUS_NS="${OTEL_STATUS_NS:-$ECDS_NS}"
if [[ -n "$OTEL_NS" ]]; then dns1123 "$OTEL_NS" "OTel namespace"; fi
if [[ -n "$OTEL_SVC" ]]; then dns1123 "$OTEL_SVC" "OTel Service"; fi
dns1123 "$OTEL_STATUS_NS" "OTel status ConfigMap namespace"

resolve_ecds_service() {
  local json count
  if kubectl -n "$ECDS_NS" get svc "$ECDS_SVC" >/dev/null 2>&1; then
    json="$(kubectl -n "$ECDS_NS" get svc "$ECDS_SVC" -o json)"
  else
    json="$(kubectl -n "$ECDS_NS" get svc -l app.kubernetes.io/component=ecds -o json)"
    count="$(python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("items") or []))' <<<"$json")"
    if [[ "$count" != "1" ]]; then
      echo "need exactly one ECDS Service in ${ECDS_NS} (name ${ECDS_SVC} missing; label matches=${count})" >&2
      exit 1
    fi
  fi
  python3 - "$json" "$ECDS_PORT" <<'PY'
import ipaddress, json, sys

doc = json.loads(sys.argv[1])
port_override = sys.argv[2]
obj = doc["items"][0] if "items" in doc else doc
spec = obj.get("spec") or {}
ip = spec.get("clusterIP") or ""
if not ip or ip in ("None", "none"):
    raise SystemExit("ECDS Service ClusterIP is empty/None")
ipaddress.ip_address(ip)
port = ""
for p in spec.get("ports") or []:
    if p.get("name") == "ecds":
        port = str(p.get("port") or "")
        break
if port_override:
    port = port_override
if not port:
    raise SystemExit("ECDS Service has no port named ecds")
print(ip)
print(port)
print(obj.get("metadata", {}).get("name", ""))
PY
}

readarray -t _ecds < <(resolve_ecds_service)
ECDS_IP="${ECDS_IP:-${_ecds[0]}}"
ECDS_PORT="${ECDS_PORT:-${_ecds[1]}}"
if [[ -z "$ECDS_IP" || "$ECDS_IP" == "None" ]]; then
  echo "could not resolve kubeWAF ECDS Service ClusterIP in ${ECDS_NS}/${ECDS_SVC}" >&2
  exit 1
fi
python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$ECDS_IP" \
  || { echo "ECDS ClusterIP is not an IP: ${ECDS_IP}" >&2; exit 1; }

# Exact Service name only (do not use items[0] label lookup for Collector).
resolve_otel_service() {
  if [[ -n "$OTEL_IP" ]]; then
    if [[ -z "$OTEL_PORT" ]]; then
      OTEL_PORT=4317
    fi
    return 0
  fi
  if [[ -z "$OTEL_SVC" ]]; then
    return 1
  fi
  if ! kubectl -n "$OTEL_NS" get svc "$OTEL_SVC" >/dev/null 2>&1; then
    echo "note: Collector Service ${OTEL_NS}/${OTEL_SVC} not found; merging ECDS-only (remesh after Collector exists)" >&2
    return 1
  fi
  local json ip port
  json="$(kubectl -n "$OTEL_NS" get svc "$OTEL_SVC" -o json)"
  readarray -t _otel < <(python3 - "$json" "$OTEL_PORT" <<'PY'
import ipaddress, json, sys
doc = json.loads(sys.argv[1])
port_override = sys.argv[2]
if "items" in doc:
    raise SystemExit("otel lookup must use an exact Service name, not a list")
spec = doc.get("spec") or {}
ip = spec.get("clusterIP") or ""
if not ip or ip in ("None", "none"):
    raise SystemExit("OTel Service ClusterIP is empty/None")
ipaddress.ip_address(ip)
port = ""
for p in spec.get("ports") or []:
    if p.get("name") in ("otlp-grpc", "grpc", "otlp") or int(p.get("port") or 0) == 4317:
        port = str(p.get("port") or "")
        break
if port_override:
    port = port_override
if not port:
    port = "4317"
print(ip)
print(port)
PY
)
  OTEL_IP="${_otel[0]}"
  OTEL_PORT="${_otel[1]}"
}

OTEL_MERGED=0
if resolve_otel_service; then
  python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$OTEL_IP" \
    || { echo "OTel ClusterIP is not an IP: ${OTEL_IP}" >&2; exit 1; }
  OTEL_MERGED=1
fi

dump_from_cm() {
  local ns="$1" name="$2"
  [[ -n "$name" ]] || return 1
  kubectl -n "$ns" get configmap "$name" >/dev/null 2>&1 || return 1
  local data
  data="$(kubectl -n "$ns" get configmap "$name" -o jsonpath='{.data.bootstrap-config\.json}' 2>/dev/null || true)"
  [[ -n "$data" ]] || return 1
  if ! printf '%s' "$data" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
    return 1
  fi
  printf '%s' "$data"
}

dump_from_ds() {
  local ns="$1" ds="$2" container="$3"
  kubectl -n "$ns" get ds "$ds" >/dev/null 2>&1 || return 1
  local path
  for path in /var/run/cilium/envoy/bootstrap-config.json /etc/cilium/envoy/bootstrap-config.json; do
    if kubectl -n "$ns" exec "ds/${ds}" -c "$container" -- cat "$path" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

current_cm=""
if command -v helm >/dev/null 2>&1; then
  current_cm="$(helm get values "$CILIUM_RELEASE" -n "$CILIUM_NS" -o json 2>/dev/null \
    | python3 -c 'import json,sys
try:
    v=json.load(sys.stdin)
except Exception:
    v={}
print(((v or {}).get("envoy") or {}).get("bootstrapConfigMap") or "")' || true)"
fi

# Prefer the ConfigMap Envoy actually starts from. Cilium 1.19's chart JSON is
# protojson camelCase (staticResources). Exec is a fallback when that CM is gone.
BOOTSTRAP=""
if BOOTSTRAP="$(dump_from_cm "$CM_NS" "$current_cm")"; then
  echo "dumped bootstrap from ConfigMap ${CM_NS}/${current_cm}" >&2
elif BOOTSTRAP="$(dump_from_cm "$CILIUM_NS" cilium-envoy-config)"; then
  echo "dumped bootstrap from ConfigMap ${CILIUM_NS}/cilium-envoy-config" >&2
elif BOOTSTRAP="$(dump_from_ds "$CILIUM_NS" cilium-envoy cilium-envoy)"; then
  echo "dumped bootstrap via kubectl exec ds/cilium-envoy -c cilium-envoy" >&2
elif BOOTSTRAP="$(dump_from_ds "$CILIUM_NS" cilium-envoy envoy)"; then
  echo "dumped bootstrap via kubectl exec ds/cilium-envoy -c envoy" >&2
else
  echo "could not dump bootstrap from ConfigMap cilium-envoy-config or kubectl exec ds/cilium-envoy" >&2
  exit 1
fi

tmp_in="$(mktemp)"
tmp_json="$(mktemp)"
tmp_yaml="$(mktemp)"
tmp_prev="$(mktemp)"
cleanup() { rm -f "$tmp_in" "$tmp_json" "$tmp_yaml" "$tmp_prev"; }
trap cleanup EXIT
printf '%s' "$BOOTSTRAP" >"$tmp_in"

MERGE_ARGS=(--ip "$ECDS_IP" --port "$ECDS_PORT" --name "$ECDS_CLUSTER_NAME")
if [[ "$OTEL_MERGED" -eq 1 ]]; then
  MERGE_ARGS+=(--otel-ip "$OTEL_IP" --otel-port "$OTEL_PORT" --otel-name "$OTEL_CLUSTER_NAME")
fi
python3 "$HERE/cilium_envoy_ecds_merge.py" "$tmp_in" "$tmp_json" "${MERGE_ARGS[@]}"
python3 - "$tmp_json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
if "staticResources" in doc:
    raise SystemExit("merged bootstrap still has camelCase staticResources (duplicate-key crash)")
sr = doc.get("static_resources") or {}
names = [c.get("name", "?") for c in sr.get("clusters") or []]
print("merged clusters: " + ", ".join(names), file=sys.stderr)
PY

kubectl create configmap "$CM_NAME" -n "$CM_NS" \
  --from-file=bootstrap-config.json="$tmp_json" \
  --dry-run=client -o yaml >"$tmp_yaml"

write_otel_status_cm() {
  local merged="$1"
  # Script-owned; Helm must not create or overwrite kubewaf-cilium-otel.
  kubectl create configmap kubewaf-cilium-otel -n "$OTEL_STATUS_NS" \
    --from-literal=ciliumOtelMerged="$merged" \
    --dry-run=client -o yaml | kubectl apply -f -
}

prev_cm=""
if [[ "$APPLY" -eq 1 ]]; then
  prev_cm="$(dump_from_cm "$CM_NS" "$CM_NAME" || true)"
  kubectl apply -f "$tmp_yaml"
  echo "applied ConfigMap ${CM_NS}/${CM_NAME} (${ECDS_CLUSTER_NAME}=${ECDS_IP}:${ECDS_PORT})"
  if [[ "$OTEL_MERGED" -eq 1 ]]; then
    echo "merged ${OTEL_CLUSTER_NAME}=${OTEL_IP}:${OTEL_PORT} (HTTP/2 STATIC) + stats_tags (no OTel stats sink; Cilium Envoy 1.36 crash-loops on it)"
    write_otel_status_cm true
  else
    echo "note: Collector absent — ECDS-only merge; remesh with --otel-service after the Collector Service exists"
    write_otel_status_cm false
  fi
  echo "note: STATIC ClusterIP is pinned; if the ECDS Service is deleted that IP can be reused. Re-merge or revert on uninstall (see script header)."
else
  cat "$tmp_yaml"
  echo "# dry-run; re-run with --apply to write ${CM_NS}/${CM_NAME}" >&2
  echo "# helm upgrade must pass --version <installed Cilium chart> (never unpinned)" >&2
  if [[ "$OTEL_MERGED" -ne 1 ]]; then
    echo "# Collector absent: ECDS-only. After Collector exists: --otel-service ${OTEL_SVC:-kubewaf-otel-collector}" >&2
  fi
fi

cilium_chart_version() {
  helm get metadata "$CILIUM_RELEASE" -n "$CILIUM_NS" 2>/dev/null \
    | awk -F': *' '/^VERSION:/{print $2; exit}'
}

restart_cilium_envoy() {
  if ! kubectl -n "$CILIUM_NS" get ds cilium-envoy >/dev/null 2>&1; then
    echo "ds/cilium-envoy not found; not restarting ds/cilium (would bounce the CNI)" >&2
    return 0
  fi
  kubectl -n "$CILIUM_NS" rollout restart ds/cilium-envoy
  if ! kubectl -n "$CILIUM_NS" rollout status ds/cilium-envoy --timeout=5m; then
    echo "cilium-envoy rollout failed; last logs:" >&2
    kubectl -n "$CILIUM_NS" logs -l k8s-app=cilium-envoy --tail=80 --all-containers --prefix 2>&1 || true
    kubectl -n "$CILIUM_NS" describe pod -l k8s-app=cilium-envoy 2>&1 | tail -80 || true
    return 1
  fi
}

if [[ "$HELM_UPGRADE" -eq 1 ]]; then
  need helm
  if [[ "$current_cm" == "$CM_NAME" ]]; then
    echo "Cilium release ${CILIUM_RELEASE} already uses envoy.bootstrapConfigMap=${CM_NAME}; skip helm upgrade"
  else
    ver="$(cilium_chart_version)"
    if [[ -z "$ver" ]]; then
      echo "cannot resolve installed Cilium chart version for ${CILIUM_RELEASE}; refuse unpinned helm upgrade" >&2
      exit 1
    fi
    helm upgrade "$CILIUM_RELEASE" "$CILIUM_CHART" -n "$CILIUM_NS" --reuse-values \
      --version "$ver" --set-string "envoy.bootstrapConfigMap=${CM_NAME}"
    current_cm="$CM_NAME"
  fi
  restart_cilium_envoy
  echo "cilium-envoy bootstrap ConfigMap ${CM_NAME} (${ECDS_CLUSTER_NAME} STATIC ${ECDS_IP}:${ECDS_PORT})"
elif [[ "$APPLY" -eq 1 ]]; then
  if [[ "$current_cm" == "$CM_NAME" ]]; then
    printf '%s' "$prev_cm" >"$tmp_prev"
    if [[ -n "$prev_cm" ]] && python3 -c 'import json,sys
a=json.load(open(sys.argv[1], encoding="utf-8"))
b=json.load(open(sys.argv[2], encoding="utf-8"))
raise SystemExit(0 if a==b else 1)' "$tmp_json" "$tmp_prev"; then
      echo "bootstrap ConfigMap ${CM_NAME} unchanged; skip cilium-envoy restart"
    else
      echo "ConfigMap already referenced by Cilium; rolling ds/cilium-envoy to pick up ClusterIP"
      restart_cilium_envoy
    fi
  else
    echo "ConfigMap written but Cilium envoy.bootstrapConfigMap is ${current_cm:-unset}; point Helm at ${CM_NAME} (pinned --version) then rollout ds/cilium-envoy" >&2
  fi
fi
