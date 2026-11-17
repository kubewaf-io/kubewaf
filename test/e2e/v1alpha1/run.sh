#!/usr/bin/env bash
# Kind e2e for the v1alpha1 operator. Prints the HTTP codes it observes.
# Requires docker, kind, kubectl, helm, and a checkout of this repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
mkdir -p "$ROOT/bin"
CLUSTER="${KIND_CLUSTER:-kubewaf-v1a1}"
NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.34.0}"
OPERATOR_IMAGE="${OPERATOR_IMAGE:-kubewaf-operator:dev}"
KEEP="${E2E_KEEP:-false}"

log() { printf '== %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ "$KEEP" != "true" ]]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || die "missing $1"; }
need docker
need kind
need kubectl
need helm
need go
need curl

log "kind cluster $CLUSTER on $NODE_IMAGE"
# nftables: this kernel has no xt_statistic, so kube-proxy iptables never
# programs ClusterIP (webhook dials time out, Envoy has no listeners). Kind
# on GitHub-hosted runners accepts the same mode.
if ! kind get clusters | grep -qx "$CLUSTER"; then
  cat >"$ROOT/bin/kind-v1alpha1.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  kubeProxyMode: nftables
nodes:
  - role: control-plane
    image: ${NODE_IMAGE}
EOF
  kind create cluster --name "$CLUSTER" --config "$ROOT/bin/kind-v1alpha1.yaml"
fi
kubectl config use-context "kind-$CLUSTER"

load() {
  local img="$1"
  docker pull --platform linux/amd64 "$img" || docker pull "$img"
  python3 "$ROOT/test/e2e/v1alpha1/load_image.py" "$img" "$CLUSTER"
}

log "build operator and composer-cp"
CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "$ROOT/bin/operator" "$ROOT/cmd/operator"
docker build -t "$OPERATOR_IMAGE" -f "$ROOT/Dockerfile.operator" "$ROOT/bin"
python3 "$ROOT/test/e2e/v1alpha1/load_image.py" "$OPERATOR_IMAGE" "$CLUSTER"

cat >"$ROOT/bin/Dockerfile.composer-cp" <<'EOF'
FROM ghcr.io/tetratelabs/built-on-envoy/composer:0.13.0 AS src
FROM busybox:1.36
COPY --from=src /libcomposer.so /libcomposer.so
ENTRYPOINT ["cp", "/libcomposer.so", "/modules/libcomposer.so"]
EOF
docker build -t composer-cp:0.13.0 -f "$ROOT/bin/Dockerfile.composer-cp" "$ROOT/bin"
python3 "$ROOT/test/e2e/v1alpha1/load_image.py" composer-cp:0.13.0 "$CLUSTER"
load docker.io/envoyproxy/gateway:v1.10.0
load docker.io/envoyproxy/envoy:distroless-v1.40.2

log "install Envoy Gateway v1.10.0"
helm upgrade --install eg oci://docker.io/envoyproxy/gateway-helm \
  --version v1.10.0 --namespace envoy-gateway-system --create-namespace \
  --wait --timeout 10m

QUICK="$ROOT/bin/eg-quickstart.yaml"
curl -fsSL -o "$QUICK" https://github.com/envoyproxy/gateway/releases/download/v1.10.0/quickstart.yaml
# Preload backend images referenced by the quickstart.
grep -Eo 'image:[[:space:]]*[^[:space:]]+' "$QUICK" | awk '{print $2}' | sort -u | while read -r img; do
  load "$img" || true
done
kubectl apply -f "$QUICK"
kubectl wait --for=condition=Available deployment/backend -n default --timeout=180s || true

log "platform EnvoyProxy and Gateway parametersRef"
kubectl apply -f "$ROOT/config/samples/envoygateway/platform-envoyproxy.yaml"
kubectl patch gateway eg -n default --type merge -p '{"spec":{"infrastructure":{"parametersRef":{"group":"gateway.envoyproxy.io","kind":"EnvoyProxy","name":"platform"}}}}'
PROXY_BEFORE="$(kubectl get envoyproxy platform -n default -o jsonpath='{.spec}')"
GW_BEFORE="$(kubectl get gateway eg -n default -o jsonpath='{.spec.infrastructure.parametersRef}')"

# Kind has no load balancer. Give the Envoy service the node IP so the Gateway is programmed.
NODE_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CLUSTER}-control-plane")"
for _ in $(seq 1 60); do
  SVC="$(kubectl get svc -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [[ -n "$SVC" ]] && break
  sleep 5
done
[[ -n "${SVC:-}" ]] || die "envoy service for Gateway eg did not appear"
kubectl patch svc "$SVC" -n envoy-gateway-system --subresource=status --type merge \
  -p '{"status":{"loadBalancer":{"ingress":[{"ip":"'"$NODE_IP"'"}]}}}' || true

log "install kubeWAF v1alpha1 chart"
helm upgrade --install kubewaf "$ROOT/charts/kubewaf" \
  --namespace kubewaf-system --create-namespace \
  --set image.repository="${OPERATOR_IMAGE%:*}" \
  --set image.tag="${OPERATOR_IMAGE##*:}" \
  --set image.pullPolicy=IfNotPresent \
  --wait --timeout 5m

kubectl rollout status deployment/kubewaf -n kubewaf-system --timeout=180s
apply_ok=false
for _ in $(seq 1 12); do
  if kubectl apply -f "$ROOT/test/e2e/v1alpha1/block-sqlmap.yaml"; then
    apply_ok=true
    break
  fi
  kubectl get pods -n kubewaf-system -o wide || true
  kubectl logs -n kubewaf-system -l app.kubernetes.io/name=kubewaf --tail=80 || true
  sleep 5
done
[[ "$apply_ok" == "true" ]] || die "SecRule/SecPolicy were not admitted"
kubectl wait --for=condition=Ready secrule/block-sqlmap -n default --timeout=120s
dump_attach() {
  kubectl get secpolicy edge -n default -o yaml || true
  kubectl get envoyextensionpolicy -A -o yaml || true
  kubectl get pods -A -o wide || true
  kubectl logs -n kubewaf-system -l app.kubernetes.io/name=kubewaf --tail=160 || true
  kubectl logs -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg -c envoy --tail=80 || true
}
ready=false
for _ in $(seq 1 48); do
  line="$(kubectl get secpolicy edge -n default -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason} {.message}{" | "}{end}' 2>/dev/null || true)"
  log "secpolicy $line"
  # Match the Ready condition only. EngineReady=True/Ready also contains Ready=True.
  if [[ " $line" == *" Ready=True/"* ]]; then
    ready=true
    break
  fi
  sleep 5
done
if [[ "$ready" != "true" ]]; then
  dump_attach
  die "secpolicy edge did not become Ready"
fi
kubectl get envoyextensionpolicy kubewaf-edge -n default -o yaml || true

NODEPORT="$(kubectl get svc "$SVC" -n envoy-gateway-system -o jsonpath='{.spec.ports[0].nodePort}')"
probe() {
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
    -H 'Host: www.example.com' "$@" "http://${NODE_IP}:${NODEPORT}/" 2>/dev/null || true)"
  if [[ "$code" =~ ^[0-9]{3}$ ]]; then
    printf '%s\n' "$code"
  else
    printf '000\n'
  fi
}

CLEAN=""
SQLMAP=""
for _ in $(seq 1 30); do
  CLEAN="$(probe)"
  SQLMAP="$(probe -H 'User-Agent: sqlmap/1.0')"
  log "probe clean=$CLEAN sqlmap=$SQLMAP"
  [[ "$CLEAN" == "200" && "$SQLMAP" == "403" ]] && break
  sleep 5
done
[[ "$CLEAN" == "200" && "$SQLMAP" == "403" ]] || die "want clean 200 and sqlmap 403, got $CLEAN and $SQLMAP"

log "no operator services on 18001 18002 5005"
if kubectl get svc -n kubewaf-system -o json | grep -E '"port": (18001|18002|5005)' >/dev/null; then
  die "operator namespace still exposes 18001, 18002, or 5005"
fi

PROXY_AFTER="$(kubectl get envoyproxy platform -n default -o jsonpath='{.spec}')"
GW_AFTER="$(kubectl get gateway eg -n default -o jsonpath='{.spec.infrastructure.parametersRef}')"
[[ "$PROXY_BEFORE" == "$PROXY_AFTER" ]] || die "EnvoyProxy spec changed"
[[ "$GW_BEFORE" == "$GW_AFTER" ]] || die "Gateway parametersRef changed"

log "edit the rule and expect the new match without restarting Envoy"
kubectl patch secrule block-sqlmap -n default --type=json \
  -p '[{"op":"replace","path":"/spec/chain/0/operator/value","value":"(?i)badbot"}]'
EDITED_SQL=""
EDITED_BOT=""
for _ in $(seq 1 60); do
  EDITED_SQL="$(probe -H 'User-Agent: sqlmap/1.0')"
  EDITED_BOT="$(probe -H 'User-Agent: badbot/1.0')"
  log "probe after edit sqlmap=$EDITED_SQL badbot=$EDITED_BOT"
  [[ "$EDITED_SQL" == "200" && "$EDITED_BOT" == "403" ]] && break
  sleep 5
done
[[ "$EDITED_SQL" == "200" && "$EDITED_BOT" == "403" ]] || die "want sqlmap 200 and badbot 403 after edit, got $EDITED_SQL and $EDITED_BOT"

log "delete SecPolicy and expect the edited rule to stop blocking"
kubectl delete secpolicy edge -n default --wait=true
for _ in $(seq 1 30); do
  if ! kubectl get envoyextensionpolicy kubewaf-edge -n default >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
kubectl get envoyextensionpolicy kubewaf-edge -n default >/dev/null 2>&1 && die "EnvoyExtensionPolicy was not deleted"
AFTER_DELETE=""
for _ in $(seq 1 30); do
  AFTER_DELETE="$(probe -H 'User-Agent: badbot/1.0')"
  log "probe after delete badbot=$AFTER_DELETE"
  [[ "$AFTER_DELETE" == "200" ]] && break
  sleep 5
done
[[ "$AFTER_DELETE" == "200" ]] || die "want badbot 200 after delete, got $AFTER_DELETE"

log "restore the sqlmap rule and attach it with Protection"
kubectl patch secrule block-sqlmap -n default --type=json \
  -p '[{"op":"replace","path":"/spec/chain/0/operator/value","value":"(?i)sqlmap"}]'
kubectl apply -f "$ROOT/test/e2e/v1alpha1/protection.yaml"
prot_ready=false
for _ in $(seq 1 48); do
  line="$(kubectl get protection edge -n default -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason} {.message}{" | "}{end}' 2>/dev/null || true)"
  log "protection $line"
  if [[ " $line" == *" Ready=True/"* ]]; then
    prot_ready=true
    break
  fi
  sleep 5
done
if [[ "$prot_ready" != "true" ]]; then
  kubectl get protection edge -n default -o yaml || true
  kubectl logs -n kubewaf-system -l app.kubernetes.io/name=kubewaf --tail=160 || true
  die "protection edge did not become Ready"
fi
PROT_CLEAN=""
PROT_ATTACK=""
for _ in $(seq 1 30); do
  PROT_CLEAN="$(probe)"
  PROT_ATTACK="$(probe -H 'User-Agent: sqlmap/1.0')"
  log "probe protection clean=$PROT_CLEAN sqlmap=$PROT_ATTACK"
  [[ "$PROT_CLEAN" == "200" && "$PROT_ATTACK" == "403" ]] && break
  sleep 5
done
[[ "$PROT_CLEAN" == "200" && "$PROT_ATTACK" == "403" ]] || die "want protection clean 200 and sqlmap 403, got $PROT_CLEAN and $PROT_ATTACK"
kubectl delete protection edge -n default --wait=true
for _ in $(seq 1 30); do
  if ! kubectl get envoyextensionpolicy kubewaf-p-edge -n default >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
kubectl get envoyextensionpolicy kubewaf-p-edge -n default >/dev/null 2>&1 && die "Protection EnvoyExtensionPolicy was not deleted"
PROT_AFTER=""
for _ in $(seq 1 30); do
  PROT_AFTER="$(probe -H 'User-Agent: sqlmap/1.0')"
  log "probe after protection delete sqlmap=$PROT_AFTER"
  [[ "$PROT_AFTER" == "200" ]] && break
  sleep 5
done
[[ "$PROT_AFTER" == "200" ]] || die "want sqlmap 200 after protection delete, got $PROT_AFTER"

if [[ "${E2E_CRS:-false}" == "true" ]]; then
  log "nightly CRS includes"
  kubectl apply -f "$ROOT/test/e2e/v1alpha1/crs-includes.yaml"
  kubectl wait --for=condition=Ready include/crs-setup include/owasp secpolicy/crs -n default --timeout=180s
  CRS=""
  for _ in $(seq 1 30); do
    CRS="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: www.example.com' \
      --get --data-urlencode "id=1' OR '1'='1" "http://${NODE_IP}:${NODEPORT}/" || echo 000)"
    log "probe crs=$CRS"
    [[ "$CRS" == "403" ]] && break
    sleep 5
  done
  [[ "$CRS" == "403" ]] || die "want CRS 403, got $CRS"
fi

log "PASS clean=$CLEAN sqlmap=$SQLMAP after_edit sqlmap=$EDITED_SQL badbot=$EDITED_BOT after_delete=$AFTER_DELETE protection clean=$PROT_CLEAN sqlmap=$PROT_ATTACK after_delete=$PROT_AFTER"
