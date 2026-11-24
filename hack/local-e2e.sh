#!/usr/bin/env bash
# hack/local-e2e.sh - full local kubeWAF test on Kind, end to end.
#
# Run from anywhere inside a kubewaf-io/kubewaf checkout
# (branch cursor/m5-inline-directives-1bfe, PR #154 or later):
#
#   hack/local-e2e.sh                # create/reuse cluster, install everything, test
#   hack/local-e2e.sh --fresh        # delete the cluster first, then run
#   hack/local-e2e.sh --protection   # also test the Protection API afterwards
#   hack/local-e2e.sh --cleanup      # delete the Kind cluster and exit
#
# Steps follow test/e2e/v1alpha1/run.sh and .github/workflows/test-e2e.yml:
#   1 Kind cluster   2 images   3 Envoy Gateway + quickstart   4 platform EnvoyProxy
#   5 kubeWAF chart  6 SecPolicy probes (200/403) and live rule edit (sqlmap -> badbot)
# Safe to re-run: every step is apply/upgrade, existing cluster is reused.
set -euo pipefail

# ---------------------------------------------------------------- settings
CLUSTER_NAME="${CLUSTER_NAME:-kubewaf-local}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.34.0}"
EG_VERSION="${EG_VERSION:-v1.10.0}"
ENVOY_IMAGE="${ENVOY_IMAGE:-docker.io/envoyproxy/envoy:distroless-v1.40.2}"
COMPOSER_VERSION="${COMPOSER_VERSION:-0.13.0}"
OPERATOR_REPO="${OPERATOR_REPO:-kubewaf-operator}"   # tag = hash of the built binary
KEEP="${KEEP:-true}"        # keep the cluster after the run (false = delete on exit)
REUSE="${REUSE:-true}"      # reuse an existing cluster with CLUSTER_NAME
PROTECTION="${PROTECTION:-false}"
LOCAL_PORT="${LOCAL_PORT:-18080}"   # port-forward fallback port on localhost
REACH="${REACH:-auto}"      # auto | nodeport | port-forward

for arg in "$@"; do
  case "$arg" in
    --cleanup) MODE=cleanup ;;
    --fresh) REUSE=false ;;
    --no-keep) KEEP=false ;;
    --protection) PROTECTION=true ;;
    --port-forward) REACH=port-forward ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
MODE="${MODE:-run}"

# ---------------------------------------------------------------- helpers
START_TS=$(date +%s)
log()  { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
PF_PID=""
RESULT="FAIL"

diagnostics() {
  set +e
  echo; echo "================ DIAGNOSTICS ================"
  echo "--- pods";                      kubectl get pods -A -o wide
  echo "--- kubeWAF objects";           kubectl get secpolicy,protection,secrule,include -A -o wide
  echo "--- SecPolicy edge conditions"; kubectl get secpolicy edge -n default -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
  echo "--- EnvoyExtensionPolicy";      kubectl get envoyextensionpolicy -A -o yaml | grep -vE '^\s+(directives|- ")' | sed -n '1,200p'
  echo "--- Gateway eg";                kubectl get gateway eg -n default -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
  echo "--- operator logs";             kubectl logs -n kubewaf-system -l app.kubernetes.io/name=kubewaf --tail=120
  echo "--- envoy gateway logs";        kubectl logs -n envoy-gateway-system deploy/envoy-gateway --tail=60
  echo "--- envoy proxy logs";          kubectl logs -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg -c envoy --tail=60
  echo "--- events (last 30)";          kubectl get events -A --sort-by=.lastTimestamp | tail -30
  echo "============================================="
}
die() { printf '\n\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; diagnostics; DIAG_DONE=1; exit 1; }
on_exit() {
  local rc=$?
  if [[ -n "$PF_PID" ]]; then kill "$PF_PID" 2>/dev/null || true; fi
  if [[ $rc -ne 0 && "$RESULT" != "PASS" && "${DIAG_DONE:-}" != 1 ]]; then
    printf '\n\033[1;31mFAIL: command failed (exit %s)\033[0m\n' "$rc" >&2
    command -v kubectl >/dev/null && kubectl config current-context >/dev/null 2>&1 && diagnostics
  fi
  if [[ "$KEEP" != "true" && "$MODE" == run ]]; then
    kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  fi
  echo "total runtime: $(( $(date +%s) - START_TS ))s"
}
trap on_exit EXIT

# ---------------------------------------------------------------- prereqs
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "run this inside the kubewaf checkout" >&2; exit 1; }
cd "$ROOT"
mkdir -p "$ROOT/bin"
[[ -f "$ROOT/test/e2e/v1alpha1/block-sqlmap.yaml" && -f "$ROOT/config/samples/envoygateway/platform-envoyproxy.yaml" ]] \
  || { echo "this checkout has no v1alpha1 e2e fixtures; use branch cursor/m5-inline-directives-1bfe (PR #154) or later" >&2; exit 1; }

if [[ "$MODE" == cleanup ]]; then
  command -v kind >/dev/null || { echo "missing kind" >&2; exit 1; }
  kind delete cluster --name "$CLUSTER_NAME"
  RESULT=PASS; exit 0
fi

log "prerequisites"
missing=()
for t in docker kind kubectl helm go curl git; do command -v "$t" >/dev/null || missing+=("$t"); done
if (( ${#missing[@]} )); then
  echo "missing tools: ${missing[*]}" >&2
  nixpkgs="$(printf '%s\n' "${missing[@]}" | sed -e 's/^helm$/kubernetes-helm/' -e 's/^go$/go_1_26/' | tr '\n' ' ')"
  echo "on NixOS e.g.: nix-shell -p ${nixpkgs}python3 --run $0" >&2
  DIAG_DONE=1; exit 1
fi
docker info >/dev/null 2>&1 || { echo "docker daemon not reachable (is it running? is your user in the docker group / DOCKER_HOST set for rootless?)" >&2; exit 1; }
HAVE_PY="${HAVE_PY:-}"; [[ -z "$HAVE_PY" ]] && { HAVE_PY=false; command -v python3 >/dev/null && HAVE_PY=true; }
info "docker  $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
info "kind    $(kind version | awk '{print $2}')"
info "kubectl $(kubectl version --client -o yaml 2>/dev/null | awk '/gitVersion/{print $2; exit}')"
info "helm    $(helm version --short)"
info "go      $(go version | awk '{print $3}') (go.mod wants $(awk '/^go /{print $2}' go.mod))"
info "curl    $(curl --version | awk 'NR==1{print $2}')"
info "python3 $($HAVE_PY && python3 --version | awk '{print $2}' || echo 'not found (uses nix-shell -p python3, else docker save | ctr import)')"
info "repo    $(git rev-parse --abbrev-ref HEAD) @ $(git rev-parse --short HEAD)"
ARCH="$(go env GOARCH)"
[[ "$ARCH" == amd64 ]] || info "WARNING: host arch $ARCH; the repo e2e only pins/tests linux/amd64 images"
if docker info 2>/dev/null | grep -qi rootless; then
  info "rootless docker detected: node IP is not reachable from the host, using port-forward"
  [[ "$REACH" == auto ]] && REACH=port-forward
fi

# ---------------------------------------------------------------- 1 kind
log "1/6 Kind cluster $CLUSTER_NAME ($KIND_NODE_IMAGE)"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  if [[ "$REUSE" == true ]]; then info "reusing existing cluster"
  else info "deleting existing cluster (--fresh)"; kind delete cluster --name "$CLUSTER_NAME"; fi
fi
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  # nftables as in run.sh: kernels without xt_statistic never program ClusterIPs in iptables mode.
  cat >"$ROOT/bin/kind-local.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  kubeProxyMode: nftables
nodes:
  - role: control-plane
    image: ${KIND_NODE_IMAGE}
EOF
  kind create cluster --name "$CLUSTER_NAME" --config "$ROOT/bin/kind-local.yaml" --wait 120s
fi
kubectl config use-context "kind-$CLUSTER_NAME" >/dev/null
NODE="${CLUSTER_NAME}-control-plane"
kubectl wait --for=condition=Ready node --all --timeout=180s

# ---------------------------------------------------------------- 2 images
log "2/6 build operator + composer-cp and load images into Kind"
node_has() { docker exec "$NODE" ctr -n k8s.io images ls -q 2>/dev/null | grep -qx "$1"; }
full_ref() { case "$1" in docker.io/*|*.*/*|localhost/*) echo "$1";; */*) echo "docker.io/$1";; *) echo "docker.io/library/$1";; esac; }
import_img() {   # repo helper (fixes multi-arch docker save); fallbacks if python3 is missing
  if $HAVE_PY; then python3 "$ROOT/test/e2e/v1alpha1/load_image.py" "$1" "$CLUSTER_NAME"; return; fi
  if command -v nix-shell >/dev/null; then
    nix-shell -p python3 --run "python3 '$ROOT/test/e2e/v1alpha1/load_image.py' '$1' '$CLUSTER_NAME'" && return
  fi
  docker save --platform "linux/$ARCH" "$1" 2>/dev/null | docker exec -i "$NODE" ctr -n k8s.io images import - >/dev/null 2>&1 && return
  kind load docker-image "$1" --name "$CLUSTER_NAME"
}
load() {   # pull (amd64 like CI) and import into the node, skip if already there
  local img="$1"
  if node_has "$(full_ref "$img")"; then info "already in node: $img"; return 0; fi
  docker pull -q --platform "linux/$ARCH" "$img" >/dev/null || docker pull -q "$img" >/dev/null
  import_img "$img"
}
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$ROOT/bin/operator" "$ROOT/cmd/operator"
OPERATOR_IMAGE="${OPERATOR_REPO}:local-$(sha256sum "$ROOT/bin/operator" | cut -c1-12)"
docker build -q -t "$OPERATOR_IMAGE" -f "$ROOT/Dockerfile.operator" "$ROOT/bin" >/dev/null
node_has "$(full_ref "$OPERATOR_IMAGE")" || import_img "$OPERATOR_IMAGE"
info "operator image $OPERATOR_IMAGE"

cat >"$ROOT/bin/Dockerfile.composer-cp" <<EOF
FROM ghcr.io/tetratelabs/built-on-envoy/composer:${COMPOSER_VERSION} AS src
FROM busybox:1.36
COPY --from=src /libcomposer.so /libcomposer.so
ENTRYPOINT ["cp", "/libcomposer.so", "/modules/libcomposer.so"]
EOF
if ! node_has "docker.io/library/composer-cp:${COMPOSER_VERSION}"; then
  docker build -q -t "composer-cp:${COMPOSER_VERSION}" -f "$ROOT/bin/Dockerfile.composer-cp" "$ROOT/bin" >/dev/null
  import_img "composer-cp:${COMPOSER_VERSION}"
fi
load "docker.io/envoyproxy/gateway:${EG_VERSION}"
load "$ENVOY_IMAGE"

# ---------------------------------------------------------------- 3 envoy gateway
log "3/6 Envoy Gateway $EG_VERSION + quickstart"
helm upgrade --install eg oci://docker.io/envoyproxy/gateway-helm \
  --version "$EG_VERSION" --namespace envoy-gateway-system --create-namespace \
  --wait --timeout 10m
kubectl wait --for=condition=Available deployment/envoy-gateway -n envoy-gateway-system --timeout=300s

QUICK="$ROOT/bin/eg-quickstart.yaml"
curl -fsSL -o "$QUICK" "https://github.com/envoyproxy/gateway/releases/download/${EG_VERSION}/quickstart.yaml"
grep -Eo 'image:[[:space:]]*[^[:space:]]+' "$QUICK" | awk '{print $2}' | sort -u | while read -r img; do
  load "$img" || info "could not preload $img (kubelet will pull it)"
done
kubectl apply -f "$QUICK"
kubectl wait --for=condition=Available deployment/backend -n default --timeout=300s

# ---------------------------------------------------------------- 4 platform
log "4/6 platform EnvoyProxy (Coraza dynamic module) + Gateway parametersRef"
kubectl apply -f "$ROOT/config/samples/envoygateway/platform-envoyproxy.yaml"
kubectl patch gateway eg -n default --type merge \
  -p '{"spec":{"infrastructure":{"parametersRef":{"group":"gateway.envoyproxy.io","kind":"EnvoyProxy","name":"platform"}}}}'
SVC=""
for _ in $(seq 1 60); do
  SVC="$(kubectl get svc -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [[ -n "$SVC" ]] && break; sleep 5
done
[[ -n "$SVC" ]] || die "envoy service for Gateway eg did not appear"
# Kind has no load balancer: give the service the node IP so the Gateway is Programmed (as run.sh does).
NODE_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NODE")"
kubectl patch svc "$SVC" -n envoy-gateway-system --subresource=status --type merge \
  -p '{"status":{"loadBalancer":{"ingress":[{"ip":"'"$NODE_IP"'"}]}}}' >/dev/null || true
DEP="$(kubectl get deploy -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg -o jsonpath='{.items[0].metadata.name}')"
for _ in $(seq 1 30); do   # wait until the proxy deployment carries the composer init container
  kubectl get deploy "$DEP" -n envoy-gateway-system -o jsonpath='{.spec.template.spec.initContainers[*].name}' | grep -q install-composer && break
  sleep 2
done
kubectl rollout status deploy/"$DEP" -n envoy-gateway-system --timeout=300s
info "envoy service $SVC, node IP $NODE_IP"

# ---------------------------------------------------------------- 5 kubewaf
log "5/6 kubeWAF chart"
# A first install that failed (e.g. EG namespace missing) leaves a release with no deployed revision.
if helm status kubewaf -n kubewaf-system >/dev/null 2>&1 && \
   ! helm history kubewaf -n kubewaf-system -o yaml 2>/dev/null | grep -qE 'status: (deployed|superseded)'; then
  info "removing failed earlier kubewaf release"; helm uninstall kubewaf -n kubewaf-system --wait || true
fi
HAD_RELEASE=false; helm status kubewaf -n kubewaf-system >/dev/null 2>&1 && HAD_RELEASE=true
helm upgrade --install kubewaf "$ROOT/charts/kubewaf" \
  --namespace kubewaf-system --create-namespace \
  --set image.repository="${OPERATOR_IMAGE%:*}" \
  --set image.tag="${OPERATOR_IMAGE##*:}" \
  --set image.pullPolicy=IfNotPresent \
  --wait --timeout 5m 2> >(grep -v 'unrecognized format' >&2)
if $HAD_RELEASE; then
  # The chart generates a new webhook CA on every upgrade; a running pod keeps the old cert until
  # the kubelet refreshes the secret (~1 min), so restart it to serve the new cert right away.
  kubectl rollout restart deployment/kubewaf -n kubewaf-system >/dev/null
fi
kubectl rollout status deployment/kubewaf -n kubewaf-system --timeout=180s

# ---------------------------------------------------------------- 6 test
log "6/6 SecPolicy probes and live rule edit"
FIX="$ROOT/test/e2e/v1alpha1/block-sqlmap.yaml"
ok=false
for _ in $(seq 1 12); do   # webhook may need a few seconds after rollout
  if out="$(kubectl apply -f "$FIX" 2>&1)"; then echo "$out"; ok=true; break; fi
  info "webhook not ready yet, retrying in 5s ($(grep -oE 'tls: [^(]*|connection refused|no endpoints available|context deadline exceeded' <<<"$out" | head -1))"
  last_out="$out"; sleep 5
done
$ok || die "SecRule/SecPolicy were not admitted by the webhook: ${last_out:-}"
kubectl wait --for=condition=Ready secrule/block-sqlmap -n default --timeout=120s
ready=false
for _ in $(seq 1 48); do
  line="$(kubectl get secpolicy edge -n default -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason} {end}' 2>/dev/null || true)"
  info "secpolicy: $line"
  [[ " $line" == *" Ready=True/"* && "$line" == *"EngineReady=True"* && "$line" == *"Programmed=True"* ]] && { ready=true; break; }
  sleep 5
done
$ready || die "SecPolicy edge did not reach Ready/EngineReady/Programmed=True"

# --- reach the gateway: NodeIP:NodePort like run.sh, else kubectl port-forward
NODEPORT="$(kubectl get svc "$SVC" -n envoy-gateway-system -o jsonpath='{.spec.ports[0].nodePort}')"
SVCPORT="$(kubectl get svc "$SVC" -n envoy-gateway-system -o jsonpath='{.spec.ports[0].port}')"
URL=""
raw_code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -H 'Host: www.example.com' "$@" 2>/dev/null || true; }
start_pf() {
  if [[ -n "$PF_PID" ]]; then kill "$PF_PID" 2>/dev/null || true; fi
  kubectl port-forward -n envoy-gateway-system "svc/$SVC" "${LOCAL_PORT}:${SVCPORT}" >"$ROOT/bin/port-forward.log" 2>&1 &
  PF_PID=$!
  for _ in $(seq 1 20); do [[ "$(raw_code "http://127.0.0.1:${LOCAL_PORT}/")" =~ ^[1-5][0-9][0-9]$ ]] && return 0; sleep 1; done
  return 1
}
if [[ "$REACH" != port-forward ]]; then
  for _ in $(seq 1 6); do
    [[ "$(raw_code "http://${NODE_IP}:${NODEPORT}/")" =~ ^[1-5][0-9][0-9]$ ]] && { URL="http://${NODE_IP}:${NODEPORT}/"; break; }
    sleep 2
  done
fi
if [[ -z "$URL" ]]; then
  [[ "$REACH" == nodeport ]] && die "gateway not reachable on ${NODE_IP}:${NODEPORT}"
  [[ "$REACH" == port-forward ]] || info "node IP ${NODE_IP}:${NODEPORT} not reachable from this host, falling back to port-forward"
  info "kubectl port-forward svc/$SVC -> 127.0.0.1:${LOCAL_PORT}"
  start_pf || die "port-forward to svc/$SVC failed: $(cat "$ROOT/bin/port-forward.log")"
  URL="http://127.0.0.1:${LOCAL_PORT}/"
fi
info "gateway URL $URL (Host: www.example.com)"
probe() {
  local code; code="$(raw_code "$@" "$URL")"
  if [[ ! "$code" =~ ^[1-5][0-9][0-9]$ && -n "$PF_PID" ]]; then start_pf >/dev/null 2>&1 || true; code="$(raw_code "$@" "$URL")"; fi
  [[ "$code" =~ ^[0-9]{3}$ ]] && echo "$code" || echo 000
}

CLEAN=""; SQLMAP=""
for _ in $(seq 1 30); do
  CLEAN="$(probe)"; SQLMAP="$(probe -H 'User-Agent: sqlmap/1.0')"
  info "probe clean=$CLEAN sqlmap=$SQLMAP"
  [[ "$CLEAN" == 200 && "$SQLMAP" == 403 ]] && break; sleep 3
done
[[ "$CLEAN" == 200 && "$SQLMAP" == 403 ]] || die "want clean=200 sqlmap=403, got clean=$CLEAN sqlmap=$SQLMAP"

info "editing SecRule block-sqlmap: (?i)sqlmap -> (?i)badbot"
t0=$(date +%s%N)
kubectl patch secrule block-sqlmap -n default --type=json \
  -p '[{"op":"replace","path":"/spec/chain/0/operator/value","value":"(?i)badbot"}]'
E_SQL=""; E_BOT=""
for _ in $(seq 1 120); do
  E_SQL="$(probe -H 'User-Agent: sqlmap/1.0')"; E_BOT="$(probe -H 'User-Agent: badbot/1.0')"
  [[ "$E_SQL" == 200 && "$E_BOT" == 403 ]] && break; sleep 0.5
done
EDIT_S="$(awk -v a="$t0" -v b="$(date +%s%N)" 'BEGIN{printf "%.1f", (b-a)/1e9}')"
info "probe after edit sqlmap=$E_SQL badbot=$E_BOT (edit applied in ${EDIT_S}s)"
[[ "$E_SQL" == 200 && "$E_BOT" == 403 ]] || die "want after_edit sqlmap=200 badbot=403, got sqlmap=$E_SQL badbot=$E_BOT"

PROT_SUMMARY=""
if [[ "$PROTECTION" == true ]]; then
  log "optional: Protection API (SecPolicy removed first to avoid double attachment)"
  kubectl delete secpolicy edge -n default --wait=true
  kubectl patch secrule block-sqlmap -n default --type=json \
    -p '[{"op":"replace","path":"/spec/chain/0/operator/value","value":"(?i)sqlmap"}]'
  kubectl apply -f "$ROOT/test/e2e/v1alpha1/protection.yaml"
  ok=false
  for _ in $(seq 1 48); do
    line="$(kubectl get protection edge -n default -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason} {end}' 2>/dev/null || true)"
    info "protection: $line"; [[ " $line" == *" Ready=True/"* ]] && { ok=true; break; }; sleep 5
  done
  $ok || die "Protection edge did not become Ready"
  P_CLEAN=""; P_SQL=""
  for _ in $(seq 1 30); do
    P_CLEAN="$(probe)"; P_SQL="$(probe -H 'User-Agent: sqlmap/1.0')"
    info "probe protection clean=$P_CLEAN sqlmap=$P_SQL"
    [[ "$P_CLEAN" == 200 && "$P_SQL" == 403 ]] && break; sleep 3
  done
  [[ "$P_CLEAN" == 200 && "$P_SQL" == 403 ]] || die "want protection clean=200 sqlmap=403, got $P_CLEAN/$P_SQL"
  PROT_SUMMARY=" protection clean=$P_CLEAN sqlmap=$P_SQL"
  kubectl delete protection edge -n default --wait=true >/dev/null
  kubectl apply -f "$FIX" >/dev/null   # back to the SecPolicy fixture (rule matches sqlmap again)
fi

RESULT=PASS
printf '\n\033[1;32mPASS\033[0m clean=%s sqlmap=%s after_edit sqlmap=%s badbot=%s edit_applied=%ss%s\n' \
  "$CLEAN" "$SQLMAP" "$E_SQL" "$E_BOT" "$EDIT_S" "$PROT_SUMMARY"
cat <<EOF

Try it yourself:
  curl -i -H 'Host: www.example.com' -H 'User-Agent: badbot/1.0' $URL   # 403 (sqlmap after --protection)
  (port-forward URLs only work while this script runs; start one with:
   kubectl port-forward -n envoy-gateway-system svc/$SVC ${LOCAL_PORT}:${SVCPORT})
Cluster kept: kind-$CLUSTER_NAME   delete with: $0 --cleanup
EOF
