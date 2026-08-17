#!/usr/bin/env bash
# Run CRS go-ftw against a kubeWAF Kind e2e provider gateway.
#
# Required env:
#   FTW_PROVIDER   envoy-gateway|istio|cilium
#   FTW_LOG_NS     namespace of Envoy data-plane pods
#   FTW_LOG_SEL    label selector for those pods (e.g. app.kubernetes.io/component=proxy)
#   FTW_PF_NS      namespace of Service to port-forward
#   FTW_PF_SVC     Service name
#   FTW_PF_PORT    Service port (default 80)
#
# Optional:
#   FTW_LOCAL_PORT   local port-forward port (default 18080)
#   FTW_INCLUDE      go-ftw -i regex (default ^913 — scanner detection smoke)
#   FTW_CLOUDMODE    true|false (default false — needs logs)
#   CRS_VERSION      default v4.27.0
#   GO_FTW_VERSION   default 2.5.0
#   FTW_WORKDIR      default test/e2e/ftw/.work
#
# Usage (from repo root):
#   FTW_PROVIDER=envoy-gateway FTW_LOG_NS=envoy-gateway-system \
#     FTW_LOG_SEL='app.kubernetes.io/component=proxy' \
#     FTW_PF_NS=envoy-gateway-system FTW_PF_SVC=envoy-demo-... \
#     ./test/e2e/ftw/run-ftw.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
WORKDIR="${FTW_WORKDIR:-$SCRIPT_DIR/.work}"
CRS_CACHE="${CRS_CACHE:-$SCRIPT_DIR/.crs-cache}"
CRS_VERSION="${CRS_VERSION:-v4.27.0}"
GO_FTW_VERSION="${GO_FTW_VERSION:-2.5.0}"
# Empty FTW_INCLUDE means full CRS suite (helpers pass "" for E2E_FTW_INCLUDE=all).
# Use ${VAR-default} (no colon) so an explicit empty value is not replaced by ^913.
if [ -z "${FTW_INCLUDE+x}" ]; then
  FTW_INCLUDE="^913"
fi
FTW_CLOUDMODE="${FTW_CLOUDMODE:-false}"
FTW_LOCAL_PORT="${FTW_LOCAL_PORT:-18080}"
FTW_PF_PORT="${FTW_PF_PORT:-80}"
FTW_HOST="${FTW_HOST:-demo.local}"
FTW_RATE_LIMIT="${FTW_RATE_LIMIT:-500ms}"
FTW_MAX_MARKER_RETRIES="${FTW_MAX_MARKER_RETRIES:-80}"
FTW_MARKER_SETTLE="${FTW_MARKER_SETTLE:-8}"
KUBECTL="${KUBECTL:-kubectl}"

: "${FTW_PROVIDER:?FTW_PROVIDER is required}"
: "${FTW_LOG_NS:?FTW_LOG_NS is required}"
: "${FTW_LOG_SEL:?FTW_LOG_SEL is required}"
: "${FTW_PF_NS:?FTW_PF_NS is required}"
: "${FTW_PF_SVC:?FTW_PF_SVC is required}"

LOGFILE="$WORKDIR/envoy.log"
FTW_YML="$WORKDIR/ftw.yml"
PF_PID=""
LOG_PID=""

kill_tree() {
  local pid="$1"
  [[ -z "$pid" ]] && return 0
  # Kill descendants first, then the parent (best-effort; ignore races).
  local kids
  kids=$(pgrep -P "$pid" 2>/dev/null || true)
  for k in $kids; do
    kill_tree "$k"
  done
  kill "$pid" 2>/dev/null || true
}

cleanup() {
  # Never hang EXIT trap on wait — use short timeout + SIGKILL.
  for pid in "${UNWRAP_PID:-}" "${LOG_PID:-}" "${PF_PID:-}"; do
    kill_tree "$pid"
  done
  # Reap without blocking forever.
  for pid in "${UNWRAP_PID:-}" "${LOG_PID:-}" "${PF_PID:-}"; do
    [[ -z "$pid" ]] && continue
    for _ in 1 2 3 4 5; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.2
    done
    kill -9 "$pid" 2>/dev/null || true
  done
  # Defined later; safe at EXIT time.
  if declare -F cleanup_bridge_pod >/dev/null 2>&1; then
    cleanup_bridge_pod || true
  fi
}
trap cleanup EXIT

mkdir -p "$WORKDIR"
: >"$LOGFILE"

prepare_crs_cache() {
  local marker="$CRS_CACHE/.crs-version"
  if [[ -f "$marker" ]] && [[ "$(cat "$marker")" == "$CRS_VERSION" ]] \
      && [[ -d "$CRS_CACHE/tests/regression/tests" ]]; then
    return 0
  fi
  echo "==> Fetching CRS $CRS_VERSION test corpus for go-ftw"
  rm -rf "$CRS_CACHE"
  mkdir -p "$CRS_CACHE"
  local tarball="$CRS_CACHE/crs.tar.gz"
  curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" -o "$tarball"
  tar -xzf "$tarball" -C "$CRS_CACHE" --strip-components 1
  rm -f "$tarball"
  echo "$CRS_VERSION" >"$marker"
}

write_ftw_yml() {
  # Start from repo template; override dest/logfile for this run.
  python3 - "$SCRIPT_DIR/ftw.yml" "$FTW_YML" "$LOGFILE" "$FTW_LOCAL_PORT" "$FTW_HOST" <<'PY'
import sys, pathlib
src, dst, logfile, port, host = sys.argv[1:6]
text = pathlib.Path(src).read_text()
# Replace known defaults from the template.
text = text.replace("logfile: '/tmp/kubewaf-e2e-ftw/envoy.log'", f"logfile: '{logfile}'")
text = text.replace("dest_addr: 127.0.0.1", "dest_addr: 127.0.0.1")
text = text.replace("port: 18080", f"port: {port}")
text = text.replace("Host: demo.local", f"Host: {host}")
pathlib.Path(dst).write_text(text)
print(f"wrote {dst}")
PY
}

pick_free_port() {
  # Prefer FTW_LOCAL_PORT if free; else ask the kernel for an ephemeral port.
  local p="${FTW_LOCAL_PORT}"
  if ! (echo >/dev/tcp/127.0.0.1/"$p") >/dev/null 2>&1; then
    echo "$p"
    return 0
  fi
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

rewrite_ftw_dest() {
  local addr="$1" port="$2"
  python3 - "$FTW_YML" "$addr" "$port" <<'PY'
import pathlib, re, sys
p, addr, port = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
t = p.read_text()
t = re.sub(r"(?m)^(\s*dest_addr:\s*).*$", r"\g<1>" + addr, t, count=1)
t = re.sub(r"(?m)^(\s*port:\s*)\d+\s*$", r"\g<1>" + port, t, count=1)
p.write_text(t)
print(f"ftw dest -> {addr}:{port}")
PY
}

# Cilium Gateway Services often have no pod selector (BPF/LB VIP). kubectl
# port-forward cannot attach. Prefer an in-cluster bridge (ClusterIP works with
# kubeWAF Wasm); NodePort from the host often hits Cilium bpf_metadata issues
# (500) once a custom CEC owns the L7 path.
BRIDGE_POD=""
cleanup_bridge_pod() {
  if [[ -n "${BRIDGE_POD:-}" ]]; then
    "$KUBECTL" -n "$FTW_PF_NS" delete pod "$BRIDGE_POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    BRIDGE_POD=""
  fi
}

http_code() {
  curl -sS -o /dev/null --max-time 5 -w "%{http_code}" \
    -H "Host: ${FTW_HOST}" \
    -H "User-Agent: kubewaf-ftw-probe" \
    "$1" 2>/dev/null || echo "000"
}

# Bridge via temporary socat pod → ClusterIP (works for Cilium + kubeWAF CEC).
try_incluster_bridge() {
  local code
  BRIDGE_POD="ftw-bridge-$$"
  echo "==> In-cluster bridge pod ${FTW_PF_NS}/${BRIDGE_POD} -> ${FTW_PF_SVC}:${FTW_PF_PORT}"
  "$KUBECTL" -n "$FTW_PF_NS" delete pod "$BRIDGE_POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  if ! "$KUBECTL" -n "$FTW_PF_NS" run "$BRIDGE_POD" \
      --image=alpine/socat:1.8.0.0 \
      --restart=Never \
      --labels="kubewaf.io/ftw-bridge=true" \
      --command -- socat TCP-LISTEN:8080,fork,reuseaddr \
      "TCP:${FTW_PF_SVC}.${FTW_PF_NS}.svc.cluster.local:${FTW_PF_PORT}" >/dev/null 2>&1; then
    BRIDGE_POD=""
    return 1
  fi
  if ! "$KUBECTL" -n "$FTW_PF_NS" wait --for=condition=Ready "pod/${BRIDGE_POD}" --timeout=60s >/dev/null 2>&1; then
    cleanup_bridge_pod
    return 1
  fi
  FTW_LOCAL_PORT="$(pick_free_port)"
  FTW_DEST_ADDR="127.0.0.1"
  "$KUBECTL" -n "$FTW_PF_NS" port-forward "pod/${BRIDGE_POD}" "${FTW_LOCAL_PORT}:8080" \
    >/tmp/kubewaf-ftw-pf.log 2>&1 &
  PF_PID=$!
  local retries=40
  while [[ "$retries" -gt 0 ]]; do
    if ! kill -0 "$PF_PID" 2>/dev/null; then
      cleanup_bridge_pod
      return 1
    fi
    code=$(http_code "http://127.0.0.1:${FTW_LOCAL_PORT}/")
    # 200 (benign app/albedo) or 403 (WAF block) mean the path is live.
    if [[ "$code" == "200" || "$code" == "403" || "$code" == "404" ]]; then
      echo "==> In-cluster bridge ready on :${FTW_LOCAL_PORT} (HTTP ${code})"
      rewrite_ftw_dest "127.0.0.1" "$FTW_LOCAL_PORT"
      return 0
    fi
    retries=$((retries - 1))
    sleep 0.5
  done
  kill "$PF_PID" 2>/dev/null || true
  PF_PID=""
  cleanup_bridge_pod
  return 1
}

try_nodeport_access() {
  local node_port
  node_port=$("$KUBECTL" -n "$FTW_PF_NS" get svc "$FTW_PF_SVC" \
    -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || true)
  if [[ -z "$node_port" || "$node_port" == "0" ]]; then
    return 1
  fi
  local node_ip
  node_ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "${KIND_CLUSTER:-kubewaf-e2e}-control-plane" 2>/dev/null || true)
  if [[ -z "$node_ip" ]]; then
    node_ip=$("$KUBECTL" get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)
  fi
  if [[ -z "$node_ip" ]]; then
    return 1
  fi
  echo "==> Probing NodePort path ${node_ip}:${node_port} (svc without selector)"
  local code
  code=$(http_code "http://${node_ip}:${node_port}/")
  # Accept only healthy path; 5xx means Cilium host-path L7 is broken for this setup.
  if [[ "$code" == "200" || "$code" == "403" || "$code" == "404" ]]; then
    echo "==> Using NodePort path ${node_ip}:${node_port} (HTTP ${code})"
    FTW_DEST_ADDR="$node_ip"
    FTW_LOCAL_PORT="$node_port"
    rewrite_ftw_dest "$FTW_DEST_ADDR" "$FTW_LOCAL_PORT"
    # go-ftw container uses --network host so it can reach Kind node IP.
    return 0
  fi
  echo "==> NodePort not usable (HTTP ${code}); will try in-cluster bridge"
  return 1
}

start_port_forward() {
  # Prefer NodePort when the Service has no selector (Cilium Gateway), else bridge.
  local selector
  selector=$("$KUBECTL" -n "$FTW_PF_NS" get svc "$FTW_PF_SVC" \
    -o jsonpath='{.spec.selector}' 2>/dev/null || true)
  if [[ -z "$selector" || "$selector" == "{}" || "$selector" == "map[]" ]]; then
    if try_nodeport_access; then
      PF_PID=""
      return 0
    fi
    if try_incluster_bridge; then
      return 0
    fi
    echo "WARN: service has no selector and bridge paths failed; trying port-forward anyway" >&2
  fi

  FTW_LOCAL_PORT="$(pick_free_port)"
  FTW_DEST_ADDR="127.0.0.1"
  echo "==> Port-forward ${FTW_PF_NS}/svc/${FTW_PF_SVC}:${FTW_PF_PORT} -> 127.0.0.1:${FTW_LOCAL_PORT}"
  sleep 0.5
  "$KUBECTL" -n "$FTW_PF_NS" port-forward "svc/${FTW_PF_SVC}" "${FTW_LOCAL_PORT}:${FTW_PF_PORT}" \
    >/tmp/kubewaf-ftw-pf.log 2>&1 &
  PF_PID=$!
  local retries=40
  while [[ "$retries" -gt 0 ]]; do
    if ! kill -0 "$PF_PID" 2>/dev/null; then
      # Fall back to NodePort if port-forward dies (e.g. no selector).
      if try_nodeport_access; then
        PF_PID=""
        return 0
      fi
      echo "ERROR: port-forward process exited early:" >&2
      cat /tmp/kubewaf-ftw-pf.log >&2 || true
      return 1
    fi
    # Any HTTP response (incl. 4xx/5xx) means the tunnel works.
    if curl -sS -o /dev/null --max-time 2 -w '' \
        -H "Host: ${FTW_HOST}" \
        "http://127.0.0.1:${FTW_LOCAL_PORT}/" 2>/dev/null; then
      echo "==> Port-forward ready on :${FTW_LOCAL_PORT}"
      rewrite_ftw_dest "127.0.0.1" "$FTW_LOCAL_PORT"
      return 0
    fi
    retries=$((retries - 1))
    sleep 0.5
  done
  if try_nodeport_access; then
    PF_PID=""
    return 0
  fi
  echo "ERROR: port-forward not ready" >&2
  cat /tmp/kubewaf-ftw-pf.log >&2 || true
  return 1
}

# EG proxy pods are multi-container (envoy + shutdown-manager). Always pin -c.
FTW_LOG_CONTAINER="${FTW_LOG_CONTAINER:-envoy}"

start_log_collector() {
  echo "==> Collecting logs: ns=${FTW_LOG_NS} sel=${FTW_LOG_SEL} container=${FTW_LOG_CONTAINER}"
  # Poll + follow: plain `kubectl logs -f` is flaky with multi-pod selectors and
  # dies when a pod rolls. Polling guarantees rule_match lines land in LOGFILE.
  (
    set +e
    "$KUBECTL" -n "$FTW_LOG_NS" logs -l "$FTW_LOG_SEL" -c "$FTW_LOG_CONTAINER" \
      --tail=500 --prefix=true --max-log-requests=20 >>"$LOGFILE" 2>/dev/null
    # Background follow (best-effort).
    "$KUBECTL" -n "$FTW_LOG_NS" logs -l "$FTW_LOG_SEL" -c "$FTW_LOG_CONTAINER" \
      -f --prefix=true --max-log-requests=20 >>"$LOGFILE" 2>/dev/null &
    follow_pid=$!
    while kill -0 "$follow_pid" 2>/dev/null; do
      sleep 3
      # Periodic snapshot in case -f stalls.
      "$KUBECTL" -n "$FTW_LOG_NS" logs -l "$FTW_LOG_SEL" -c "$FTW_LOG_CONTAINER" \
        --tail=100 --prefix=true --max-log-requests=20 >>"$LOGFILE" 2>/dev/null
    done
  ) &
  LOG_PID=$!
  sleep 2
}

prime_waf() {
  echo "==> Priming WAF (markers + request through gateway)"
  local i
  for i in 1 2 3 4 5; do
    curl -sS -o /dev/null --max-time 5 \
      -H "Host: ${FTW_HOST}" \
      -H "X-CRS-Test: ftw-prime-${i}" \
      "http://${FTW_DEST_ADDR:-127.0.0.1}:${FTW_LOCAL_PORT}/status/200" || true
  done
  sleep "$FTW_MARKER_SETTLE"
}

# Envoy JSON app logs escape wasm payload: {"message":"... {\"event\":\"rule_match\",\"id\":N}"}
# Text app logs keep raw: ... logJson() {"event":"rule_match","id":N}
# Match both forms.
has_rule_match() {
  grep -qE 'rule_match' "$LOGFILE" 2>/dev/null
}

# Produce a go-ftw-friendly log: one pure-JSON wasm object per matching line so
# go-ftw's `"id":N` regex works even under Envoy json_format application logs.
unwrap_logs_for_ftw() {
  local raw="$1" out="$2"
  python3 - "$raw" "$out" <<'PY'
import json, re, sys
src, dst = sys.argv[1], sys.argv[2]
# Strip kubectl --prefix: [pod/name/container] ...
prefix_re = re.compile(r"^\[pod/[^\]]+\]\s*")
# Inner JSON object starting at first { that looks like our component.
inner_re = re.compile(r"\{[^{}]*\"component\"\s*:\s*\"modsecurity-proxy-wasm\".*$")
with open(src, "r", errors="replace") as fin, open(dst, "w") as fout:
    for line in fin:
        line = line.rstrip("\n")
        line = prefix_re.sub("", line)
        payload = None
        # Outer Envoy JSON application log?
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                msg = obj.get("message") or obj.get("Message") or ""
                if isinstance(msg, str) and "{" in msg:
                    # Prefer last JSON object in the message (wasm payload).
                    idx = msg.rfind('{"component"')
                    if idx < 0:
                        idx = msg.find("{")
                    if idx >= 0:
                        candidate = msg[idx:]
                        try:
                            json.loads(candidate)
                            payload = candidate
                        except json.JSONDecodeError:
                            # Truncated lines — still emit for marker text search.
                            payload = candidate
            except json.JSONDecodeError:
                pass
        if payload is None:
            # Text Envoy prefix ... logJson() {json}
            m = re.search(r"(\{\"component\"\s*:\s*\"modsecurity-proxy-wasm\".*)$", line)
            if m:
                payload = m.group(1)
            elif '"component":"modsecurity-proxy-wasm"' in line or '"id":' in line:
                payload = line
        if payload:
            fout.write(payload + "\n")
print(f"unwrapped {src} -> {dst}", file=sys.stderr)
PY
}

wait_for_rule_logs() {
  local retries=60 code
  echo "==> Waiting for modsecurity-proxy-wasm rule_match JSON in ${LOGFILE}"
  while [[ "$retries" -gt 0 ]]; do
    code=$(curl -sS -o /dev/null --max-time 5 -w '%{http_code}' \
      -H "Host: ${FTW_HOST}" \
      -H "User-Agent: sqlmap" \
      -H "X-CRS-Test: ftw-wait-${retries}" \
      "http://${FTW_DEST_ADDR:-127.0.0.1}:${FTW_LOCAL_PORT}/get" 2>/dev/null || echo "000")
    # Refresh log snapshot (since-time catches new lines after pod log buffer churn).
    "$KUBECTL" -n "$FTW_LOG_NS" logs -l "$FTW_LOG_SEL" -c "$FTW_LOG_CONTAINER" \
      --since=2m --prefix=true --max-log-requests=20 >>"$LOGFILE" 2>/dev/null || true
    if has_rule_match; then
      echo "==> rule_match found in logs (last probe HTTP ${code})"
      return 0
    fi
    sleep 2
    retries=$((retries - 1))
  done
  echo "ERROR: no rule_match logs yet; last 40 log lines:" >&2
  tail -n 40 "$LOGFILE" >&2 || true
  echo "ERROR: recent envoy logs:" >&2
  "$KUBECTL" -n "$FTW_LOG_NS" logs -l "$FTW_LOG_SEL" -c "$FTW_LOG_CONTAINER" \
    --since=2m --prefix=true --max-log-requests=20 2>&1 | tail -n 40 >&2 || true
  return 1
}

UNWRAP_PID=""

start_live_unwrap() {
  local unwrapped="$1"
  : >"$unwrapped"
  # Seed from current LOGFILE.
  unwrap_logs_for_ftw "$LOGFILE" "$unwrapped" 2>/dev/null || true

  # Write a small line-unwrap helper (must NOT use a heredoc as python stdin —
  # that would steal the pipe from kubectl logs -f).
  local helper="$WORKDIR/unwrap_line.py"
  cat >"$helper" <<'PY'
#!/usr/bin/env python3
import json, re, sys
out_path = sys.argv[1]
prefix_re = re.compile(r"^\[pod/[^\]]+\]\s*")
fout = open(out_path, "a", buffering=1)
for line in sys.stdin:
    line = line.rstrip("\n")
    line = prefix_re.sub("", line)
    payload = None
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            msg = obj.get("message") or ""
            if isinstance(msg, str) and "{" in msg:
                idx = msg.rfind('{"component"')
                if idx < 0:
                    idx = msg.find("{")
                if idx >= 0:
                    payload = msg[idx:]
        except json.JSONDecodeError:
            pass
    if payload is None:
        m = re.search(r'(\{"component"\s*:\s*"modsecurity-proxy-wasm".*)$', line)
        if m:
            payload = m.group(1)
    if payload:
        fout.write(payload + "\n")
        fout.flush()
PY
  chmod +x "$helper"

  (
    set +e
    "$KUBECTL" -n "$FTW_LOG_NS" logs -l "$FTW_LOG_SEL" -c "$FTW_LOG_CONTAINER" \
      -f --prefix=true --max-log-requests=20 2>/dev/null \
      | python3 -u "$helper" "$unwrapped"
  ) &
  UNWRAP_PID=$!
}

run_go_ftw() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required to run ghcr.io/coreruleset/go-ftw" >&2
    return 1
  fi

  local include_args=()
  if [[ -n "$FTW_INCLUDE" ]]; then
    include_args=(-i "$FTW_INCLUDE")
    echo "==> FTW_INCLUDE=${FTW_INCLUDE}"
  else
    echo "==> FTW_INCLUDE empty (full CRS regression suite)"
  fi

  # Final snapshot into LOGFILE, then live-unwrap for go-ftw (`"id":N` must be raw).
  "$KUBECTL" -n "$FTW_LOG_NS" logs -l "$FTW_LOG_SEL" -c "$FTW_LOG_CONTAINER" \
    --tail=2000 --prefix=true --max-log-requests=20 >>"$LOGFILE" 2>/dev/null || true
  local unwrapped="$WORKDIR/envoy.unwrapped.log"
  start_live_unwrap "$unwrapped"
  sleep 2

  # Point ftw.yml at the unwrapped file (container path).
  python3 - "$FTW_YML" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
t = p.read_text()
t = re.sub(r"logfile:\s*'[^']*'", "logfile: '/work/envoy.unwrapped.log'", t, count=1)
p.write_text(t)
PY

  echo "==> Running go-ftw ${GO_FTW_VERSION} (provider=${FTW_PROVIDER})"
  # --network host: container hits host port-forward on 127.0.0.1:FTW_LOCAL_PORT
  # WORKDIR is RW so go-ftw can seek the growing unwrapped log (mount RW).
  set +e
  # Cap go-ftw runtime so a stuck marker loop cannot hang the e2e suite forever.
  timeout --signal=TERM --kill-after=30s "${FTW_TIMEOUT:-15m}" \
    docker run --rm --network host \
      -v "${WORKDIR}:/work" \
      -v "${CRS_CACHE}:/workspace/coreruleset:ro" \
      -w /workspace \
      "ghcr.io/coreruleset/go-ftw:${GO_FTW_VERSION}" \
      run -d /workspace/coreruleset/tests/regression/tests \
        --config /work/ftw.yml \
        --read-timeout=10s \
        --rate-limit="$FTW_RATE_LIMIT" \
        --max-marker-retries="$FTW_MAX_MARKER_RETRIES" \
        --cloud="$FTW_CLOUDMODE" \
        "${include_args[@]}"
  local rc=$?
  set -e
  kill_tree "${UNWRAP_PID:-}"
  UNWRAP_PID=""
  return "$rc"
}

echo "==> kubeWAF e2e go-ftw (provider=${FTW_PROVIDER}, CRS=${CRS_VERSION})"
prepare_crs_cache
write_ftw_yml

start_port_forward
start_log_collector
prime_waf
if [[ "$FTW_CLOUDMODE" != "true" ]]; then
  wait_for_rule_logs
fi
run_go_ftw
echo "==> go-ftw finished OK (provider=${FTW_PROVIDER})"
