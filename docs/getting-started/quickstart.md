# Quick Start

Get a working WAF-protected HTTP service in under 10 minutes.

## Assumptions

- You have already [installed the operator](installation.md)
- You are using **Envoy Gateway** (or are willing to install it) — this is currently the easiest way to attach WAF policies

If you are not using Envoy Gateway yet, you can still define rules and RuleSets; attachment to traffic will be available via future `WAFInstance` support.

## 1. Install Envoy Gateway (if not already present)

```bash
helm install eg oci://docker.io/envoyproxy/gateway-helm \
  --version v1.0.2 \
  --namespace envoy-gateway-system \
  --create-namespace
```

Wait for it to be ready:

```bash
kubectl wait --timeout=5m -n envoy-gateway-system deployment/envoy-gateway --for=condition=Available
```

## 2. Create a simple Backend Application

We'll use a basic `httpbin` pod as our protected backend.

```yaml
# backend.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: demo
---
apiVersion: v1
kind: Pod
metadata:
  name: httpbin
  namespace: demo
  labels:
    app: httpbin
spec:
  containers:
  - name: httpbin
    image: kennethreitz/httpbin
    ports:
    - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: httpbin
  namespace: demo
spec:
  selector:
    app: httpbin
  ports:
  - port: 80
    targetPort: 80
```

Apply it:

```bash
kubectl apply -f backend.yaml
```

## 3. Create a Gateway and HTTPRoute (standard Gateway API)

```yaml
# gateway.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: demo-gateway
  namespace: demo
spec:
  gatewayClassName: eg
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: httpbin
  namespace: demo
spec:
  parentRefs:
  - name: demo-gateway
  hostnames:
  - "demo.local"
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: httpbin
      port: 80
```

Apply:

```bash
kubectl apply -f gateway.yaml
```

## 4. Define a Simple Security Rule

Let's create a rule that blocks requests containing a known malicious pattern in the `User-Agent`.

```yaml
# rule-block-bad-ua.yaml
apiVersion: seclang.kubewaf.io/v1beta1
kind: SecRule
metadata:
  name: block-bad-user-agent
  namespace: demo
  labels:
    app: demo-waf
spec:
  secLangRules:
  - metadata:
      id: 100001
      phase: "1"
      message: "Blocked malicious User-Agent"
      severity: "ERROR"
      tags:
        - "attack-generic"
    conditions:
    - variables:
      - name: REQUEST_HEADERS
        collection: User-Agent
      operator:
        name: rx
        value: (?:nikto|sqlmap|nessus|openvas)
    actions:
      disruptive:
        disruptiveActionType: deny
      status:
        statusActionType: "403"
      message: "Malicious scanner detected"
```

Apply the rule:

```bash
kubectl apply -f rule-block-bad-ua.yaml
```

## 5. Group the Rule into a RuleSet

```yaml
# ruleset-demo.yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: RuleSet
metadata:
  name: demo-rules
  namespace: demo
spec:
  ruleRefs:
  - kind: SecRule
    group: seclang.kubewaf.io
    version: v1beta1
    selector:
      matchLabels:
        app: demo-waf
```

Apply:

```bash
kubectl apply -f ruleset-demo.yaml
```

## 6. Attach WAF Policy to Your Route

```yaml
# waf-policy.yaml
apiVersion: waf.kubewaf.io/v1beta1
kind: WAF
metadata:
  name: demo-waf
  namespace: demo
spec:
  parentRefs:
    targetRef:
      group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: httpbin
      namespace: demo

  ruleRefs:
  - kind: RuleSet
    name: demo-rules
    namespace: demo
    group: waf.kubewaf.io
    version: v1beta1

  # Optional: enable the full OWASP CRS on top of your custom rules
  crsEnable: false
  logLevel: 4
```

Apply:

```bash
kubectl apply -f waf-policy.yaml
```

## 7. Test the Protection

Port-forward the Envoy Gateway service or use `kubectl port-forward` on the Envoy proxy pod.

```bash
# Find the envoy proxy pod (created by Envoy Gateway)
kubectl get pods -n envoy-gateway-system | grep envoy
```

Send a normal request:

```bash
curl -H "Host: demo.local" http://<envoy-ip>/get
```

Now send a blocked User-Agent:

```bash
curl -H "Host: demo.local" -H "User-Agent: sqlmap/1.0" http://<envoy-ip>/get -I
```

You should receive a **403 Forbidden** response from the WAF.

## 8. Enable the OWASP Core Rule Set (optional but powerful)

Change `crsEnable: true` in your `WAF` and re-apply. The operator will automatically merge hundreds of high-quality rules from the CRS.

```bash
kubectl patch wafenvoygateway demo-waf -n demo --type merge -p '{"spec":{"crsEnable":true}}'
```

## What Just Happened?

1. You defined a security rule in Kubernetes YAML.
2. You grouped it into a reusable `RuleSet`.
3. You attached that policy to a Gateway API route using `WAF`.
4. Envoy Gateway loaded the Coraza WASM module with your rules.
5. Malicious traffic is now blocked **before** it reaches your application.

## Next Steps

- Learn how to [write more powerful rules](https://kubewaf.io/guides/writing-rules/)
- Explore the full [OWASP CRS integration](https://kubewaf.io/guides/using-crs/)
- Dive into the [CRD reference](https://kubewaf.io/reference/crds/secrule/)

Congratulations — you now have a Kubernetes-native WAF! 🎉