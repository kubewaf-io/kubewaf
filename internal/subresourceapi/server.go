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

// Package subresourceapi is the capability-agnostic Subresource API Server shell
// plus v1 probe handlers. It does not run go-coraza request evaluation (K29).
package subresourceapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	subv1alpha1 "github.com/kubewaf-io/kubewaf/api/subresources/v1alpha1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/probeassemble"
	"github.com/kubewaf-io/kubewaf/internal/probetest/api"
	"github.com/kubewaf-io/kubewaf/internal/references2"
)

const (
	maxBodyBytes = 1 * 1024 * 1024
	// DefaultGlobalMaxInFlight caps concurrent probe evals process-wide.
	DefaultGlobalMaxInFlight = 32
	// DefaultQueryPerNamespace caps concurrent metrics/traces queries per namespace.
	// Headlamp's WAF detail page issues ~10 GETs; this is independent of the probe cap (4).
	DefaultQueryPerNamespace = 16
	// DefaultQueryGlobalMax caps concurrent metrics/traces queries process-wide.
	DefaultQueryGlobalMax = 64
	// maxNSSemEntries bounds the per-namespace semaphore map.
	maxNSSemEntries = 4096
)

// AuthMode controls authentication behavior.
type AuthMode string

const (
	// AuthInsecureDev trusts a fixed identity without requestheader verification.
	AuthInsecureDev AuthMode = "insecure-dev"
	// AuthRequestHeader requires verified peer cert and X-Remote-* headers.
	AuthRequestHeader AuthMode = "requestheader"
)

// SARAuthorizer checks parent get access for the calling user.
// Optional/stubable for unit tests (K9).
type SARAuthorizer interface {
	// CanGetParent returns nil if allowed, or a MappedError.
	CanGetParent(ctx context.Context, user string, groups []string, kind ParentKind, namespace, name string) *MappedError
}

// AllowAllSAR is a test/dev SAR that always allows.
// Production: only for insecure-dev (never for requestheader, even with -skip-kube).
type AllowAllSAR struct{}

// CanGetParent always allows.
func (AllowAllSAR) CanGetParent(context.Context, string, []string, ParentKind, string, string) *MappedError {
	return nil
}

// Config configures the Subresource API Server.
type Config struct {
	// Auth mode: insecure-dev (default for unit tests) or requestheader.
	Auth AuthMode
	// DevUser is used in insecure-dev mode.
	DevUser string
	// EvalClient calls the Test HTTP Server (required for probe evaluation).
	EvalClient EvalClient
	// Kube client for live Get of parents (optional for discovery-only).
	Client client.Client
	// SAR authorizer. Nil defaults: AllowAll for insecure-dev, DenyAll for requestheader.
	SAR SARAuthorizer
	// PerNamespaceConcurrency default 4 (K21). Probe evals only.
	PerNamespaceConcurrency int
	// GlobalMaxInFlight caps concurrent probes (default 32).
	GlobalMaxInFlight int
	// PerNamespaceQueryConcurrency caps metrics/traces GETs per namespace
	// (default 16). Independent of the probe budget so a WAF detail page
	// does not 429 against the probe cap of 4.
	PerNamespaceQueryConcurrency int
	// GlobalQueryMaxInFlight caps metrics/traces GETs process-wide (default 64).
	GlobalQueryMaxInFlight int
	// Logger optional.
	Logger *slog.Logger
	// DataFiles provider for ResolveDataFiles (optional).
	DataFiles probeassemble.ListBodyProvider
	// SkipAssembly when true uses empty preamble-only directives (PR0 stub path).
	// When Client is nil, assembly is always stubbed.
	SkipAssembly bool
	// RequirePeerCert forces TLS peer verification for requestheader (default true in that mode).
	// Set false only in tests that inject identity without a TLS listener.
	RequirePeerCert *bool
	// RequestHeaderAllowedNames is the set of allowed client cert Common Names / DNS SANs.
	// Empty means any verified peer is accepted (after ClientAuth verify).
	RequestHeaderAllowedNames []string
	// DisableProbes omits /probes. Zero value keeps probes registered (tests).
	DisableProbes bool
	// DisableDirectives omits GET …/wafs/{name}/directives.
	DisableDirectives bool
	// DisableQuery omits GET …/metrics, /traces, and /clustermetrics.
	DisableQuery bool
	// Query is the in-cluster Prom/Jaeger client. Nil makes query handlers 503.
	Query *QueryBackend
	// EnableProbes is computed from DisableProbes (exported for tests).
	EnableProbes bool
	// EnableDirectives is computed from DisableDirectives.
	EnableDirectives bool
	// EnableQuery is computed from DisableQuery.
	EnableQuery bool
}

// Server is the Subresource API HTTP server.
type Server struct {
	cfg            Config
	log            *slog.Logger
	nsSem          map[string]chan struct{}
	nsMu           sync.Mutex
	globalSem      chan struct{}
	queryNSSem     map[string]chan struct{}
	queryGlobalSem chan struct{}
	sar            SARAuthorizer
	eval           EvalClient
	client         client.Client
	query          *QueryBackend
}

// NewServer creates a Server.
func NewServer(cfg Config) *Server {
	if cfg.Auth == "" {
		cfg.Auth = AuthInsecureDev
	}
	if cfg.DevUser == "" {
		cfg.DevUser = "system:anonymous"
	}
	if cfg.PerNamespaceConcurrency <= 0 {
		cfg.PerNamespaceConcurrency = 4
	}
	if cfg.GlobalMaxInFlight <= 0 {
		cfg.GlobalMaxInFlight = DefaultGlobalMaxInFlight
	}
	if cfg.PerNamespaceQueryConcurrency <= 0 {
		cfg.PerNamespaceQueryConcurrency = DefaultQueryPerNamespace
	}
	if cfg.GlobalQueryMaxInFlight <= 0 {
		cfg.GlobalQueryMaxInFlight = DefaultQueryGlobalMax
	}
	cfg.EnableProbes = !cfg.DisableProbes
	cfg.EnableDirectives = !cfg.DisableDirectives
	cfg.EnableQuery = !cfg.DisableQuery
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	sar := cfg.SAR
	if sar == nil {
		// Fail closed for requestheader; allow-all only for insecure-dev unit tests.
		if cfg.Auth == AuthRequestHeader {
			sar = DenyAllSAR{}
		} else {
			sar = AllowAllSAR{}
		}
	}
	return &Server{
		cfg:            cfg,
		log:            log,
		nsSem:          make(map[string]chan struct{}),
		globalSem:      make(chan struct{}, cfg.GlobalMaxInFlight),
		queryNSSem:     make(map[string]chan struct{}),
		queryGlobalSem: make(chan struct{}, cfg.GlobalQueryMaxInFlight),
		sar:            sar,
		eval:           cfg.EvalClient,
		client:         cfg.Client,
		query:          cfg.Query,
	}
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/openapi/v2", s.handleOpenAPIV2)
	mux.HandleFunc("/openapi/v3", s.handleOpenAPIV3)
	// Group discovery
	mux.HandleFunc("/apis/"+subv1alpha1.Group, s.handleAPIGroup)
	mux.HandleFunc("/apis/"+subv1alpha1.Group+"/", s.handleAPIGroupSlash)
	// Version discovery + probes — catch-all under version
	mux.HandleFunc("/apis/"+subv1alpha1.Group+"/"+subv1alpha1.Version, s.handleAPIResourceList)
	mux.HandleFunc("/apis/"+subv1alpha1.Group+"/"+subv1alpha1.Version+"/", s.handleVersionPaths)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	// When an EvalClient implements ReadyChecker, require Test Server readiness.
	if s.eval != nil {
		if rc, ok := s.eval.(ReadyChecker); ok {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := rc.Ready(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("test server not ready"))
				return
			}
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleOpenAPIV2(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, MinimalOpenAPIV2())
}

func (s *Server) handleOpenAPIV3(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, MinimalOpenAPIV3())
}

func (s *Server) handleAPIGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteMethodNotAllowed(w)
		return
	}
	writeJSON(w, APIGroupDocument())
}

func (s *Server) handleAPIGroupSlash(w http.ResponseWriter, r *http.Request) {
	// /apis/subresources.kubewaf.io/ or deeper without matching version handler
	path := strings.TrimPrefix(r.URL.Path, "/apis/"+subv1alpha1.Group)
	if path == "" || path == "/" {
		s.handleAPIGroup(w, r)
		return
	}
	// Fall through for version paths that didn't match exact routes.
	if strings.HasPrefix(path, "/"+subv1alpha1.Version) {
		s.handleVersionPaths(w, r)
		return
	}
	WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "not found"})
}

func (s *Server) handleAPIResourceList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteMethodNotAllowed(w)
		return
	}
	writeJSON(w, APIResourceListDocumentWith(DiscoveryFlags{
		Probes:     s.cfg.EnableProbes,
		Directives: s.cfg.EnableDirectives,
		Query:      s.cfg.EnableQuery,
	}))
}

func (s *Server) handleVersionPaths(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	// Exact version root
	if path == "/apis/"+subv1alpha1.Group+"/"+subv1alpha1.Version ||
		path == "/apis/"+subv1alpha1.Group+"/"+subv1alpha1.Version+"/" {
		s.handleAPIResourceList(w, r)
		return
	}
	if isClusterMetricsPath(path) {
		s.handleClusterMetrics(w, r)
		return
	}
	if route, err := ParseWAFSubresourcePath(path); err == nil {
		switch route.Subresource {
		case WAFSubresourceDirectives:
			s.handleDirectives(w, r)
		case WAFSubresourceMetrics:
			s.handleWAFMetrics(w, r)
		case WAFSubresourceTraces:
			s.handleWAFTraces(w, r)
		default:
			WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "not found"})
		}
		return
	}
	if isProbeSubresourcePath(path) {
		s.handleProbe(w, r)
		return
	}
	WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "not found"})
}

func isClusterMetricsPath(urlPath string) bool {
	p := strings.TrimSuffix(urlPath, "/")
	return p == "/apis/"+subv1alpha1.Group+"/"+subv1alpha1.Version+"/clustermetrics"
}

func isProbeSubresourcePath(urlPath string) bool {
	p := strings.TrimSuffix(urlPath, "/")
	const prefix = "/apis/" + subv1alpha1.Group + "/" + subv1alpha1.Version
	p = strings.TrimPrefix(p, prefix)
	parts := splitPath(p)
	return len(parts) >= 5 && parts[0] == "namespaces" && parts[4] == "probes"
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.EnableProbes {
		WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "probes subresource is disabled"})
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, ok := AllowedMethods[r.Method]; !ok {
		WriteMethodNotAllowed(w)
		return
	}

	// Auth first (avoids leaking route existence for unauthenticated callers).
	user, groups, authErr := s.authenticate(r)
	if authErr != nil {
		WriteStatus(w, authErr)
		return
	}

	// Path parse: SecAction deferred only when resource segment is "secactions" (not ns/name).
	route, err := ParseProbePath(r.URL.Path, r.URL.RawQuery)
	if err != nil {
		WriteStatus(w, mapPathError(err))
		return
	}

	// SAR before concurrency so unprivileged callers cannot burn slots.
	if merr := s.sar.CanGetParent(r.Context(), user, groups, route.ParentKind, route.Namespace, route.Name); merr != nil {
		WriteStatus(w, merr)
		return
	}

	ctrl, err := ParseControlHeaders(r.Header)
	if err != nil {
		WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: err.Error()})
		return
	}
	if ctrl.TraceID == "" {
		ctrl.TraceID = uuid.NewString()
	}
	if ctrl.CrsEnable != nil && *ctrl.CrsEnable {
		WriteStatus(w, &MappedError{HTTPStatus: 422, Reason: ReasonCRSPathA, Message: "CRS Path A is not supported under probe go-coraza"})
		return
	}

	// Read/size-check body before concurrency slots so slow uploads do not hold slots.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: "failed to read body"})
		return
	}
	if len(body) > maxBodyBytes {
		WriteStatus(w, &MappedError{HTTPStatus: http.StatusRequestEntityTooLarge, Reason: "RequestEntityTooLarge", Message: "body exceeds 1 MiB"})
		return
	}

	// Global in-flight gate.
	select {
	case s.globalSem <- struct{}{}:
		defer func() { <-s.globalSem }()
	default:
		WriteStatus(w, &MappedError{HTTPStatus: 429, Reason: ReasonTooManyRequests, Message: "global concurrency limit exceeded"})
		return
	}

	// Per-namespace concurrency gate.
	slot := s.acquireNS(route.Namespace)
	if slot == nil {
		WriteStatus(w, &MappedError{HTTPStatus: 429, Reason: ReasonTooManyRequests, Message: "per-namespace concurrency limit exceeded"})
		return
	}
	defer s.releaseNS(route.Namespace, slot)

	appHeaders := FilterAppHeaders(r.Header)

	// Assemble directives.
	assembly, dataFiles, parentUID, merr := s.assemble(r.Context(), route)
	if merr != nil {
		WriteStatus(w, merr)
		return
	}

	if s.eval == nil {
		WriteStatus(w, &MappedError{HTTPStatus: 503, Reason: "TestServerUnreachable", Message: "eval client not configured"})
		return
	}

	evalReq := &api.EvalRequest{
		Directives: assembly.Directives,
		DataFiles:  dataFiles.Files,
		Request: api.EvalHTTPRequest{
			Method:     r.Method,
			Path:       route.AppPath,
			RawQuery:   route.RawQuery,
			Headers:    appHeaders,
			Body:       body,
			RemoteAddr: ctrl.RemoteAddr,
		},
		Options: api.EvalOptions{
			MaxMatches:     ctrl.MaxMatches,
			TimeoutSeconds: ctrl.TimeoutSeconds,
			PreferNoCache:  true,
		},
		TraceID: ctrl.TraceID,
	}

	evalResp, merr := s.eval.Eval(r.Context(), evalReq, ctrl.TimeoutSeconds)
	if merr != nil {
		WriteStatus(w, merr)
		return
	}

	probe := MapEvalToProbe(route, ctrl, assembly, len(dataFiles.Files), dataFiles.DroppedBasenames, evalResp, parentUID)
	if probe.Status.RequestEcho != nil {
		probe.Status.RequestEcho.Method = r.Method
	}
	writeJSON(w, probe)
}

func mapPathError(err error) *MappedError {
	if pe, ok := err.(*PathError); ok {
		status := 404
		switch pe.Reason {
		case ReasonInvalidProbePath:
			// Empty segments and other client path errors → 400.
			status = 400
		case "SecActionProbesDeferred":
			status = 400
		case ReasonNotFound:
			// Unknown suffix (e.g. not /http) → 404 per design.
			status = 404
		}
		return &MappedError{HTTPStatus: status, Reason: pe.Reason, Message: pe.Message}
	}
	return &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "invalid probe path"}
}

func (s *Server) assemble(ctx context.Context, route *ProbeRoute) (*probeassemble.AssemblyResult, *probeassemble.DataFilesResult, string, *MappedError) {
	if s.cfg.SkipAssembly || s.client == nil {
		// Stub assembly for discovery/PR0 path: preamble only + a harmless pass rule.
		doc := probeassemble.JoinDocument(probeassemble.Preamble(), []string{
			`SecRule ARGS "@rx ." "id:999999,phase:2,pass,nolog,msg:'stub'"`,
		})
		return &probeassemble.AssemblyResult{
			Directives:      doc,
			RulesLoaded:     1,
			DirectivesCount: probeassemble.CountNonEmptyLines(doc),
		}, &probeassemble.DataFilesResult{Files: map[string][]byte{}}, "", nil
	}

	switch route.ParentKind {
	case ParentSecRule:
		return s.assembleSecRule(ctx, route)
	case ParentRuleSet:
		return s.assembleRuleSet(ctx, route)
	case ParentWAF:
		return s.assembleWAF(ctx, route)
	default:
		return nil, nil, "", &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: "unknown parent kind"}
	}
}

func (s *Server) assembleSecRule(ctx context.Context, route *ProbeRoute) (*probeassemble.AssemblyResult, *probeassemble.DataFilesResult, string, *MappedError) {
	sr := &seclangv1beta1.SecRule{}
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: route.Namespace, Name: route.Name}, sr); err != nil {
		return nil, nil, "", mapKubeError(err)
	}
	asm, err := probeassemble.AssembleSecRule(sr)
	if err != nil {
		return nil, nil, "", mapAssemblyErr(err)
	}
	return s.withDataFiles(ctx, route.Namespace, probeassemble.PhraseListPolicyFailClosed, asm, string(sr.UID))
}

func (s *Server) assembleRuleSet(ctx context.Context, route *ProbeRoute) (*probeassemble.AssemblyResult, *probeassemble.DataFilesResult, string, *MappedError) {
	rs := &wafv1beta1.RuleSet{}
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: route.Namespace, Name: route.Name}, rs); err != nil {
		return nil, nil, "", mapKubeError(err)
	}
	objects, merr := s.resolveRuleRefs(ctx, probeassemble.DefaultRuleRefs(rs.Namespace, rs.Spec.RuleRefs), rs)
	if merr != nil {
		return nil, nil, "", merr
	}
	asm, err := probeassemble.AssembleResolved(objects, true, nil)
	if err != nil {
		return nil, nil, "", mapAssemblyErr(err)
	}
	return s.withDataFiles(ctx, route.Namespace, probeassemble.PhraseListPolicyFailClosed, asm, string(rs.UID))
}

func (s *Server) assembleWAF(ctx context.Context, route *ProbeRoute) (*probeassemble.AssemblyResult, *probeassemble.DataFilesResult, string, *MappedError) {
	waf := &wafv1beta1.WAF{}
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: route.Namespace, Name: route.Name}, waf); err != nil {
		return nil, nil, "", mapKubeError(err)
	}
	if waf.Spec.CRSEnable {
		return nil, nil, "", &MappedError{HTTPStatus: 422, Reason: ReasonCRSPathA, Message: "CRS Path A is not supported under probe go-coraza"}
	}
	objects, merr := s.resolveRuleRefs(ctx, probeassemble.DefaultRuleRefs(waf.Namespace, waf.Spec.RuleSetRefs), waf)
	if merr != nil {
		return nil, nil, "", merr
	}
	crs := probeassemble.CRSTuningFromWAF(waf.Spec.CRS)
	asm, err := probeassemble.AssembleResolved(objects, crs == nil, crs)
	if err != nil {
		return nil, nil, "", mapAssemblyErr(err)
	}
	return s.withDataFiles(ctx, route.Namespace, probeassemble.PhraseListPolicyFromWAF(waf.Spec.PhraseListPolicy), asm, string(waf.UID))
}

func (s *Server) resolveRuleRefs(ctx context.Context, refs []wafv1beta1.RuleRef, source client.Object) ([]unstructured.Unstructured, *MappedError) {
	resolver := references2.NewRuleRefResolver(s.client, s.client.Scheme())
	objects, refErrs, err := resolver.Resolve(ctx, refs, source)
	if err != nil {
		return nil, &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "failed to resolve rule references"}
	}
	if len(refErrs) > 0 {
		msgs := make([]string, 0, len(refErrs))
		for _, e := range refErrs {
			msgs = append(msgs, e.Error())
		}
		return nil, &MappedError{
			HTTPStatus: 422,
			Reason:     ReasonReferencesUnresolved,
			Message:    (&probeassemble.ReferenceFailures{Messages: msgs}).Error(),
		}
	}
	return objects, nil
}

func (s *Server) withDataFiles(ctx context.Context, namespace string, policy probeassemble.PhraseListPolicy, asm *probeassemble.AssemblyResult, uid string) (*probeassemble.AssemblyResult, *probeassemble.DataFilesResult, string, *MappedError) {
	lines := strings.Split(asm.Directives, "\n")
	df, err := probeassemble.ResolveDataFiles(ctx, s.cfg.DataFiles, namespace, policy, lines, nil)
	if err != nil {
		return nil, nil, "", mapAssemblyDataErr(err)
	}
	// Apply IgnoreUnknown SecLang rewrite when basenames were dropped
	// (including full drop where EffectiveLines is empty).
	if len(df.DroppedBasenames) > 0 {
		asm.Directives = strings.Join(df.EffectiveLines, "\n")
		asm.DirectivesCount = probeassemble.CountNonEmptyLines(asm.Directives)
	}
	return asm, df, uid, nil
}

func mapKubeError(err error) *MappedError {
	if apierrors.IsNotFound(err) {
		return &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "parent object not found"}
	}
	return &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "failed to load parent object"}
}

func mapAssemblyErr(err error) *MappedError {
	switch {
	case errors.Is(err, probeassemble.ErrRuleIDsUnresolved):
		return &MappedError{HTTPStatus: 422, Reason: ReasonRuleIDsUnresolved, Message: "rule ids unresolved; wait for controller AssignedIDs"}
	case errors.Is(err, probeassemble.ErrReferencesUnresolved):
		return &MappedError{HTTPStatus: 422, Reason: ReasonReferencesUnresolved, Message: err.Error()}
	case errors.Is(err, probeassemble.ErrCRSPathA):
		return &MappedError{HTTPStatus: 422, Reason: ReasonCRSPathA, Message: "CRS Path A is not supported under probe go-coraza"}
	default:
		return &MappedError{HTTPStatus: 422, Reason: ReasonAssemblyFailed, Message: "failed to assemble parent"}
	}
}

func mapAssemblyDataErr(err error) *MappedError {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "PhraseListNotReady"):
		return &MappedError{HTTPStatus: 422, Reason: "PhraseListNotReady", Message: "phrase/ip list not ready"}
	case strings.Contains(msg, "DataFileUnresolved"):
		return &MappedError{HTTPStatus: 422, Reason: "DataFileUnresolved", Message: "data file unresolved"}
	case strings.Contains(msg, "PhraseFilesTooLarge"):
		return &MappedError{HTTPStatus: 422, Reason: "PhraseFilesTooLarge", Message: "data files too large"}
	default:
		return &MappedError{HTTPStatus: 422, Reason: ReasonAssemblyFailed, Message: "data file assembly failed"}
	}
}

func (s *Server) authenticate(r *http.Request) (user string, groups []string, merr *MappedError) {
	switch s.cfg.Auth {
	case AuthInsecureDev:
		return s.cfg.DevUser, nil, nil
	case AuthRequestHeader:
		// Trust X-Remote-* only when peer client cert was verified by TLS.
		requirePeer := true
		if s.cfg.RequirePeerCert != nil {
			requirePeer = *s.cfg.RequirePeerCert
		}
		if requirePeer {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				return "", nil, &MappedError{HTTPStatus: 401, Reason: "Unauthorized", Message: "client certificate required"}
			}
			// Enforce requestheader-allowed-names when configured (empty = any verified peer).
			if len(s.cfg.RequestHeaderAllowedNames) > 0 {
				if !peerCertNameAllowed(r, s.cfg.RequestHeaderAllowedNames) {
					return "", nil, &MappedError{HTTPStatus: 401, Reason: "Unauthorized", Message: "client certificate name not allowed"}
				}
			}
		}
		u := r.Header.Get("X-Remote-User")
		if u == "" {
			return "", nil, &MappedError{HTTPStatus: 401, Reason: "Unauthorized", Message: "missing X-Remote-User"}
		}
		g := r.Header.Values("X-Remote-Group")
		return u, g, nil
	default:
		return s.cfg.DevUser, nil, nil
	}
}

// peerCertNameAllowed reports whether any verified peer cert CN or DNS SAN is in allowed.
func peerCertNameAllowed(r *http.Request, allowed []string) bool {
	if r.TLS == nil {
		return false
	}
	set := make(map[string]struct{}, len(allowed))
	for _, n := range allowed {
		n = strings.TrimSpace(n)
		if n != "" {
			set[n] = struct{}{}
		}
	}
	if len(set) == 0 {
		return true
	}
	for _, cert := range r.TLS.PeerCertificates {
		if _, ok := set[cert.Subject.CommonName]; ok {
			return true
		}
		for _, dns := range cert.DNSNames {
			if _, ok := set[dns]; ok {
				return true
			}
		}
	}
	return false
}

func (s *Server) acquireNS(ns string) chan struct{} {
	return s.acquireNamedSem(s.nsSem, s.cfg.PerNamespaceConcurrency, ns)
}

func (s *Server) acquireQueryNS(ns string) chan struct{} {
	return s.acquireNamedSem(s.queryNSSem, s.cfg.PerNamespaceQueryConcurrency, ns)
}

func (s *Server) acquireNamedSem(m map[string]chan struct{}, n int, ns string) chan struct{} {
	s.nsMu.Lock()
	sem, ok := m[ns]
	if !ok {
		if len(m) >= maxNSSemEntries {
			// Evict idle namespaces (semaphore with no held slots).
			for k, ch := range m {
				if len(ch) == 0 {
					delete(m, k)
					if len(m) < maxNSSemEntries {
						break
					}
				}
			}
		}
		if len(m) >= maxNSSemEntries {
			s.nsMu.Unlock()
			return nil
		}
		if n <= 0 {
			n = 1
		}
		sem = make(chan struct{}, n)
		m[ns] = sem
	}
	s.nsMu.Unlock()
	select {
	case sem <- struct{}{}:
		return sem
	default:
		return nil
	}
}

func (s *Server) releaseNS(ns string, sem chan struct{}) {
	select {
	case <-sem:
	default:
	}
	_ = ns
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// Ensure metav1 import used when encoding Status via WriteStatus.
var _ = metav1.Status{}
