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

package subresourceapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/references2"
)

var maxDirectivesBytes = 4 * 1024 * 1024

// DirectivesResponse is the default JSON body for GET …/wafs/{name}/directives.
type DirectivesResponse struct {
	Directives  []string `json:"directives"`
	Count       int      `json:"count"`
	ContentHash string   `json:"contentHash"`
}

func (s *Server) handleDirectives(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		WriteMethodNotAllowed(w)
		return
	}
	if !s.cfg.EnableDirectives {
		WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "directives subresource is disabled"})
		return
	}
	user, groups, authErr := s.authenticate(r)
	if authErr != nil {
		WriteStatus(w, authErr)
		return
	}
	route, err := ParseWAFSubresourcePath(r.URL.Path)
	if err != nil {
		WriteStatus(w, mapPathError(err))
		return
	}
	if merr := s.sar.CanGetParent(r.Context(), user, groups, ParentWAF, route.Namespace, route.Name); merr != nil {
		WriteStatus(w, merr)
		return
	}
	dirs, hash, merr := s.assembleWAFDirectives(r.Context(), route.Namespace, route.Name)
	if merr != nil {
		WriteStatus(w, merr)
		return
	}
	joined := strings.Join(dirs, "\n")
	if len(joined) > maxDirectivesBytes {
		WriteStatus(w, &MappedError{HTTPStatus: 413, Reason: "RequestEntityTooLarge", Message: "rendered directives exceed 4 MiB"})
		return
	}
	if prefersPlainText(r.Header.Get("Accept")) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(joined))
		return
	}
	writeJSON(w, DirectivesResponse{
		Directives:  dirs,
		Count:       len(dirs),
		ContentHash: hash,
	})
}

func prefersPlainText(accept string) bool {
	accept = strings.ToLower(accept)
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(accept), "text/plain")
}

func (s *Server) assembleWAFDirectives(ctx context.Context, ns, name string) ([]string, string, *MappedError) {
	if s.client == nil {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "kube client not configured"}
	}
	waf := &wafv1beta1.WAF{}
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, waf); err != nil {
		return nil, "", mapKubeError(err)
	}
	resolver := references2.NewRuleRefResolver(s.client, s.client.Scheme())
	objects, refErrs, err := resolver.Resolve(ctx, waf.Spec.RuleSetRefs, waf)
	if err != nil {
		return nil, "", &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "failed to resolve rule references"}
	}
	if len(refErrs) > 0 {
		msgs := make([]string, 0, len(refErrs))
		for _, e := range refErrs {
			msgs = append(msgs, e.Error())
		}
		return nil, "", &MappedError{HTTPStatus: 422, Reason: ReasonReferencesUnresolved, Message: strings.Join(msgs, "; ")}
	}
	rules, err := references2.GetSecRule(objects)
	if err != nil {
		return nil, "", &MappedError{HTTPStatus: 422, Reason: ReasonAssemblyFailed, Message: err.Error()}
	}
	dirs := config.BuildDirectives(waf, rules)
	phrase := config.DiscoverAndResolvePhraseFiles(ctx, s.client, waf, dirs, objects)
	if phrase != nil && phrase.Error != nil {
		return nil, "", &MappedError{HTTPStatus: 422, Reason: "PhraseFilesFailed", Message: phrase.Error.Error()}
	}
	if phrase != nil && len(phrase.DroppedBasenames) > 0 {
		dirs = phrase.Directives
	}
	joined := strings.Join(dirs, "\n")
	sum := sha256.Sum256([]byte(joined))
	return dirs, "sha256:" + hex.EncodeToString(sum[:]), nil
}
