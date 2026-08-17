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

// Package pipeline is the single build+publish path shared by the leader WAF
// controller and every-replica dataplane sync. Keeping one pipeline prevents
// leader/sync drift on challenge HMAC, provider discovery, and ECDS publish.
package pipeline

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/challenge"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/extensionserver"
	"github.com/kubewaf-io/kubewaf/internal/references2"
)

// Publishers are in-memory dataplane sinks (safe on every replica).
type Publishers struct {
	ECDS        *ecds.Server
	EGExtension *extensionserver.Server
}

// Options configure Build / BuildAndPublish.
type Options struct {
	BuildOpts config.BuildOptions
	Scheme    *runtime.Scheme

	// EnsureChallengeSecret creates/adopts managed challenge Secrets (leader only).
	EnsureChallengeSecret bool

	// LockRefs writes finalizers/back-references on resolved objects (leader only).
	// Non-leader sync must leave this false.
	LockRefs bool

	// SkipECDS skips ECDS Upsert. Default false: Upsert when Publishers.ECDS != nil.
	SkipECDS bool

	// RequireRefsOK aborts Build when any reference error is present.
	// Dataplane sync sets this so unresolved RuleSets never replace a last-good
	// ECDS snapshot. Leader Build also refuses Publish when refs fail.
	RequireRefsOK bool
}

// Result is the portable artifact plus metadata useful for status.
type Result struct {
	Portable          *config.PortableConfig
	Challenge         challenge.ChallengeHMACResult
	ProviderDetection string
	ReferenceErrors   []references2.ReferenceError
	ResolvedObjects   []unstructured.Unstructured
	ResolvedObjectN   int
	// PhraseFiles holds inject resolution for PhraseList/IPList data_files.
	PhraseFiles *config.PhraseFilesResult
}

// Build resolves rules (read-only), challenge HMAC, provider auto-discovery,
// and returns a PortableConfig. It does not write Kubernetes status or slots.
func Build(
	ctx context.Context,
	c client.Client,
	waf *wafv1beta1.WAF,
	opts Options,
) (*Result, error) {
	if waf == nil {
		return nil, fmt.Errorf("waf is nil")
	}

	resolver := references2.NewRuleRefResolver(c, opts.Scheme)
	var (
		objects []unstructured.Unstructured
		refErrs []references2.ReferenceError
		err     error
	)
	if opts.LockRefs {
		objects, refErrs, err = resolver.AddUpdateReconcile(ctx, waf.Spec.RuleSetRefs, waf)
	} else {
		objects, refErrs, err = resolver.Resolve(ctx, waf.Spec.RuleSetRefs, waf)
	}
	if err != nil {
		return nil, err
	}
	if opts.RequireRefsOK && len(refErrs) > 0 {
		return &Result{
			ReferenceErrors:   refErrs,
			ResolvedObjectN:   len(objects),
			ProviderDetection: "explicit (spec.provider.type)",
		}, fmt.Errorf("%d reference error(s): %v", len(refErrs), refErrs)
	}

	rules, err := references2.GetSecRule(objects)
	if err != nil {
		return nil, err
	}

	buildOpts := opts.BuildOpts
	var challengeRes challenge.ChallengeHMACResult
	if challenge.ChallengeEnabled(waf.Spec.Challenge) {
		challengeRes, err = challenge.ResolveChallengeHMAC(ctx, c, opts.Scheme, waf, challenge.ResolveOptions{
			EnsureManaged: opts.EnsureChallengeSecret,
		})
		if err != nil {
			return nil, fmt.Errorf("challenge hmac: %w", err)
		}
		buildOpts.ChallengeHMAC = challengeRes.Value
	}

	providerDetection := "explicit (spec.provider.type)"
	if config.NeedsProviderDiscovery(waf) {
		discovered, derr := config.DiscoverProvider(ctx, c, waf)
		if derr != nil {
			return nil, fmt.Errorf("provider discovery: %w", derr)
		}
		config.ApplyDiscovery(&buildOpts, discovered)
		providerDetection = discovered.Reason
		if providerDetection == "" {
			providerDetection = "auto"
		}
	}

	// PhraseList/IPList discovery / inject (ModSecurity Path B; always on).
	// Build provisional directives the same way BuildFromWAF will so scans match published SecLang.
	provisional := config.BuildDirectives(waf, rules)
	phraseRes := config.DiscoverAndResolvePhraseFiles(
		ctx, c, waf, provisional, objects,
	)
	if phraseRes != nil && phraseRes.Error != nil && !phraseRes.Ready {
		return &Result{
			PhraseFiles:       phraseRes,
			ProviderDetection: providerDetection,
			ReferenceErrors:   refErrs,
			ResolvedObjects:   objects,
			ResolvedObjectN:   len(objects),
		}, fmt.Errorf("phrase lists: %w", phraseRes.Error)
	}
	if phraseRes != nil && len(phraseRes.Files) > 0 {
		buildOpts.PhraseFiles = phraseRes.Files
		buildOpts.OverrideCRSCount = phraseRes.OverrideCRSCount
	}
	// Use rewritten directives (IgnoreUnknown) when discovery dropped custom lines.
	rulesForBuild := rules
	if phraseRes != nil && len(phraseRes.DroppedBasenames) > 0 {
		// Rebuild rules path: pass rewritten full directive list by replacing
		// user rules segment is complex; instead feed full rewritten directives
		// as a single synthetic rule blob via empty setup is wrong.
		// BuildFromWAF re-runs BuildDirectives — apply rewrite on the user rules
		// only by setting PhraseFiles and relying on DropSecLang applied to full
		// provisional list via DirectivesOverride.
		buildOpts.DirectivesOverride = phraseRes.Directives
		rulesForBuild = nil
	}

	portable, err := config.BuildFromWAF(waf, rulesForBuild, buildOpts)
	if err != nil {
		return nil, fmt.Errorf("build portable config: %w", err)
	}

	return &Result{
		Portable:          portable,
		Challenge:         challengeRes,
		ProviderDetection: providerDetection,
		ReferenceErrors:   refErrs,
		ResolvedObjects:   objects,
		ResolvedObjectN:   len(objects),
		PhraseFiles:       phraseRes,
	}, nil
}

// Publish writes the portable config to local ECDS and EG extension indexes.
// Kubernetes platform slots (Istio/Cilium) are leader-only and not handled here.
func Publish(p *config.PortableConfig, pubs Publishers, opts Options) error {
	if p == nil {
		return fmt.Errorf("portable config is nil")
	}
	if !opts.SkipECDS {
		if pubs.ECDS == nil {
			// Stable reason string for controller status (matches historical markNotReady reason).
			return fmt.Errorf("ECDSNotConfigured: ECDS server is not configured on the reconciler")
		}
		if err := pubs.ECDS.Upsert(p); err != nil {
			return fmt.Errorf("ECDSUpsertFailed: %w", err)
		}
	}
	if pubs.EGExtension != nil {
		// No-op for non-EG providers inside Upsert (filters by provider).
		pubs.EGExtension.Upsert(p)
	}
	return nil
}

// BuildAndPublish is the shared leader/sync entrypoint for in-memory dataplane.
func BuildAndPublish(
	ctx context.Context,
	c client.Client,
	waf *wafv1beta1.WAF,
	pubs Publishers,
	opts Options,
) (*Result, error) {
	res, err := Build(ctx, c, waf, opts)
	if err != nil {
		return res, err
	}
	// Never publish a partial rule set. Unresolved refs must keep the last
	// good ECDS snapshot (fail-closed). Callers that need the error list
	// still receive it on Result.
	if res != nil && len(res.ReferenceErrors) > 0 {
		return res, fmt.Errorf("%d reference error(s): %v", len(res.ReferenceErrors), res.ReferenceErrors)
	}
	if err := Publish(res.Portable, pubs, opts); err != nil {
		return res, err
	}
	return res, nil
}

// DropLocal removes in-memory state for a deleted WAF (every replica).
func DropLocal(namespace, name string, pubs Publishers) {
	ext := config.ExtensionName(namespace, name)
	if pubs.ECDS != nil {
		_ = pubs.ECDS.Delete(ext)
	}
	if pubs.EGExtension != nil {
		pubs.EGExtension.Delete(namespace, name)
	}
}
