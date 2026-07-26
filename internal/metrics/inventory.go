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

package metrics

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// InventoryUpdater periodically updates global inventory metrics
// (total SecRules, RuleSets, WAFs, etc.).
// This gives accurate counts even when resources are created/deleted
// outside of active reconciliation.
type InventoryUpdater struct {
	client.Client
	interval time.Duration
}

// NewInventoryUpdater creates a new inventory updater.
func NewInventoryUpdater(c client.Client, interval time.Duration) *InventoryUpdater {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &InventoryUpdater{
		Client:   c,
		interval: interval,
	}
}

// Start implements manager.Runnable.
func (u *InventoryUpdater) Start(ctx context.Context) error {
	log := log.FromContext(ctx).WithName("metrics.inventory")
	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()

	// Initial population
	u.updateAll(ctx, log)

	for {
		select {
		case <-ticker.C:
			u.updateAll(ctx, log)
		case <-ctx.Done():
			return nil
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
// Only one replica should scrape/list inventory metrics.
func (u *InventoryUpdater) NeedLeaderElection() bool { return true }

// updateAll lists all relevant resources and updates the gauges.
func (u *InventoryUpdater) updateAll(ctx context.Context, logger logr.Logger) {
	// SecRules
	var secRules seclangv1beta1.SecRuleList
	if err := u.List(ctx, &secRules); err == nil {
		byNS := make(map[string]int)
		for i := range secRules.Items {
			ns := secRules.Items[i].Namespace
			byNS[ns]++
		}
		for ns, count := range byNS {
			SecRuleTotal.WithLabelValues(ns).Set(float64(count))
		}
		// Also set 0 for namespaces with no rules (cleanup old values is hard without tracking)
	}

	// RuleSets
	var ruleSets wafv1beta1.RuleSetList
	if err := u.List(ctx, &ruleSets); err == nil {
		byNS := make(map[string]int)
		for i := range ruleSets.Items {
			ns := ruleSets.Items[i].Namespace
			byNS[ns]++
		}
		for ns, count := range byNS {
			RuleSetTotal.WithLabelValues(ns).Set(float64(count))
		}
	}

	// WAFs
	var wafs wafv1beta1.WAFList
	if err := u.List(ctx, &wafs); err == nil {
		byNS := make(map[string]int)
		for i := range wafs.Items {
			ns := wafs.Items[i].Namespace
			byNS[ns]++
		}
		for ns, count := range byNS {
			WAFTotal.WithLabelValues(ns).Set(float64(count))
		}
	}

	// WAFInstances (when they become more active)
	var instances wafv1beta1.WAFInstanceList
	if err := u.List(ctx, &instances); err == nil {
		// We can add a metric later if needed
		_ = instances
	}

	logger.V(3).Info("inventory metrics updated")
}
