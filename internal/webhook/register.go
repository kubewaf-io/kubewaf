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

package webhook

import (
	ctrl "sigs.k8s.io/controller-runtime"
)

// SetupWithManager registers all validating webhooks.
func SetupWithManager(mgr ctrl.Manager) error {
	if err := SetupSecRuleWebhook(mgr); err != nil {
		return err
	}
	if err := SetupSecActionWebhook(mgr); err != nil {
		return err
	}
	if err := SetupPhraseListWebhook(mgr); err != nil {
		return err
	}
	if err := SetupIPListWebhook(mgr); err != nil {
		return err
	}
	if err := SetupRuleSetWebhook(mgr); err != nil {
		return err
	}
	if err := SetupWAFWebhook(mgr); err != nil {
		return err
	}
	return nil
}
