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

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	seclangv1beta1 "github.com/buzz-it/kubewaf/api/seclang/v1beta1"
	"github.com/buzz-it/kubewaf/api/seclang/v1beta1/convert"
	"github.com/buzz-it/kubewaf/internal/coraza"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(seclangv1beta1.AddToScheme(scheme))
}

type loadedSecRule struct {
	seclangv1beta1.SecRule `json:",inline"`
	SecLang                string `json:"secLang,omitempty"`
	LoadedToCoraza         bool   `json:"loadedToCoraza"`
	LoadError              string `json:"loadError,omitempty"`
}

func main() {
	kubeconfig := flag.String("test-kubeconfig", "", "(optional) absolute path to the kubeconfig file")
	port := flag.Int("port", 8080, "port to listen on")
	flag.Parse()

	log.Printf("Starting test-service on port %d", *port)

	// Setup Kubernetes client
	var cfg *rest.Config
	var err error
	if *kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	} else {
		cfg, err = ctrlconfig.GetConfig()
	}
	if err != nil {
		log.Fatalf("Failed to get kubeconfig: %v", err)
	}

	k8sClient, err := client.New(cfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		log.Fatal("Failed to create client: ", err)
	}

	// Load all SecRules and prepare Coraza WAF for each
	ctx := context.Background()
	var secRuleList seclangv1beta1.SecRuleList
	if err := k8sClient.List(ctx, &secRuleList); err != nil {
		log.Printf("Warning: Failed to list SecRules: %v. Starting with empty list.", err)
	}

	rules := make(map[string]loadedSecRule)
	for i := range secRuleList.Items {
		rule := secRuleList.Items[i]
		key := fmt.Sprintf("%s/%s", rule.Namespace, rule.Name)
		lr := loadedSecRule{
			SecRule:        rule,
			LoadedToCoraza: false,
		}

		// Convert to directives and load into Coraza WAF
		directives, convErr := convert.ConvertSecRule(rule)
		if convErr != nil {
			lr.LoadError = fmt.Sprintf("convert error: %v", convErr)
		} else {
			secLang := convert.ConvertToSecLangString(directives)
			lr.SecLang = secLang

			_, loadErr := coraza.LoadAndValidateSeclangDirectives(directives)
			if loadErr != nil {
				lr.LoadError = fmt.Sprintf("coraza load error: %v", loadErr)
			} else {
				lr.LoadedToCoraza = true
			}
		}

		rules[key] = lr
		log.Printf("Loaded SecRule %s (Coraza: %t)", key, lr.LoadedToCoraza)
	}

	log.Printf("Loaded %d SecRules", len(rules))

	// HTTP handler for /secrule/<namespace>/<name>
	http.HandleFunc("/secrule/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(r.URL.Path, "/")
		parts := strings.Split(path, "/")
		if len(parts) < 3 || parts[0] != "secrule" {
			http.Error(w, "Invalid path. Use /secrule/<namespace>/<name>", http.StatusBadRequest)
			return
		}

		ns := parts[1]
		name := parts[2]
		key := fmt.Sprintf("%s/%s", ns, name)

		lr, exists := rules[key]
		if !exists {
			http.Error(w, fmt.Sprintf("SecRule %s not found", key), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(lr); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	// Health check
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	// List all available rules
	http.HandleFunc("/secrules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		summary := make(map[string]map[string]bool)
		for k, lr := range rules {
			summary[k] = map[string]bool{
				"loadedToCoraza": lr.LoadedToCoraza,
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":  len(rules),
			"rules":  summary,
			"status": "SecRules loaded as Coraza WAF instances",
		})
	})

	log.Printf("Server listening on :%d", *port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil); err != nil {
		log.Fatal("Server failed: ", err)
	}
}
