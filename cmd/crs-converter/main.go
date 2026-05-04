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
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/coreruleset/crslang/translator"
	types "github.com/coreruleset/crslang/types"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"
)

var (
	customScheme = runtime.NewScheme()
)

func init() {
	_ = v1beta1.AddToScheme(customScheme)
}

func main() {
	inputPath := flag.String("input", "", "Path to SecLang file or directory containing .conf files")
	outputDir := flag.String("output-dir", "config/samples/crs", "Directory to write generated YAML CRs")
	crsVersion := flag.String("crs-version", "4.3.0", "CRS version for labels")
	namespace := flag.String("namespace", "", "Namespace for generated resources (empty = cluster scoped in metadata)")
	namePrefix := flag.String("name-prefix", "crs-", "Prefix for CR names")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  CRS to kubeWAF SecRule converter\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprint(os.Stderr, "  "+os.Args[0]+" -input=hack/crs-converted \\\n")
		fmt.Fprint(os.Stderr, "    -output-dir=hack/crs-converted -crs-version=4.3.0\n")
	}
	flag.Parse()

	if *inputPath == "" {
		flag.Usage()
		log.Fatal("input path is required")
	}

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	if err := processInput(*inputPath, *outputDir, *crsVersion, *namePrefix, *namespace); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Successfully converted rules from %s to %s\n", *inputPath, *outputDir)
}

func processInput(inputPath, outputDir, crsVersion, namePrefix, ns string) error {
	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("failed to stat input: %w", err)
	}

	if info.IsDir() {
		return processDirectory(inputPath, outputDir, crsVersion, namePrefix, ns)
	}
	return processFile(inputPath, outputDir, crsVersion, ns, info.Name())
}

func processDirectory(dir, outputDir, crsVersion, namePrefix, ns string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		nameLower := strings.ToLower(info.Name())
		if !strings.HasSuffix(nameLower, ".conf") && !strings.HasSuffix(info.Name(), ".rules") {
			return nil
		}

		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		outName := strings.ToLower(strings.ReplaceAll(base, "_", "-"))
		if namePrefix != "" {
			outName = namePrefix + outName
		}

		return processFile(path, outputDir, crsVersion, ns, outName)
	})
}

func processFile(inputFile, outputDir, crsVersion, ns, crName string) error {
	fmt.Printf("Processing %s...\n", inputFile)

	secLangs, err := translator.LoadSeclang(inputFile)
	if err != nil {
		return fmt.Errorf("failed to load seclang from %s: %w", inputFile, err)
	}

	secLangs = *translator.ToCRSLang(secLangs)

	kubeSecRule := v1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
	}

	if ns != "" {
		kubeSecRule.Namespace = ns
	}

	labels := map[string]string{
		"app.kubernetes.io/part-of": "coreruleset",
		"coreruleset/version":       crsVersion,
		"coreruleset/file":          filepath.Base(inputFile),
	}
	kubeSecRule.Labels = labels

	// SecMarker is stored in the Marker field of DirectiveList, not inside Directives.
	// We only attach it to the *last* SecRule in each group.
	for _, secLangRules := range secLangs.DirectiveList {
		marker := ""
		if secLangRules.Marker.Name == types.SecMarker {
			marker = secLangRules.Marker.Parameter
		}

		// Count real rules so we know which is the last one
		ruleCount := 0
		for _, r := range secLangRules.Directives {
			if _, ok := r.(*types.RuleWithCondition); ok {
				ruleCount++
			}
		}

		current := 0
		for _, rule := range secLangRules.Directives {
			if r, ok := rule.(*types.RuleWithCondition); ok {
				current++
				m := ""
				if marker != "" && current == ruleCount {
					m = marker // only the last rule gets the marker
				}
				if err := translateSecRule(r, &kubeSecRule, m); err != nil {
					return fmt.Errorf("failed to translate rule in %s: %w", inputFile, err)
				}
			}
		}
	}

	if len(kubeSecRule.Spec.SecRules) == 0 {
		fmt.Printf("No rules found in %s, skipping\n", inputFile)
		return nil
	}

	outputPath := filepath.Join(outputDir, crName+".yaml")
	if err := writeAsYAML(&kubeSecRule, outputPath); err != nil {
		return fmt.Errorf("failed to write YAML for %s: %w", crName, err)
	}

	fmt.Printf("  -> Generated %s with %d rules\n", outputPath, len(kubeSecRule.Spec.SecRules))
	return nil
}

func translateSecRule(secRule *types.RuleWithCondition, kubeSecRule *v1beta1.SecRule, secMarker string) error {
	target, err := convert.ConvertCrsRule(*secRule, secMarker)
	if err != nil {
		return err
	}

	kubeSecRule.Spec.SecRules = append(kubeSecRule.Spec.SecRules, target)
	return nil
}

func writeAsYAML(obj runtime.Object, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	printer := printers.NewTypeSetter(customScheme).
		ToPrinter(&printers.YAMLPrinter{})

	return printer.PrintObj(obj, f)
}
