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
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	nonDNS       = regexp.MustCompile(`[^a-z0-9-]+`)
)

func init() {
	_ = v1beta1.AddToScheme(customScheme)
}

func main() {
	inputPath := flag.String("input", "", "Path to SecLang file or directory containing .conf files")
	outputDir := flag.String("output-dir", "config/samples/crs", "Directory to write generated YAML CRs")
	crsVersion := flag.String("crs-version", "4.27.0", "CRS version for labels (match engine-embedded CRS when possible)")
	namespace := flag.String("namespace", "", "Namespace for generated resources (empty = no namespace in metadata)")
	namePrefix := flag.String("name-prefix", "crs-", "Prefix for CR names")
	// mode: one = one SecRule CR per logical rule (canonical match[] form, default)
	//       bag = legacy one multi-rule CR per .conf file (secLangRules[])
	mode := flag.String("mode", "one", "Output mode: one (one CR per rule, default) or bag (one multi-rule CR per file)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  CRS to kubeWAF SecRule converter\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprint(os.Stderr, "  "+os.Args[0]+" -input=/path/to/coreruleset/rules \\\n")
		fmt.Fprint(os.Stderr, "    -output-dir=config/samples/crs -crs-version=4.27.0 -mode=one\n")
	}
	flag.Parse()

	if *inputPath == "" {
		flag.Usage()
		log.Fatal("input path is required")
	}
	switch strings.ToLower(*mode) {
	case "one", "bag":
	default:
		log.Fatalf("invalid -mode %q (want one|bag)", *mode)
	}

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	if err := processInput(
		*inputPath, *outputDir, *crsVersion, *namePrefix, *namespace, strings.ToLower(*mode),
	); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Successfully converted rules from %s to %s (mode=%s)\n", *inputPath, *outputDir, *mode)
}

func processInput(inputPath, outputDir, crsVersion, namePrefix, ns, mode string) error {
	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("failed to stat input: %w", err)
	}

	if info.IsDir() {
		return processDirectory(inputPath, outputDir, crsVersion, namePrefix, ns, mode)
	}
	base := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	outName := strings.ToLower(strings.ReplaceAll(base, "_", "-"))
	if namePrefix != "" {
		outName = namePrefix + outName
	}
	return processFile(inputPath, outputDir, crsVersion, ns, namePrefix, outName, mode)
}

func processDirectory(dir, outputDir, crsVersion, namePrefix, ns, mode string) error {
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

		return processFile(path, outputDir, crsVersion, ns, namePrefix, outName, mode)
	})
}

type ruleEntry struct {
	rule   *types.RuleWithCondition
	marker string
}

func processFile(inputFile, outputDir, crsVersion, ns, namePrefix, fileCRName, mode string) error {
	fmt.Printf("Processing %s...\n", inputFile)

	secLangs, err := translator.LoadSeclang(inputFile)
	if err != nil {
		return fmt.Errorf("failed to load seclang from %s: %w", inputFile, err)
	}

	secLangs = *translator.ToCRSLang(secLangs)

	labels := map[string]string{
		"app.kubernetes.io/part-of": "coreruleset",
		"coreruleset/version":       crsVersion,
		"coreruleset/file":          filepath.Base(inputFile),
	}

	var entries []ruleEntry

	for _, secLangRules := range secLangs.DirectiveList {
		marker := ""
		if secLangRules.Marker.Name == types.SecMarker {
			marker = secLangRules.Marker.Parameter
		}

		ruleCount := 0
		for _, r := range secLangRules.Directives {
			if _, ok := r.(*types.RuleWithCondition); ok {
				ruleCount++
			}
		}

		current := 0
		for _, rule := range secLangRules.Directives {
			r, ok := rule.(*types.RuleWithCondition)
			if !ok {
				continue
			}
			current++
			m := ""
			if marker != "" && current == ruleCount {
				m = marker
			}
			entries = append(entries, ruleEntry{rule: r, marker: m})
		}
	}

	if len(entries) == 0 {
		fmt.Printf("No rules found in %s, skipping\n", inputFile)
		return nil
	}

	if mode == "bag" {
		return writeBagMode(entries, labels, ns, fileCRName, outputDir)
	}
	return writeOnePerRuleMode(entries, labels, ns, namePrefix, fileCRName, outputDir)
}

func writeBagMode(entries []ruleEntry, labels map[string]string, ns, crName, outputDir string) error {
	kubeSecRule := v1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:   crName,
			Labels: labels,
		},
	}
	if ns != "" {
		kubeSecRule.Namespace = ns
	}
	for _, e := range entries {
		target, err := convert.ConvertCrsRule(*e.rule, e.marker)
		if err != nil {
			return fmt.Errorf("convert rule: %w", err)
		}
		kubeSecRule.Spec.SecRules = append(kubeSecRule.Spec.SecRules, target)
	}
	outputPath := filepath.Join(outputDir, crName+".yaml")
	if err := writeAsYAML([]runtime.Object{&kubeSecRule}, outputPath); err != nil {
		return err
	}
	fmt.Printf("  -> Generated %s with %d rules (bag mode)\n", outputPath, len(kubeSecRule.Spec.SecRules))
	return nil
}

func writeOnePerRuleMode(
	entries []ruleEntry, labels map[string]string, ns, namePrefix, fileCRName, outputDir string,
) error {
	objs := make([]runtime.Object, 0, len(entries))
	usedNames := map[string]int{}

	for i, e := range entries {
		spec, err := convert.ConvertCrsRuleToSingleForm(*e.rule, e.marker)
		if err != nil {
			return fmt.Errorf("convert rule to single form: %w", err)
		}
		// Ensure order from id when present.
		if spec.Order == 0 && spec.Metadata != nil && spec.Metadata.Id > 0 {
			spec.Order = int32(spec.Metadata.Id)
		}

		name := ruleCRName(namePrefix, fileCRName, spec, i)
		// Deduplicate names within file.
		if n, ok := usedNames[name]; ok {
			usedNames[name] = n + 1
			name = fmt.Sprintf("%s-%d", name, n+1)
		} else {
			usedNames[name] = 1
		}

		// Per-rule labels (include id when known for selectors).
		rlabels := map[string]string{}
		for k, v := range labels {
			rlabels[k] = v
		}
		if spec.Metadata != nil && spec.Metadata.Id > 0 {
			rlabels[v1beta1.LabelID] = strconv.Itoa(spec.Metadata.Id)
			rlabels[v1beta1.LabelOrder] = strconv.Itoa(int(spec.Order))
			if spec.Metadata.Phase != "" {
				rlabels[v1beta1.LabelPhase] = spec.Metadata.Phase
			}
			// Tag labels for RuleSet selection.
			for _, tag := range spec.Metadata.Tags {
				if key := v1beta1.TagToLabelKey(tag); key != "" {
					rlabels[key] = "true"
				}
			}
		}

		sr := &v1beta1.SecRule{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: rlabels,
			},
			Spec: spec,
		}
		if ns != "" {
			sr.Namespace = ns
		}
		objs = append(objs, sr)
	}

	outputPath := filepath.Join(outputDir, fileCRName+".yaml")
	if err := writeAsYAML(objs, outputPath); err != nil {
		return err
	}
	fmt.Printf("  -> Generated %s with %d SecRule CRs (one-per-rule)\n", outputPath, len(objs))
	return nil
}

// ruleCRName builds a DNS-1123-ish name: {prefix}{id} or {fileCRName}-{idx}.
func ruleCRName(namePrefix, fileCRName string, spec v1beta1.SecRuleSpec, index int) string {
	if spec.Metadata != nil && spec.Metadata.Id > 0 {
		base := namePrefix + strconv.Itoa(spec.Metadata.Id)
		return sanitizeName(base)
	}
	// No id (rare): fall back to file + index.
	return sanitizeName(fmt.Sprintf("%s-n%d", fileCRName, index+1))
}

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = nonDNS.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "rule"
	}
	// Kubernetes name max 253; keep short.
	if len(s) > 63 {
		s = s[:63]
		s = strings.TrimRight(s, "-")
	}
	return s
}

func writeAsYAML(objs []runtime.Object, outputPath string) error {
	// YAMLPrinter already terminates each object with "---\n".
	printer := printers.NewTypeSetter(customScheme).
		ToPrinter(&printers.YAMLPrinter{})

	var buf bytes.Buffer
	for _, obj := range objs {
		if err := printer.PrintObj(obj, &buf); err != nil {
			return err
		}
	}
	// Safety net: CRS comments (and any other multi-line strings) must not
	// leave 3+ consecutive blank lines — yamllint empty-lines.max is 2
	// (.github/configs/lintconf.yaml). ConvertCrsRule also sanitizes comments.
	out := convert.CollapseEmptyLines(buf.String(), convert.MaxYAMLEmptyLines)
	return os.WriteFile(outputPath, []byte(out), 0o644)
}
