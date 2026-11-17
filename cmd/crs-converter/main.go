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

// Command crs-converter writes v1alpha1 SecRule and SecAction YAML from an upstream CRS checkout.
// It does not use crslang. The operator does not ship the generated objects.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/crsconvert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func main() {
	input := flag.String("input", "", "SecLang file or directory of .conf files")
	outputDir := flag.String("output-dir", "config/samples/crs", "directory for generated YAML")
	namespace := flag.String("namespace", "", "metadata.namespace; empty omits it")
	prefix := flag.String("name-prefix", "crs-", "prefix for object names")
	flag.Parse()
	if *input == "" {
		log.Fatal("input path is required")
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		log.Fatal(err)
	}
	info, err := os.Stat(*input)
	if err != nil {
		log.Fatal(err)
	}
	if !info.IsDir() {
		if err := convertFile(*input, *outputDir, *namespace, *prefix); err != nil {
			log.Fatal(err)
		}
		return
	}
	err = filepath.WalkDir(*input, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".conf") {
			return err
		}
		return convertFile(path, *outputDir, *namespace, *prefix)
	})
	if err != nil {
		log.Fatal(err)
	}
}

func convertFile(path, outputDir, namespace, prefix string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	objects, err := crsconvert.Parse(string(src), prefix)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(objects) == 0 {
		return nil
	}
	var docs []byte
	for _, obj := range objects {
		raw, err := marshal(obj, namespace)
		if err != nil {
			return err
		}
		if len(docs) > 0 {
			docs = append(docs, []byte("---\n")...)
		}
		docs = append(docs, raw...)
		if !strings.HasSuffix(string(docs), "\n") {
			docs = append(docs, '\n')
		}
	}
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	base = strings.ToLower(strings.ReplaceAll(base, "_", "-"))
	return os.WriteFile(filepath.Join(outputDir, base+".yaml"), docs, 0o644)
}

func marshal(obj crsconvert.Object, namespace string) ([]byte, error) {
	if obj.Rule != nil {
		obj.Rule.TypeMeta = metav1.TypeMeta{APIVersion: seclangv1alpha1.GroupVersion.String(), Kind: "SecRule"}
		obj.Rule.Namespace = namespace
		return yaml.Marshal(obj.Rule)
	}
	obj.Action.TypeMeta = metav1.TypeMeta{APIVersion: seclangv1alpha1.GroupVersion.String(), Kind: "SecAction"}
	obj.Action.Namespace = namespace
	return yaml.Marshal(obj.Action)
}
