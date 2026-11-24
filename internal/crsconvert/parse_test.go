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

package crsconvert

import (
	"os"
	"strings"
	"testing"

	"github.com/kubewaf-io/kubewaf/internal/compile"
)

func TestParseCRS942100(t *testing.T) {
	src, err := os.ReadFile("../compile/testdata/crs/942100.upstream")
	if err != nil {
		t.Fatal(err)
	}
	objects, err := Parse(string(src), "crs-")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].Rule == nil {
		t.Fatalf("objects %+v", objects)
	}
	if objects[0].Rule.Name != "crs-942100" || objects[0].Rule.Spec.Metadata.ID != 942100 {
		t.Fatalf("rule %+v", objects[0].Rule)
	}
	got, err := compile.EmitRule(objects[0].Rule)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../compile/testdata/crs/942100.seclang")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != strings.TrimSpace(string(want)) {
		t.Fatalf("canonical\n%s", got)
	}
	if err := compile.Parse(got); err != nil {
		t.Fatal(err)
	}
}
