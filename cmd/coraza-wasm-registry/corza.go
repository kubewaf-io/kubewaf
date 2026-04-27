package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/buzz-it/kubewaf/api/seclang/v1beta1"
	"github.com/buzz-it/kubewaf/api/seclang/v1beta1/convert"
	"github.com/buzz-it/kubewaf/internal/wasmregistry"
	"github.com/otiai10/copy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

const src = "/tmp/coraza-proxy-wasm"
const dst = "/tmp/builds/"
const wasmlib = "/tmp/wasmlib/"

// CreateCoraza is an alias to the shared type from the client library.
type CreateCoraza = wasmregistry.CreateRequest

func createCorazaHandler(w http.ResponseWriter, r *http.Request) {
	var input CreateCoraza
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON err=%s", err.Error()))
		return
	}

	if input.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	f, err := os.MkdirTemp(dst, "")
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	if err := copy.Copy(src, f); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
	}
	if err := os.Mkdir(fmt.Sprintf("%s/wasmplugin/rules/kubewaf/", f), 0755); err != nil  {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	rules, err := GetSecRule(input.Objects)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	for idx, rule := range rules {
		if err := os.WriteFile(fmt.Sprintf("%s/wasmplugin/rules/kubewaf/%v.conf", f, idx), []byte(rule), 0644); err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
	}

	err = BuildToWASM(f, wasmlib+input.Name)

	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	respondJSON(w, http.StatusCreated, APIResponse{
		Success: true,
	})
}

func getCorazaHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/v1beta1/coraza/"):]
	b, err := os.ReadFile(wasmlib + id)

	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	_, err = respondData(w, http.StatusOK, b)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func GetSecRule(objects []unstructured.Unstructured) ([]string, error) {
	var (
		rules []string
	)
	for _, obj := range objects {
		switch obj.GetKind() {
		case "SecRule":
			var secRule v1beta1.SecRule
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &secRule)
			if err != nil {
				return rules, err
			}
			typedRules, err := convert.ConvertSecRule(secRule)
			if err != nil {
				return rules, err
			}
			rules = append(rules, convert.ConvertToSecLangString(typedRules))
		}
	}

	return rules, nil
}
