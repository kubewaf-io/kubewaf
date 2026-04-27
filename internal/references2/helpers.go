package references2

import (
	"github.com/buzz-it/kubewaf/api/seclang/v1beta1"
	"github.com/buzz-it/kubewaf/api/seclang/v1beta1/convert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

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
