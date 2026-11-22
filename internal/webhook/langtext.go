package webhook

import (
	"net/http"

	"github.com/iwosmu/aghpen/internal/i18n"
)

// localize renders the test result and the error messages of the settings
// routes in the language the API chose for the response (Content-Language).
// The webhook message itself stays Polish.
func localize(w http.ResponseWriter, v any) any {
	if w.Header().Get("Content-Language") != "en" {
		return v
	}
	switch x := v.(type) {
	case TestResult:
		x.Error = i18n.ErrorMessage(x.Error, "en")
		return x
	case map[string]any:
		if e, ok := x["error"].(map[string]string); ok {
			e["message"] = i18n.ErrorMessage(e["message"], "en")
		}
	}
	return v
}
