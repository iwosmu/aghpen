package reprobe

import (
	"net/http"

	"github.com/iwosmu/aghpen/internal/i18n"
)

// localize renders the reasons of a plan and the error messages in the
// language the API chose for the response (Content-Language). Polish
// passes unchanged.
func localize(w http.ResponseWriter, v any) any {
	if w.Header().Get("Content-Language") != "en" {
		return v
	}
	switch x := v.(type) {
	case Plan:
		x.Blocked = i18n.Text(x.Blocked, "en")
		for i := range x.Probes {
			x.Probes[i].Reason = i18n.Text(x.Probes[i].Reason, "en")
		}
		for i := range x.Skipped {
			x.Skipped[i].Reason = i18n.Text(x.Skipped[i].Reason, "en")
		}
		return x
	case map[string]any:
		if e, ok := x["error"].(map[string]string); ok {
			e["message"] = i18n.ErrorMessage(e["message"], "en")
		}
	}
	return v
}
