package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestEncodeJSONNilSlicesAndZeroTimes(t *testing.T) {
	type inner struct {
		Tags []string  `json:"tags"`
		At   time.Time `json:"at"`
	}
	type outer struct {
		List   []inner           `json:"list"`
		Nested inner             `json:"nested"`
		Ptr    *inner            `json:"ptr"`
		Map    map[string][]int  `json:"map"`
		Raw    json.RawMessage   `json:"raw"`
		Bytes  []byte            `json:"bytes"`
		Any    any               `json:"any"`
		Host   model.Host        `json:"host"`
		Empty  map[string]string `json:"empty"`
	}
	v := outer{List: []inner{{}}, Ptr: &inner{}, Map: map[string][]int{"a": nil}, Raw: json.RawMessage(`{"x":null}`), Any: inner{}}
	b, err := encodeJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"list":[{"tags":[],"at":null}]`, `"nested":{"tags":[],"at":null}`, `"ptr":{"tags":[],"at":null}`, `"map":{"a":[]}`, `"raw":{"x":null}`, `"any":{"tags":[],"at":null}`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if strings.Contains(s, "0001-01-01") || strings.Contains(s, `"hostnames":null`) || strings.Contains(s, `"tags":null`) {
		t.Errorf("a zero time or a null list leaked: %s", s)
	}
	// The input is not changed.
	if v.List[0].Tags != nil || v.Map["a"] != nil {
		t.Error("encodeJSON changed its input")
	}
	// A nil top-level slice is [].
	if b, _ := encodeJSON([]model.Host(nil)); string(b) != "[]" {
		t.Errorf("nil slice: %s", b)
	}
	// A real time is kept.
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	if b, _ := encodeJSON(inner{At: at}); !strings.Contains(string(b), "2026-11-21T10:00:00Z") {
		t.Errorf("time: %s", b)
	}
}
