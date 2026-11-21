package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Builtin returns the starter pack of rules, ordered by id. YAML holds the
// text of each rule on its own, ready to be stored.
func Builtin() ([]*Rule, error) {
	files, err := fs.Glob(builtinFS, "builtin/*.yaml")
	if err != nil {
		return nil, err
	}
	var out []*Rule
	for _, f := range files {
		raw, err := builtinFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		rs, val := ParseMany(string(raw))
		if !val.OK {
			var msgs []string
			for _, is := range val.Issues {
				msgs = append(msgs, is.Path+": "+is.Message)
			}
			return nil, fmt.Errorf("rules: built-in %s: %s", f, strings.Join(msgs, "; "))
		}
		out = append(out, rs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
