package analyze

import (
	"io/fs"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/iwosmu/aghpen/signatures"
)

// SigText is the Polish and English text of one built-in signature, from
// its YAML file (name, name_en, description, description_en). An empty
// English field means the Polish one reads the same in English (a product
// name) or has no translation yet.
type SigText struct {
	Name, NameEN               string
	Description, DescriptionEN string
}

type sigCatalog struct {
	bySlug map[string]SigText
	byName map[string]string // Polish name → English name
	names  []string          // Polish names with an English name, longest first
}

var sigTexts = sync.OnceValue(func() sigCatalog {
	c := sigCatalog{bySlug: map[string]SigText{}, byName: map[string]string{}}
	files, _ := fs.Glob(signatures.FS, "*.yaml")
	for _, f := range files {
		raw, err := fs.ReadFile(signatures.FS, f)
		if err != nil {
			continue
		}
		var defs []struct {
			ID            string `yaml:"id"`
			Name          string `yaml:"name"`
			NameEN        string `yaml:"name_en"`
			Description   string `yaml:"description"`
			DescriptionEN string `yaml:"description_en"`
		}
		if yaml.Unmarshal(raw, &defs) != nil {
			continue
		}
		for _, d := range defs {
			t := SigText{Name: strings.TrimSpace(d.Name), NameEN: strings.TrimSpace(d.NameEN),
				Description: strings.TrimSpace(d.Description), DescriptionEN: strings.TrimSpace(d.DescriptionEN)}
			c.bySlug[strings.TrimSpace(d.ID)] = t
			if t.NameEN != "" && t.Name != "" {
				c.byName[t.Name] = t.NameEN
			}
		}
	}
	for n := range c.byName {
		c.names = append(c.names, n)
	}
	sort.Slice(c.names, func(i, j int) bool { return len(c.names[i]) > len(c.names[j]) })
	return c
})

// BuiltinSigText returns the texts of the built-in signature slug.
func BuiltinSigText(slug string) (SigText, bool) {
	t, ok := sigTexts().bySlug[slug]
	return t, ok
}

// SignatureNameIn returns the display name of a signature in lang. name is
// the name a match or a stored text carries (the Polish one). A name that
// starts with a built-in Polish name followed by a version ("Stopka 3.1")
// keeps the version.
func SignatureNameIn(name, lang string) string {
	if lang != "en" || name == "" {
		return name
	}
	c := sigTexts()
	if en, ok := c.byName[name]; ok {
		return en
	}
	for _, pl := range c.names {
		if rest, ok := strings.CutPrefix(name, pl+" "); ok {
			return c.byName[pl] + " " + rest
		}
	}
	return name
}

// SignatureTextIn returns the name and description of a stored signature in
// lang. Only a built-in signature whose stored text is still the Polish text
// of the library gets the English one; a text an analyst edited stays.
func SignatureTextIn(slug, name, desc string, builtin bool, lang string) (string, string) {
	if lang != "en" || !builtin {
		return name, desc
	}
	t, ok := BuiltinSigText(slug)
	if !ok {
		return name, desc
	}
	if t.NameEN != "" && name == t.Name {
		name = t.NameEN
	}
	if t.DescriptionEN != "" && desc == t.Description {
		desc = t.DescriptionEN
	}
	return name, desc
}
