package main

import (
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/sig"
)

const twoNamed = `id: tech-detect
info:
  name: Wappalyzer Technology Detection
  author: x
  severity: info
  tags: tech
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        name: acme-cms
        words: ["acme-cms-generator-v1"]
        part: body
      - type: word
        name: other-app
        words: ["other-app-loader.js"]
        part: body
      - type: word
        name: acme-cms
        words: ["/static/acme-cms/"]
        part: body
    extractors:
      - type: regex
        regex: ["version ([0-9.]+)"]
`

const commit = "1ad258956016afba455d4284539812eb24be690a"

func TestSplitGroupsNamedMatchers(t *testing.T) {
	parts := split([]byte(twoNamed))
	if len(parts) != 2 {
		t.Fatalf("got %d templates, want 2 (acme-cms twice is one technology)", len(parts))
	}
	first := string(parts[0])
	if !strings.Contains(first, "id: tech-detect-acme-cms") || !strings.Contains(first, "/static/acme-cms/") || strings.Contains(first, "other-app") {
		t.Errorf("first template:\n%s", first)
	}
	if strings.Contains(first, "extractors") {
		t.Error("a shared extractor must not stay on a split template")
	}
	if !strings.Contains(first, "name: Acme CMS") {
		t.Errorf("display name not set:\n%s", first)
	}
}

func TestOneConvertsAndMarksSource(t *testing.T) {
	parts := split([]byte(twoNamed))
	c, why := one(parts[0], "http/technologies/tech-detect.yaml", "http/technologies", commit, map[string]string{}, map[string]bool{})
	if why != "" {
		t.Fatalf("dropped: %s", why)
	}
	if c.ID != "nuclei-td-acme-cms" || c.Tech != "Acme CMS" || c.OptIn {
		t.Errorf("candidate %+v", c)
	}
	for _, want := range []string{"source: ", "licence=MIT", "1ad258956016", "id=tech-detect-acme-cms", "nuclei-templates"} {
		if !strings.Contains(c.YAML, want) {
			t.Errorf("YAML lacks %q:\n%s", want, c.YAML)
		}
	}
	if _, v := sig.Parse(c.YAML); hasError(v) {
		t.Errorf("converted signature does not validate: %+v", v.Issues)
	}
	// Ours win: the same technology in the hand-written library drops the import.
	if _, why := one(parts[0], "x.yaml", "http/technologies", commit, map[string]string{"acmecms": "acme"}, nil); why == "" {
		t.Error("an import of one of our technologies was kept")
	}
}

func TestNamesAndFilters(t *testing.T) {
	ours := map[string]string{"nginx": "nginx", "swaggerui": "swagger-ui", "apache": "apache-httpd", "phpmyadmin": "phpmyadmin"}
	for name, want := range map[string]bool{
		"Default Nginx Page": true, "Swagger": true, "Phpmyadmin": true, "Nginxs": true,
		"Apache Airflow": false, "Gotify": false,
	} {
		if got := sameAsOurs(name, ours) || ours[key(name)] != ""; got != want {
			t.Errorf("sameAsOurs(%q) = %v, want %v", name, got, want)
		}
	}
	for in, want := range map[string]string{
		"Grafana Login Panel - Detect": "Grafana",
		"Phpmyadmin":                   "Phpmyadmin",
		"Jenkins - Detect":             "Jenkins",
		"Gitea Installer":              "Gitea",
	} {
		if got := strings.TrimSpace(detectSuffix.ReplaceAllString(in, "")); got != want {
			t.Errorf("technology of %q = %q, want %q", in, got, want)
		}
	}
	for _, lib := range []string{"font-awesome", "Google Tag Manager", "jsdelivr", "jQuery UI"} {
		if !libraryRe.MatchString(lib) {
			t.Errorf("%q is not seen as a library", lib)
		}
	}
	for _, app := range []string{"Gitea", "Nextcloud", "Zabbix"} {
		if libraryRe.MatchString(app) {
			t.Errorf("%q is seen as a library", app)
		}
	}
	if generic(sig.Def{Rules: []sig.RuleDef{{Type: "body", Contains: []string{"Login"}}}}) == "" {
		t.Error("a 5-character pattern is not generic")
	}
	if generic(sig.Def{Rules: []sig.RuleDef{{Type: "favicon", MMH3: []int32{116323821}}}}) != "" {
		t.Error("a favicon hash is specific")
	}
	if got := longestLiteral(`<title>Acme(?:CMS)?</title>`); got != 11 {
		t.Errorf("longestLiteral = %d, want 11", got)
	}
	if id := shortID(strings.Repeat("a", 80)); len(id) > 64 || id == shortID(strings.Repeat("a", 79)+"b") {
		t.Errorf("shortID %q: too long or not unique", id)
	}
}

func TestExplains(t *testing.T) {
	if !explains("Clickhouse", "tech-detect-clickhouse", []string{"clickhouse-server", "ClickHouse"}) {
		t.Error("ClickHouse truth does not explain ClickHouse")
	}
	if explains("Saltstack", "fingerprinthub-web-fingerprints-saltstack", []string{"base-notebook", "Jupyter"}) {
		t.Error("Jupyter truth explains SaltStack")
	}
	if exportTag("/x/e2e/zoo/out/before/06-db/export.json") != "zoo:06-db" || exportTag("/x/lab-export.json") != "lab" {
		t.Error("exportTag")
	}
}
