package sig

import (
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func page(status int, title, body string) *model.ServiceResult {
	return &model.ServiceResult{Port: 8080, Proto: "tcp", Name: "http", HTTP: &model.HTTPFingerprint{
		Scheme: "http", Status: status, Title: title, BodyExcerpt: body, Host: "10.0.0.5"}}
}

func TestSelfDescribe(t *testing.T) {
	cases := []struct {
		svc           *model.ServiceResult
		name, version string
	}{
		{page(200, "Home", `<html><head><meta name="application-name" content="Shiori"></head>`), "Shiori", ""},
		{page(200, "x", `<meta content='Acme Wiki' property='og:site_name'>`), "Acme Wiki", ""},
		{page(200, "x", `<meta name="generator" content="Hugo 0.121.1">`), "Hugo", "0.121.1"},
		{page(200, "Sign In - Gitea: Git with a cup of tea", ""), "Gitea", ""},
		{page(200, "Sign in · Forgejo", ""), "Forgejo", ""},
		{page(200, "Kanboard - Login", ""), "Kanboard", ""},
		{page(200, "Log in to Rocket.Chat", ""), "", ""}, // a dotted single word reads as a host name
		{page(401, "Gotify Login", ""), "Gotify", ""},
		// Generic titles and shells never become a product.
		{page(200, "Login", ""), "", ""},
		{page(200, "Welcome", ""), "", ""},
		{page(200, "Admin - Login", ""), "", ""},
		{page(200, "React App", ""), "", ""},
		{page(200, "Portal Pracowniczy", ""), "", ""},
		{page(200, "Welcome to nginx!", ""), "", ""},
		{page(200, "intranet.example.com - Login", ""), "", ""},
		{page(404, "Kanboard - Login", ""), "", ""},
	}
	for _, c := range cases {
		n, v, _ := selfDescribe(c.svc)
		if n != c.name || v != c.version {
			t.Errorf("title %q: got %q %q, want %q %q", c.svc.HTTP.Title, n, v, c.name, c.version)
		}
	}
}

func TestSelfDescribedOnlyWithoutAProduct(t *testing.T) {
	svc := page(200, "Kanboard - Login", `<script src="/assets/js/app.min.js?v=1.2.58"></script><link href="/assets/css/app.min.css?v=1.2.58">`)
	techs := addSelfDescribed(svc, []model.Technology{{Name: "nginx", Category: model.CatWebServer, Sources: []string{"nginx"}}})
	var got *model.Technology
	for i := range techs {
		if techs[i].Name == "Kanboard" {
			got = &techs[i]
		}
	}
	if got == nil || got.Version != "1.2.58" || got.Confidence >= 0.5 || got.Sources[0] != "self-described: title" {
		t.Fatalf("self-described technology: %+v", techs)
	}
	named := []model.Technology{{Name: "Grafana", Category: model.CatPanel, Sources: []string{"grafana"}}}
	if out := addSelfDescribed(svc, named); len(out) != 1 {
		t.Errorf("a signature already names the product, yet: %+v", out)
	}
	// nmap's guess alone does not name the application.
	nm := []model.Technology{{Name: "Golang net/http server", Category: model.CatOther, Sources: []string{"nmap"}}}
	if out := addSelfDescribed(svc, nm); len(out) != 2 {
		t.Errorf("nmap's product blocked self-description: %+v", out)
	}
}

func TestGenericVersion(t *testing.T) {
	h := &model.HTTPFingerprint{Server: "Gotify/2.6.1", BodyExcerpt: ""}
	if v := genericVersion("Gotify", h); v != "2.6.1" {
		t.Errorf("Server token: %q", v)
	}
	h = &model.HTTPFingerprint{BodyExcerpt: `<script src="/a.js?ver=1.0"></script><script src="/b.js?ver=2.0"></script>`}
	if v := genericVersion("X", h); v != "" {
		t.Errorf("disagreeing assets gave %q", v)
	}
	h = &model.HTTPFingerprint{BodyExcerpt: `<script src="https://cdn.example/a.js?v=3.4.1"></script><script src="//cdn.example/b.js?v=3.4.1"></script>`}
	if v := genericVersion("X", h); v != "" {
		t.Errorf("CDN assets gave %q", v)
	}
	h = &model.HTTPFingerprint{BodyExcerpt: `<script src="/a.js?v=3.4.1"></script>`}
	if v := genericVersion("X", h); v != "" {
		t.Errorf("one asset gave %q", v)
	}
}

func TestBuiltinEngineSelfDescribes(t *testing.T) {
	e, err := NewBuiltinEngine()
	if err != nil {
		t.Fatal(err)
	}
	svc := page(200, "Sign in · Zzyzx Tracker", "<form><input type=password name=pw></form>")
	_, techs, _ := e.Match(svc)
	found := false
	for _, tc := range techs {
		if tc.Name == "Zzyzx Tracker" && tc.Confidence < 0.5 {
			found = true
		}
	}
	if !found {
		t.Errorf("no self-described product: %+v", techs)
	}
}
