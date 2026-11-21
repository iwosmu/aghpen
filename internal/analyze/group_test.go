package analyze

import (
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func page(title, simhash string, techs ...string) model.ServiceResult {
	s := httpSvc(80, title, 200)
	s.HTTP.BodySimhash = simhash
	for _, t := range techs {
		s.Technologies = append(s.Technologies, model.Technology{Name: t, Confidence: 0.9})
	}
	return s
}

func TestTitleTemplate(t *testing.T) {
	cases := map[string]string{
		"Printer HP-4050 (10.1.2.3)":   "printer hp-# (<ip>)",
		"Login - node17.example.org":   "login - <host>",
		"  Jenkins   2.440 ":           "jenkins #.#",
		"Session 9f86d081884c7d659a2f": "session #",
	}
	for in, want := range cases {
		if got := TitleTemplate(in, "node17.example.org"); got != want {
			t.Errorf("TitleTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGroupKey(t *testing.T) {
	a := page("Printer 10.0.0.1", "a1b2c3d4e5f60718", "HP JetDirect")
	b := page("Printer 10.0.0.2", "a1b2c3d4e5f60719", "HP JetDirect") // 1 bit away, other IP in the title
	c := page("Printer 10.0.0.3", "a1b2c3d4e5f60718", "WordPress")
	d := page("Sklep", "a1b2c3d4e5f60718", "HP JetDirect")
	// Volatile headers must not split a group.
	b.HTTP.Headers["Date"] = []string{"other"}
	b.HTTP.Headers["X-Request-Id"] = []string{"1"}

	if GroupKey(a) != GroupKey(b) {
		t.Errorf("near-identical pages must share a key")
	}
	if GroupKey(a) == GroupKey(c) {
		t.Errorf("different technology must not share a key")
	}
	if GroupKey(a) == GroupKey(d) {
		t.Errorf("different title must not share a key")
	}
	if len(GroupKey(a)) != 16 {
		t.Errorf("key = %q", GroupKey(a))
	}
	ssh1 := model.ServiceResult{Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.6"}
	ssh2 := model.ServiceResult{Port: 2222, Name: "ssh", Product: "OpenSSH", Version: "9.6"}
	ssh3 := model.ServiceResult{Port: 22, Name: "ssh", Product: "OpenSSH", Version: "8.2"}
	if GroupKey(ssh1) != GroupKey(ssh2) || GroupKey(ssh1) == GroupKey(ssh3) {
		t.Errorf("non-web services group by name, product and version")
	}
}

func TestAssignGroupKeysJoinsAcrossBucketBorder(t *testing.T) {
	// The two hashes differ in the top bit only: different buckets, distance 1.
	a := page("Kamera", "7fffffffffffffff", "Hikvision")
	b := page("Kamera", "ffffffffffffffff", "Hikvision")
	far := page("Kamera", "0000000000000000", "Hikvision")
	other := page("Router", "7fffffffffffffff", "MikroTik")
	if GroupKey(a) == GroupKey(b) {
		t.Fatalf("test setup: the single keys should fall in two buckets")
	}
	keys := AssignGroupKeys([]GroupItem{{Service: a}, {Service: b}, {Service: far}, {Service: other}})
	if keys[0] != keys[1] {
		t.Errorf("pages 1 bit apart must share a key: %v", keys)
	}
	if keys[0] == keys[2] || keys[0] == keys[3] {
		t.Errorf("far or different pages must not share the key: %v", keys)
	}
	again := AssignGroupKeys([]GroupItem{{Service: b}, {Service: a}})
	if again[0] != keys[0] {
		t.Errorf("the key must not depend on the order")
	}
}

func TestGroupLabel(t *testing.T) {
	if got := GroupLabel(page("Jenkins", "", "Jenkins", "Jetty")); got != "Jenkins · Jenkins, Jetty" {
		t.Errorf("label = %q", got)
	}
	if got := GroupLabel(model.ServiceResult{Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.6"}); got != "OpenSSH 9.6" {
		t.Errorf("label = %q", got)
	}
}
