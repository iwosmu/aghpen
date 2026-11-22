package main

import (
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestReadTruth(t *testing.T) {
	in := "# comment\n01-cms\t2368\ttcp\tcms\tghost:6\thttp\t^Ghost$\t6.78\tNode\\.js,Express\tlogin\t\tPHP\thttp/\n"
	rows, err := ReadTruth(strings.NewReader(in))
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	r := rows[0]
	if r.Port != 2368 || r.Product != "^Ghost$" || len(r.Techs) != 2 || r.Classes[0] != "login" || r.OK[0] != "PHP" || r.Ready != "http/" {
		t.Fatalf("parsed %+v", r)
	}
	if _, err := ReadTruth(strings.NewReader("a\tb\n")); err == nil {
		t.Fatal("short line accepted")
	}
}

func TestVersionMatch(t *testing.T) {
	for _, c := range []struct {
		want, got string
		ok        bool
	}{{"11.6", "11.6.16", true}, {"11.6", "11.60", false}, {"6.78", "6.78", true}, {"0.65.6.3", "v0.65.6.3", true}, {"2", "", false}, {"7", "7.103", true}} {
		if versionMatch(c.want, c.got) != c.ok {
			t.Errorf("versionMatch(%q, %q) != %v", c.want, c.got, c.ok)
		}
	}
}

func TestScore(t *testing.T) {
	row := Row{Port: 3000, Proto: "tcp", Service: "http", Product: "^Grafana$", Version: "11.6", Classes: []string{"login"}, OK: []string{"Go"}}
	svc := &model.ServiceResult{Port: 3000, Proto: "tcp", State: "open", Name: "http",
		Technologies: []model.Technology{{Name: "Grafana", Version: "11.6.16"}, {Name: "Go"}, {Name: "WordPress"}},
		Classes:      []string{"login", "staging"}}
	r := Score(row, svc, nil)
	if !r.Found || !r.Named || !r.Product || r.Version == nil || !*r.Version || r.Classes == nil || !*r.Classes {
		t.Fatalf("score %+v", r)
	}
	if strings.Join(r.Wrong, ",") != "WordPress,class:staging" {
		t.Fatalf("wrong %v", r.Wrong)
	}
	miss := Score(row, nil, nil)
	if miss.Found || miss.Version == nil || *miss.Version || miss.Classes == nil || *miss.Classes {
		t.Fatalf("missing service scored %+v", miss)
	}
	// nmap-style product only
	n := Score(Row{Port: 22, Proto: "tcp", Service: "ssh", Product: "OpenSSH", Version: "10.3"}, &model.ServiceResult{State: "open", Name: "ssh", Product: "OpenSSH", Version: "10.3p1"}, nil)
	if !n.Product || !*n.Version {
		t.Fatalf("nmap product %+v", n)
	}
	var tl Tally
	tl.Add(r)
	tl.Add(miss)
	if tl.Rows != 2 || tl.Found != 1 || tl.VersionN != 2 || tl.Version != 1 || tl.Wrong != 2 {
		t.Fatalf("tally %+v", tl)
	}
}

func TestFind(t *testing.T) {
	hs := []model.HostResult{{Services: []model.ServiceResult{{Port: 53, Proto: "udp", State: "open"}, {Port: 53, Proto: "tcp", State: "closed"}}}}
	if Find(hs, 53, "udp") == nil || Find(hs, 53, "tcp") != nil {
		t.Fatal("find")
	}
}
