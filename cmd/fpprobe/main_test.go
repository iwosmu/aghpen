package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/sig"
)

const foreign = "../../internal/sig/testdata/foreign/"

func TestRunConvert(t *testing.T) {
	cases := []struct {
		file       string
		code, sigs int
		stdout     []string // texts the converted YAML must have
		stderr     []string // texts the messages must have
	}{
		{"nuclei-panel.yaml", 0, 1, []string{"id: acme-gateway-detect", "path: /gateway/login", "classes: [login]"}, nil},
		{"nuclei-tech.yaml", 0, 1, []string{"type: favicon, mmh3: [-1840324437]"}, []string{"warning: http[0].extractors[1]"}},
		{"list.json", 0, 2, []string{"id: acme-portal", "---\nid: router-admin"}, nil},
		{"synonyms.yaml", 0, 2, []string{"id: campus-login", "id: old-printer-ui"}, nil},
		{"technologies.json", 0, 1, []string{"id: example-cms", "version_group: 1"}, []string{"error: [1].match", "część sygnatur odrzucono"}},
		{"nuclei-active.yaml", 1, 0, nil, []string{"error [tryb bezpieczny]: http[0].raw", "payloads", "plik odrzucony"}},
		{"no-such-file.yaml", 2, 0, nil, []string{"fpprobe:"}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runConvert(foreign+tc.file, &stdout, &stderr); code != tc.code {
				t.Fatalf("exit code %d, want %d; stderr:\n%s", code, tc.code, stderr.String())
			}
			for _, want := range tc.stdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout has no %q:\n%s", want, stdout.String())
				}
			}
			for _, want := range tc.stderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr has no %q:\n%s", want, stderr.String())
				}
			}
			// The output is plain Czujka YAML: it loads again with no error.
			if tc.sigs > 0 {
				sigs, val := sig.Parse(stdout.String())
				if !val.OK || len(sigs) != tc.sigs {
					t.Errorf("the output gives %d signatures (ok=%v), want %d: %+v", len(sigs), val.OK, tc.sigs, val.Issues)
				}
			} else if stdout.Len() != 0 {
				t.Errorf("a refused file must print no YAML:\n%s", stdout.String())
			}
		})
	}
}

func TestShorten(t *testing.T) {
	if got := shorten("krótki", 100); got != "krótki" {
		t.Errorf("shorten = %q", got)
	}
	// The cut must not split the two bytes of "ó".
	if got := shorten("kró"+strings.Repeat("x", 50), 3); !strings.HasPrefix(got, "kr… [") {
		t.Errorf("shorten = %q", got)
	}
}
