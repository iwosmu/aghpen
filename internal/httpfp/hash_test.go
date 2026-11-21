package httpfp

import (
	"strings"
	"testing"
)

func TestMurmur3Vectors(t *testing.T) {
	// Reference vectors of MurmurHash3_x86_32.
	for _, tc := range []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"", 0, 0},
		{"", 1, 0x514e28b7},
		{"a", 0, 0x3c2569b2},
		{"abc", 0, 0xb3dd93fa},
		{"abcd", 0, 0x43ed676a},
		{"Hello, world!", 0, 0xc0363e43},
		{"The quick brown fox jumps over the lazy dog", 0, 0x2e4ff723},
		{"The quick brown fox jumps over the lazy dog", 0x9747b28c, 0x2fa826cd},
	} {
		if got := Murmur3([]byte(tc.in), tc.seed); got != tc.want {
			t.Errorf("Murmur3(%q, %#x) = %#x, want %#x", tc.in, tc.seed, got, tc.want)
		}
	}
}

func TestPythonBase64Layout(t *testing.T) {
	data := []byte(strings.Repeat("x", 100))
	got := string(pythonBase64(data))
	lines := strings.Split(got, "\n")
	if len(lines) != 3 || len(lines[0]) != 76 || lines[2] != "" {
		t.Fatalf("layout = %q", got)
	}
	if string(pythonBase64(nil)) != "" {
		t.Errorf("empty input must give empty text")
	}
	if got := string(pythonBase64([]byte("hi"))); got != "aGk=\n" {
		t.Errorf("short input = %q", got)
	}
}

func TestSimhash(t *testing.T) {
	base := "<html><head><title>Grafana</title></head><body>" + strings.Repeat("<div class=\"panel\">Welcome to the dashboard of the monitoring system</div> ", 30)
	a := base + "<input type=\"hidden\" name=\"csrf\" value=\"8f14e45fceea167a5a36dedd4bea2543\"></body></html>"
	b := base + "<input type=\"hidden\" name=\"csrf\" value=\"c9f0f895fb98ab9159f51fd0297e236d\"></body></html>"
	c := "<html><body>" + strings.Repeat("Completely different content about printers and toner levels. ", 30) + "</body></html>"
	near := SimhashDistance(SimhashHex(a), SimhashHex(b))
	far := SimhashDistance(SimhashHex(a), SimhashHex(c))
	if near < 0 || near > 3 {
		t.Errorf("near-duplicate distance = %d", near)
	}
	if far < 12 {
		t.Errorf("different pages distance = %d", far)
	}
	if SimhashHex("") != "" || SimhashDistance("", "zz") != -1 {
		t.Errorf("empty and invalid input handling")
	}
	if SimhashHex("word") == "0000000000000000" {
		t.Errorf("a single word must still hash")
	}
}
