package main

import "testing"

func TestParseUp(t *testing.T) {
	out := "# Nmap 7.99 scan\nHost: 10.66.70.20 ()\tStatus: Up\nHost: 10.66.70.21 ()\tStatus: Down\n# Nmap done\n"
	up := parseUp(out)
	if !up["10.66.70.20"] || up["10.66.70.21"] || len(up) != 1 {
		t.Fatalf("parseUp = %v", up)
	}
	if mark(true) != "UP  " || mark(false) != "down" {
		t.Fatal("mark is wrong")
	}
}
