package main

import (
	"strings"
	"testing"
)

func TestClassifyAndSummarize(t *testing.T) {
	in := strings.Join([]string{
		"100.10 ARP, Request who-has 10.66.1.5 tell 10.66.0.30, length 28",
		"100.100002 ARP, Request who-has 10.66.1.5 tell 10.66.0.30, length 28", // the same frame reported twice
		"100.20 IP 10.66.0.30.40000 > 10.66.1.10.80: Flags [S], seq 1, win 1024, options [mss 1460], length 0",
		"100.30 IP 10.66.0.30.40001 > 10.66.1.10.80: Flags [S], seq 1, win 64240, options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0",
		"100.40 IP 10.66.0.30.40000 > 10.66.1.10.80: Flags [R], seq 2, win 0, length 0",
		"100.50 IP 10.66.0.30.5353 > 10.66.0.53.53: 1234+ A? x.lab.czujka.test. (35)",
		"100.60 IP 10.66.0.30 > 10.66.1.1: ICMP echo request, id 1, seq 1, length 8",
		"102.00 IP 10.66.0.30.61000 > 10.66.20.41.123: NTPv4, Client, length 48",
		"102.10 IP 10.66.0.30.40001 > 10.66.1.10.80: Flags [P.], seq 1:100, ack 1, win 502, length 99: HTTP: GET / HTTP/1.1",
		"102.20 IP 10.66.1.10.80 > 10.66.0.30.40000: Flags [S.], seq 2, ack 2, win 64240, options [mss 1460], length 0",
		"102.30 ARP, Reply 10.66.1.5 is-at 02:42:0a:42:01:05, length 28",
		"102.40 ARP, Request who-has 10.66.1.6 tell 10.66.0.31, length 28",
	}, "\n")
	bins, err := Bin(strings.NewReader(in), "10.66.0.30")
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(bins, 3)
	if s.Seconds != 3 || s.RawMax != 3 || s.Over != 0 || s.AllMax != 6 {
		t.Errorf("summary = %+v", s)
	}
	want := map[string]int{ClassARP: 1, ClassSYN: 1, ClassKernel: 2, ClassRST: 1, ClassDNS: 1, ClassICMP: 1, ClassUDP: 1}
	for c, n := range want {
		if s.Total[c] != n {
			t.Errorf("%s = %d, want %d (%v)", c, s.Total[c], n, s.Total)
		}
	}
}
