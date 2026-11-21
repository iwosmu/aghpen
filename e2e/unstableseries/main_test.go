package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestSummarizeAndPrint(t *testing.T) {
	at := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	rows := []Row{
		{RunID: 1, At: at, IP: "10.66.70.21", Name: "tod-office", Truth: true, Seen: true, Attempts: 1, Status: model.HostUp},
		{RunID: 2, At: at.Add(time.Minute), IP: "10.66.70.21", Name: "tod-office", Truth: false, Seen: false, Attempts: 3, Status: model.HostUnstable, Changes: []string{"host_missing"}},
		{RunID: 3, At: at.Add(2 * time.Minute), IP: "10.66.70.21", Name: "tod-office", Truth: false, Seen: true, Attempts: 1, Status: model.HostUp, Changes: []string{"host_gone (expected)"}},
	}
	s := Summarize(rows)
	if len(s) != 1 || s[0].Runs != 3 || s[0].Agree != 2 || s[0].Retried != 1 || s[0].Missing != 1 || s[0].Gone != 1 || s[0].Expected != 1 || s[0].FirstGoneRun != 3 {
		t.Fatalf("summary = %+v", s)
	}
	var buf bytes.Buffer
	Print(&buf, rows, "1h/168h")
	if !strings.Contains(buf.String(), "| 2 | 14:01:00 | tod-office | — | — | 3 | unstable |") {
		t.Errorf("timeline row missing:\n%s", buf.String())
	}
}
