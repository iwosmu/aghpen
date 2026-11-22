package wire

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// An SSH server over its connection limit closes the connection before the
// banner; nmap names the port "tcpwrapped". The second scan of the
// unchanged 10 000-host scale lab reported 8 018 technology and class
// changes for such ports and resolved 3 948 remote-access findings. The
// answer says nothing: no change, and the finding stays open.
func TestTcpwrappedAnswerChangesNothing(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	an := NewAnalysis(st, time.UTC, quiet())
	const ip = "10.77.0.5"
	ssh := model.ServiceResult{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "Dropbear sshd", Version: "2025.88",
		Banner: "SSH-2.0-dropbear_2025.88", Confidence: 1,
		Technologies: []model.Technology{{Name: "Dropbear SSH", Version: "2025.88", Sources: []string{"banner"}}}}
	wrapped := model.ServiceResult{Port: 22, Proto: "tcp", State: "open", Name: "tcpwrapped"}
	at := time.Now().UTC().Add(-time.Hour)
	run := func(s model.ServiceResult) []string {
		t.Helper()
		r, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunAnalyzing, Trigger: "manual", ProfileName: "test"})
		if err != nil {
			t.Fatal(err)
		}
		at = at.Add(10 * time.Minute)
		h := model.HostResult{RunID: r.ID, ObservedAt: at, IP: ip, Up: true, Reason: "syn-ack", Services: []model.ServiceResult{s}}
		if err := st.IngestHosts(ctx, []model.HostResult{h}, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := an.AnalyzeRun(ctx, r.ID); err != nil {
			t.Fatal(err)
		}
		page, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: r.ID, ListOpts: store.ListOpts{Limit: 100}})
		var out []string
		for k := range kinds(page.Items) {
			out = append(out, k)
		}
		return out
	}
	open := func() int {
		page, err := st.ListFindings(ctx, store.FindingFilter{Status: []string{string(model.FindingNew)}})
		if err != nil {
			t.Fatal(err)
		}
		return page.Total
	}
	run(ssh)
	run(ssh)
	before := open()
	if before == 0 {
		t.Fatal("the SSH service has no finding to keep")
	}
	if k := run(wrapped); len(k) != 0 {
		t.Errorf("tcpwrapped after ssh: %v, want no change", k)
	}
	if n := open(); n != before {
		t.Errorf("open findings after the tcpwrapped scan: %d, want %d", n, before)
	}
	if k := run(ssh); len(k) != 0 {
		t.Errorf("ssh after tcpwrapped: %v, want no change", k)
	}
}
