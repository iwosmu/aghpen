package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

var update = flag.Bool("update", false, "rewrite docs/samples/raport-przyklad.{html,md}")

const sampleDir = "../../docs/samples"

// The sample files in docs/ are the exact output of the code for the sample
// input. "go test ./internal/report -update" rewrites them.
func TestSampleFilesAreCurrent(t *testing.T) {
	in := sampleInput()
	html, err := HTML(in)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"raport-przyklad.html": html, "raport-przyklad.md": []byte(Markdown(in))}
	for name, want := range files {
		path := filepath.Join(sampleDir, name)
		if *update {
			if err := os.MkdirAll(sampleDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("wrote %s (%d bytes)", path, len(want))
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run: go test ./internal/report -update)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale; run: go test ./internal/report -update", path)
		}
	}
}

func TestSampleContent(t *testing.T) {
	in := sampleInput()
	b, err := HTML(in)
	if err != nil {
		t.Fatal(err)
	}
	html, md := string(b), Markdown(in)

	for _, out := range []string{html, md} {
		for _, want := range []string{
			"Raport z przebiegu #42",
			"Przybyło: 1 host i 5 usług. Ubyło: 1 host i 3 usługi.",
			"Bez odpowiedzi w tym przebiegu: 1 host (2 usługi bez potwierdzenia)",
			"Host 10.66.1.80 nie odpowiedział w tym przebiegu (w poprzednim aktywny, 2 otwarte usługi)",
			"Najpierw sprawdź 5 zmian o wadze średniej lub wysokiej.",
			"Co nowego", "Co zniknęło", "Co się zmieniło",
			"Nowa usługa 10.66.3.17:8080 (Jetty 10.0.20)",
			"Host 10.66.2.5 zgłoszony jako nieaktywny",
			"9 zmian oczekiwanych",
			"Panel administracyjny: Jenkins (10.66.3.17:8080)",
			"2.440.1", // evidence of the Jenkins finding
			"także: narzędzie deweloperskie",
			"zwykle aktywny pn–pt 14–15",
			"oraz 7 hostów o tym samym rytmie",
			"GET, HEAD",
			"14 260", // packets actually sent
			"44,8 pakietów/s (45% limitu 100)",
			"Czujka/1.0",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output does not contain %q", want)
			}
		}
		// Expected changes are folded: the fifth workstation is not listed anywhere.
		if strings.Contains(out, "10.66.2.35") {
			t.Error("an expected change is listed on its own")
		}
	}

	// The reading order of the brief.
	order := []string{"class=\"lead\"", "class=\"figures\"", "Co nowego", "Co zniknęło", "Co się zmieniło", "class=\"expected\"",
		"Najważniejsze obserwacje", "Hosty niestabilne", "Parametry skanu", "Ruch faktycznie wysłany"}
	last := -1
	for _, o := range order {
		i := strings.Index(html, o)
		if i < 0 || i < last {
			t.Errorf("%q is missing or out of order (at %d, previous at %d)", o, i, last)
		}
		last = i
	}

	// Self-contained: no script, no external asset, no link that loads anything.
	for _, bad := range []string{"<script", "<link", "<img", "<iframe", "@import", "url(", "src="} {
		if strings.Contains(html, bad) {
			t.Errorf("the HTML report contains %q", bad)
		}
	}
	if !strings.Contains(html, "<html lang=\"pl\">") || !strings.Contains(html, "@page{size:A4") {
		t.Error("language or A4 page rule is missing")
	}
}

func TestSameContentInBothFormats(t *testing.T) {
	in := sampleInput()
	d := build(in)
	b, _ := HTML(in)
	html, md := string(b), Markdown(in)
	n := 0
	for _, s := range d.Sections {
		for _, r := range s.Rows {
			n++
			// The first words are free of characters that either format escapes.
			head := strings.SplitN(r.Summary, " (", 2)[0]
			head = strings.SplitN(head, ": ", 2)[0]
			if !strings.Contains(html, head) || !strings.Contains(md, head) {
				t.Errorf("change %q is not in both formats", head)
			}
		}
	}
	if n != 17 {
		t.Errorf("sample has %d listed changes, want 17", n)
	}
	for _, f := range d.Findings {
		if !strings.Contains(md, "`"+f.Addr+"`") {
			t.Errorf("finding %q is not in the Markdown", f.Addr)
		}
	}
}

func TestDeterministic(t *testing.T) {
	a, _ := HTML(sampleInput())
	b, _ := HTML(sampleInput())
	if !bytes.Equal(a, b) || Markdown(sampleInput()) != Markdown(sampleInput()) {
		t.Error("two renders of the same input differ")
	}
}

// Titles, banners and evidence come from scanned hosts. They must not be able
// to add markup to the report.
func TestHostileTextIsEscaped(t *testing.T) {
	evil := "<script>alert(1)</script><img src=x onerror=alert(2)>"
	prev := int64(1)
	in := Input{
		Run:     model.ScanRun{ID: 2, Status: model.RunCompleted},
		Summary: model.RunDiffSummary{PrevRunID: &prev, ServicesNew: 1},
		Changes: []model.Change{{Kind: model.ChangeServiceNew, Severity: model.SevMedium, IP: "10.0.0.1", Port: 80,
			Summary: "Nowa usługa 10.0.0.1:80 (" + evil + ") | a | b"}},
		Findings: []model.Finding{{Key: "k", Title: evil + " [x](javascript:alert(3))", IP: "10.0.0.1", Port: 80, Interest: 50,
			URL: "http://10.0.0.1/\"><script>", Evidence: []model.Evidence{{Where: "title", Snippet: evil + "\n| pipe | `tick`"}}}},
		Services: []model.Service{{IP: "10.0.0.1", Port: 80, Title: evil, Interest: 50,
			InterestWhy: []model.InterestReason{{Code: "x", Points: 5, Text: evil}}}},
		Hosts:  []model.Host{{IP: "10.0.0.2", Label: evil, Pattern: evil, Status: model.HostUnstable}},
		Policy: model.SafetyPolicy{UserAgent: evil, AllowedMethods: []string{"GET"}},
	}
	b, err := HTML(in)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	if strings.Contains(html, "<script") || strings.Contains(html, "<img") || strings.Contains(html, "onerror=alert(2)>") {
		t.Error("hostile text reached the HTML unescaped")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)") {
		t.Error("the hostile text should still be visible as text")
	}
	md := Markdown(in)
	if strings.Contains(md, "<script") || strings.Contains(md, "<img") || strings.Contains(md, "[x](") {
		t.Error("hostile text reached the Markdown unescaped")
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "|") && strings.Count(strings.ReplaceAll(line, "\\|", ""), "|") > 7 {
			t.Errorf("a pipe from the data added a table cell: %s", line)
		}
		if strings.HasPrefix(line, "- ") && strings.Count(line, "`") > 2 {
			t.Errorf("a backtick from the data opened a code span: %s", line)
		}
	}
}

func TestFirstRunHasNoChangeSections(t *testing.T) {
	in := Input{Run: model.ScanRun{ID: 1, Status: model.RunCompleted, Stats: model.RunStats{HostsUp: 12, ServicesOpen: 30}}}
	b, _ := HTML(in)
	html := string(b)
	if !strings.Contains(html, "To pierwszy przebieg tego profilu") || !strings.Contains(html, "brak (pierwszy przebieg)") {
		t.Error("first run is not explained")
	}
	if strings.Contains(html, "Co nowego") || strings.Contains(html, "Nic nowego") {
		t.Error("a first run has no baseline, so it must not show change sections")
	}
}

func TestQuietRun(t *testing.T) {
	prev := int64(7)
	in := Input{Run: model.ScanRun{ID: 8, Status: model.RunCompleted}, Summary: model.RunDiffSummary{PrevRunID: &prev, ByKind: map[string]int{"expected": 3}},
		Changes: []model.Change{
			{Kind: model.ChangeHostGone, Severity: model.SevInfo, IP: "10.0.0.7", Expected: true, Summary: "x"},
			{Kind: model.ChangeHostGone, Severity: model.SevInfo, IP: "10.0.0.8", Expected: true, Summary: "y"},
			{Kind: model.ChangeHostBack, Severity: model.SevInfo, IP: "10.0.0.9", Expected: true, Summary: "z"},
		}}
	md := Markdown(in)
	for _, want := range []string{"nie ma zmian, które wymagają uwagi", "Nic nowego.", "Nic nie zniknęło.", "3 zmiany oczekiwane", "(10.0.0.7, 10.0.0.8, 10.0.0.9)"} {
		if !strings.Contains(md, want) {
			t.Errorf("quiet run: %q is missing", want)
		}
	}
}

func TestLimitsCutLongLists(t *testing.T) {
	prev := int64(1)
	in := Input{Run: model.ScanRun{ID: 2, Status: model.RunCompleted}, Summary: model.RunDiffSummary{PrevRunID: &prev, ServicesNew: 30}, Limits: Limits{Changes: 5, Findings: 2}}
	for i := 0; i < 30; i++ {
		sev := model.SevLow
		if i == 29 {
			sev = model.SevHigh
		}
		in.Changes = append(in.Changes, model.Change{Kind: model.ChangeServiceNew, Severity: sev, IP: "10.0.0.9", Port: 1000 + i, Summary: "Nowa usługa nr " + string(rune('A'+i))})
		in.Findings = append(in.Findings, model.Finding{Key: "k" + string(rune('A'+i)), Title: "Obserwacja", IP: "10.0.1.1", Port: 2000 + i, Interest: i})
	}
	d := build(in)
	if got := len(d.Sections[0].Rows); got != 5 {
		t.Fatalf("rows = %d, want 5", got)
	}
	if d.Sections[0].Rows[0].Sev != "high" {
		t.Error("the most severe change must be first")
	}
	if want := "i jeszcze 25 zmian o tej samej lub niższej wadze"; !strings.HasPrefix(d.Sections[0].More, want) {
		t.Errorf("more = %q", d.Sections[0].More)
	}
	if len(d.Findings) != 2 || d.Findings[0].Interest != 29 || !strings.HasPrefix(d.FindingsMore, "i jeszcze 28 obserwacji") {
		t.Errorf("findings = %d, first interest %d, more %q", len(d.Findings), d.Findings[0].Interest, d.FindingsMore)
	}
}

func TestFindingsOfOneServiceMakeOneBlock(t *testing.T) {
	ev := []model.Evidence{{Where: "title", Snippet: "Dashboard"}}
	in := Input{Run: model.ScanRun{ID: 9}, Findings: []model.Finding{
		{Key: "new-exposure/10.0.0.1/tcp-8080", Title: "Nowa ekspozycja: Dashboard", IP: "10.0.0.1", Port: 8080, Interest: 70, FirstRunID: 9, Evidence: ev},
		{Key: "admin-panel/10.0.0.1/tcp-8080/x", Title: "Panel administracyjny: X", IP: "10.0.0.1", Port: 8080, Interest: 70, FirstRunID: 9,
			Evidence: append([]model.Evidence{{Where: "header:X", Snippet: "1"}}, ev...)},
		{Key: "default-page/10.0.0.2/tcp-80", Title: "Strona domyślna", IP: "10.0.0.2", Port: 80, Interest: 5},
	}}
	prev := int64(8)
	in.Summary.PrevRunID = &prev
	d := build(in)
	if len(d.Findings) != 2 {
		t.Fatalf("blocks = %d, want 2", len(d.Findings))
	}
	f := d.Findings[0]
	if f.Title != "Panel administracyjny: X" || len(f.Evidence) != 2 {
		t.Errorf("first block = %q with %d evidence rows, want the admin panel with 2 (duplicates removed)", f.Title, len(f.Evidence))
	}
	if strings.Join(f.Notes, "|") != "nowa w tym przebiegu|także: nowa ekspozycja" {
		t.Errorf("notes = %q", f.Notes)
	}
}

func TestResolvedAndFalsePositiveFindingsAreLeftOut(t *testing.T) {
	in := Input{Run: model.ScanRun{ID: 2}, Findings: []model.Finding{
		{Key: "a", Title: "Zamknięta", IP: "10.0.0.1", Port: 1, Status: model.FindingResolved, Interest: 90},
		{Key: "b", Title: "Fałszywa", IP: "10.0.0.1", Port: 2, Status: model.FindingFalsePositive, Interest: 80},
		{Key: "c", Title: "Otwarta", IP: "10.0.0.1", Port: 3, Status: model.FindingTriaged, Interest: 10},
	}}
	d := build(in)
	if len(d.Findings) != 1 || d.Findings[0].Title != "Otwarta" || d.Findings[0].Notes[0] != "potwierdzona" {
		t.Errorf("findings = %+v", d.Findings)
	}
}

func TestUnfinishedRunIsMarked(t *testing.T) {
	prev := int64(1)
	in := Input{Run: model.ScanRun{ID: 2, Status: model.RunPaused, PauseReason: model.PauseWindowClosed,
		Stats: model.RunStats{AddressesTotal: 2048, AddressesDone: 512}}, Summary: model.RunDiffSummary{PrevRunID: &prev}}
	md := Markdown(in)
	want := "Przebieg nie jest zakończony (stan: wstrzymany, okno czasowe się zamknęło). Sprawdzono 512 z 2 048 adresów, więc lista zmian jest niepełna."
	if !strings.Contains(md, want) {
		t.Errorf("notice is missing:\n%s", md[:400])
	}
}

func TestImportedRunSaysNoTraffic(t *testing.T) {
	in := Input{Run: model.ScanRun{ID: 3, Status: model.RunCompleted, Trigger: "import"}}
	if !strings.Contains(Markdown(in), "Czujka nie wysłała w nim żadnych pakietów") {
		t.Error("an imported run must say that no packets were sent")
	}
}

func TestTextHelpers(t *testing.T) {
	plurals := map[int]string{1: "host", 2: "hosty", 4: "hosty", 5: "hostów", 12: "hostów", 14: "hostów", 21: "hostów", 22: "hosty", 112: "hostów", 0: "hostów"}
	for n, want := range plurals {
		if got := plural(n, "host", "hosty", "hostów"); got != want {
			t.Errorf("plural(%d) = %s, want %s", n, got, want)
		}
	}
	nums := map[int64]string{0: "0", 999: "999", 1000: "1 000", 14260: "14 260", 1234567: "1 234 567", -5: "−5"}
	for n, want := range nums {
		if got := num(n); got != want {
			t.Errorf("num(%d) = %q, want %q", n, got, want)
		}
	}
	durs := map[int64]string{0: "0 s", 42: "42 s", 60: "1 min", 318: "5 min 18 s", 3600: "1 h 0 min", 4500: "1 h 15 min"}
	for s, want := range durs {
		if got := dur(s); got != want {
			t.Errorf("dur(%d) = %q, want %q", s, got, want)
		}
	}
	w := windowsText([]model.Window{{Days: []int{1, 2, 3, 4, 5}, Start: "22:00", End: "06:00"}, {Days: []int{0, 1, 2, 3, 4, 5, 6}, Start: "01:00", End: "04:00"}})
	if w != "pn, wt, śr, cz, pt 22:00–06:00; codziennie 01:00–04:00" {
		t.Errorf("windowsText = %q", w)
	}
	if got := discoveryText(model.DiscoveryOpts{SkipDiscovery: true}); !strings.Contains(got, "pominięte") {
		t.Errorf("discoveryText = %q", got)
	}
}

func TestTimesUseTheGivenZone(t *testing.T) {
	start := time.Date(2026, 11, 21, 1, 0, 0, 0, time.UTC)
	end := start.Add(26 * time.Hour)
	in := Input{Location: warsaw, Run: model.ScanRun{ID: 5, StartedAt: &start, FinishedAt: &end}}
	if md := Markdown(in); !strings.Contains(md, "21.11.2026 02:00 – 22.11.2026 04:00") {
		t.Errorf("times are not in Europe/Warsaw:\n%s", md[:300])
	}
}
