// unstableseries turns the output of e2e/unstable-series.sh into a timeline:
// for every run and every watched host, what the lab's availability rule
// says, what Czujka saw (and how many probe rounds it used), the host status
// after the run, and the changes Czujka reported.
//
//	go run ./e2e/unstableseries -dir e2e/out/unstable-czus-... -truth lab/ground-truth/t0.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/lab/labcfg"
	"github.com/iwosmu/aghpen/lab/truth"
)

// Row is one host in one run.
type Row struct {
	RunID    int64
	At       time.Time
	IP       string
	Name     string
	Truth    bool // the lab's rule says the host is up at At
	Seen     bool
	Attempts int
	Status   model.HostStatus
	PAlive   float64
	Changes  []string
}

// Watched are the hosts of the series scope: no-icmp (stable control),
// flapper, tod-office, tod-night.
var Watched = []string{"10.66.70.10", "10.66.70.20", "10.66.70.21", "10.66.70.22"}

// readExport reads a Czujka JSON export: the {"hosts": [...]} envelope or a bare list.
func readExport(path string) ([]model.HostResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []model.HostResult
	if json.Unmarshal(raw, &list) == nil {
		return list, nil
	}
	var env struct {
		Hosts []model.HostResult `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return env.Hosts, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// Load reads every run of a series directory.
func Load(dir string, t *truth.File) ([]Row, error) {
	hosts := map[string]truth.Host{}
	for _, h := range t.Hosts {
		hosts[h.IP] = h
	}
	watched := []string{}
	for _, ip := range Watched {
		if _, ok := hosts[ip]; ok {
			watched = append(watched, ip)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "runs", "export-*.json"))
	var rows []Row
	for _, f := range files {
		idText := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "export-"), ".json")
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil {
			continue
		}
		exp, err := readExport(f)
		if err != nil {
			return nil, err
		}
		var hp struct {
			Items []model.Host `json:"items"`
		}
		_ = readJSON(filepath.Join(dir, "runs", fmt.Sprintf("hosts-%d.json", id)), &hp)
		var cp struct {
			Items []model.Change `json:"items"`
		}
		_ = readJSON(filepath.Join(dir, "runs", fmt.Sprintf("changes-%d.json", id)), &cp)
		var run model.ScanRun
		_ = readJSON(filepath.Join(dir, "runs", fmt.Sprintf("run-%d.json", id)), &run)
		status := map[string]model.Host{}
		for _, h := range hp.Items {
			status[h.IP] = h
		}
		// The export lists the hosts that answered (and known hosts that
		// went silent); a watched host that is absent did not answer.
		byIP := map[string]model.HostResult{}
		for _, hr := range exp {
			byIP[hr.IP] = hr
		}
		for _, ip := range watched {
			th := hosts[ip]
			hr, ok := byIP[ip]
			if !ok {
				hr = model.HostResult{IP: ip}
			}
			at := hr.ObservedAt
			if at.IsZero() && run.FinishedAt != nil {
				at = *run.FinishedAt
			}
			r := Row{RunID: id, At: at, IP: hr.IP, Name: th.Name, Truth: (*labcfg.Avail)(th.Availability).UpAt(at),
				Seen: hr.Up, Attempts: hr.Attempts, Status: status[hr.IP].Status, PAlive: status[hr.IP].PAlive}
			for _, c := range cp.Items {
				if c.IP == hr.IP {
					s := string(c.Kind)
					if c.Expected {
						s += " (expected)"
					}
					r.Changes = append(r.Changes, s)
				}
			}
			rows = append(rows, r)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].RunID != rows[j].RunID {
			return rows[i].RunID < rows[j].RunID
		}
		return rows[i].IP < rows[j].IP
	})
	return rows, nil
}

func yes(b bool) string {
	if b {
		return "up"
	}
	return "—"
}

// Summary counts, per host, the agreement with the lab rule and the reports.
type Summary struct {
	Name                                           string
	Runs, Agree, Retried                           int
	Missing, Gone, Back, Unstable, Expected, Other int
	Statuses                                       map[model.HostStatus]int
	FirstGoneRun                                   int64
}

func Summarize(rows []Row) []Summary {
	by := map[string]*Summary{}
	var order []string
	for _, r := range rows {
		s, ok := by[r.IP]
		if !ok {
			s = &Summary{Name: r.Name + " " + r.IP, Statuses: map[model.HostStatus]int{}}
			by[r.IP] = s
			order = append(order, r.IP)
		}
		s.Runs++
		if r.Truth == r.Seen {
			s.Agree++
		}
		if r.Attempts > 1 {
			s.Retried++
		}
		s.Statuses[r.Status]++
		for _, c := range r.Changes {
			if strings.HasSuffix(c, "(expected)") {
				s.Expected++
			}
			switch strings.TrimSuffix(c, " (expected)") {
			case string(model.ChangeHostMissing):
				s.Missing++
			case string(model.ChangeHostGone):
				s.Gone++
				if s.FirstGoneRun == 0 {
					s.FirstGoneRun = r.RunID
				}
			case string(model.ChangeHostBack):
				s.Back++
			case string(model.ChangeHostUnstable):
				s.Unstable++
			default:
				s.Other++
			}
		}
	}
	sort.Strings(order)
	out := make([]Summary, 0, len(order))
	for _, ip := range order {
		out = append(out, *by[ip])
	}
	return out
}

func Print(w io.Writer, rows []Row, clock string) {
	fmt.Fprintf(w, "# Seria skanów hostów niestabilnych\n\nZegar modelu dostępności: %s. Każdy wiersz: jeden host w jednym przebiegu.\n\n", clock)
	fmt.Fprintln(w, "| przebieg | czas (UTC) | host | reguła labu | Czujka widzi | rundy sond | status po przebiegu | p_alive | zmiany |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, r := range rows {
		fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %d | %s | %.2f | %s |\n", r.RunID, r.At.UTC().Format("15:04:05"), r.Name, yes(r.Truth), yes(r.Seen),
			r.Attempts, r.Status, r.PAlive, strings.Join(r.Changes, ", "))
	}
	fmt.Fprint(w, "\n## Podsumowanie\n\n")
	fmt.Fprintln(w, "| host | przebiegi | zgodne z regułą | z ponowieniem | host_missing | host_unstable | host_gone | host_back | expected | statusy |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, s := range Summarize(rows) {
		var st []string
		for k, v := range s.Statuses {
			st = append(st, fmt.Sprintf("%s %d", k, v))
		}
		sort.Strings(st)
		fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %d | %d | %d | %d | %s |\n", s.Name, s.Runs, s.Agree, s.Retried, s.Missing, s.Unstable, s.Gone, s.Back, s.Expected, strings.Join(st, ", "))
	}
}

func main() {
	dir := flag.String("dir", "", "output directory of e2e/unstable-series.sh")
	truthPath := flag.String("truth", "lab/ground-truth/t0.json", "ground-truth file")
	clock := flag.String("clock", "1h/168h", "availability clock of the series (text only)")
	flag.Parse()
	t, err := truth.Load(*truthPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rows, err := Load(*dir, t)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	Print(os.Stdout, rows, *clock)
}
