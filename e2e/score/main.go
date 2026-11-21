// score compares a Czujka JSON export ([]model.HostResult) with the ground
// truth of the lab and prints precision, recall and F1.
//
// One state:
//
//	score -truth lab/ground-truth/t0.json -export export-t0.json
//
// Changes between two scans (the two-pass check):
//
//	score -changes lab/ground-truth/changes-t0-t1.json \
//	      -truth-from lab/ground-truth/t0.json -truth lab/ground-truth/t1.json \
//	      -from export-t0.json -to export-t1.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/lab/truth"
)

func loadExport(path string) ([]model.HostResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var hosts []model.HostResult
	if err := json.Unmarshal(raw, &hosts); err != nil {
		// Also accept {"items": [...]} and {"hosts": [...]} envelopes.
		var env struct {
			Items []model.HostResult `json:"items"`
			Hosts []model.HostResult `json:"hosts"`
		}
		if err2 := json.Unmarshal(raw, &env); err2 != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		hosts = append(env.Items, env.Hosts...)
	}
	return hosts, nil
}

// loadProductChanges reads a Page<model.Change> or a bare []model.Change.
func loadProductChanges(path string) ([]model.Change, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []model.Change
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var page struct {
		Items []model.Change `json:"items"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return page.Items, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "score:", err)
	os.Exit(1)
}

func main() {
	truthPath := flag.String("truth", "", "ground-truth file of the scanned state")
	exportPath := flag.String("export", "", "Czujka JSON export to score")
	changesPath := flag.String("changes", "", "expected-changes file (switches to change mode)")
	truthFrom := flag.String("truth-from", "", "change mode: ground truth of the first state")
	fromPath := flag.String("from", "", "change mode: export of the first scan")
	toPath := flag.String("to", "", "change mode: export of the second scan")
	productChanges := flag.String("product-changes", "", "change mode: score the product's own change list of the second run (GET /changes?run_id=N) instead of the diff of the exports")
	strict := flag.Bool("strict", false, "count the documented hard cases as ordinary misses")
	minConf := flag.Float64("min-confidence", 0, "ignore technologies under this confidence")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	maxList := flag.Int("max-list", 40, "longest list of misses or false positives to print (0: all)")
	minF1 := flag.Float64("min-f1", 0, "exit 1 when hosts or ports F1 (or the change F1) is under this value")
	ignore := flag.String("ignore", "", "more addresses to leave out, comma separated (for example the address of the scanner itself)")
	flag.Parse()
	// addIgnored extends the ignore list of a ground-truth file with the -ignore addresses.
	addIgnored := func(t *truth.File) {
		for _, ip := range strings.Split(*ignore, ",") {
			if ip = strings.TrimSpace(ip); ip != "" && t != nil {
				t.Ignore = append(t.Ignore, ip)
			}
		}
	}

	if *changesPath != "" {
		if *fromPath == "" || *toPath == "" {
			fail(fmt.Errorf("change mode needs -from and -to"))
		}
		cf, err := truth.LoadChanges(*changesPath)
		if err != nil {
			fail(err)
		}
		var before, after *truth.File
		if *truthFrom != "" {
			if before, err = truth.Load(*truthFrom); err != nil {
				fail(err)
			}
		}
		if *truthPath != "" {
			if after, err = truth.Load(*truthPath); err != nil {
				fail(err)
			}
		}
		addIgnored(before)
		addIgnored(after)
		from, err := loadExport(*fromPath)
		if err != nil {
			fail(err)
		}
		to, err := loadExport(*toPath)
		if err != nil {
			fail(err)
		}
		var observed []truth.Change
		if *productChanges != "" {
			list, err := loadProductChanges(*productChanges)
			if err != nil {
				fail(err)
			}
			observed = ProductChanges(list)
			if observed == nil {
				observed = []truth.Change{}
			}
		}
		rep := CompareChangeList(cf, before, after, from, to, observed)
		if *asJSON {
			printJSON(rep)
		} else {
			printChangeReport(os.Stdout, rep, *maxList)
		}
		if rep.Metric.F1 < *minF1 {
			os.Exit(1)
		}
		return
	}

	if *truthPath == "" || *exportPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	t, err := truth.Load(*truthPath)
	if err != nil {
		fail(err)
	}
	export, err := loadExport(*exportPath)
	if err != nil {
		fail(err)
	}
	addIgnored(t)
	rep := Score(t, export, Options{Strict: *strict, MinConfidence: *minConf})
	if *asJSON {
		printJSON(rep)
	} else {
		printReport(os.Stdout, rep, *maxList)
	}
	if rep.Metrics[0].F1 < *minF1 || rep.Metrics[1].F1 < *minF1 {
		os.Exit(1)
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func printList(w io.Writer, title string, items []string, max int) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s (%d):\n", title, len(items))
	for i, it := range items {
		if max > 0 && i == max {
			fmt.Fprintf(w, "    ... and %d more\n", len(items)-max)
			break
		}
		fmt.Fprintf(w, "    %s\n", it)
	}
}

func printMetricTable(w io.Writer, ms []Metric) {
	fmt.Fprintf(w, "%-22s %5s %5s %5s %10s %8s %8s\n", "category", "TP", "FP", "FN", "precision", "recall", "F1")
	for _, m := range ms {
		fmt.Fprintf(w, "%-22s %5d %5d %5d %10.3f %8.3f %8.3f\n", m.Name, m.TP, m.FP, m.FN, m.Precision, m.Recall, m.F1)
	}
}

func printReport(w io.Writer, r *Report, max int) {
	mode := "hard cases excused"
	if r.Strict {
		mode = "strict"
	}
	fmt.Fprintf(w, "Ground truth state %s (%s)\n\n", r.State, mode)
	printMetricTable(w, r.Metrics)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-46s %7s %7s\n", "check (recall only)", "right", "share")
	for _, a := range r.Accuracies {
		if a.Total == 0 {
			continue
		}
		fmt.Fprintf(w, "%-46s %3d/%-3d %7.3f\n", a.Name, a.Right, a.Total, a.Share)
	}
	fmt.Fprintln(w)
	for _, m := range r.Metrics {
		if len(m.Missed)+len(m.Extra) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s\n", strings.ToUpper(m.Name))
		printList(w, "missed", m.Missed, max)
		printList(w, "false positives", m.Extra, max)
	}
	for _, a := range r.Accuracies {
		if len(a.Wrong) > 0 {
			fmt.Fprintf(w, "%s\n", strings.ToUpper(a.Name))
			printList(w, "wrong or missing", a.Wrong, max)
		}
	}
	if len(r.HardMisses) > 0 {
		fmt.Fprintln(w, "HARD CASES")
		printList(w, "missed, excused", r.HardMisses, max)
	}
	if len(r.Unstable) > 0 {
		fmt.Fprintln(w, "UNSTABLE HOSTS (not in the metrics)")
		for _, u := range r.Unstable {
			exp := "expected state unknown (no observation time)"
			if u.ExpectedUp != nil {
				exp = fmt.Sprintf("availability model says up=%v at %s", *u.ExpectedUp, u.ObservedAt)
			}
			fmt.Fprintf(w, "    %-14s %-12s seen up=%-5v %s\n", u.IP, u.Name, u.SeenUp, exp)
		}
	}
}

func printChangeReport(w io.Writer, r *ChangeReport, max int) {
	fmt.Fprintf(w, "Expected changes %s -> %s (observed: %s)\n\n", r.From, r.To, r.Source)
	printMetricTable(w, []Metric{r.Metric})
	fmt.Fprintln(w)
	printList(w, "matched", r.Matched, max)
	printList(w, "expected, not observed", r.Metric.Missed, max)
	printList(w, "observed, not expected", r.Metric.Extra, max)
	printList(w, "not checked: the exports hold no data of that kind", r.NotChecked, max)
}
