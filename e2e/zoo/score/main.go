// score compares the zoo runs (e2e/zoo/out/<phase>/<batch>/export.json, the Czujka JSON export of the run) and plain
// nmap -sV (nmap.xml of the same batch) with the truth table e2e/zoo/truth.tsv. It prints a Markdown report: one line
// per port, then totals per category for each tool, then the technologies and classes reported that the truth does
// not allow (false positives).
//
//	go run ./e2e/zoo/score -phase before [-nmap-phase before] [-batch 01-cms]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/iwosmu/aghpen/e2e/nmapconv"
	"github.com/iwosmu/aghpen/internal/model"
)

func main() {
	truthPath := flag.String("truth", "e2e/zoo/truth.tsv", "truth table")
	out := flag.String("out", "e2e/zoo/out", "results directory")
	phase := flag.String("phase", "before", "phase to score (subdirectory of -out)")
	nmapPhase := flag.String("nmap-phase", "", "phase whose nmap.xml is the baseline (default: -phase)")
	only := flag.String("batch", "", "score one batch only")
	flag.Parse()
	if *nmapPhase == "" {
		*nmapPhase = *phase
	}
	f, err := os.Open(*truthPath)
	if err != nil {
		fail(err)
	}
	rows, err := ReadTruth(f)
	f.Close()
	if err != nil {
		fail(err)
	}
	type batchData struct {
		cz, nm   []model.HostResult
		findings []model.Finding
		ok, nmOK bool
	}
	data := map[string]*batchData{}
	load := func(b string) *batchData {
		if d, ok := data[b]; ok {
			return d
		}
		d := &batchData{}
		if raw, err := os.ReadFile(filepath.Join(*out, *phase, b, "export.json")); err == nil {
			var env struct {
				Hosts []model.HostResult `json:"hosts"`
			}
			if json.Unmarshal(raw, &env) == nil && env.Hosts != nil {
				d.cz, d.ok = env.Hosts, true
			} else {
				d.ok = json.Unmarshal(raw, &d.cz) == nil
			}
		}
		if raw, err := os.ReadFile(filepath.Join(*out, *phase, b, "findings.json")); err == nil {
			var page struct{ Items []model.Finding }
			if json.Unmarshal(raw, &page) == nil {
				d.findings = page.Items
			}
		}
		if fh, err := os.Open(filepath.Join(*out, *nmapPhase, b, "nmap.xml")); err == nil {
			if hs, err := nmapconv.Parse(fh); err == nil {
				d.nm, d.nmOK = hs, true
			}
			fh.Close()
		}
		data[b] = d
		return d
	}

	cats := []string{}
	cz := map[string]*Tally{}
	nm := map[string]*Tally{}
	var wrong []string
	fmt.Printf("# Zoo: %s\n\n", *phase)
	fmt.Println("| batch | port | expected | Czujka | ok | nmap -sV | ok |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- |")
	for _, row := range rows {
		if *only != "" && row.Batch != *only {
			continue
		}
		d := load(row.Batch)
		if !d.ok {
			continue
		}
		if cz[row.Category] == nil {
			cats = append(cats, row.Category)
			cz[row.Category], nm[row.Category] = &Tally{}, &Tally{}
		}
		rc := Score(row, Find(d.cz, row.Port, row.Proto), d.findings)
		cz[row.Category].Add(rc)
		rn := Result{}
		if d.nmOK {
			nrow := row
			nrow.Techs, nrow.Classes, nrow.Finding = nil, nil, ""
			rn = Score(nrow, Find(d.nm, row.Port, row.Proto), nil)
			// nmap names no technologies or classes: the rows that ask for them count as misses.
			if len(row.Techs) > 0 {
				rn.Techs = ptr(false)
			}
			if len(row.Classes) > 0 {
				rn.Classes = ptr(false)
			}
			rn.Wrong = nil
			nm[row.Category].Add(rn)
		}
		exp := strings.TrimSpace(row.Product + " " + row.Version)
		if len(row.Classes) > 0 {
			exp += " {" + strings.Join(row.Classes, ",") + "}"
		}
		fmt.Printf("| %s | %d/%s | %s | %s | %s | %s | %s |\n", row.Batch, row.Port, row.Proto, md(exp), md(rc.Said), marks(rc), md(rn.Said), marks(rn))
		if len(rc.Wrong) > 0 || len(rc.Missing) > 0 {
			wrong = append(wrong, fmt.Sprintf("| %s | %d/%s | %s | %s |", row.Batch, row.Port, row.Proto, md(strings.Join(rc.Missing, ", ")), md(strings.Join(rc.Wrong, ", "))))
		}
	}
	sort.Strings(cats)
	fmt.Println()
	fmt.Println("## Per category")
	fmt.Println()
	fmt.Println("| category | ports | tool | found | named | product | version | technologies | classes | wrong |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	tc, tn := &Tally{}, &Tally{}
	for _, c := range cats {
		fmt.Println(tallyLine(c, "Czujka", cz[c]))
		fmt.Println(tallyLine(c, "nmap -sV", nm[c]))
		sum(tc, cz[c])
		sum(tn, nm[c])
	}
	fmt.Println(tallyLine("**all**", "**Czujka**", tc))
	fmt.Println(tallyLine("**all**", "**nmap -sV**", tn))
	fmt.Println()
	fmt.Println("## Missing and wrong (Czujka)")
	fmt.Println()
	fmt.Println("| batch | port | missing | wrong (false positive) |")
	fmt.Println("| --- | --- | --- | --- |")
	for _, w := range wrong {
		fmt.Println(w)
	}
}

func sum(dst, src *Tally) {
	dst.Rows += src.Rows
	dst.Found += src.Found
	dst.Named += src.Named
	dst.Product += src.Product
	dst.Version += src.Version
	dst.VersionN += src.VersionN
	dst.Techs += src.Techs
	dst.TechsN += src.TechsN
	dst.Classes += src.Classes
	dst.ClassesN += src.ClassesN
	dst.Wrong += src.Wrong
}

func tallyLine(cat, tool string, t *Tally) string {
	return fmt.Sprintf("| %s | %d | %s | %d | %d | %d | %d/%d | %d/%d | %d/%d | %d |", cat, t.Rows, tool, t.Found, t.Named, t.Product,
		t.Version, t.VersionN, t.Techs, t.TechsN, t.Classes, t.ClassesN, t.Wrong)
}

func marks(r Result) string {
	if !r.Found {
		return "–"
	}
	s := ""
	add := func(ok bool, c string) {
		if ok {
			s += c
		} else {
			s += "·"
		}
	}
	add(r.Named, "N")
	add(r.Product, "P")
	if r.Version != nil {
		add(*r.Version, "V")
	}
	if r.Techs != nil {
		add(*r.Techs, "T")
	}
	if r.Classes != nil {
		add(*r.Classes, "C")
	}
	if r.Finding != nil {
		add(*r.Finding, "F")
	}
	return s
}

func md(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func fail(err error) {
	fmt.Fprintln(os.Stderr, "score:", err)
	os.Exit(1)
}
