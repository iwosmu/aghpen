// Command dojoprobe is a developer tool for the DefectDojo integration.
//
//	dojoprobe test                               check the URL and the token, print the server version
//	dojoprobe derive -in scan.xml > f.json       import results (nmap XML, JSON, CSV) and derive findings
//	dojoprobe convert -in scan.xml -to csv       import results and export them as xml, json or csv
//	dojoprobe push -file f.json                  export findings (a JSON array of model.Finding)
//	dojoprobe nmap -file scan.xml [-title T]     upload nmap XML as an "Nmap Scan" import
//	dojoprobe list -test ID                      list the findings of a test with their endpoints
//	dojoprobe generic -in f.json -to json|csv    write findings as DefectDojo Generic Findings Import
//	dojoprobe fimport -in file                   import findings (Generic JSON/CSV, API list, Czujka export)
//	dojoprobe pull -file f.json                  propose status updates from DefectDojo (findings need dojo_id)
//	dojoprobe lifecycle -file f.json             close resolved / reopen observed findings in DefectDojo
//	dojoprobe attach -file f.json [-test ID -in run.xml]  upload evidence files (and a run's nmap XML)
//
// The URL and the token come from -url / -token or DOJO_URL / DOJO_TOKEN.
// Use it only against an instance you own (see lab/defectdojo).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/defectdojo"
	"github.com/iwosmu/aghpen/internal/interchange"
	"github.com/iwosmu/aghpen/internal/model"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	urlFlag := fs.String("url", envOr("DOJO_URL", "http://127.0.0.1:18080"), "DefectDojo base URL")
	token := fs.String("token", os.Getenv("DOJO_TOKEN"), "API v2 token (or DOJO_TOKEN)")
	insecure := fs.Bool("insecure", false, "do not verify the TLS certificate")
	timeout := fs.Duration("timeout", 30*time.Second, "timeout of one API call")
	file := fs.String("file", "", "input file")
	in := fs.String("in", "", "input file of derive and convert")
	to := fs.String("to", "json", "output format of convert: xml, json, csv")
	title := fs.String("title", "", "test title of an nmap import")
	testID := fs.Int64("test", 0, "test id for list")
	productType := fs.String("product-type", "", "product type name (default: "+defectdojo.DefaultProductType+")")
	product := fs.String("product", "", "product name (default: "+defectdojo.DefaultProduct+")")
	engagement := fs.String("engagement", "", "engagement name (default: "+defectdojo.DefaultEngagement+")")
	fs.Parse(args)

	target := defectdojo.Target{ProductTypeName: *productType, ProductName: *product, EngagementName: *engagement}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	switch cmd {
	case "derive":
		die(derive(firstNonEmpty(*in, *file)))
		return
	case "convert":
		die(convert(firstNonEmpty(*in, *file), *to))
		return
	case "generic":
		die(generic(firstNonEmpty(*in, *file), *to))
		return
	case "fimport":
		die(fimport(firstNonEmpty(*in, *file)))
		return
	}
	client, err := defectdojo.New(defectdojo.Config{URL: *urlFlag, APIKey: *token, VerifyTLS: !*insecure, Timeout: *timeout})
	die(err)

	switch cmd {
	case "test":
		info, err := client.Test(ctx)
		printJSON(info)
		die(err)
	case "push":
		data, err := os.ReadFile(*file)
		die(err)
		var findings []model.Finding
		die(json.Unmarshal(data, &findings))
		out, err := client.ExportFindings(ctx, target, findings)
		printJSON(map[string]any{"input": len(findings), "result": out.Result, "patched": out.Patched, "location": out.Location})
		die(err)
		if out.Result.Failed > 0 {
			os.Exit(1)
		}
	case "nmap":
		f, err := os.Open(*file)
		die(err)
		defer f.Close()
		res, err := client.ImportNmapXML(ctx, target, *title, f, time.Now())
		printJSON(res)
		die(err)
	case "list":
		views, err := client.ListFindings(ctx, *testID)
		die(err)
		for _, v := range views {
			fmt.Printf("#%-4d %-6s active=%-5v %-58s endpoints=[%s] key=%s tags=%s\n", v.ID, v.Severity, v.Active, clip(v.Title, 58),
				strings.Join(v.Endpoints, " "), v.Key, strings.Join(v.Tags, ","))
		}
		fmt.Printf("%d findings in test %d (%s/test/%d)\n", len(views), *testID, client.BaseURL(), *testID)
	case "pull":
		findings := readFindings(*file)
		local := make([]defectdojo.LocalStatus, len(findings))
		for i, f := range findings {
			local[i] = defectdojo.LocalStatus{Finding: f}
		}
		res, err := client.PullStatus(ctx, local)
		printJSON(res)
		die(err)
	case "lifecycle":
		res, err := client.SyncLifecycle(ctx, readFindings(*file), time.Now())
		printJSON(res)
		die(err)
	case "attach":
		findings := readFindings(*file)
		n, errs := client.AttachEvidence(ctx, findings)
		out := map[string]any{"evidence_files": n, "errors": errs}
		if *testID != 0 && *in != "" {
			xml, err := os.ReadFile(*in)
			die(err)
			if err := client.AttachRunXML(ctx, *testID, 1, xml); err != nil {
				out["xml_error"] = err.Error()
			} else {
				out["xml_attached_to_test"] = *testID
			}
		}
		printJSON(out)
	default:
		usage()
		os.Exit(2)
	}
}

func readFindings(path string) []model.Finding {
	data, err := os.ReadFile(path)
	die(err)
	var findings []model.Finding
	die(json.Unmarshal(data, &findings))
	return findings
}

// generic writes findings (a JSON array of model.Finding) as a DefectDojo
// Generic Findings Import file.
func generic(path, to string) error {
	findings := readFindings(path)
	if to == "csv" {
		return interchange.WriteDojoGenericCSV(os.Stdout, findings)
	}
	return interchange.WriteDojoGenericJSON(os.Stdout, findings)
}

// fimport reads a findings file in any supported format and prints the
// report and the findings.
func fimport(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	findings, rep, err := interchange.ImportFindings(f, interchange.FindingsOptions{})
	fmt.Fprintf(os.Stderr, "format %s: %d findings, %d skipped\n", rep.Format, rep.Findings, rep.Skipped)
	for _, inv := range rep.Invalid {
		fmt.Fprintf(os.Stderr, "  invalid line %d: %s\n", inv.Line, inv.Reason)
	}
	for _, x := range findings {
		dojo := ""
		if x.DojoID != nil {
			dojo = fmt.Sprintf(" dojo=#%d", *x.DojoID)
		}
		fmt.Fprintf(os.Stderr, "  %-6s %-15s %s:%d manual=%v type=%s key=%s%s | %s\n", x.Severity, x.Status, x.IP, x.Port, x.Manual, x.Type, x.Key, dojo, clip(x.Title, 50))
	}
	if err != nil {
		return err
	}
	printJSON(findings)
	return nil
}

// derive imports a result file and prints the findings the analysis library derives from it.
func derive(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hosts, rep, err := interchange.Import(f, interchange.Options{})
	if err != nil {
		return err
	}
	findings := []model.Finding{}
	for i, h := range hosts {
		in := analyze.FindingInput{HostID: int64(i + 1), IP: h.IP, Hostnames: h.Hostnames, RunID: 1, At: h.ObservedAt}
		for _, s := range h.Services {
			score, _ := analyze.Interest(analyze.InterestInput{Service: s, Hostnames: h.Hostnames, Now: h.ObservedAt})
			in.Services = append(in.Services, analyze.FindingService{Result: s, Interest: score})
		}
		findings = append(findings, analyze.DeriveFindings(in)...)
	}
	fmt.Fprintf(os.Stderr, "imported %s: %d hosts, %d services, %d invalid rows -> %d findings\n", rep.Format, rep.Hosts, rep.Services, len(rep.Invalid), len(findings))
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// convert imports a result file and writes it in another format. It prints
// one line per service to stderr, so two files can be compared.
func convert(path, to string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hosts, rep, err := interchange.Import(f, interchange.Options{})
	if err != nil {
		return err
	}
	format := map[string]string{"xml": interchange.FormatNmapXML, "json": interchange.FormatJSON, "csv": interchange.FormatCSV}[to]
	if format == "" {
		return fmt.Errorf("unknown format %q (use xml, json or csv)", to)
	}
	fmt.Fprintf(os.Stderr, "imported %s: %d hosts, %d services, %d invalid rows\n", rep.Format, rep.Hosts, rep.Services, len(rep.Invalid))
	for _, h := range hosts {
		for _, s := range h.Services {
			fmt.Fprintf(os.Stderr, "  %s %d/%s %s %s product=%q version=%q\n", h.IP, s.Port, s.Proto, s.State, s.Name, s.Product, s.Version)
		}
	}
	return interchange.Export(os.Stdout, format, hosts, interchange.Meta{RunID: 1, Args: "czujka export"})
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dojoprobe test|derive|convert|push|nmap|list [flags]   (dojoprobe <command> -h shows the flags)")
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
