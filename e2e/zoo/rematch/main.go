// Command rematch reruns the signature engine on a stored Czujka export, so a
// signature change can be measured on old scans without scanning again. The
// HTTP data in the export (root page, favicon, the paths fetched then) stays as
// it was: a signature that needs a path the old scan did not fetch cannot fire.
//
//	go run ./e2e/zoo/rematch -in export.json -out rematched.json [-no-community]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
)

func main() {
	in := flag.String("in", "", "export (czujka-json)")
	out := flag.String("out", "", "rematched export")
	noCommunity := flag.Bool("no-community", false, "leave out the imported corpora (signatures/community)")
	flag.Parse()
	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: rematch -in export.json -out rematched.json")
		os.Exit(2)
	}
	if err := run(*in, *out, *noCommunity); err != nil {
		fmt.Fprintln(os.Stderr, "rematch:", err)
		os.Exit(1)
	}
}

func engine(noCommunity bool) (*sig.Engine, error) {
	all, err := sig.Builtin()
	if err != nil {
		return nil, err
	}
	var keep []model.Signature
	for _, s := range all {
		if noCommunity && strings.HasPrefix(s.Slug, "nuclei-") {
			continue
		}
		keep = append(keep, s)
	}
	e := sig.NewEngine()
	if rep := e.Load(keep); len(rep.Rejected) > 0 {
		return nil, fmt.Errorf("signature %s rejected", rep.Rejected[0].Slug)
	}
	return e, nil
}

func run(in, out string, noCommunity bool) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	var hosts []model.HostResult
	if err := json.Unmarshal(env["hosts"], &hosts); err != nil {
		return err
	}
	e, err := engine(noCommunity)
	if err != nil {
		return err
	}
	for hi := range hosts {
		h := &hosts[hi]
		for si := range h.Services {
			svc := &h.Services[si]
			m, t, c := e.MatchHost(svc, h.Hostnames...)
			svc.Matches, svc.Technologies, svc.Classes = m, t, c
		}
	}
	hb, err := json.Marshal(hosts)
	if err != nil {
		return err
	}
	env["hosts"] = hb
	ob, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, ob, 0o644)
}
