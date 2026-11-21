package report

import (
	"fmt"
	"strings"
)

var mdReplacer = strings.NewReplacer(
	"\\", "\\\\", "|", "\\|", "*", "\\*", "_", "\\_", "`", "'", "<", "&lt;", ">", "&gt;",
	"[", "\\[", "]", "\\]", "\n", " ", "\r", " ",
)

// md escapes text from the network so that it cannot add Markdown or HTML
// structure to the report.
func md(s string) string { return mdReplacer.Replace(s) }

// mdCode wraps text in a code span. Text with angle brackets is escaped as
// plain text instead: a code span would show the entities literally.
func mdCode(s string) string {
	if strings.ContainsAny(s, "<>") {
		return md(s)
	}
	s = strings.NewReplacer("`", "'", "|", "\\|", "\n", " ", "\r", " ").Replace(s)
	if s == "" {
		return ""
	}
	return "`" + s + "`"
}

// Markdown renders the same report as Markdown.
func Markdown(in Input) string {
	d := build(in)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# %s\n\n", md(d.Title))
	head := md(d.Brand)
	if d.Generated != "" {
		head += " · " + md(d.Generated)
	}
	w("%s\n\n", head)
	kvTable := func(rows []kv, k, v string) {
		w("| %s | %s |\n| --- | --- |\n", k, v)
		for _, r := range rows {
			w("| %s | %s |\n", md(r.K), md(r.V))
		}
		w("\n")
	}
	kvTable(d.Meta, "Przebieg", "")
	if d.Notice != "" {
		w("> **%s**\n\n", md(d.Notice))
	}
	w("**%s**\n\n", md(d.Lead))

	w("|")
	for _, f := range d.Figures {
		w(" %s |", md(f.Label))
	}
	w("\n|")
	for range d.Figures {
		w(" ---: |")
	}
	w("\n|")
	for _, f := range d.Figures {
		v := "**" + md(f.Value) + "**"
		if f.Note != "" {
			v += " (" + md(f.Note) + ")"
		}
		w(" %s |", v)
	}
	w("\n\n")

	for _, s := range d.Sections {
		if len(s.Rows) == 0 && s.Empty == "" {
			continue
		}
		if s.Count > 0 {
			w("## %s (%d)\n\n", s.Title, s.Count)
		} else {
			w("## %s\n\n", s.Title)
		}
		if len(s.Rows) == 0 {
			w("%s\n\n", s.Empty)
			continue
		}
		for _, r := range s.Rows {
			w("- **%s** — %s\n", r.SevLabel, md(r.Summary))
		}
		if s.More != "" {
			w("- _%s_\n", md(s.More))
		}
		w("\n")
	}
	if d.Expected != "" {
		w("_%s_\n\n", md(d.Expected))
	}

	if len(d.Findings) > 0 {
		w("## Najważniejsze obserwacje\n\n")
		for _, f := range d.Findings {
			w("### %s\n\n", md(f.Title))
			line := "waga: **" + f.SevLabel + "** · ciekawość **" + fmt.Sprint(f.Interest) + "**/100 · " + mdCode(f.Addr)
			for _, n := range f.Notes {
				line += " · " + md(n)
			}
			w("%s\n\n", line)
			for _, e := range f.Evidence {
				w("- %s: %s\n", mdCode(e.Where), md(e.Snippet))
			}
			if f.EvidenceMore > 0 {
				w("- i %d więcej w aplikacji\n", f.EvidenceMore)
			}
			if len(f.Evidence) > 0 {
				w("\n")
			}
		}
		if d.FindingsMore != "" {
			w("_%s_\n\n", md(d.FindingsMore))
		}
	}

	if len(d.Services) > 0 {
		w("## Najciekawsze usługi\n\n| Adres | Usługa | Dlaczego | Ciekawość |\n| --- | --- | --- | ---: |\n")
		for _, s := range d.Services {
			why := make([]string, len(s.Why))
			for i, x := range s.Why {
				why[i] = md(x)
			}
			w("| %s | %s | %s | %d |\n", mdCode(s.Addr), md(s.What), strings.Join(why, "; "), s.Interest)
		}
		w("\n")
	}

	if len(d.Hosts) > 0 {
		w("## Hosty niestabilne i nieaktywne\n\n| Host | Stan | Zwykły rytm | Szansa, że nadal istnieje | Odpowiada w | Braki z rzędu |\n| --- | --- | --- | ---: | ---: | ---: |\n")
		for _, h := range d.Hosts {
			host := mdCode(h.IP)
			if h.Name != "" {
				host += " " + md(h.Name)
			}
			w("| %s | %s | %s | %s | %s skanów | %d |\n", host, md(h.Status), md(h.Pattern), h.PAlive, h.Stability, h.Misses)
		}
		if d.HostsMore != "" {
			w("\n_%s_\n", md(d.HostsMore))
		}
		w("\n")
	}

	w("## Parametry skanu\n\n")
	kvTable(d.Params, "Parametr", "Wartość")
	w("## Ruch faktycznie wysłany\n\n")
	kvTable(d.Traffic, "Miara", "Wartość")
	w("%s\n\n", md(d.Safety))
	w("_%s_\n", md(d.Footer))
	return b.String()
}
