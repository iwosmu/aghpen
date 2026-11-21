// Package report renders the report of one scan run: what changed since the
// previous run, the top findings, the unstable hosts and the traffic the
// scanner sent. HTML and Markdown come from the same intermediate document,
// so both always say the same.
//
// The functions are pure: no database, no clock, no network. The caller
// (the API layer) fills Input from the store.
package report

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Limits caps the length of each list. Zero means the default.
type Limits struct {
	Changes  int // rows per change section (new, gone, changed); default 8
	Findings int // default 6
	Evidence int // evidence rows per finding; default 3
	Services int // default 5
	Hosts    int // unstable hosts; default 8
}

func (l Limits) withDefaults() Limits {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.Changes, 8)
	def(&l.Findings, 6)
	def(&l.Evidence, 3)
	def(&l.Services, 5)
	def(&l.Hosts, 8)
	return l
}

// Input is everything the report shows.
type Input struct {
	// Organization is shown next to the product name, for example "CBI AGH".
	Organization string
	// GeneratedAt is printed in the header. The zero value hides it.
	GeneratedAt time.Time
	// Location is the time zone of all printed times. Nil means UTC.
	Location *time.Location

	Run     model.ScanRun
	PrevRun *model.ScanRun     // the run the changes are compared with; nil on a first run
	Profile *model.ScanProfile // parameters of the run; nil for an imported run
	Policy  model.SafetyPolicy // the safety policy that was in force
	Scopes  []string           // names of the scanned scopes

	Summary model.RunDiffSummary
	Changes []model.Change // all changes of the run, in any order

	Findings []model.Finding // candidates for "top findings"; the report sorts and cuts
	Services []model.Service // candidates for "top services by interest"
	// Carried counts the services this run did not scan (their ports were
	// outside the run's coverage); they keep the state of an earlier run and
	// are not in Run.Stats.ServicesOpen.
	Carried int
	Hosts   []model.Host // unstable, expected-offline and inactive hosts

	Limits Limits
}

// ---------- intermediate document ----------

type kv struct{ K, V string }

type figure struct {
	Value, Label, Note string
}

type changeRow struct {
	Sev      string // info | low | medium | high
	SevLabel string
	Summary  string
}

type changeSection struct {
	Title string
	Count int
	Rows  []changeRow
	More  string
	Empty string
}

type evidenceRow struct{ Where, Snippet string }

type findingRow struct {
	Sev, SevLabel string
	Title         string
	Addr          string
	Interest      int
	Notes         []string // "nowa w tym przebiegu", status
	Evidence      []evidenceRow
	EvidenceMore  int
}

type serviceRow struct {
	Addr     string
	What     string
	Interest int
	Why      []string
}

type hostRow struct {
	IP, Name, Status, Pattern string
	PAlive, Stability         string
	Misses                    int
}

type doc struct {
	Title     string
	Brand     string
	Generated string
	Meta      []kv
	Notice    string // set when the run did not finish
	Lead      string
	Figures   []figure

	Sections []changeSection // new, gone, changed
	Expected string          // one line for all expected changes

	Findings     []findingRow
	FindingsMore string
	Services     []serviceRow
	Hosts        []hostRow
	HostsMore    string

	Params  []kv
	Traffic []kv
	Safety  string
	Footer  string
}

// ---------- Polish text helpers ----------

// plural picks the Polish noun form for n: 1 host, 2 hosty, 5 hostów.
func plural(n int, one, few, many string) string {
	if n < 0 {
		n = -n
	}
	if n == 1 {
		return one
	}
	if d, h := n%10, n%100; d >= 2 && d <= 4 && !(h >= 12 && h <= 14) {
		return few
	}
	return many
}

func nHosts(n int) string { return num(int64(n)) + " " + plural(n, "host", "hosty", "hostów") }
func nServices(n int) string {
	return num(int64(n)) + " " + plural(n, "usługa", "usługi", "usług")
}
func nChanges(n int) string {
	return num(int64(n)) + " " + plural(n, "zmiana", "zmiany", "zmian")
}

// num formats an integer with a no-break space between thousands.
func num(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteRune(' ')
		}
		b.WriteRune(r)
	}
	if neg {
		return "−" + b.String()
	}
	return b.String()
}

func dur(sec int64) string {
	if sec <= 0 {
		return "0 s"
	}
	h, m, s := sec/3600, sec%3600/60, sec%60
	switch {
	case h > 0:
		return fmt.Sprintf("%d h %d min", h, m)
	case m > 0 && s > 0:
		return fmt.Sprintf("%d min %d s", m, s)
	case m > 0:
		return fmt.Sprintf("%d min", m)
	}
	return fmt.Sprintf("%d s", s)
}

var sevLabels = map[model.Severity]string{
	model.SevInfo: "informacja", model.SevLow: "niska", model.SevMedium: "średnia", model.SevHigh: "wysoka",
}

func sevRank(s model.Severity) int {
	switch s {
	case model.SevHigh:
		return 3
	case model.SevMedium:
		return 2
	case model.SevLow:
		return 1
	}
	return 0
}

func sevClass(s model.Severity) string {
	if _, ok := sevLabels[s]; ok {
		return string(s)
	}
	return string(model.SevInfo)
}

func sevLabel(s model.Severity) string {
	if l, ok := sevLabels[s]; ok {
		return l
	}
	return sevLabels[model.SevInfo]
}

var runStatusPL = map[model.RunStatus]string{
	model.RunQueued: "w kolejce", model.RunRunning: "w toku", model.RunPaused: "wstrzymany",
	model.RunAnalyzing: "analiza wyników", model.RunCompleted: "zakończony", model.RunFailed: "nieudany",
	model.RunCancelled: "anulowany",
}

var pausePL = map[string]string{
	model.PauseWindowClosed: "okno czasowe się zamknęło", model.PauseManual: "wstrzymany ręcznie",
	model.PauseEmergency: "zatrzymanie awaryjne",
}

var triggerPL = map[string]string{"manual": "ręcznie", "schedule": "z harmonogramu", "import": "import pliku"}

var hostStatusPL = map[model.HostStatus]string{
	model.HostUp: "aktywny", model.HostUnstable: "niestabilny", model.HostDown: "nieaktywny",
	model.HostExpectedOffline: "przerwa zgodna z rytmem", model.HostUnknown: "nieznany",
}

var findingStatusPL = map[model.FindingStatus]string{
	model.FindingTriaged: "potwierdzona", model.FindingAccepted: "zaakceptowana",
}

var kindPL = map[model.ChangeKind]string{
	model.ChangeHostNew: "Nowy host", model.ChangeHostGone: "Host nieaktywny", model.ChangeHostBack: "Host znów odpowiada",
	model.ChangeHostUnstable: "Host niestabilny", model.ChangeHostMissing: "Nie odpowiada (niepotwierdzone)", model.ChangeServiceUnreachable: "Usługa nie odpowiada (niepotwierdzone)", model.ChangeServiceNew: "Nowa usługa", model.ChangeServiceGone: "Usługa zniknęła",
	model.ChangeServiceChanged: "Zmiana usługi", model.ChangeTechNew: "Nowa technologia", model.ChangeTechGone: "Technologia zniknęła",
	model.ChangeTechVersion: "Zmiana wersji", model.ChangeTitle: "Zmiana tytułu", model.ChangeHTTPStatus: "Zmiana statusu HTTP",
	model.ChangeCert: "Zmiana certyfikatu", model.ChangeHeaders: "Zmiana nagłówków", model.ChangeCookies: "Zmiana ciasteczek",
	model.ChangeContent: "Zmiana treści", model.ChangeRedirect: "Zmiana przekierowania", model.ChangeClass: "Zmiana klasy usługi",
	model.ChangeServiceReturned: "Usługa wróciła", model.ChangeResponseSlower: "Wolniejsza odpowiedź", model.ChangeResponseRecovered: "Odpowiedź w normie",
}

var dayPL = [7]string{"nd", "pn", "wt", "śr", "cz", "pt", "sb"}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}

func lowerFirst(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToLower(string(r[:1])) + string(r[1:])
}

func hostPort(ip string, port int) string {
	if port <= 0 {
		return ip
	}
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}

func ipLess(a, b string) bool {
	x, ex := netip.ParseAddr(a)
	y, ey := netip.ParseAddr(b)
	if ex == nil && ey == nil {
		return x.Less(y)
	}
	return a < b
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " i " + parts[len(parts)-1]
}

// ---------- building the document ----------

func (in *Input) loc() *time.Location {
	if in.Location != nil {
		return in.Location
	}
	return time.UTC
}

func (in *Input) stamp(t time.Time) string { return t.In(in.loc()).Format("02.01.2006 15:04") }

func changeGroup(k model.ChangeKind) int {
	switch k {
	case model.ChangeHostNew, model.ChangeHostBack, model.ChangeServiceNew, model.ChangeServiceReturned:
		return 0
	case model.ChangeHostGone, model.ChangeServiceGone, model.ChangeHostMissing, model.ChangeServiceUnreachable:
		return 1
	}
	return 2
}

func build(in Input) doc {
	lim := in.Limits.withDefaults()
	run := in.Run
	var d doc
	d.Title = "Raport z przebiegu #" + strconv.FormatInt(run.ID, 10)
	d.Brand = "Czujka"
	if in.Organization != "" {
		d.Brand += " · " + in.Organization
	}
	if !in.GeneratedAt.IsZero() {
		d.Generated = "wygenerowano " + in.stamp(in.GeneratedAt)
	}

	// --- meta line
	profile := run.ProfileName
	if profile == "" && in.Profile != nil {
		profile = in.Profile.Name
	}
	if profile == "" {
		profile = "—"
	}
	if t, ok := triggerPL[run.Trigger]; ok {
		profile += " (" + t + ")"
	}
	d.Meta = append(d.Meta, kv{"Profil", profile})
	scope := strings.Join(in.Scopes, ", ")
	if run.Stats.AddressesTotal > 0 {
		addrs := num(run.Stats.AddressesTotal) + " " + plural(int(run.Stats.AddressesTotal), "adres", "adresy", "adresów")
		if scope != "" {
			scope += " · " + addrs
		} else {
			scope = addrs
		}
	}
	if scope != "" {
		d.Meta = append(d.Meta, kv{"Zakres", scope})
	}
	when := "—"
	if run.StartedAt != nil {
		when = in.stamp(*run.StartedAt)
		if run.FinishedAt != nil {
			end := run.FinishedAt.In(in.loc())
			if end.Format("02.01.2006") == run.StartedAt.In(in.loc()).Format("02.01.2006") {
				when += "–" + end.Format("15:04")
			} else {
				when += " – " + in.stamp(*run.FinishedAt)
			}
		}
	}
	d.Meta = append(d.Meta, kv{"Czas", when})
	first := in.PrevRun == nil && in.Summary.PrevRunID == nil
	switch {
	case in.PrevRun != nil:
		cmp := "przebieg #" + strconv.FormatInt(in.PrevRun.ID, 10)
		if in.PrevRun.StartedAt != nil {
			cmp += " z " + in.stamp(*in.PrevRun.StartedAt)
		}
		d.Meta = append(d.Meta, kv{"Porównanie z", cmp})
	case in.Summary.PrevRunID != nil:
		d.Meta = append(d.Meta, kv{"Porównanie z", "przebieg #" + strconv.FormatInt(*in.Summary.PrevRunID, 10)})
	default:
		d.Meta = append(d.Meta, kv{"Porównanie z", "brak (pierwszy przebieg)"})
	}

	if run.Status != "" && run.Status != model.RunCompleted {
		st := runStatusPL[run.Status]
		if st == "" {
			st = string(run.Status)
		}
		d.Notice = "Przebieg nie jest zakończony (stan: " + st
		if p := pausePL[run.PauseReason]; p != "" {
			d.Notice += ", " + p
		}
		d.Notice += ")."
		if run.Stats.AddressesTotal > 0 {
			d.Notice += fmt.Sprintf(" Sprawdzono %s z %s adresów, więc lista zmian jest niepełna.", num(run.Stats.AddressesDone), num(run.Stats.AddressesTotal))
		}
		if run.Error != "" {
			d.Notice += " Błąd: " + oneLine(run.Error, 200)
		}
	}

	// --- changes: split, sort, cut
	var groups [3][]model.Change
	var expected []model.Change
	attention := 0
	for _, c := range in.Changes {
		if c.Expected {
			expected = append(expected, c)
			continue
		}
		groups[changeGroup(c.Kind)] = append(groups[changeGroup(c.Kind)], c)
		if sevRank(c.Severity) >= 2 {
			attention++
		}
	}
	unexpected := len(groups[0]) + len(groups[1]) + len(groups[2])
	titles := [3]string{"Co nowego", "Co zniknęło", "Co się zmieniło"}
	empties := [3]string{"Nic nowego.", "Nic nie zniknęło.", "Bez zmian w znanych usługach."}
	for g := range groups {
		cs := groups[g]
		sort.SliceStable(cs, func(i, j int) bool {
			if a, b := sevRank(cs[i].Severity), sevRank(cs[j].Severity); a != b {
				return a > b
			}
			if cs[i].IP != cs[j].IP {
				return ipLess(cs[i].IP, cs[j].IP)
			}
			if cs[i].Port != cs[j].Port {
				return cs[i].Port < cs[j].Port
			}
			return cs[i].Kind < cs[j].Kind
		})
		sec := changeSection{Title: titles[g], Count: len(cs)}
		if len(cs) == 0 && !first {
			sec.Empty = empties[g]
		}
		for i, c := range cs {
			if i == lim.Changes {
				rest := len(cs) - i
				sec.More = "i jeszcze " + nChanges(rest) + " o tej samej lub niższej wadze; pełna lista jest w aplikacji."
				break
			}
			sum := oneLine(c.Summary, 240)
			if sum == "" {
				sum = kindPL[c.Kind]
				if sum == "" {
					sum = string(c.Kind)
				}
				sum += " " + hostPort(c.IP, c.Port)
			}
			sec.Rows = append(sec.Rows, changeRow{Sev: sevClass(c.Severity), SevLabel: sevLabel(c.Severity), Summary: sum})
		}
		d.Sections = append(d.Sections, sec)
	}

	nExpected := len(expected)
	if n := in.Summary.ByKind["expected"]; n > nExpected {
		nExpected = n
	}
	if nExpected > 0 {
		seen := map[string]bool{}
		var ips []string
		for _, c := range expected {
			if c.IP != "" && !seen[c.IP] {
				seen[c.IP] = true
				ips = append(ips, c.IP)
			}
		}
		sort.Slice(ips, func(i, j int) bool { return ipLess(ips[i], ips[j]) })
		d.Expected = nChanges(nExpected) + " " + plural(nExpected, "oczekiwana", "oczekiwane", "oczekiwanych") +
			": hosty, które o tej porze zwykle nie odpowiadają albo odpowiadają nieregularnie"
		if len(ips) > 0 {
			show := ips
			if len(show) > 4 {
				show = show[:4]
			}
			d.Expected += " (" + strings.Join(show, ", ")
			if rest := len(ips) - len(show); rest > 0 {
				d.Expected += " i " + num(int64(rest)) + " " + plural(rest, "inny", "inne", "innych")
			}
			d.Expected += ")"
		}
		d.Expected += ". Model dostępności je wyjaśnia, więc nie są liczone powyżej."
	}

	// --- lead sentence
	s := in.Summary
	switch {
	case first:
		d.Lead = "To pierwszy przebieg tego profilu. Nie ma jeszcze punktu odniesienia, więc raport pokazuje stan sieci, a nie zmiany."
	case unexpected == 0 && s.HostsNew+s.HostsGone+s.HostsBack+s.HostsMissing+s.ServicesNew+s.ServicesGone+s.ServicesChanged == 0:
		d.Lead = "Od poprzedniego przebiegu nie ma zmian, które wymagają uwagi."
	default:
		var parts []string
		var add []string
		if s.HostsNew > 0 {
			add = append(add, nHosts(s.HostsNew))
		}
		if s.ServicesNew > 0 {
			add = append(add, nServices(s.ServicesNew))
		}
		if len(add) > 0 {
			parts = append(parts, "Przybyło: "+joinAnd(add)+".")
		}
		var gone []string
		if s.HostsGone > 0 {
			gone = append(gone, nHosts(s.HostsGone))
		}
		if s.ServicesGone > 0 {
			gone = append(gone, nServices(s.ServicesGone))
		}
		if len(gone) > 0 {
			parts = append(parts, "Ubyło: "+joinAnd(gone)+".")
		}
		if s.HostsMissing > 0 {
			miss := "Nie odpowiada (niepotwierdzone): " + nHosts(s.HostsMissing)
			if s.ServicesUnreachable > 0 {
				miss += ", z nimi " + nServices(s.ServicesUnreachable)
			}
			parts = append(parts, miss+". Ponowne sondowanie potwierdzi, czy wróciły, czy zniknęły.")
		}
		if s.HostsBack > 0 {
			parts = append(parts, "Powroty po nieaktywności: "+nHosts(s.HostsBack)+".")
		}
		if n := len(groups[2]); n > 0 {
			parts = append(parts, "Zmiany w znanych hostach i usługach: "+num(int64(n))+".")
		}
		if len(parts) == 0 {
			parts = append(parts, "Od poprzedniego przebiegu: "+nChanges(unexpected)+".")
		}
		if attention > 0 {
			parts = append(parts, "Najpierw sprawdź "+num(int64(attention))+" "+plural(attention, "zmianę", "zmiany", "zmian")+" o wadze średniej lub wysokiej.")
		}
		d.Lead = strings.Join(parts, " ")
	}

	// --- findings
	var fs []model.Finding
	newFindings := 0
	for _, f := range in.Findings {
		if f.Status == model.FindingResolved || f.Status == model.FindingFalsePositive {
			continue
		}
		if f.FirstRunID == run.ID && run.ID != 0 {
			newFindings++
		}
		fs = append(fs, f)
	}
	if s.FindingsNew > newFindings {
		newFindings = s.FindingsNew
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Interest != fs[j].Interest {
			return fs[i].Interest > fs[j].Interest
		}
		if a, b := sevRank(fs[i].Severity), sevRank(fs[j].Severity); a != b {
			return a > b
		}
		return fs[i].Key < fs[j].Key
	})
	// One block per service: several findings of one service share most of
	// their evidence, and the reader wants the service once.
	type target struct {
		ip   string
		port int
	}
	byTarget := map[target][]model.Finding{}
	var targets []target
	for _, f := range fs {
		k := target{f.IP, f.Port}
		if _, ok := byTarget[k]; !ok {
			targets = append(targets, k)
		}
		byTarget[k] = append(byTarget[k], f)
	}
	shown := 0
	for i, k := range targets {
		if i == lim.Findings {
			rest := len(fs) - shown
			d.FindingsMore = "i jeszcze " + num(int64(rest)) + " " + plural(rest, "obserwacja", "obserwacje", "obserwacji") + " o niższym priorytecie; pełna lista jest w aplikacji."
			break
		}
		group := byTarget[k]
		shown += len(group)
		f := group[0]
		row := findingRow{Sev: sevClass(f.Severity), SevLabel: sevLabel(f.Severity), Title: oneLine(f.Title, 160), Interest: f.Interest}
		row.Addr = f.URL
		if row.Addr == "" {
			row.Addr = hostPort(f.IP, f.Port)
		}
		isNew := false
		for _, g := range group {
			isNew = isNew || (g.FirstRunID == run.ID && run.ID != 0)
		}
		if isNew && !first {
			row.Notes = append(row.Notes, "nowa w tym przebiegu")
		}
		if st := findingStatusPL[f.Status]; st != "" {
			row.Notes = append(row.Notes, st)
		}
		// The other findings of the same service, by their short name.
		var also []string
		seenAlso := map[string]bool{}
		for _, g := range group[1:] {
			name, _, _ := strings.Cut(g.Title, ":")
			name = lowerFirst(oneLine(name, 60))
			if name != "" && !seenAlso[name] {
				seenAlso[name] = true
				also = append(also, name)
			}
		}
		if len(also) > 0 {
			row.Notes = append(row.Notes, "także: "+strings.Join(also, ", "))
		}
		seenEv := map[evidenceRow]bool{}
		more := 0
		for _, g := range group {
			for _, e := range g.Evidence {
				where := e.Where
				if where == "" {
					where = e.Matcher
				}
				if g.URL != "" && where == "url:"+g.URL {
					continue // the address line already shows it
				}
				er := evidenceRow{Where: oneLine(where, 60), Snippet: oneLine(e.Snippet, 140)}
				if seenEv[er] {
					continue
				}
				seenEv[er] = true
				if len(row.Evidence) == lim.Evidence {
					more++
					continue
				}
				row.Evidence = append(row.Evidence, er)
			}
		}
		row.EvidenceMore = more
		d.Findings = append(d.Findings, row)
	}

	// --- services
	svcs := append([]model.Service(nil), in.Services...)
	sort.SliceStable(svcs, func(i, j int) bool {
		if svcs[i].Interest != svcs[j].Interest {
			return svcs[i].Interest > svcs[j].Interest
		}
		if svcs[i].IP != svcs[j].IP {
			return ipLess(svcs[i].IP, svcs[j].IP)
		}
		return svcs[i].Port < svcs[j].Port
	})
	for i, sv := range svcs {
		if i == lim.Services || sv.Interest <= 0 {
			break
		}
		row := serviceRow{Addr: hostPort(sv.IP, sv.Port), Interest: sv.Interest}
		what := strings.TrimSpace(sv.Product + " " + sv.Version)
		if what == "" {
			what = sv.Name
		}
		if sv.Title != "" {
			if what != "" {
				what += " · "
			}
			what += "„" + oneLine(sv.Title, 60) + "”"
		}
		if sv.Hostname != "" {
			what = sv.Hostname + " · " + what
		}
		row.What = oneLine(what, 140)
		if sv.Carried {
			row.What += " · nie skanowana w tym przebiegu (stan z wcześniejszego)"
		}
		for j, w := range sv.InterestWhy {
			if j == 2 {
				if rest := len(sv.InterestWhy) - j; rest > 0 {
					row.Why = append(row.Why, "i "+strconv.Itoa(rest)+" "+plural(rest, "inny powód", "inne powody", "innych powodów"))
				}
				break
			}
			row.Why = append(row.Why, fmt.Sprintf("%s (+%d)", oneLine(w.Text, 80), w.Points))
		}
		d.Services = append(d.Services, row)
	}

	// --- hosts
	hosts := append([]model.Host(nil), in.Hosts...)
	order := map[model.HostStatus]int{model.HostDown: 0, model.HostUnstable: 1, model.HostExpectedOffline: 2}
	sort.SliceStable(hosts, func(i, j int) bool {
		a, ok := order[hosts[i].Status]
		if !ok {
			a = 3
		}
		b, ok := order[hosts[j].Status]
		if !ok {
			b = 3
		}
		if a != b {
			return a < b
		}
		return ipLess(hosts[i].IP, hosts[j].IP)
	})
	// Hosts that are off on schedule with the same rhythm make one row.
	var rows []hostRow
	same := map[hostRow]int{} // row without IP and name -> index in rows
	others := map[int]int{}
	for _, h := range hosts {
		row := hostRow{Misses: h.ConsecutiveMisses, Pattern: h.Pattern}
		row.Status = hostStatusPL[h.Status]
		if row.Status == "" {
			row.Status = string(h.Status)
		}
		if row.Pattern == "" {
			row.Pattern = "za mało danych"
		}
		row.PAlive = strconv.Itoa(int(h.PAlive*100+0.5)) + "%"
		row.Stability = strconv.Itoa(int(h.Stability*100+0.5)) + "%"
		if h.Status == model.HostExpectedOffline {
			if i, ok := same[row]; ok {
				others[i]++
				continue
			}
			same[row] = len(rows)
		}
		row.IP = h.IP
		row.Name = h.Label
		if row.Name == "" && len(h.Hostnames) > 0 {
			row.Name = h.Hostnames[0]
		}
		rows = append(rows, row)
	}
	for i, row := range rows {
		if i == lim.Hosts {
			rest := 0
			for j := i; j < len(rows); j++ {
				rest += 1 + others[j]
			}
			d.HostsMore = "i jeszcze " + nHosts(rest) + "."
			break
		}
		if n := others[i]; n > 0 {
			row.Name = "oraz " + nHosts(n) + " o tym samym rytmie"
		}
		d.Hosts = append(d.Hosts, row)
	}

	// --- headline figures
	st := run.Stats
	fig := func(v int64, label, note string) { d.Figures = append(d.Figures, figure{num(v), label, note}) }
	note := ""
	if attention > 0 {
		note = "w tym " + num(int64(attention)) + " o wadze średniej lub wysokiej"
	}
	if first {
		note = "pierwszy przebieg"
	}
	fig(int64(unexpected), "zmiany do przejrzenia", note)
	fig(int64(newFindings), plural(newFindings, "nowa obserwacja", "nowe obserwacje", "nowych obserwacji"), "")
	delta := func(plus, minus int) string {
		if first || plus+minus == 0 {
			return ""
		}
		return "+" + num(int64(plus)) + " / −" + num(int64(minus))
	}
	fig(int64(st.HostsUp), plural(st.HostsUp, "aktywny host", "aktywne hosty", "aktywnych hostów"), delta(s.HostsNew+s.HostsBack, s.HostsGone))
	// Run.Stats.ServicesOpen counts the open services this run saw; services
	// it did not scan (carried) are named in the note, not counted.
	svcNote := delta(s.ServicesNew, s.ServicesGone)
	if in.Carried > 0 {
		c := "bez " + num(int64(in.Carried)) + " " + plural(in.Carried, "usługi nieskanowanej", "usług nieskanowanych", "usług nieskanowanych") + " w tym przebiegu (stan zachowany)"
		if svcNote != "" {
			svcNote += "; " + c
		} else {
			svcNote = c
		}
	}
	fig(int64(st.ServicesOpen), plural(st.ServicesOpen, "otwarta usługa", "otwarte usługi", "otwartych usług"), svcNote)
	fig(int64(st.HTTPServices), plural(st.HTTPServices, "usługa WWW", "usługi WWW", "usług WWW"), "")
	exNote := ""
	if nExpected > 0 {
		exNote = "nie wymagają reakcji"
	}
	fig(int64(nExpected), plural(nExpected, "zmiana oczekiwana", "zmiany oczekiwane", "zmian oczekiwanych"), exNote)

	// --- parameters and traffic
	pol := in.Policy
	if p := in.Profile; p != nil {
		if p.Ports != "" {
			d.Params = append(d.Params, kv{"Porty", p.Ports})
		}
		d.Params = append(d.Params, kv{"Wykrywanie hostów", discoveryText(p.Discovery)})
		sd := "nie"
		if p.ServiceDetection {
			sd = "tak, intensywność " + strconv.Itoa(p.VersionIntensity) + " z 9"
		}
		d.Params = append(d.Params, kv{"Rozpoznawanie usług", sd})
		ht := "nie"
		if p.HTTP.Enabled {
			ht = "tak"
			if p.HTTP.SignaturePaths {
				ht += "; dodatkowe ścieżki sygnatur"
				if pol.MaxPathsPerHost > 0 {
					ht += " (najwyżej " + strconv.Itoa(pol.MaxPathsPerHost) + " na usługę)"
				}
			}
			if p.HTTP.MaxRedirects > 0 {
				ht += "; do " + strconv.Itoa(p.HTTP.MaxRedirects) + " " + plural(p.HTTP.MaxRedirects, "przekierowania", "przekierowań", "przekierowań")
			}
		}
		d.Params = append(d.Params, kv{"Zbieranie HTTP i TLS", ht})
		var lims []string
		if p.Rate.MaxPPS > 0 {
			lims = append(lims, "do "+num(int64(p.Rate.MaxPPS))+" pakietów/s")
		}
		if p.Rate.HTTPRPS > 0 {
			lims = append(lims, "do "+ffloat(p.Rate.HTTPRPS)+" żądań HTTP/s")
		}
		if p.Rate.PerHostConcurrency > 0 {
			lims = append(lims, strconv.Itoa(p.Rate.PerHostConcurrency)+" "+plural(p.Rate.PerHostConcurrency, "połączenie", "połączenia", "połączeń")+" naraz na host")
		}
		if len(lims) > 0 {
			d.Params = append(d.Params, kv{"Limity profilu", strings.Join(lims, ", ")})
		}
		if w := windowsText(p.Schedule.Windows); w != "" {
			d.Params = append(d.Params, kv{"Okno skanowania", w})
		}
	}
	var pl []string
	if pol.MaxPPS > 0 {
		pl = append(pl, "do "+num(int64(pol.MaxPPS))+" pakietów/s")
	}
	if pol.MaxHTTPRPS > 0 {
		pl = append(pl, "do "+ffloat(pol.MaxHTTPRPS)+" żądań HTTP/s")
	}
	if pol.MaxPerHostRPS > 0 {
		pl = append(pl, "do "+ffloat(pol.MaxPerHostRPS)+"/s na jeden host")
	}
	if len(pl) > 0 {
		d.Params = append(d.Params, kv{"Polityka bezpieczeństwa", strings.Join(pl, ", ")})
	}
	methods := strings.Join(pol.AllowedMethods, ", ")
	if methods != "" {
		d.Params = append(d.Params, kv{"Metody HTTP", methods})
	}
	if pol.DeniedPorts != "" {
		d.Params = append(d.Params, kv{"Porty zabronione", pol.DeniedPorts})
	}
	if n := len(pol.Exclusions); n > 0 {
		show := pol.Exclusions
		if n > 3 {
			show = show[:3]
		}
		ex := strings.Join(show, ", ")
		if n > 3 {
			ex += " i " + strconv.Itoa(n-3) + " " + plural(n-3, "inne", "inne", "innych")
		}
		d.Params = append(d.Params, kv{"Wykluczenia", ex})
	}
	if pol.UserAgent != "" {
		d.Params = append(d.Params, kv{"User-Agent", pol.UserAgent})
	}

	if st.AddressesTotal > 0 {
		d.Traffic = append(d.Traffic, kv{"Sprawdzone adresy", num(st.AddressesDone) + " z " + num(st.AddressesTotal)})
	}
	d.Traffic = append(d.Traffic, kv{"Wysłane pakiety (szacunek)", num(st.PacketsSent)})
	d.Traffic = append(d.Traffic, kv{"Żądania HTTP", num(st.HTTPRequests)})
	if st.AvgPPS > 0 {
		pps := ffloat(st.AvgPPS) + " pakietów/s"
		limit := pol.MaxPPS
		if in.Profile != nil && in.Profile.Rate.MaxPPS > 0 && (limit == 0 || in.Profile.Rate.MaxPPS < limit) {
			limit = in.Profile.Rate.MaxPPS
		}
		if limit > 0 {
			pps += fmt.Sprintf(" (%d%% limitu %s)", int(st.AvgPPS/float64(limit)*100+0.5), num(int64(limit)))
		}
		d.Traffic = append(d.Traffic, kv{"Średnie tempo", pps})
	}
	d.Traffic = append(d.Traffic, kv{"Czas aktywnego skanowania", dur(st.ElapsedSec)})
	if st.ChunksTotal > 0 {
		d.Traffic = append(d.Traffic, kv{"Fragmenty zakresu", strconv.Itoa(st.ChunksDone) + " z " + strconv.Itoa(st.ChunksTotal)})
	}
	d.Traffic = append(d.Traffic, kv{"Hosty sondowane ponownie", num(int64(st.Retried))})
	d.Traffic = append(d.Traffic, kv{"Błędy", num(int64(st.Errors))})

	if run.Trigger == "import" {
		d.Safety = "Ten przebieg pochodzi z importu pliku. Czujka nie wysłała w nim żadnych pakietów."
	} else {
		d.Safety = "Czujka wykrywa obecność usług i ich cech. Nie loguje się, nie wysyła payloadów i nie zgaduje haseł."
		if methods != "" {
			d.Safety += " Polityka w chwili skanu dopuszczała tylko metody HTTP: " + methods + "."
		}
	}
	d.Footer = "Obserwacje w raporcie są informacyjne: opisują to, co widać z sieci, a nie potwierdzone podatności."
	return d
}

func ffloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return strings.Replace(s, ".", ",", 1)
}

func discoveryText(o model.DiscoveryOpts) string {
	if o.SkipDiscovery {
		return "pominięte: każdy adres traktowany jak aktywny"
	}
	var p []string
	if o.ICMPEcho {
		p = append(p, "ICMP echo")
	}
	if o.ICMPTimestamp {
		p = append(p, "ICMP timestamp")
	}
	if len(o.TCPSynPorts) > 0 {
		p = append(p, "TCP SYN na porty "+ports(o.TCPSynPorts))
	}
	if len(o.TCPAckPorts) > 0 {
		p = append(p, "TCP ACK na porty "+ports(o.TCPAckPorts))
	}
	if o.ARP {
		p = append(p, "ARP w sieci lokalnej")
	}
	if len(p) == 0 {
		return "domyślne"
	}
	return strings.Join(p, ", ")
}

func ports(p []int) string {
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ", ")
}

func windowsText(ws []model.Window) string {
	var out []string
	for _, w := range ws {
		var days []string
		for _, d := range w.Days {
			if d >= 0 && d < 7 {
				days = append(days, dayPL[d])
			}
		}
		t := w.Start + "–" + w.End
		if len(days) > 0 && len(days) < 7 {
			t = strings.Join(days, ", ") + " " + t
		} else {
			t = "codziennie " + t
		}
		out = append(out, t)
	}
	return strings.Join(out, "; ")
}

// HTML renders the report as one self-contained HTML document: inline CSS,
// no scripts, no external assets. All text from the network (titles, banners,
// evidence) is escaped by html/template.
func HTML(in Input) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, in); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteHTML writes the HTML report to w.
func WriteHTML(w io.Writer, in Input) error {
	return htmlTemplate.Execute(w, build(in))
}
