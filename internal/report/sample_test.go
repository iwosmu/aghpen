package report

import (
	"math/rand"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/model"
)

// The sample input is a small campus network. Its numbers are not typed in:
// the changes come from analyze.Diff over two snapshots, the host states from
// analyze.Assess over four weeks of observations, the findings from
// analyze.DeriveFindings and the scores from analyze.Interest. So the sample
// report shows the text and the numbers the product really produces.

func mustLoc(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

var warsaw = mustLoc("Europe/Warsaw")

var (
	sampleStart = time.Date(2026, 10, 26, 2, 0, 0, 0, warsaw)  // Monday, first scan of the history
	samplePrev  = time.Date(2026, 11, 20, 14, 0, 0, 0, warsaw) // Friday afternoon
	sampleCur   = time.Date(2026, 11, 21, 2, 0, 0, 0, warsaw)  // Saturday night
)

func svc(port int, name, product, version string) model.ServiceResult {
	return model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: name, Product: product, Version: version, Confidence: 1}
}

func web(s model.ServiceResult, scheme, host, title string, status int, headers map[string][]string) model.ServiceResult {
	if headers == nil {
		headers = map[string][]string{}
	}
	server := ""
	if v := headers["Server"]; len(v) > 0 {
		server = v[0]
	}
	s.HTTP = &model.HTTPFingerprint{
		Scheme: scheme, URL: scheme + "://" + host + "/", FinalURL: scheme + "://" + host + "/", Host: host,
		Status: status, Title: title, Headers: headers, Server: server, BodyLength: 4200, BodySimhash: "9f3a55c0a1b2c3d4",
	}
	if scheme == "https" {
		s.Tunnel = "ssl"
	}
	return s
}

func cert(cn, issuer, sha string, notAfter time.Time) *model.TLSInfo {
	days := int(notAfter.Sub(sampleCur).Hours() / 24)
	return &model.TLSInfo{
		Version: "TLS 1.3", SubjectCN: cn, SANs: []string{cn}, Issuer: issuer, NotBefore: notAfter.AddDate(0, 0, -90),
		NotAfter: notAfter, SHA256: sha, Expired: notAfter.Before(sampleCur), DaysLeft: days, KeyType: "ECDSA", KeyBits: 256,
	}
}

// history builds an availability profile from sampleStart to end, one
// observation every 12 hours.
func history(end time.Time, up func(time.Time) bool) analyze.Profile {
	var p analyze.Profile
	for t := sampleStart; !t.After(end); t = t.Add(12 * time.Hour) {
		p.Add(model.HostObservation{At: t, Up: up(t)}, warsaw)
	}
	return p
}

type sampleHost struct {
	id        int64
	ip        string
	hostnames []string
	prev, cur []model.ServiceResult
	isNew     bool // not in the previous run
	// up reports if the host answers at t; nil means always.
	up func(time.Time) bool
	// prevStatus overrides the status of the previous run (host that was inactive).
	prevStatus model.HostStatus
}

func officeHours(t time.Time) bool {
	l := t.In(warsaw)
	return l.Weekday() >= time.Monday && l.Weekday() <= time.Friday && l.Hour() >= 8 && l.Hour() < 18
}

func sampleHosts() []sampleHost {
	sec := map[string][]string{
		"Server": {"nginx"}, "Content-Security-Policy": {"default-src 'self'"}, "X-Frame-Options": {"DENY"},
	}
	noCSP := map[string][]string{"Server": {"nginx"}, "X-Frame-Options": {"DENY"}}
	le := "R11, Let's Encrypt"

	www80 := web(svc(80, "http", "nginx", "1.24.0"), "http", "www.kampus.example", "301 Moved Permanently", 301, map[string][]string{"Server": {"nginx/1.24.0"}})
	wwwOld := web(svc(443, "https", "nginx", "1.24.0"), "https", "www.kampus.example", "Kampus – strona główna", 200, map[string][]string{"Server": {"nginx/1.24.0"}})
	wwwNew := wwwOld
	wwwOld.TLS = cert("www.kampus.example", le, "5b1f0c7e9a2d4466", time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC))
	wwwNew.TLS = cert("www.kampus.example", le, "c94e21aa07b35f18", time.Date(2027, 2, 18, 10, 0, 0, 0, time.UTC))

	dz := func(version string) model.ServiceResult {
		s := web(svc(80, "http", "Apache httpd", version), "http", "dziekanat.kampus.example", "Dziekanat – logowanie", 200,
			map[string][]string{"Server": {"Apache/" + version + " (Debian)"}})
		s.Classes = []string{model.ClassLogin}
		return s
	}

	mail := web(svc(443, "https", "nginx", ""), "https", "poczta.kampus.example", "Poczta – logowanie", 200, map[string][]string{"Server": {"nginx"}})
	mail.Classes = []string{model.ClassLogin}
	mail.TLS = cert("poczta.kampus.example", le, "77a0d3e1b6c2f945", time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC))

	app := web(svc(80, "http", "Apache httpd", "2.4.62"), "http", "10.66.1.55", "Rejestracja na zajęcia", 200, map[string][]string{"Server": {"Apache"}})
	mysql := svc(3306, "mysql", "MySQL", "8.0.36")

	stOld := web(svc(443, "https", "nginx", ""), "https", "staging.kampus.example", "Portal studenta (test)", 200, sec)
	stNew := web(svc(443, "https", "nginx", ""), "https", "staging.kampus.example", "Portal studenta 2.0 (test)", 200, noCSP)
	stOld.TLS = cert("staging.kampus.example", le, "0e6f1b2c3d4a5978", time.Date(2027, 1, 20, 9, 0, 0, 0, time.UTC))
	stNew.TLS = stOld.TLS

	ssh := svc(22, "ssh", "OpenSSH", "9.6p1")
	smb := svc(445, "microsoft-ds", "", "")
	files := web(svc(443, "https", "nginx", ""), "https", "pliki.kampus.example", "Pliki wydziałowe", 200, map[string][]string{"Server": {"nginx"}})
	gitlab := web(svc(443, "https", "nginx", ""), "https", "git.kampus.example", "Sign in · GitLab", 200, map[string][]string{"Server": {"nginx"}})
	cups := web(svc(631, "ipp", "CUPS", "2.4"), "http", "10.66.2.9:631", "Home - CUPS 2.4.7", 200, map[string][]string{"Server": {"CUPS/2.4 IPP/2.1"}})

	jenkins := web(svc(8080, "http", "Jetty", "10.0.20"), "http", "10.66.3.17:8080", "Dashboard [Jenkins]", 200,
		map[string][]string{"Server": {"Jetty(10.0.20)"}, "X-Jenkins": {"2.440.1"}})
	jenkins.Matches = []model.SigMatch{{
		Signature: "jenkins", Name: "Jenkins", Category: model.CatDevOps, Version: "2.440.1", Confidence: 0.97, Interest: 20,
		Classes: []string{model.ClassAdminPanel, model.ClassDevTool},
		Evidence: []model.Evidence{
			{Matcher: "header", Where: "header:X-Jenkins", Snippet: "2.440.1"},
			{Matcher: "title", Where: "title", Snippet: "Dashboard [Jenkins]"},
		},
	}}
	jenkins.Technologies = []model.Technology{{Name: "Jenkins", Category: model.CatDevOps, Version: "2.440.1", Confidence: 0.97, Sources: []string{"jenkins"}}}

	printer := web(svc(80, "http", "HP LaserJet http config", ""), "http", "10.66.3.40", "HP LaserJet Pro M404dn", 200, map[string][]string{"Server": {"HP HTTP Server; HP LaserJet Pro M404dn"}})
	printer.Matches = []model.SigMatch{{
		Signature: "hp-laserjet", Name: "HP LaserJet", Category: model.CatIoT, Confidence: 0.9, Interest: 10,
		Classes:  []string{model.ClassIoT},
		Evidence: []model.Evidence{{Matcher: "header", Where: "header:Server", Snippet: "HP HTTP Server; HP LaserJet Pro M404dn"}},
	}}
	redis := svc(6379, "redis", "Redis key-value store", "7.2.4")

	hosts := []sampleHost{
		{id: 1, ip: "10.66.1.10", hostnames: []string{"www.kampus.example"}, prev: []model.ServiceResult{www80, wwwOld}, cur: []model.ServiceResult{www80, wwwNew}},
		{id: 2, ip: "10.66.1.20", hostnames: []string{"dziekanat.kampus.example"}, prev: []model.ServiceResult{dz("2.4.57")}, cur: []model.ServiceResult{dz("2.4.62")}},
		{id: 3, ip: "10.66.1.30", hostnames: []string{"poczta.kampus.example"}, prev: []model.ServiceResult{mail}, cur: []model.ServiceResult{mail}},
		{id: 4, ip: "10.66.1.55", prev: []model.ServiceResult{app, mysql}, cur: []model.ServiceResult{app}},
		{id: 5, ip: "10.66.1.60", hostnames: []string{"staging.kampus.example"}, prev: []model.ServiceResult{stOld}, cur: []model.ServiceResult{stNew}},
		{id: 6, ip: "10.66.1.80", hostnames: []string{"pliki.kampus.example"}, prev: []model.ServiceResult{ssh, files}, cur: []model.ServiceResult{ssh, files},
			up: func(t time.Time) bool { return t.Before(sampleCur) }},
		{id: 7, ip: "10.66.2.5", hostnames: []string{"git.kampus.example"}, prev: []model.ServiceResult{ssh, gitlab}, cur: []model.ServiceResult{ssh, gitlab},
			up: func(t time.Time) bool { return t.Before(samplePrev) }},
		{id: 8, ip: "10.66.2.9", hostnames: []string{"drukserwer.kampus.example"}, prev: nil, cur: []model.ServiceResult{cups}, prevStatus: model.HostDown},
		{id: 17, ip: "10.66.2.77", prev: []model.ServiceResult{ssh}, cur: []model.ServiceResult{ssh}},
		{id: 18, ip: "10.66.3.17", hostnames: []string{"ci.kampus.example"}, prev: []model.ServiceResult{ssh}, cur: []model.ServiceResult{ssh, jenkins}},
		{id: 19, ip: "10.66.3.40", cur: []model.ServiceResult{printer, svc(631, "ipp", "", ""), svc(9100, "jetdirect", "", "")}, isNew: true},
		{id: 20, ip: "10.66.3.90", hostnames: []string{"cache-01.kampus.example"}, prev: []model.ServiceResult{ssh}, cur: []model.ServiceResult{ssh, redis}},
	}
	// Eight lab workstations that are on in office hours only.
	for i := 0; i < 8; i++ {
		hosts = append(hosts, sampleHost{id: int64(9 + i), ip: "10.66.2." + string(rune('0'+3)) + string(rune('1'+i)),
			prev: []model.ServiceResult{smb}, cur: []model.ServiceResult{smb}, up: officeHours})
	}
	// One host that answers in about half of the scans, with no pattern.
	rng := rand.New(rand.NewSource(7))
	flaky := map[int64]bool{}
	for t := sampleStart; !t.After(sampleCur); t = t.Add(12 * time.Hour) {
		flaky[t.Unix()] = rng.Intn(2) == 0
	}
	flaky[samplePrev.Unix()], flaky[sampleCur.Unix()] = true, false
	for i := range hosts {
		if hosts[i].ip == "10.66.2.77" {
			hosts[i].up = func(t time.Time) bool { return flaky[t.Unix()] }
		}
	}
	return hosts
}

func sampleInput() Input {
	hosts := sampleHosts()
	prev := analyze.Snapshot{RunID: 41, At: samplePrev}
	cur := analyze.Snapshot{RunID: 42, At: sampleCur}
	var findings []model.Finding
	var services []model.Service
	var unstable []model.Host
	newFindings := 0

	for _, h := range hosts {
		up := h.up
		if up == nil {
			up = func(time.Time) bool { return true }
		}
		assessAt := func(end time.Time) (analyze.Assessment, int) {
			p := history(end, up)
			n := 0
			for _, b := range p.Buckets {
				n += b.Up + b.Down
			}
			return analyze.Assess(p, warsaw), n
		}
		if !h.isNew {
			a, n := assessAt(samplePrev)
			st := a.Status
			if h.prevStatus != "" {
				st = h.prevStatus
			}
			prev.Hosts = append(prev.Hosts, analyze.HostSnapshot{HostID: h.id, IP: h.ip, Up: st == model.HostUp, Status: st,
				Pattern: a.Pattern, Stability: a.Stability, Observations: n, Services: h.prev})
		}
		var a analyze.Assessment
		n := 1
		if h.isNew {
			var p analyze.Profile
			p.Add(model.HostObservation{At: sampleCur, Up: true}, warsaw)
			a = analyze.Assess(p, warsaw)
		} else {
			a, n = assessAt(sampleCur)
		}
		isUp := a.Status == model.HostUp
		cur.Hosts = append(cur.Hosts, analyze.HostSnapshot{HostID: h.id, IP: h.ip, Up: isUp, Status: a.Status,
			Pattern: a.Pattern, Stability: a.Stability, Observations: n, Services: h.cur})

		if !isUp {
			mh := model.Host{ID: h.id, IP: h.ip, Hostnames: h.hostnames}
			analyze.ApplyToHost(&mh, a)
			unstable = append(unstable, mh)
			continue
		}
		before := map[int]bool{}
		for _, s := range h.prev {
			before[s.Port] = true
		}
		in := analyze.FindingInput{HostID: h.id, IP: h.ip, Hostnames: h.hostnames, RunID: cur.RunID, At: sampleCur}
		for _, s := range h.cur {
			isNew := !before[s.Port] && h.prevStatus == ""
			score, why := analyze.Interest(analyze.InterestInput{Service: s, Hostnames: h.hostnames, NewExposure: isNew, ScopeCriticality: 3, Now: sampleCur})
			in.Services = append(in.Services, analyze.FindingService{Result: s, New: isNew, Interest: score})
			ms := model.Service{HostID: h.id, IP: h.ip, Port: s.Port, Proto: s.Proto, State: model.ServiceOpen, Name: s.Name,
				Product: s.Product, Version: s.Version, Interest: score, InterestWhy: why}
			if len(h.hostnames) > 0 {
				ms.Hostname = h.hostnames[0]
			}
			if s.HTTP != nil {
				ms.Title = s.HTTP.Title
			}
			services = append(services, ms)
		}
		for _, f := range analyze.DeriveFindings(in) {
			// The store keeps the first run of a finding it already has.
			if before[f.Port] {
				f.FirstRunID = 12
				f.FirstSeen = sampleStart
			} else {
				newFindings++
			}
			findings = append(findings, f)
		}
	}

	changes, summary := analyze.Diff(&prev, cur, analyze.DiffOptions{})
	summary.FindingsNew = newFindings

	started, finished := sampleCur, sampleCur.Add(5*time.Minute+18*time.Second)
	prevStarted := samplePrev
	profile := model.ScanProfile{
		ID: 3, Name: "Kampus – co 12 godzin", Ports: "top-100",
		Discovery:        model.DiscoveryOpts{ICMPEcho: true, TCPSynPorts: []int{22, 80, 443}, ARP: true},
		ServiceDetection: true, VersionIntensity: 5,
		HTTP: model.HTTPOpts{Enabled: true, MaxRedirects: 3, SignaturePaths: true, Favicon: true},
		Rate: model.RateLimits{MaxPPS: 100, HTTPRPS: 10, PerHostConcurrency: 2},
	}
	return Input{
		Organization: "sieć przykładowa",
		GeneratedAt:  finished.Add(40 * time.Second),
		Location:     warsaw,
		Run: model.ScanRun{
			ID: 42, ProfileName: profile.Name, Status: model.RunCompleted, Trigger: "schedule", StartedAt: &started, FinishedAt: &finished,
			Stats: model.RunStats{AddressesTotal: 1024, AddressesDone: 1024, ChunksTotal: 16, ChunksDone: 16, HostsUp: 58, ServicesOpen: 143,
				HTTPServices: 36, PacketsSent: 14260, HTTPRequests: 412, AvgPPS: 44.8, ElapsedSec: 318, Retried: 11, Errors: 0},
		},
		PrevRun: &model.ScanRun{ID: 41, StartedAt: &prevStarted},
		Profile: &profile,
		Policy: model.SafetyPolicy{MaxPPS: 300, MaxHTTPRPS: 20, MaxPerHostRPS: 2, MaxPathsPerHost: 8, DeniedPorts: "9100-9103",
			Exclusions: []string{"10.66.0.1", "10.66.0.128/28"}, AllowedMethods: []string{"GET", "HEAD"},
			UserAgent: "Czujka/1.0 (+https://czujka.kampus.example/o-skanerze)"},
		Scopes:   []string{"Kampus – sieć laboratoryjna"},
		Summary:  summary,
		Changes:  changes,
		Findings: findings,
		Services: services,
		Hosts:    unstable,
	}
}
