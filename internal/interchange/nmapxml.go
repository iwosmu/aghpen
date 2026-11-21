package interchange

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Script ids that carry Czujka data inside nmap XML. Real nmap ignores
// unknown script ids; Czujka reads them back on import.
const (
	scriptTech    = "czujka-technologies"
	scriptClasses = "czujka-classes"
)

type xScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type xPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"state"`
	Service struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		Method    string   `xml:"method,attr"`
		Conf      string   `xml:"conf,attr"`
		OSType    string   `xml:"ostype,attr"`
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []xScript `xml:"script"`
}

type xHost struct {
	StartTime string `xml:"starttime,attr"`
	EndTime   string `xml:"endtime,attr"`
	Status    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports   []xPort `xml:"ports>port"`
	OSMatch []struct {
		Name     string `xml:"name,attr"`
		Accuracy string `xml:"accuracy,attr"`
	} `xml:"os>osmatch"`
	HostScripts []xScript `xml:"hostscript>script"`
	Times       struct {
		SRTT string `xml:"srtt,attr"`
	} `xml:"times"`
}

// importNmapXML reads nmap XML host by host (the file is never held in
// memory as a whole) and calls emit for each valid host.
func importNmapXML(r io.Reader, opts Options, rep *report, emit func(model.HostResult) error) error {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	// nmap output is UTF-8 or ASCII; accept any declared charset as is.
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var runStart time.Time
	sawRoot := false
	index := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if !sawRoot {
				return fmt.Errorf("plik nie jest poprawnym XML: %w", err)
			}
			rep.invalid(index+1, "", "uszkodzony XML: "+err.Error())
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "nmaprun":
			sawRoot = true
			for _, a := range se.Attr {
				if a.Name.Local == "start" {
					runStart = unixAttr(a.Value)
				}
			}
		case "host":
			if !sawRoot {
				return errors.New("to nie jest plik nmap XML (brak elementu nmaprun)")
			}
			index++
			var xh xHost
			if err := dec.DecodeElement(&xh, &se); err != nil {
				rep.invalid(index, "", "uszkodzony element host: "+err.Error())
				var syn *xml.SyntaxError
				if errors.As(err, &syn) {
					return nil // the file is cut or broken here; keep what was read
				}
				continue
			}
			h, err := convertNmapHost(&xh, runStart, opts)
			if err != nil {
				var re *rowError
				if errors.As(err, &re) {
					rep.invalid(index, re.value, re.reason)
					continue
				}
				return err
			}
			if !h.Up && !opts.IncludeDown {
				rep.Skipped++
				continue
			}
			if err := emit(h); err != nil {
				return err
			}
		default:
			if !sawRoot {
				return errors.New("to nie jest plik nmap XML (brak elementu nmaprun)")
			}
		}
	}
	if !sawRoot {
		return errors.New("to nie jest plik nmap XML (brak elementu nmaprun)")
	}
	return nil
}

func unixAttr(s string) time.Time {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func convertNmapHost(x *xHost, runStart time.Time, opts Options) (model.HostResult, error) {
	h := model.HostResult{RunID: opts.RunID, Attempts: 1, Hostnames: []string{}, Services: []model.ServiceResult{}}
	for _, a := range x.Addresses {
		switch a.AddrType {
		case "ipv4":
			h.IP = a.Addr
		case "ipv6":
			if h.IP == "" {
				h.IP = a.Addr
			}
		case "mac":
			h.MAC = a.Addr
			h.Vendor = a.Vendor
		}
	}
	h.Up = x.Status.State == "up"
	h.Reason = x.Status.Reason
	if h.Reason == "" {
		h.Reason = "imported"
	}
	for _, n := range x.Hostnames {
		if n.Name != "" && !contains(h.Hostnames, n.Name) {
			h.Hostnames = append(h.Hostnames, n.Name)
		}
	}
	h.ObservedAt = unixAttr(x.EndTime)
	if h.ObservedAt.IsZero() {
		h.ObservedAt = unixAttr(x.StartTime)
	}
	if h.ObservedAt.IsZero() {
		h.ObservedAt = runStart
	}
	if h.ObservedAt.IsZero() {
		h.ObservedAt = opts.now()
	}
	if us, err := strconv.ParseFloat(x.Times.SRTT, 64); err == nil && us > 0 {
		h.RTTMs = us / 1000
	}
	best := -1
	for _, m := range x.OSMatch {
		acc, _ := strconv.Atoi(m.Accuracy)
		if acc > best {
			best, h.OSGuess = acc, m.Name
		}
	}
	for _, s := range x.HostScripts {
		h.Scripts = append(h.Scripts, model.ScriptResult{ID: s.ID, Output: s.Output})
	}
	for i := range x.Ports {
		p := &x.Ports[i]
		port, err := strconv.Atoi(p.PortID)
		if err != nil || port < 1 || port > 65535 {
			return h, &rowError{h.IP + " port " + p.PortID, "niepoprawny numer portu"}
		}
		svc := model.ServiceResult{
			Port: port, Proto: firstNonEmpty(p.Protocol, "tcp"), State: firstNonEmpty(p.State.State, "open"),
			Name: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version, ExtraInfo: p.Service.ExtraInfo,
			Tunnel: p.Service.Tunnel,
		}
		for _, c := range p.Service.CPE {
			if c = strings.TrimSpace(c); c != "" {
				svc.CPE = append(svc.CPE, c)
			}
		}
		if conf, err := strconv.Atoi(p.Service.Conf); err == nil {
			svc.Confidence = float64(conf) / 10
		}
		if h.OSGuess == "" && p.Service.OSType != "" {
			h.OSGuess = p.Service.OSType
		}
		if svc.Product != "" {
			t := model.Technology{Name: svc.Product, Version: svc.Version, Confidence: svc.Confidence, Sources: []string{"nmap"}}
			if len(svc.CPE) > 0 {
				t.CPE = svc.CPE[0]
			}
			svc.Technologies = append(svc.Technologies, t)
		}
		title, server := "", ""
		for _, s := range p.Scripts {
			switch s.ID {
			case scriptTech:
				for _, item := range splitList(s.Output) {
					name, ver := splitTech(item)
					if !hasTech(svc.Technologies, name) {
						svc.Technologies = append(svc.Technologies, model.Technology{Name: name, Version: ver, Sources: []string{"import"}})
					}
				}
				continue
			case scriptClasses:
				svc.Classes = append(svc.Classes, splitList(s.Output)...)
				continue
			case "banner":
				svc.Banner = s.Output
			case "http-title":
				first := strings.TrimSpace(strings.SplitN(s.Output, "\n", 2)[0])
				if !strings.HasPrefix(first, "Site doesn't have a title") && !strings.HasPrefix(first, "Did not follow redirect") {
					title = first
				}
			case "http-server-header":
				server = strings.TrimSpace(s.Output)
			}
			svc.Scripts = append(svc.Scripts, model.ScriptResult{ID: s.ID, Output: s.Output})
		}
		if title != "" || server != "" {
			scheme := "http"
			if svc.Tunnel == "ssl" {
				scheme = "https"
			}
			fp := &model.HTTPFingerprint{Scheme: scheme, Title: title, Server: server, Host: h.IP}
			fp.URL = fmt.Sprintf("%s://%s/", scheme, hostPort(h.IP, port))
			if server != "" {
				fp.Headers = map[string][]string{"Server": {server}}
			}
			svc.HTTP = fp
		}
		h.Services = append(h.Services, svc)
	}
	if h.IP == "" {
		return h, &rowError{"", "host bez adresu IP"}
	}
	if err := validateHost(&h); err != nil {
		return h, err
	}
	return h, nil
}

func hasTech(ts []model.Technology, name string) bool {
	for _, t := range ts {
		if strings.EqualFold(t.Name, name) {
			return true
		}
	}
	return false
}

func hostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------- export ----------

// xmlWriter streams nmap XML. The output follows the nmap DTD closely enough
// for tools that read nmap XML; DefectDojo's "Nmap Scan" parser accepts it.
type xmlWriter struct {
	w      *bufio.Writer
	meta   Meta
	up     int
	down   int
	closed bool
}

func newXMLWriter(w io.Writer, meta Meta) (*xmlWriter, error) {
	x := &xmlWriter{w: bufio.NewWriter(w), meta: meta}
	start := meta.generatedAt()
	args := firstNonEmpty(meta.Args, "czujka export")
	fmt.Fprint(x.w, xml.Header)
	fmt.Fprint(x.w, "<!DOCTYPE nmaprun>\n")
	fmt.Fprintf(x.w, "<!-- Czujka export, run %d. Format: nmap XML. -->\n", meta.RunID)
	fmt.Fprintf(x.w, "<nmaprun scanner=\"nmap\" args=%s start=\"%d\" startstr=%s version=%s xmloutputversion=\"1.05\">\n",
		attr(args), start.Unix(), attr(start.UTC().Format("Mon Jan  2 15:04:05 2006")), attr(firstNonEmpty(meta.ScannerVersion, "7.95")))
	fmt.Fprint(x.w, "<scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"0\" services=\"\"/>\n")
	fmt.Fprint(x.w, "<verbose level=\"0\"/>\n<debugging level=\"0\"/>\n")
	return x, x.w.Flush()
}

func attr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	// EscapeText escapes quotes, new lines and control characters for attributes too.
	_ = xml.EscapeText(&b, []byte(strings.ToValidUTF8(s, "?")))
	b.WriteByte('"')
	return b.String()
}

func (x *xmlWriter) WriteHost(h model.HostResult) error {
	if x.closed {
		return errors.New("interchange: writer is closed")
	}
	w := x.w
	ts := h.ObservedAt.Unix()
	if h.ObservedAt.IsZero() {
		ts = x.meta.generatedAt().Unix()
	}
	state := "down"
	if h.Up {
		state = "up"
		x.up++
	} else {
		x.down++
	}
	reason := h.Reason
	if reason == "" || reason == "imported" {
		reason = "user-set"
	}
	fmt.Fprintf(w, "<host starttime=\"%d\" endtime=\"%d\"><status state=\"%s\" reason=%s reason_ttl=\"0\"/>\n", ts, ts, state, attr(reason))
	addrType := "ipv4"
	if strings.Contains(h.IP, ":") {
		addrType = "ipv6"
	}
	fmt.Fprintf(w, "<address addr=%s addrtype=\"%s\"/>\n", attr(h.IP), addrType)
	if h.MAC != "" {
		fmt.Fprintf(w, "<address addr=%s addrtype=\"mac\"", attr(h.MAC))
		if h.Vendor != "" {
			fmt.Fprintf(w, " vendor=%s", attr(h.Vendor))
		}
		fmt.Fprint(w, "/>\n")
	}
	fmt.Fprint(w, "<hostnames>")
	for _, n := range h.Hostnames {
		fmt.Fprintf(w, "<hostname name=%s type=\"user\"/>", attr(n))
	}
	fmt.Fprint(w, "</hostnames>\n<ports>")
	for i := range h.Services {
		s := &h.Services[i]
		fmt.Fprintf(w, "\n<port protocol=%s portid=\"%d\"><state state=%s reason=\"%s\" reason_ttl=\"0\"/>",
			attr(firstNonEmpty(s.Proto, "tcp")), s.Port, attr(firstNonEmpty(s.State, "open")), portReason(s.State))
		if s.Name != "" || s.Product != "" {
			fmt.Fprintf(w, "<service name=%s", attr(firstNonEmpty(s.Name, "unknown")))
			for _, kv := range [][2]string{{"product", s.Product}, {"version", s.Version}, {"extrainfo", s.ExtraInfo}, {"tunnel", s.Tunnel}} {
				if kv[1] != "" {
					fmt.Fprintf(w, " %s=%s", kv[0], attr(kv[1]))
				}
			}
			method, conf := "table", 3
			if s.Product != "" || s.Confidence > 0 {
				method = "probed"
				conf = int(s.Confidence*10 + 0.5)
				if conf <= 0 || conf > 10 {
					conf = 10
				}
			}
			fmt.Fprintf(w, " method=\"%s\" conf=\"%d\">", method, conf)
			for _, c := range s.CPE {
				fmt.Fprint(w, "<cpe>")
				_ = xml.EscapeText(w, []byte(c))
				fmt.Fprint(w, "</cpe>")
			}
			fmt.Fprint(w, "</service>")
		}
		for _, sc := range exportScripts(s) {
			fmt.Fprintf(w, "<script id=%s output=%s/>", attr(sc.ID), attr(sc.Output))
		}
		fmt.Fprint(w, "</port>")
	}
	fmt.Fprint(w, "\n</ports>\n")
	if h.OSGuess != "" {
		fmt.Fprintf(w, "<os><osmatch name=%s accuracy=\"100\" line=\"0\"/></os>\n", attr(h.OSGuess))
	}
	if len(h.Scripts) > 0 {
		fmt.Fprint(w, "<hostscript>")
		for _, sc := range h.Scripts {
			fmt.Fprintf(w, "<script id=%s output=%s/>", attr(sc.ID), attr(sc.Output))
		}
		fmt.Fprint(w, "</hostscript>\n")
	}
	if h.RTTMs > 0 {
		fmt.Fprintf(w, "<times srtt=\"%d\" rttvar=\"0\" to=\"1000000\"/>\n", int(h.RTTMs*1000+0.5))
	}
	fmt.Fprint(w, "</host>\n")
	return w.Flush()
}

func portReason(state string) string {
	switch state {
	case "closed":
		return "conn-refused"
	case "filtered":
		return "no-response"
	}
	return "syn-ack"
}

// exportScripts returns the scripts of a port: the imported ones, the title
// and the banner as the nmap scripts of the same name, and Czujka's
// technologies and classes under their own ids.
func exportScripts(s *model.ServiceResult) []model.ScriptResult {
	out := append([]model.ScriptResult{}, s.Scripts...)
	has := func(id string) bool {
		for _, sc := range out {
			if sc.ID == id {
				return true
			}
		}
		return false
	}
	if s.HTTP != nil && s.HTTP.Title != "" && !has("http-title") {
		out = append(out, model.ScriptResult{ID: "http-title", Output: s.HTTP.Title})
	}
	if s.HTTP != nil && s.HTTP.Server != "" && !has("http-server-header") {
		out = append(out, model.ScriptResult{ID: "http-server-header", Output: s.HTTP.Server})
	}
	if s.Banner != "" && !has("banner") {
		out = append(out, model.ScriptResult{ID: "banner", Output: s.Banner})
	}
	var techs []string
	for _, t := range s.Technologies {
		if t.Name != "" && !(strings.EqualFold(t.Name, s.Product) && t.Version == s.Version) {
			techs = append(techs, techText(t))
		}
	}
	if len(techs) > 0 {
		out = append(out, model.ScriptResult{ID: scriptTech, Output: strings.Join(techs, "; ")})
	}
	if len(s.Classes) > 0 {
		out = append(out, model.ScriptResult{ID: scriptClasses, Output: strings.Join(s.Classes, "; ")})
	}
	return out
}

func (x *xmlWriter) Close() error {
	if x.closed {
		return nil
	}
	x.closed = true
	end := x.meta.generatedAt()
	fmt.Fprintf(x.w, "<runstats><finished time=\"%d\" timestr=%s elapsed=\"0\" summary=%s exit=\"success\"/><hosts up=\"%d\" down=\"%d\" total=\"%d\"/></runstats>\n</nmaprun>\n",
		end.Unix(), attr(end.UTC().Format("Mon Jan  2 15:04:05 2006")),
		attr(fmt.Sprintf("Czujka export; %d hosts (%d up)", x.up+x.down, x.up)), x.up, x.down, x.up+x.down)
	return x.w.Flush()
}
