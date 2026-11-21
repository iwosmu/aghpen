package probe

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type xHost struct {
	TimedOut string `xml:"timedout,attr"` // "true": nmap gave up on the host (--host-timeout)
	Status   struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr   string `xml:"addr,attr"`
		Type   string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	ExtraPorts []struct {
		State string `xml:"state,attr"`
		Count int    `xml:"count,attr"`
	} `xml:"ports>extraports"`
	Ports []xPort `xml:"ports>port"`
	Times struct {
		SRTT string `xml:"srtt,attr"`
	} `xml:"times"`
}

type xPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
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
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
}

// ParseXML reads nmap XML output ("-oX") as a stream. It keeps the hosts
// that are up and their open ports. Down hosts, which nmap lists in verbose
// mode, are only counted.
func ParseXML(r io.Reader) (*Result, error) {
	res := &Result{}
	dec := xml.NewDecoder(r)
	dec.Strict = false
	sawRoot, finished := false, false
	exit, errMsg := "", ""
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if sawRoot && len(res.Hosts) > 0 {
				// truncated output (the process was stopped): keep what is complete
				return res, fmt.Errorf("nmap xml: %w", err)
			}
			return nil, fmt.Errorf("nmap xml: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "nmaprun":
			sawRoot = true
		case "host":
			var xh xHost
			if err := dec.DecodeElement(&xh, &se); err != nil {
				return res, fmt.Errorf("nmap xml host: %w", err)
			}
			res.Scanned++
			if xh.Status.State != "up" {
				continue
			}
			res.Hosts = append(res.Hosts, convertHost(xh))
		case "finished":
			finished = true
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "exit":
					exit = a.Value
				case "errormsg":
					errMsg = a.Value
				}
			}
		case "hosts":
			for _, a := range se.Attr {
				if a.Name.Local == "total" {
					if n, err := strconv.Atoi(a.Value); err == nil {
						res.Scanned = n
					}
				}
			}
		}
	}
	if !sawRoot {
		return nil, fmt.Errorf("nmap xml: no nmaprun element")
	}
	if finished && exit != "" && exit != "success" {
		return res, fmt.Errorf("nmap exit %q: %s", exit, errMsg)
	}
	if !finished {
		return res, fmt.Errorf("nmap xml: output is incomplete (no runstats)")
	}
	return res, nil
}

func convertHost(xh xHost) Host {
	h := Host{Up: true, Reason: xh.Status.Reason}
	for _, a := range xh.Addresses {
		switch a.Type {
		case "ipv4", "ipv6":
			h.IP = a.Addr
		case "mac":
			h.MAC = a.Addr
			h.Vendor = a.Vendor
		}
	}
	for _, n := range xh.Hostnames {
		if n.Name != "" {
			h.Hostnames = append(h.Hostnames, n.Name)
		}
	}
	if us, err := strconv.ParseFloat(xh.Times.SRTT, 64); err == nil && us > 0 {
		h.RTTMs = us / 1000
	}
	if h.Reason != "" && h.Reason != "user-set" {
		h.Responded = true
	}
	if xh.TimedOut == "true" {
		// With -Pn on Ethernet nmap still resolves the MAC, so the reason is
		// "arp-response" even when the port scan never finished: the host
		// answered ARP, its ports are unknown.
		h.TimedOut = true
		h.Responded = false
		return h
	}
	for _, ep := range xh.ExtraPorts {
		if ep.State == "closed" && ep.Count > 0 {
			h.Responded = true
		}
	}
	for _, xp := range xh.Ports {
		if xp.State.State == "open" || xp.State.State == "closed" {
			h.Responded = true
		}
		if xp.State.State != "open" {
			continue
		}
		p := Port{
			Port:      xp.PortID,
			Proto:     xp.Protocol,
			State:     "open",
			Reason:    xp.State.Reason,
			Name:      xp.Service.Name,
			Product:   xp.Service.Product,
			Version:   xp.Service.Version,
			ExtraInfo: xp.Service.ExtraInfo,
			Tunnel:    xp.Service.Tunnel,
			Method:    xp.Service.Method,
		}
		for _, c := range xp.Service.CPE {
			if c = strings.TrimSpace(c); c != "" {
				p.CPE = append(p.CPE, c)
			}
		}
		if c, err := strconv.Atoi(xp.Service.Conf); err == nil {
			p.Confidence = float64(c) / 10
		}
		p.Banner = strings.TrimSpace(strings.Join(nonEmpty(p.Product, p.Version, wrapParen(p.ExtraInfo)), " "))
		h.Ports = append(h.Ports, p)
	}
	return h
}

func nonEmpty(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func wrapParen(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}
