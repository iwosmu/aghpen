package passive

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults of the Certificate Transparency source.
const (
	DefaultCTBaseURL = "https://crt.sh"
	DefaultCTTimeout = 45 * time.Second
	DefaultCTDelay   = 2 * time.Second // pause between two domains
	MaxCTBodyBytes   = 64 << 20
)

// CTSource asks crt.sh, a public Certificate Transparency search service,
// for the certificates of the scope domains.
//
// EXTERNAL SERVICE: every call sends a domain name of the scope to crt.sh,
// a third party. The source is off by default. It runs only when Enabled is
// true and Collect is called with Options.AllowExternal. It sends nothing
// else: no address, no host list, no credentials. It never contacts a host
// of the scope.
type CTSource struct {
	Enabled   bool
	BaseURL   string        // "" means DefaultCTBaseURL
	Client    *http.Client  // nil means a client with DefaultCTTimeout
	Delay     time.Duration // 0 means DefaultCTDelay
	UserAgent string        // "" means "czujka-passive"
}

func (c *CTSource) Name() string   { return "crt.sh" }
func (c *CTSource) External() bool { return true }

// Collect queries one scope domain after another with GET
// {BaseURL}/?q=%.{domain}&output=json and keeps the names below that domain.
func (c *CTSource) Collect(ctx context.Context, scope Scope) ([]Fact, error) {
	if !c.Enabled {
		return nil, ErrExternalDisabled
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = DefaultCTBaseURL
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultCTTimeout}
	}
	delay := c.Delay
	if delay <= 0 {
		delay = DefaultCTDelay
	}
	ua := c.UserAgent
	if ua == "" {
		ua = "czujka-passive"
	}
	var facts []Fact
	var firstErr error
	done := map[string]bool{}
	n := 0
	for _, d := range scope.Domains {
		domain, _, ok := cleanHost(d)
		if !ok || done[domain] {
			continue
		}
		done[domain] = true
		if n > 0 {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return facts, ctx.Err()
			case <-t.C:
			}
		}
		n++
		got, err := c.domain(ctx, client, base, ua, domain)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("crt.sh, domena %s: %w", domain, err)
			}
			continue
		}
		one := Scope{Domains: []string{domain}}
		for _, f := range got {
			if one.ContainsHost(f.Hostname) {
				f.Source = c.Name()
				f.IP = "" // a certificate list says nothing about addresses
				facts = append(facts, f)
			}
		}
	}
	return facts, firstErr
}

func (c *CTSource) domain(ctx context.Context, client *http.Client, base, ua, domain string) ([]Fact, error) {
	q := url.Values{"q": {"%." + domain}, "output": {"json"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxCTBodyBytes))
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(body))) == 0 || strings.TrimSpace(string(body)) == "[]" {
		return nil, nil
	}
	facts, _, err := Parse(strings.NewReader(string(body)), "crt.sh")
	return facts, err
}
