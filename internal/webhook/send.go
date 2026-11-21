package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Timeout of one delivery. There is no retry: a slow or broken endpoint
// costs at most this per analysed run.
const Timeout = 10 * time.Second

// SignatureHeader carries "sha256=" + hex(HMAC-SHA256(secret, body)) when a
// secret is set.
const SignatureHeader = "X-Czujka-Signature"

const userAgent = "Czujka/1.0 (webhook)"

// Sign returns the value of SignatureHeader for body.
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// CheckURL accepts an absolute http or https URL with a host.
func CheckURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("adres webhooka musi być pełnym adresem http:// albo https://")
	}
	return nil
}

// Client posts the payloads. It does not follow redirects.
type Client struct{ HTTP *http.Client }

func (c Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Result of one delivery.
type Result struct {
	Status int    `json:"status"` // HTTP status; 0 when no answer
	Ms     int64  `json:"ms"`
	Error  string `json:"error,omitempty"`
}

// Post sends body once. A status outside 2xx is an error.
func (c Client) Post(ctx context.Context, endpoint, secret, event string, body []byte) (res Result) {
	start := time.Now()
	defer func() { res.Ms = time.Since(start).Milliseconds() }()
	if err := CheckURL(endpoint); err != nil {
		res.Error = err.Error()
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(endpoint), bytes.NewReader(body))
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Czujka-Event", event)
	if secret != "" {
		req.Header.Set(SignatureHeader, Sign(secret, body))
	}
	resp, err := c.http().Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	res.Status = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Only the status: the body of an internal endpoint may hold
		// anything, and it would reach the UI and the audit log (security review L2).
		res.Error = fmt.Sprintf("odpowiedź HTTP %d", resp.StatusCode)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			res.Error += " (przekierowanie; Czujka nie podąża za przekierowaniem, podaj adres docelowy)"
		}
	}
	return res
}
