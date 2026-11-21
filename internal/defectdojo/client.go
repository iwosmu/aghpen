// Package defectdojo is a client for the DefectDojo API v2.
//
// It exports Czujka findings as informational findings with endpoints and
// uploads a run's nmap XML as an "Nmap Scan" import. It talks only to the
// URL in its configuration.
//
// How findings are exported (chosen by testing against DefectDojo 3.5):
//
//   - New findings go through /import-scan (first export) or /reimport-scan
//     (later exports) with the scan type "Generic Findings Import". This is
//     the route that creates the endpoints of a finding; in DefectDojo 3.x
//     POST /endpoints is gone and POST /findings takes no endpoints.
//   - Findings that already exist are found by unique_id_from_tool (the
//     Czujka finding key) and updated in place with PATCH /findings/{id}.
//     /reimport-scan alone is not enough: it matches by hash code, so a
//     finding whose description changed would be created a second time.
//
// So a second export of the same findings creates no duplicates.
package defectdojo

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Default timeouts.
const (
	DefaultTimeout       = 30 * time.Second
	DefaultImportTimeout = 5 * time.Minute // an import of a large file is slow on the server side
)

// Config configures a Client.
type Config struct {
	URL string // base URL, for example http://127.0.0.1:18080 ("/api/v2" is added)
	// LinkURL is the base of the links shown to people (test, finding,
	// product pages). Empty: URL. It differs when Czujka reaches DefectDojo
	// at an address a browser cannot open (http://host.docker.internal:18080).
	LinkURL   string
	APIKey    string // API v2 token
	VerifyTLS bool   // false accepts any certificate (lab instances with self-signed certificates)
	Timeout   time.Duration
	// ImportTimeout is the limit of one import-scan or reimport-scan call.
	ImportTimeout time.Duration
	UserAgent     string
	// HTTPClient replaces the default client (tests). Timeout and VerifyTLS are then not applied.
	HTTPClient *http.Client
}

// FromSettings builds a Config from the stored settings.
func FromSettings(s model.DefectDojoSettings) Config {
	return Config{URL: s.URL, APIKey: s.APIKey, VerifyTLS: s.VerifyTLS, LinkURL: s.LinkURL}
}

// Client is a DefectDojo API v2 client. It is safe for concurrent use.
type Client struct {
	base          *url.URL // without a trailing slash
	link          *url.URL // base of the links for people; nil: base
	key           string
	http          *http.Client
	importTimeout time.Duration
	userAgent     string
}

// New validates the configuration and returns a client.
func New(cfg Config) (*Client, error) {
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return nil, errors.New("defectdojo: brak adresu URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("defectdojo: niepoprawny adres URL %q", cfg.URL)
	}
	u.Path = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api/v2"), "/")
	u.RawQuery, u.Fragment = "", ""
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("defectdojo: brak tokenu API")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS, MinVersion: tls.VersionTLS12} //nolint:gosec // the switch is the user's explicit choice
		hc = &http.Client{Timeout: timeout, Transport: tr}
	}
	it := cfg.ImportTimeout
	if it <= 0 {
		it = DefaultImportTimeout
	}
	c := &Client{base: u, key: strings.TrimSpace(cfg.APIKey), http: hc, importTimeout: it, userAgent: firstNonEmpty(cfg.UserAgent, "czujka-defectdojo/1")}
	if l := strings.TrimSpace(cfg.LinkURL); l != "" {
		lu, err := ParseLinkURL(l)
		if err != nil {
			return nil, err
		}
		c.link = lu
	}
	return c, nil
}

// ParseLinkURL validates the public base of DefectDojo links (http or https,
// with a host) and drops a trailing slash and "/api/v2".
func ParseLinkURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("defectdojo: niepoprawny adres linków %q (wymagany http:// albo https:// z nazwą hosta)", raw)
	}
	u.Path = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api/v2"), "/")
	u.RawQuery, u.Fragment = "", ""
	return u, nil
}

// web is the base of the links for people: LinkURL, else the API base.
func (c *Client) web() string {
	if c.link != nil {
		return c.link.String()
	}
	return c.base.String()
}

// BaseURL returns the normalised base URL.
func (c *Client) BaseURL() string { return c.base.String() }

// APIError is a non-2xx answer of DefectDojo.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("DefectDojo odrzucił token API lub brak uprawnień (HTTP %d, %s %s): %s", e.Status, e.Method, e.Path, e.Body)
	case http.StatusNotFound:
		return fmt.Sprintf("DefectDojo nie zna tego zasobu (HTTP 404, %s %s); sprawdź adres URL instancji", e.Method, e.Path)
	}
	return fmt.Sprintf("DefectDojo zwrócił błąd HTTP %d (%s %s): %s", e.Status, e.Method, e.Path, e.Body)
}

func (c *Client) endpoint(path string, q url.Values) string {
	u := *c.base
	u.Path = u.Path + "/api/v2/" + strings.TrimPrefix(path, "/")
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// do sends one request and decodes a JSON answer into out (when not nil).
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body io.Reader, contentType string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path, q), body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return c.netError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &APIError{Method: method, Path: "/api/v2/" + strings.TrimPrefix(path, "/"), Status: resp.StatusCode, Body: cleanBody(b, resp.Header.Get("Content-Type"))}
	}
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return fmt.Errorf("DefectDojo odpowiedział typem %q zamiast JSON (%s %s); sprawdź adres URL instancji", ct, method, path)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("niepoprawna odpowiedź DefectDojo (%s %s): %w", method, path, err)
	}
	return nil
}

func (c *Client) netError(err error) error {
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.As(err, &certErr), strings.Contains(err.Error(), "x509:"):
		return fmt.Errorf("nie można zweryfikować certyfikatu TLS serwera DefectDojo (%s); popraw certyfikat albo wyłącz weryfikację TLS w ustawieniach: %w", c.base.Host, err)
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(err.Error(), "Client.Timeout"):
		return fmt.Errorf("DefectDojo (%s) nie odpowiedział w wyznaczonym czasie: %w", c.base.Host, err)
	}
	return fmt.Errorf("brak połączenia z DefectDojo (%s): %w", c.base.Host, err)
}

func cleanBody(b []byte, contentType string) string {
	if strings.Contains(contentType, "html") {
		return "(odpowiedź HTML)"
	}
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, q, nil, "", out)
}

func (c *Client) sendJSON(ctx context.Context, method, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, method, path, nil, bytes.NewReader(b), "application/json", out)
}

// page is the envelope of a DefectDojo list.
type page[T any] struct {
	Count   int     `json:"count"`
	Next    *string `json:"next"`
	Results []T     `json:"results"`
}

// listAll reads every page of a list endpoint.
func listAll[T any](ctx context.Context, c *Client, path string, q url.Values) ([]T, error) {
	const limit = 200
	var all []T
	if q == nil {
		q = url.Values{}
	}
	q.Set("limit", strconv.Itoa(limit))
	for offset := 0; ; offset += limit {
		q.Set("offset", strconv.Itoa(offset))
		var p page[T]
		if err := c.get(ctx, path, q, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Results...)
		if p.Next == nil || len(p.Results) == 0 || len(all) >= p.Count {
			return all, nil
		}
	}
}

// ---------- connection test ----------

// ConnInfo is the answer of the connection test.
type ConnInfo struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Version string `json:"version"`
	User    string `json:"user"`
}

var reFooterVersion = regexp.MustCompile(`Version\s+v?([0-9]+\.[0-9]+[0-9A-Za-z.\-]*)`)

// Test checks the URL and the token and reads the server version. The
// returned error is nil when the server answered; ConnInfo.OK and
// ConnInfo.Message say what happened.
func (c *Client) Test(ctx context.Context) (ConnInfo, error) {
	var profile struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := c.get(ctx, "user_profile/", nil, &profile); err != nil {
		return ConnInfo{OK: false, Message: err.Error()}, err
	}
	info := ConnInfo{OK: true, User: profile.User.Username, Version: c.version(ctx)}
	info.Message = fmt.Sprintf("Połączono z DefectDojo %s jako %s", firstNonEmpty(info.Version, "(wersja nieznana)"), info.User)
	return info, nil
}

// version reads the server version. DefectDojo has no version endpoint: the
// version is in the OpenAPI schema (info.version) and in the page footer.
func (c *Client) version(ctx context.Context) string {
	if v := c.schemaVersion(ctx); v != "" {
		return v
	}
	u := *c.base
	u.Path += "/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if m := reFooterVersion.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// schemaVersion reads info.version from the OpenAPI schema and stops there;
// the rest of the schema (about 1 MB) is not downloaded.
func (c *Client) schemaVersion(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("oa3/schema/", url.Values{"format": {"json"}}), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Token "+c.key)
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(io.LimitReader(resp.Body, 8<<20))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return ""
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return ""
		}
		if key, _ := kt.(string); key == "info" {
			var info struct {
				Version string `json:"version"`
			}
			if dec.Decode(&info) != nil {
				return ""
			}
			return info.Version
		}
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return ""
		}
	}
	return ""
}

// ---------- product type, product, engagement, test ----------

// Target names where Czujka data goes in DefectDojo.
type Target struct {
	ProductTypeName string
	ProductName     string
	EngagementName  string
}

// Default names.
const (
	DefaultProductType = "Czujka"
	DefaultProduct     = "Czujka – Attack Surface"
	DefaultEngagement  = "Czujka discovery"
	FindingsTestTitle  = "Czujka findings"
	scanTypeGeneric    = "Generic Findings Import"
	scanTypeNmap       = "Nmap Scan"
)

// TargetFromSettings builds a Target from the stored settings, with defaults.
func TargetFromSettings(s model.DefectDojoSettings) Target {
	return Target{ProductTypeName: s.ProductTypeName, ProductName: s.ProductName, EngagementName: s.EngagementName}.withDefaults()
}

func (t Target) withDefaults() Target {
	t.ProductTypeName = firstNonEmpty(strings.TrimSpace(t.ProductTypeName), DefaultProductType)
	t.ProductName = firstNonEmpty(strings.TrimSpace(t.ProductName), DefaultProduct)
	t.EngagementName = firstNonEmpty(strings.TrimSpace(t.EngagementName), DefaultEngagement)
	return t
}

// Location is the resolved ids of a Target.
type Location struct {
	ProductTypeID int64  `json:"product_type_id"`
	ProductID     int64  `json:"product_id"`
	EngagementID  int64  `json:"engagement_id"`
	ProductURL    string `json:"product_url"`
	EngagementURL string `json:"engagement_url"`
}

type named struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Title string `json:"title"`
}

// findByName returns the id of the object whose name (or title) is exactly name.
// DefectDojo filters are "contains" filters on some versions, so the exact
// comparison is done here.
func (c *Client) findByName(ctx context.Context, path string, q url.Values, field, name string) (int64, bool, error) {
	q.Set(field, name)
	items, err := listAll[named](ctx, c, path, q)
	if err != nil {
		return 0, false, err
	}
	var best int64
	found := false
	for _, it := range items {
		v := it.Name
		if field == "title" {
			v = it.Title
		}
		if v == name && (!found || it.ID < best) {
			best, found = it.ID, true
		}
	}
	return best, found, nil
}

// Ensure finds or creates the product type, the product and the engagement.
func (c *Client) Ensure(ctx context.Context, t Target) (Location, error) {
	t = t.withDefaults()
	var loc Location
	id, ok, err := c.findByName(ctx, "product_types/", url.Values{}, "name", t.ProductTypeName)
	if err != nil {
		return loc, err
	}
	if !ok {
		var created named
		if err := c.sendJSON(ctx, http.MethodPost, "product_types/", map[string]any{"name": t.ProductTypeName, "description": "Utworzone przez Czujkę"}, &created); err != nil {
			return loc, fmt.Errorf("nie można utworzyć typu produktu %q: %w", t.ProductTypeName, err)
		}
		id = created.ID
	}
	loc.ProductTypeID = id

	id, ok, err = c.findByName(ctx, "products/", url.Values{}, "name", t.ProductName)
	if err != nil {
		return loc, err
	}
	if !ok {
		var created named
		body := map[string]any{"name": t.ProductName, "prod_type": loc.ProductTypeID,
			"description": "Hosty, usługi i znaleziska z cyklicznych skanów Czujki."}
		if err := c.sendJSON(ctx, http.MethodPost, "products/", body, &created); err != nil {
			return loc, fmt.Errorf("nie można utworzyć produktu %q: %w", t.ProductName, err)
		}
		id = created.ID
	}
	loc.ProductID = id
	loc.ProductURL = fmt.Sprintf("%s/product/%d", c.web(), id)

	id, ok, err = c.findByName(ctx, "engagements/", url.Values{"product": {strconv.FormatInt(loc.ProductID, 10)}}, "name", t.EngagementName)
	if err != nil {
		return loc, err
	}
	if !ok {
		var created named
		today := time.Now().UTC()
		body := map[string]any{
			"name": t.EngagementName, "product": loc.ProductID, "status": "In Progress", "engagement_type": "CI/CD",
			"target_start": today.Format("2006-01-02"), "target_end": today.AddDate(1, 0, 0).Format("2006-01-02"),
			"description": "Znaleziska Czujki.", "deduplication_on_engagement": true,
		}
		if err := c.sendJSON(ctx, http.MethodPost, "engagements/", body, &created); err != nil {
			return loc, fmt.Errorf("nie można utworzyć engagementu %q: %w", t.EngagementName, err)
		}
		id = created.ID
	}
	loc.EngagementID = id
	loc.EngagementURL = fmt.Sprintf("%s/engagement/%d", c.web(), id)
	return loc, nil
}

// findTest returns the id of the test with this title in the engagement.
func (c *Client) findTest(ctx context.Context, engagementID int64, title string) (int64, bool, error) {
	return c.findByName(ctx, "tests/", url.Values{"engagement": {strconv.FormatInt(engagementID, 10)}}, "title", title)
}

// ---------- imports ----------

// importStats is the "statistics" object of import-scan and reimport-scan.
type importStats struct {
	After struct {
		Total struct {
			Total int `json:"total"`
		} `json:"total"`
	} `json:"after"`
	Delta *struct {
		Created     statTotal `json:"created"`
		Closed      statTotal `json:"closed"`
		Reactivated statTotal `json:"reactivated"`
		Untouched   statTotal `json:"untouched"`
	} `json:"delta"`
}

type statTotal struct {
	Total struct {
		Total int `json:"total"`
	} `json:"total"`
}

type importResponse struct {
	Test       int64        `json:"test"`
	TestID     int64        `json:"test_id"`
	Statistics *importStats `json:"statistics"`
}

// ImportResult is the outcome of one scan import.
type ImportResult struct {
	TestID      int64  `json:"test_id"`
	TestURL     string `json:"test_url"`
	Reimport    bool   `json:"reimport"` // the test existed and was updated
	Created     int    `json:"created"`
	Closed      int    `json:"closed"`
	Reactivated int    `json:"reactivated"`
	Untouched   int    `json:"untouched"`
	Total       int    `json:"total"` // findings in the test after the import
}

// scanImport posts a scan file. testID != 0 selects reimport-scan.
func (c *Client) scanImport(ctx context.Context, scanType string, engagementID, testID int64, title, fileName string, file io.Reader, scanDate time.Time, extra map[string]string) (ImportResult, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fields := map[string]string{
		"scan_type": scanType, "minimum_severity": "Info", "close_old_findings": "false",
		"close_old_findings_product_scope": "false", "push_to_jira": "false",
	}
	path := "import-scan/"
	if testID != 0 {
		path = "reimport-scan/"
		fields["test"] = strconv.FormatInt(testID, 10)
		fields["do_not_reactivate"] = "false"
	} else {
		fields["engagement"] = strconv.FormatInt(engagementID, 10)
		fields["test_title"] = title
	}
	if !scanDate.IsZero() {
		fields["scan_date"] = scanDate.UTC().Format("2006-01-02")
	}
	for k, v := range extra {
		fields[k] = v
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return ImportResult{}, err
		}
	}
	fw, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		return ImportResult{}, err
	}
	if _, err := io.Copy(fw, file); err != nil {
		return ImportResult{}, err
	}
	if err := mw.Close(); err != nil {
		return ImportResult{}, err
	}
	ictx, cancel := context.WithTimeout(ctx, c.importTimeout)
	defer cancel()
	var resp importResponse
	if err := c.do(ictx, http.MethodPost, path, nil, &buf, mw.FormDataContentType(), &resp); err != nil {
		return ImportResult{}, err
	}
	res := ImportResult{TestID: firstID(resp.Test, resp.TestID, testID), Reimport: testID != 0}
	res.TestURL = fmt.Sprintf("%s/test/%d", c.web(), res.TestID)
	if s := resp.Statistics; s != nil {
		res.Total = s.After.Total.Total
		if s.Delta != nil {
			res.Created, res.Closed = s.Delta.Created.Total.Total, s.Delta.Closed.Total.Total
			res.Reactivated, res.Untouched = s.Delta.Reactivated.Total.Total, s.Delta.Untouched.Total.Total
		} else {
			res.Created = res.Total
		}
	}
	return res, nil
}

func firstID(ids ...int64) int64 {
	for _, id := range ids {
		if id != 0 {
			return id
		}
	}
	return 0
}

// ImportNmapXML uploads nmap XML as an "Nmap Scan" import. The first upload
// with a title creates a test; a later upload with the same title re-imports
// into that test, so a repeated export of one run does not duplicate it.
func (c *Client) ImportNmapXML(ctx context.Context, t Target, title string, xmlFile io.Reader, scanDate time.Time) (ImportResult, error) {
	loc, err := c.Ensure(ctx, t)
	if err != nil {
		return ImportResult{}, err
	}
	title = firstNonEmpty(strings.TrimSpace(title), "Czujka nmap")
	testID, _, err := c.findTest(ctx, loc.EngagementID, title)
	if err != nil {
		return ImportResult{}, err
	}
	extra := map[string]string{"active": "true", "verified": "false", "tags": "czujka"}
	if testID != 0 {
		// A later run of the same profile replaces the picture: what the new
		// XML no longer has is closed in the test.
		extra["close_old_findings"] = "true"
	}
	res, err := c.scanImport(ctx, scanTypeNmap, loc.EngagementID, testID, title, "czujka-nmap.xml", xmlFile, scanDate, extra)
	if err != nil {
		return res, fmt.Errorf("import nmap XML do DefectDojo nie powiódł się: %w", err)
	}
	return res, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
