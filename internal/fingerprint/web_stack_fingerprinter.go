package fingerprint

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// webReadLimit caps the HTML body read to 8 KiB.
//
// Technology signatures (generator meta tags, framework-specific class names,
// global JavaScript variables) appear early in the HTML document — almost
// always within the first kilobyte of the <head> section. 8 KiB is generous
// enough to catch signatures pushed deeper by advertising scripts or large
// inline styles, while bounding memory use on large pages.
const webReadLimit = 8192

// userAgent is the HTTP User-Agent header sent with every GET request.
//
// A minimal generic desktop browser string is used rather than a custom tool
// identifier. Many production servers apply bot-detection that returns a
// non-representative response (a CAPTCHA page or a redirect) when they see an
// unfamiliar UA. Sending a plausible browser string avoids that filter so the
// body we receive for fingerprinting reflects what a real user would see.
const userAgent = "Mozilla/5.0"

// headerRule maps a response header name to a technology signature.
type headerRule struct {
	header   string // canonical HTTP header name (Title-Cased)
	value    string // substring to match in the header value (empty = header presence alone)
	name     string
	category string
}

// cookieRule maps a Set-Cookie name to a technology signature.
type cookieRule struct {
	cookieName string // substring to match in the cookie name
	name       string
	category   string
}

// bodyRule maps an HTML body substring to a technology signature.
type bodyRule struct {
	pattern  string // substring to search for in the HTML body
	name     string
	category string
}

// headerRules lists the response headers inspected for technology signals.
// Header names follow the canonical HTTP Title-Case form so net/http's
// canonical header map lookup works correctly.
var headerRules = []headerRule{
	// X-Powered-By is the most common header exposing the server-side language
	// or framework. Many stacks emit it without suppression.
	{header: "X-Powered-By", value: "php", name: "PHP", category: "Language"},
	{header: "X-Powered-By", value: "asp.net", name: "ASP.NET", category: "Framework"},
	{header: "X-Powered-By", value: "express", name: "Express.js", category: "Framework"},
	{header: "X-Powered-By", value: "next.js", name: "Next.js", category: "Framework"},
	// When X-Powered-By is present but none of the known values match, record
	// the raw value as a generic "Platform" finding so analysts have the evidence.
	{header: "X-Powered-By", value: "", name: "", category: "Platform"},

	// ASP.NET version disclosure: the exact runtime version.
	{header: "X-Aspnet-Version", value: "", name: "ASP.NET", category: "Framework"},
	{header: "X-Aspnetmvc-Version", value: "", name: "ASP.NET MVC", category: "Framework"},

	// Static site generators and CMS frameworks sometimes emit X-Generator.
	{header: "X-Generator", value: "", name: "", category: "CMS"},

	// Drupal emits X-Drupal-Cache on cached responses.
	{header: "X-Drupal-Cache", value: "", name: "Drupal", category: "CMS"},
	{header: "X-Drupal-Dynamic-Cache", value: "", name: "Drupal", category: "CMS"},
}

// cookieRules lists Set-Cookie names that betray the server-side runtime.
var cookieRules = []cookieRule{
	// PHP session cookie: exposed unless session.name is explicitly changed.
	{"PHPSESSID", "PHP", "Language"},
	// Java servlet containers (Tomcat, JBoss, WildFly) all use JSESSIONID.
	{"JSESSIONID", "Java/Tomcat", "Platform"},
	// ASP.NET session state.
	{"ASP.NET_SessionId", "ASP.NET", "Framework"},
	// Laravel framework session.
	{"laravel_session", "Laravel", "Framework"},
	// Rails uses _session_id by convention in many configurations.
	{"_session_id", "Ruby on Rails", "Framework"},
}

// bodyRules lists HTML body patterns that identify web technologies.
// All pattern matching is case-insensitive (patterns are lowercased and
// matched against a lowercased body copy).
var bodyRules = []bodyRule{
	// WordPress: the canonical content directory path appears in every theme
	// and plugin asset URL. If this path is present the site runs WordPress.
	{"wp-content/", "WordPress", "CMS"},
	{"wp-includes/", "WordPress", "CMS"},

	// Drupal: the sites/default/files path is the default managed file
	// directory and is nearly universal in Drupal deployments.
	{"sites/default/files", "Drupal", "CMS"},
	// Drupal also injects data-drupal-selector attributes in forms.
	{"data-drupal-selector", "Drupal", "CMS"},

	// Joomla: com_content is the core content component URL prefix.
	{"/components/com_content", "Joomla", "CMS"},

	// Next.js: injects its build manifest as a script with id="__NEXT_DATA__".
	// Pattern is lowercased to match the lowercased body copy.
	{"__next_data__", "Next.js", "Framework"},

	// Vue: mount point attribute added by createApp().mount().
	{"__vue_app__", "Vue.js", "Framework"},
	// Vue 3 SFC compiled output includes data-v- prefixed attributes.
	{"data-v-app", "Vue.js", "Framework"},

	// Angular: ng-version is injected on the root component by the Angular
	// runtime and is visible in the rendered HTML.
	{"ng-version=", "Angular", "Framework"},

	// React: the data-reactroot attribute is written by ReactDOM.render and
	// createRoot. Patterns are lowercase to match the lowercased body copy.
	{"data-reactroot", "React", "Framework"},

	// Gatsby (React-based static site generator): injects gatsby-announcer.
	{"gatsby-announcer", "Gatsby", "Framework"},

	// Svelte: compiled components expose _svelte attributes.
	{"__svelte", "Svelte", "Framework"},
}

// WebStackFingerprinter implements WebFingerprinter by issuing a GET / request
// with the correct Host header and inspecting both response headers and the
// HTML body for technology signatures.
//
// Why GET and not HEAD?
// HEAD returns only response headers. The most valuable technology signals —
// WordPress wp-content paths, React data-reactroot attributes, Next.js
// __NEXT_DATA__ — live in the HTML body. HEAD would miss all of them. The
// body read is capped at webReadLimit bytes so large pages do not exhaust
// memory.
//
// Why a separate struct from BannerFingerprinter?
// Single Responsibility: BannerFingerprinter identifies the protocol and
// software. WebStackFingerprinter identifies the application layer built on
// top of the software. They operate at different abstraction levels and have
// different connection lifecycles (HEAD vs GET, IP-based vs domain-based Host).
type WebStackFingerprinter struct {
	timeout    time.Duration
	httpPorts  map[int]bool
	httpsPorts map[int]bool
}

// NewWebStackFingerprinter constructs a WebStackFingerprinter with the default
// HTTP and HTTPS port routing tables. A zero or negative timeout falls back to
// the package-level default (3 seconds).
func NewWebStackFingerprinter(timeout time.Duration) *WebStackFingerprinter {
	if timeout <= 0 {
		timeout = defaultFingerprintTimeout
	}
	return &WebStackFingerprinter{
		timeout:    timeout,
		httpPorts:  buildPortMap(defaultHTTPPorts),
		httpsPorts: buildPortMap(defaultHTTPSPorts),
	}
}

// FingerprintWeb issues a GET / request to port with the Host header set to
// domain and returns all technology signatures matched against the response.
//
// TLS is used when the port is in the HTTPS port set; plain HTTP otherwise.
// InsecureSkipVerify is intentional for the same reason as in BannerFingerprinter:
// external scanning targets frequently present self-signed or misconfigured
// certificates, which are themselves findings — refusing to connect would hide
// the application stack behind a TLS error.
func (f *WebStackFingerprinter) FingerprintWeb(domain string, port models.Port) ([]models.Technology, error) {
	var body string
	var respHeaders http.Header
	var err error

	if f.httpsPorts[port.Number] {
		body, respHeaders, err = f.fetchHTTPS(domain, port)
	} else {
		body, respHeaders, err = f.fetchHTTP(domain, port)
	}
	if err != nil {
		return nil, fmt.Errorf("web_stack_fingerprinter: %s:%d: %w",
			port.IP, port.Number, err)
	}

	return detectTechnologies(respHeaders, body), nil
}

// CanFingerprint reports whether portNum is in this fingerprinter's HTTP or
// HTTPS routing table. Returns true for the standard web ports (80, 8080, 8888
// for HTTP; 443, 8443 for HTTPS) that were registered in NewWebStackFingerprinter.
//
// main.go uses this to gate web fingerprinting without embedding port numbers
// in the wiring layer — the fingerprinter owns authoritative knowledge of which
// ports speak HTTP.
func (f *WebStackFingerprinter) CanFingerprint(portNum int) bool {
	return f.httpPorts[portNum] || f.httpsPorts[portNum]
}

// fetchHTTP dials port over plain TCP, sends a GET / with the domain Host
// header, and returns the response headers and body (capped at webReadLimit).
func (f *WebStackFingerprinter) fetchHTTP(domain string, port models.Port) (string, http.Header, error) {
	addr := net.JoinHostPort(port.IP, strconv.Itoa(port.Number))
	conn, err := net.DialTimeout(port.Proto, addr, f.timeout)
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()
	return f.doGET(conn, domain, port)
}

// fetchHTTPS dials port over TLS and follows the same GET path as fetchHTTP.
func (f *WebStackFingerprinter) fetchHTTPS(domain string, port models.Port) (string, http.Header, error) {
	addr := net.JoinHostPort(port.IP, strconv.Itoa(port.Number))
	dialer := &net.Dialer{Timeout: f.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) // #nosec G402 — intentional for external recon
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()
	return f.doGET(conn, domain, port)
}

// doGET writes a GET / HTTP/1.1 request with the correct Host header, reads
// the response, and returns the headers map and body string.
//
// HTTP/1.1 is used (unlike BannerFingerprinter's HTTP/1.0) because modern
// servers may return a redirect or a richer response under 1.1. The connection
// is closed immediately after reading, so keep-alive is not relevant.
func (f *WebStackFingerprinter) doGET(conn net.Conn, domain string, port models.Port) (string, http.Header, error) {
	if err := conn.SetDeadline(time.Now().Add(f.timeout)); err != nil {
		return "", nil, err
	}

	// Include Connection: close to signal that we will not reuse the connection.
	// This encourages HTTP/1.1 servers to close after the response, terminating
	// the read loop without requiring chunk-encoding or Content-Length parsing.
	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n\r\n",
		domain, userAgent,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", nil, err
	}

	// The error from ReadAll is intentionally discarded. On a plain TCP
	// connection, io.ReadAll returns an error when the read deadline fires or
	// when the server closes the connection after sending its response — both
	// are the expected termination path for an HTTP/1.1 request with
	// "Connection: close". The bytes accumulated before the error contain the
	// complete response and are valid for fingerprinting regardless.
	raw, _ := io.ReadAll(io.LimitReader(conn, int64(webReadLimit)))
	return parseHTTPResponse(string(raw))
}

// parseHTTPResponse splits a raw HTTP response into a headers map and body string.
//
// The header block and body are separated by \r\n\r\n (the empty line after
// the last header). Each header line is parsed into canonical name → value
// pairs using net/http's header canonicalization so the caller can use the
// standard http.Header type for lookup.
func parseHTTPResponse(raw string) (string, http.Header, error) {
	// Find the header/body boundary.
	sep := strings.Index(raw, "\r\n\r\n")
	if sep == -1 {
		// No boundary found — malformed response. Return what we have as body;
		// header detection will find nothing.
		return raw, nil, nil
	}
	headerBlock := raw[:sep]
	body := raw[sep+4:]

	headers := make(http.Header)
	lines := strings.Split(headerBlock, "\r\n")
	for _, line := range lines[1:] { // skip the status line
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		name := http.CanonicalHeaderKey(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		headers[name] = append(headers[name], value)
	}
	return body, headers, nil
}

// detectTechnologies matches the response headers and body against all known
// technology rules and returns the deduplicated list of matched technologies.
//
// Deduplication is by name: if WordPress is detected from both a body pattern
// and a Set-Cookie name, only one Technology entry is returned. This prevents
// the caller from receiving duplicate entries for the same technology matched
// from different evidence sources.
//
// The three rule categories (headers, cookies, body) are delegated to
// detectHeaderTechs, detectCookieTechs, and detectBodyTechs respectively.
// Each receives the shared add callback so deduplication remains centralised
// here without passing a map or slice pointer across the call boundary.
func detectTechnologies(headers http.Header, body string) []models.Technology {
	seen := make(map[string]struct{})
	var result []models.Technology

	add := func(name, category, evidence string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		result = append(result, models.Technology{
			Name:     name,
			Category: category,
			Evidence: evidence,
		})
	}

	detectHeaderTechs(headers, add)
	detectCookieTechs(headers, add)
	detectBodyTechs(body, add)

	return result
}

// detectHeaderTechs matches HTTP response headers against the headerRules table.
// Presence-only rules (rule.value == "") treat the header value itself as the
// technology name when no name is configured (e.g. generic X-Powered-By).
func detectHeaderTechs(headers http.Header, add func(name, category, evidence string)) {
	for _, rule := range headerRules {
		vals := headers[rule.header]
		if len(vals) == 0 {
			continue
		}
		val := strings.ToLower(vals[0])
		if rule.value == "" {
			// Header presence alone is the signal. Use the raw header value as
			// evidence. If no specific name was configured (generic X-Powered-By),
			// derive the technology name from the header value itself.
			techName := rule.name
			if techName == "" {
				techName = strings.TrimSpace(vals[0])
			}
			add(techName, rule.category, rule.header+": "+vals[0])
		} else if strings.Contains(val, rule.value) {
			add(rule.name, rule.category, rule.header+": "+vals[0])
		}
	}
}

// detectCookieTechs checks Set-Cookie header values against the cookieRules
// table. Frameworks and analytics tools often set recognisable cookie names
// (e.g. PHPSESSID → PHP, _pk_id → Matomo) that reveal the underlying stack
// without requiring any active probing.
func detectCookieTechs(headers http.Header, add func(name, category, evidence string)) {
	for _, setCookie := range headers["Set-Cookie"] {
		namePart := setCookie
		if idx := strings.IndexByte(setCookie, '='); idx >= 0 {
			namePart = setCookie[:idx]
		}
		lowerName := strings.ToLower(strings.TrimSpace(namePart))
		for _, rule := range cookieRules {
			if strings.Contains(lowerName, strings.ToLower(rule.cookieName)) {
				add(rule.name, rule.category, "Set-Cookie: "+namePart)
			}
		}
	}
}

// detectBodyTechs scans the lowercased response body against the bodyRules
// table. Patterns include framework-generated HTML comments, meta generator
// tags, and characteristic script paths that are stable across versions.
func detectBodyTechs(body string, add func(name, category, evidence string)) {
	lowerBody := strings.ToLower(body)
	for _, rule := range bodyRules {
		if strings.Contains(lowerBody, rule.pattern) {
			add(rule.name, rule.category, "HTML: "+rule.pattern+" detected")
		}
	}
}
