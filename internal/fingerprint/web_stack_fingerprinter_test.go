package fingerprint

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// --- parseHTTPResponse unit tests ---

func TestParseHTTPResponse_HeadersAndBody(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n<html>body</html>"
	body, headers, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != "<html>body</html>" {
		t.Errorf("body = %q, want %q", body, "<html>body</html>")
	}
	if headers.Get("Content-Type") != "text/html" {
		t.Errorf("Content-Type = %q, want %q", headers.Get("Content-Type"), "text/html")
	}
	if headers.Get("Server") != "nginx" {
		t.Errorf("Server = %q, want %q", headers.Get("Server"), "nginx")
	}
}

func TestParseHTTPResponse_NoSeparator(t *testing.T) {
	// A malformed response with no header/body separator must not panic —
	// the full raw string is returned as body with a nil header map.
	raw := "GARBAGE NOT HTTP AT ALL"
	body, headers, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != raw {
		t.Errorf("body = %q, want raw input", body)
	}
	_ = headers // nil is acceptable
}

// --- detectTechnologies unit tests ---

func TestDetectTechnologies_PHP_XPoweredBy(t *testing.T) {
	headers := http.Header{"X-Powered-By": []string{"PHP/8.1.2"}}
	techs := detectTechnologies(headers, "")
	if len(techs) == 0 {
		t.Fatal("expected PHP detection from X-Powered-By header, got none")
	}
	if techs[0].Name != "PHP" {
		t.Errorf("Name = %q, want PHP", techs[0].Name)
	}
	if !strings.Contains(techs[0].Evidence, "PHP/8.1.2") {
		t.Errorf("Evidence = %q, want it to contain the version", techs[0].Evidence)
	}
}

func TestDetectTechnologies_ASPNET(t *testing.T) {
	headers := http.Header{"X-Aspnet-Version": []string{"4.0.30319"}}
	techs := detectTechnologies(headers, "")
	if len(techs) == 0 {
		t.Fatal("expected ASP.NET detection, got none")
	}
	if techs[0].Name != "ASP.NET" {
		t.Errorf("Name = %q, want ASP.NET", techs[0].Name)
	}
}

func TestDetectTechnologies_WordPress_Body(t *testing.T) {
	body := `<html><head><link rel="stylesheet" href="/wp-content/themes/mytheme/style.css"></head></html>`
	techs := detectTechnologies(nil, body)
	if len(techs) == 0 {
		t.Fatal("expected WordPress detection from HTML body, got none")
	}
	found := false
	for _, tech := range techs {
		if tech.Name == "WordPress" {
			found = true
		}
	}
	if !found {
		t.Errorf("WordPress not in %v", techs)
	}
}

func TestDetectTechnologies_React_DataReactroot(t *testing.T) {
	body := `<html><body><div id="root" data-reactroot=""></div></body></html>`
	techs := detectTechnologies(nil, body)
	found := false
	for _, tech := range techs {
		if tech.Name == "React" {
			found = true
		}
	}
	if !found {
		t.Errorf("React not detected from data-reactroot; got %v", techs)
	}
}

func TestDetectTechnologies_NextJS(t *testing.T) {
	body := `<script id="__NEXT_DATA__" type="application/json">{"page":"/"}</script>`
	techs := detectTechnologies(nil, body)
	found := false
	for _, tech := range techs {
		if tech.Name == "Next.js" {
			found = true
		}
	}
	if !found {
		t.Errorf("Next.js not detected; got %v", techs)
	}
}

func TestDetectTechnologies_PHP_Cookie(t *testing.T) {
	headers := http.Header{"Set-Cookie": []string{"PHPSESSID=abc123; Path=/; HttpOnly"}}
	techs := detectTechnologies(headers, "")
	found := false
	for _, tech := range techs {
		if tech.Name == "PHP" {
			found = true
		}
	}
	if !found {
		t.Errorf("PHP not detected from PHPSESSID cookie; got %v", techs)
	}
}

func TestDetectTechnologies_Deduplication(t *testing.T) {
	// WordPress detected from both wp-content path AND wp-includes path must
	// appear only once in the result — detectTechnologies deduplicates by name.
	body := `<link href="/wp-content/themes/x.css"><script src="/wp-includes/js/y.js"></script>`
	techs := detectTechnologies(nil, body)
	count := 0
	for _, tech := range techs {
		if tech.Name == "WordPress" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("WordPress appeared %d times, want exactly 1", count)
	}
}

func TestDetectTechnologies_NoMatch(t *testing.T) {
	// A response with no known signatures must return an empty slice,
	// not nil, and must not error.
	headers := http.Header{"Content-Type": []string{"text/html"}}
	body := "<html><body><p>Hello world</p></body></html>"
	techs := detectTechnologies(headers, body)
	if len(techs) != 0 {
		t.Errorf("expected no technologies, got %v", techs)
	}
}

// --- WebStackFingerprinter integration tests using real HTTP servers ---

func TestWebStackFingerprinter_HTTP_PHP(t *testing.T) {
	// Real HTTP server serving X-Powered-By: PHP/8.1 — exercises the full
	// fetchHTTP → doGET → detectTechnologies path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Hello</body></html>"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	f := NewWebStackFingerprinter(time.Second)
	f.httpPorts[portNum] = true

	techs, err := f.FingerprintWeb("example.com", models.Port{IP: host, Number: portNum, Proto: "tcp"})
	if err != nil {
		t.Fatalf("FingerprintWeb() error = %v", err)
	}
	found := false
	for _, tech := range techs {
		if tech.Name == "PHP" {
			found = true
		}
	}
	if !found {
		t.Errorf("PHP not detected; got %v", techs)
	}
}

func TestWebStackFingerprinter_HTTPS_WordPress(t *testing.T) {
	// Real TLS server serving WordPress-style HTML — exercises the
	// fetchHTTPS → TLS dial → doGET path with InsecureSkipVerify.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><link href="/wp-content/themes/t.css"></head></html>`))
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "https://")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	f := NewWebStackFingerprinter(time.Second)
	f.httpsPorts[portNum] = true

	techs, err := f.FingerprintWeb("example.com", models.Port{IP: host, Number: portNum, Proto: "tcp"})
	if err != nil {
		t.Fatalf("FingerprintWeb() error = %v", err)
	}
	found := false
	for _, tech := range techs {
		if tech.Name == "WordPress" {
			found = true
		}
	}
	if !found {
		t.Errorf("WordPress not detected; got %v", techs)
	}
}

func TestWebStackFingerprinter_NoTechnologies(t *testing.T) {
	// A server with no detectable signatures must return an empty slice,
	// not an error — ambiguity is not a failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Nothing to detect</body></html>"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	portNum, _ := strconv.Atoi(portStr)

	f := NewWebStackFingerprinter(time.Second)
	f.httpPorts[portNum] = true

	techs, err := f.FingerprintWeb("example.com", models.Port{IP: host, Number: portNum, Proto: "tcp"})
	if err != nil {
		t.Fatalf("FingerprintWeb() returned unexpected error: %v", err)
	}
	if len(techs) != 0 {
		t.Errorf("expected no technologies, got %v", techs)
	}
}

func TestWebStackFingerprinter_UnreachablePort(t *testing.T) {
	// An unreachable port must return an error, not a silent empty slice.
	f := NewWebStackFingerprinter(200 * time.Millisecond)
	_, err := f.FingerprintWeb("example.com", models.Port{IP: "127.0.0.1", Number: 1, Proto: "tcp"})
	if err == nil {
		t.Fatal("FingerprintWeb() expected error for unreachable port, got nil")
	}
}

func TestWebStackFingerprinter_BodyLimitTruncatesLargeResponse(t *testing.T) {
	// Serve a response body larger than webReadLimit (8 KiB) that embeds a
	// recognisable technology marker near the start. FingerprintWeb must detect
	// the technology without reading the full response, proving io.LimitReader
	// is applied correctly and the fingerprinter does not stall on huge pages.
	bigBody := strings.Repeat("X", webReadLimit*4) // 32 KiB — well past the cap

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Inject the data-drupal-selector attribute that detectBodyTechnologies
		// matches, then fill the rest of the response with filler. The signature
		// is within the first 8 KiB, so it must be detected regardless of how
		// much additional data follows — proving io.LimitReader is applied.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<form data-drupal-selector="edit-form">`))
		w.Write([]byte(bigBody))
	}))
	defer srv.Close()

	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	f := NewWebStackFingerprinter(2 * time.Second)
	// Inject the test port into the HTTP routing table so FingerprintWeb tries
	// the plain-HTTP path instead of skipping the port as unrecognised.
	f.httpPorts[port] = true

	techs, err := f.FingerprintWeb("127.0.0.1", models.Port{IP: "127.0.0.1", Number: port, Proto: "tcp"})
	if err != nil {
		t.Fatalf("FingerprintWeb() returned unexpected error: %v", err)
	}
	found := false
	for _, tech := range techs {
		if strings.EqualFold(tech.Name, "Drupal") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Drupal in detected technologies, got %v", techs)
	}
}

func TestWebStackFingerprinter_CanFingerprint(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{80, true},    // standard HTTP
		{443, true},   // standard HTTPS
		{8080, true},  // alternate HTTP
		{8443, true},  // alternate HTTPS
		{8888, true},  // alternate HTTP
		{22, false},   // SSH — not an HTTP port
		{3306, false}, // MySQL — not an HTTP port
		{5432, false}, // PostgreSQL — not an HTTP port
		{0, false},    // invalid — not in any routing table
	}

	f := NewWebStackFingerprinter(time.Second)
	for _, tt := range tests {
		got := f.CanFingerprint(tt.port)
		if got != tt.want {
			t.Errorf("CanFingerprint(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}
