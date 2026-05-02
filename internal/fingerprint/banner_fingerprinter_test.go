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

// --- parseServiceBanner unit tests ---
// These exercise the parsing logic in isolation without any network I/O.

func TestParseServiceBanner_SSH(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantName    string
		wantVersion string
	}{
		{
			name:        "openssh with distro comment",
			banner:      "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1",
			wantName:    "openssh",
			wantVersion: "8.4p1",
		},
		{
			name:        "openssh version only",
			banner:      "SSH-2.0-OpenSSH_7.9",
			wantName:    "openssh",
			wantVersion: "7.9",
		},
		{
			name:     "unknown software, no underscore",
			banner:   "SSH-2.0-PUTTY",
			wantName: "putty",
		},
		{
			name:     "malformed banner, two dashes only",
			banner:   "SSH-2.0",
			wantName: "ssh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion := parseServiceBanner(tt.banner)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("parseServiceBanner(%q) = (%q, %q), want (%q, %q)",
					tt.banner, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestParseServiceBanner_HTTP(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantName    string
		wantVersion string
	}{
		{
			name:        "nginx with distro comment",
			banner:      "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n",
			wantName:    "nginx",
			wantVersion: "1.18.0",
		},
		{
			name:        "apache plain",
			banner:      "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
			wantName:    "apache",
			wantVersion: "2.4.41",
		},
		{
			name:     "no server header falls back to http",
			banner:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
			wantName: "http",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion := parseServiceBanner(tt.banner)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("parseServiceBanner(%q) = (%q, %q), want (%q, %q)",
					tt.banner, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestParseServiceBanner_FTP(t *testing.T) {
	name, _ := parseServiceBanner("220 ProFTPD 1.3.6 Server ready.")
	if name != "ftp" {
		t.Errorf("parseServiceBanner(FTP) = %q, want %q", name, "ftp")
	}
}

func TestParseServiceBanner_SMTP(t *testing.T) {
	name, _ := parseServiceBanner("220 mail.example.com ESMTP Postfix (2.10.1)")
	if name != "smtp" {
		t.Errorf("parseServiceBanner(SMTP) = %q, want %q", name, "smtp")
	}
}

func TestParseServiceBanner_Empty(t *testing.T) {
	name, version := parseServiceBanner("")
	if name != "" || version != "" {
		t.Errorf("parseServiceBanner(\"\") = (%q, %q), want (\"\", \"\")", name, version)
	}
}

func TestParseServiceBanner_Unknown(t *testing.T) {
	// An unrecognised greeting should yield empty name and version.
	name, version := parseServiceBanner("GIBBERISH PROTOCOL 1.0")
	if name != "" || version != "" {
		t.Errorf("parseServiceBanner(unknown) = (%q, %q), want (\"\", \"\")", name, version)
	}
}

// --- BannerFingerprinter integration tests ---
// These use real local TCP listeners to test the full Fingerprint() path.

func TestBannerFingerprinter_RawBanner_SSH(t *testing.T) {
	// Simulate an SSH server: send the greeting immediately on connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1\r\n"))
		conn.Close()
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	f := NewBannerFingerprinter(time.Second, 256)

	svc, err := f.Fingerprint(models.Port{IP: "127.0.0.1", Number: port, Proto: "tcp"})
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if svc.Name != "openssh" {
		t.Errorf("Name = %q, want %q", svc.Name, "openssh")
	}
	if svc.Version != "8.4p1" {
		t.Errorf("Version = %q, want %q", svc.Version, "8.4p1")
	}
	if svc.Banner == "" {
		t.Error("Banner must not be empty")
	}
}

func TestBannerFingerprinter_HTTPBanner(t *testing.T) {
	// Simulate an HTTP server: wait for the client request, then respond.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Consume the incoming request so the write does not block.
		buf := make([]byte, 512)
		conn.Read(buf)
		conn.Write([]byte("HTTP/1.0 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"))
		conn.Close()
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	f := NewBannerFingerprinter(time.Second, 4096)
	// Teach the fingerprinter to use HTTP mode for this local port.
	// The httpPorts field is accessible here because the test is in the same
	// package (package fingerprint), keeping this injection internal.
	f.httpPorts[port] = true

	svc, err := f.Fingerprint(models.Port{IP: "127.0.0.1", Number: port, Proto: "tcp"})
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if svc.Name != "nginx" {
		t.Errorf("Name = %q, want %q", svc.Name, "nginx")
	}
	if svc.Version != "1.18.0" {
		t.Errorf("Version = %q, want %q", svc.Version, "1.18.0")
	}
}

func TestBannerFingerprinter_UnreachablePort(t *testing.T) {
	// Port 1 on localhost should be refused instantly; a short timeout avoids
	// slowing the suite if the system silently drops the packet instead.
	f := NewBannerFingerprinter(200*time.Millisecond, 256)
	_, err := f.Fingerprint(models.Port{IP: "127.0.0.1", Number: 1, Proto: "tcp"})
	if err == nil {
		t.Fatal("Fingerprint() expected error for unreachable port, got nil")
	}
}

func TestBannerFingerprinter_HTTPSBanner(t *testing.T) {
	// httptest.NewTLSServer creates a real TLS listener with a self-signed cert.
	// Our fingerprinter uses InsecureSkipVerify, so the cert is irrelevant —
	// this directly exercises the tls.DialWithDialer + probeHTTP path.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "apache/2.4.41")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// srv.URL is "https://127.0.0.1:<port>" — extract the port number.
	addr := strings.TrimPrefix(srv.URL, "https://")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}

	f := NewBannerFingerprinter(time.Second, 4096)
	f.httpsPorts[port] = true

	svc, err := f.Fingerprint(models.Port{IP: host, Number: port, Proto: "tcp"})
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if svc.Name != "apache" {
		t.Errorf("Name = %q, want %q", svc.Name, "apache")
	}
	if svc.Version != "2.4.41" {
		t.Errorf("Version = %q, want %q", svc.Version, "2.4.41")
	}
}

func TestNewBannerFingerprinter_Defaults(t *testing.T) {
	f := NewBannerFingerprinter(0, 0)
	if f.timeout != defaultFingerprintTimeout {
		t.Errorf("timeout = %v, want %v", f.timeout, defaultFingerprintTimeout)
	}
	if f.readLimit != defaultReadLimit {
		t.Errorf("readLimit = %d, want %d", f.readLimit, defaultReadLimit)
	}
}
