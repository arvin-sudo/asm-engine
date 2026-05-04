package fingerprint

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

const (
	// defaultReadLimit caps banner reads at 4 KiB.
	//
	// This is enough to capture any HTTP header block or SSH greeting while
	// preventing memory exhaustion if a service streams data continuously.
	defaultReadLimit = 4096

	// defaultFingerprintTimeout is the per-connection deadline for both
	// dialling and reading. Services that send immediate banners (SSH, FTP)
	// respond in milliseconds; HTTP services need a full request-response
	// round-trip. Three seconds covers both with headroom for slow hosts.
	defaultFingerprintTimeout = 3 * time.Second
)

// BannerFingerprinter implements Fingerprinter by connecting to an open port
// and reading the service's greeting (its "banner"), or by issuing a minimal
// HTTP request for web services that wait for the client to speak first.
//
// Fingerprinting is deliberately separated from port scanning because the two
// have different connection lifecycles. The scanner dials and disconnects
// immediately to confirm reachability. The fingerprinter dials, reads (and
// sometimes writes), then disconnects to identify the software. Merging them
// would make the scanner aware of protocol details it must not care about.
type BannerFingerprinter struct {
	timeout    time.Duration
	readLimit  int
	httpPorts  map[int]bool // ports expected to speak plain HTTP
	httpsPorts map[int]bool // ports expected to speak HTTPS
}

// NewBannerFingerprinter constructs a BannerFingerprinter with common HTTP and
// HTTPS port defaults.
//
// timeout is the per-connection deadline; readLimit caps bytes read per banner.
// Zero or negative values fall back to package defaults.
func NewBannerFingerprinter(timeout time.Duration, readLimit int) *BannerFingerprinter {
	if timeout <= 0 {
		timeout = defaultFingerprintTimeout
	}
	if readLimit <= 0 {
		readLimit = defaultReadLimit
	}
	return &BannerFingerprinter{
		timeout:    timeout,
		readLimit:  readLimit,
		httpPorts:  buildPortMap(defaultHTTPPorts),
		httpsPorts: buildPortMap(defaultHTTPSPorts),
	}
}

// Fingerprint connects to port and attempts to identify the running service.
//
// Strategy selection is based on port number:
//   - Known HTTPS ports: TLS dial followed by an HTTP HEAD request.
//   - Known HTTP ports:  plain dial followed by an HTTP HEAD request.
//   - All other ports:   read whatever bytes the service sends on connection.
//
// It always returns a Service. When identification is inconclusive, Name and
// Version are empty strings and Banner holds the raw bytes received —
// preserving evidence for manual analysis without treating ambiguity as a
// failure.
func (f *BannerFingerprinter) Fingerprint(port models.Port) (models.Service, error) {
	svc := models.Service{Port: port}

	var (
		banner string
		err    error
	)

	switch {
	case f.httpsPorts[port.Number]:
		banner, err = f.grabHTTPSBanner(port)
	case f.httpPorts[port.Number]:
		banner, err = f.grabHTTPBanner(port)
	default:
		banner, err = f.grabRawBanner(port)
	}

	if err != nil {
		return svc, fmt.Errorf("banner_fingerprinter: %s:%d: %w",
			port.IP, port.Number, err)
	}

	svc.Banner = banner
	svc.Name, svc.Version = parseServiceBanner(banner)
	return svc, nil
}

// grabRawBanner dials port and reads the first f.readLimit bytes without
// sending anything. Used for services that emit a greeting on connection
// (SSH, FTP, SMTP, POP3, IMAP).
func (f *BannerFingerprinter) grabRawBanner(port models.Port) (string, error) {
	addr := net.JoinHostPort(port.IP, strconv.Itoa(port.Number))
	conn, err := net.DialTimeout(port.Proto, addr, f.timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	// net.DialTimeout only bounds the dial, not subsequent reads on the
	// established connection. Set a read deadline before handing off to
	// readBanner so a silent server cannot stall the scan indefinitely.
	if err := conn.SetReadDeadline(time.Now().Add(f.timeout)); err != nil {
		return "", err
	}
	return f.readBanner(conn), nil
}

// grabHTTPBanner dials port, sends a minimal HTTP/1.0 HEAD request, and reads
// the response. HTTP/1.0 is chosen over 1.1 because 1.0 servers close the
// connection after the response, eliminating the need to parse Content-Length
// or chunked encoding just to know when to stop reading.
func (f *BannerFingerprinter) grabHTTPBanner(port models.Port) (string, error) {
	addr := net.JoinHostPort(port.IP, strconv.Itoa(port.Number))
	conn, err := net.DialTimeout(port.Proto, addr, f.timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return f.probeHTTP(conn, port)
}

// grabHTTPSBanner dials port over TLS, then follows the same HTTP probe as
// grabHTTPBanner.
//
// InsecureSkipVerify is intentional. External scanning targets frequently
// present self-signed, expired, or hostname-mismatched certificates — these
// are themselves security findings. Refusing to connect on certificate errors
// would hide the underlying service from our results.
func (f *BannerFingerprinter) grabHTTPSBanner(port models.Port) (string, error) {
	addr := net.JoinHostPort(port.IP, strconv.Itoa(port.Number))
	dialer := &net.Dialer{Timeout: f.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) // #nosec G402 — intentional for external recon
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return f.probeHTTP(conn, port)
}

// probeHTTP writes a HEAD / HTTP/1.0 request to conn and reads back the
// response headers. The deadline is set before writing so the entire
// round-trip is bounded by f.timeout.
//
// The Host header is set to the IP address and port, not the domain name.
// This is a design limitation of the Fingerprinter interface: Fingerprint
// only receives a Port (IP + number + proto) with no hostname context.
// Servers that use virtual hosting may return a generic or default response
// for an IP-based Host header rather than the intended vhost.
// The WebFingerprinter interface resolves this by accepting a domain name
// explicitly — use it when technology-level identification requires the
// correct Host header.
func (f *BannerFingerprinter) probeHTTP(conn net.Conn, port models.Port) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(f.timeout)); err != nil {
		return "", err
	}
	req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
		net.JoinHostPort(port.IP, strconv.Itoa(port.Number)))
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}
	return f.readBanner(conn), nil
}

// readBanner reads up to f.readLimit bytes from conn and returns the result as
// a trimmed string.
//
// Callers are responsible for setting a deadline on conn before calling this
// method — readBanner is a pure reader and does not modify connection state.
//
// io.ReadAll loops until EOF or error, which matters for multi-segment TCP
// responses (e.g. HTTP headers split across two packets). A single conn.Read
// would return on the first segment and silently miss any Server: header that
// arrives in a later one. When the connection deadline fires, ReadAll returns
// whatever bytes arrived — so a partial read is not treated as failure.
//
// Why no error return? The only errors io.ReadAll can return here are deadline
// errors (expected — they signal "read window over") and connection resets
// (benign — the service closed the connection after sending its banner). In
// both cases the bytes received so far are the result we want. Propagating
// these errors would cause callers to discard valid banner data.
func (f *BannerFingerprinter) readBanner(conn net.Conn) string {
	data, _ := io.ReadAll(io.LimitReader(conn, int64(f.readLimit)))
	return strings.TrimSpace(string(data))
}

// parseServiceBanner extracts a service name and version from a raw banner
// string. Returns empty strings when the banner does not match any known
// format — ambiguity is not a failure.
//
// Recognised patterns:
//   - SSH:        "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1"
//   - HTTP:       "HTTP/1.x NNN ...\r\nServer: nginx/1.18.0\r\n..."
//   - FTP / SMTP: "220 <software> ..."
//   - POP3:       "+OK Dovecot ready."
//   - IMAP:       "* OK IMAP4rev1 ..."
func parseServiceBanner(banner string) (name, version string) {
	if banner == "" {
		return
	}

	switch {
	case strings.HasPrefix(banner, "SSH-"):
		return parseSSHBanner(banner)
	case strings.HasPrefix(banner, "HTTP/"):
		return parseHTTPBanner(banner)
	case strings.HasPrefix(banner, "220"):
		return parseFTPSMTPBanner(banner)
	case strings.HasPrefix(banner, "+OK"):
		return parsePOP3Banner(banner)
	case strings.HasPrefix(banner, "* OK"):
		return parseIMAPBanner(banner)
	}
	return
}

// parseSSHBanner extracts name and version from an SSH protocol banner.
//
// The SSH wire format is: "SSH-<protoversion>-<softwareversion>[ <comments>]"
// Example: "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1"
// The software field uses an underscore to separate name from version, so
// "OpenSSH_8.4p1" becomes name="openssh", version="8.4p1".
func parseSSHBanner(banner string) (name, version string) {
	firstLine := strings.TrimRight(strings.SplitN(banner, "\n", 2)[0], "\r")
	parts := strings.SplitN(firstLine, "-", 3)
	if len(parts) < 3 {
		return "ssh", ""
	}

	// parts[2] = "OpenSSH_8.4p1 Ubuntu-6ubuntu2.1"
	// Take only the first space-delimited token to drop distro comments.
	software := strings.Fields(parts[2])
	if len(software) == 0 {
		return "ssh", ""
	}

	sub := strings.SplitN(software[0], "_", 2)
	name = strings.ToLower(sub[0])
	if len(sub) > 1 {
		version = sub[1]
	}
	return
}

// parseHTTPBanner extracts name and version from an HTTP response header block.
//
// The Server header format is: "Software/version [comment]"
// Example: "Server: nginx/1.18.0 (Ubuntu)" → name="nginx", version="1.18.0"
func parseHTTPBanner(banner string) (name, version string) {
	for _, line := range strings.Split(banner, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(strings.ToLower(line), "server:") {
			continue
		}
		val := strings.TrimSpace(line[len("server:"):])
		parts := strings.SplitN(val, "/", 2)
		name = strings.ToLower(strings.TrimSpace(parts[0]))
		if len(parts) > 1 {
			// "1.18.0 (Ubuntu)" → take only the version token, if present.
			// Guard against a trailing slash with nothing after it
			// (e.g. "Server: nginx/"), which would produce an empty fields
			// slice and panic on [0].
			if fields := strings.Fields(parts[1]); len(fields) > 0 {
				version = fields[0]
			}
		}
		return
	}
	// Response arrived but no Server header — still an HTTP server.
	name = "http"
	return
}

// parsePOP3Banner identifies a POP3 server from its "+OK" greeting.
//
// POP3 servers (RFC 1939) always open with "+OK <implementation> ready" or a
// similar "+OK" line. Version extraction is not attempted — POP3 greetings
// vary too widely across implementations to parse reliably from the first line.
func parsePOP3Banner(_ string) (name, version string) {
	return "pop3", ""
}

// parseIMAPBanner identifies an IMAP server from its "* OK" untagged greeting.
//
// IMAP4rev1 servers (RFC 3501) open with "* OK [CAPABILITY ...] Server ready"
// or a bare "* OK Server ready". The capability list is embedded in brackets
// and not consistently formatted, so we identify the service without attempting
// version extraction.
func parseIMAPBanner(_ string) (name, version string) {
	return "imap", ""
}

// parseFTPSMTPBanner identifies FTP and SMTP services from their 220 greeting.
//
// Both protocols open with "220 <hostname|software> ..." on connection. The
// distinguishing signal is whether the banner mentions known software keywords.
//
// SMTP is checked first because the FTP case includes the bare keyword "ftp",
// which can appear in hostnames (e.g. "smtp-ftp-relay.corp.com ESMTP Postfix").
// Only specific, unambiguous SMTP identifiers are used — "postfix", "sendmail",
// and "esmtp" — because the bare keyword "smtp" can appear in hostnames
// (e.g. "220 ftp.smtp-gateway.example.com ProFTPD 1.3.6") and would cause an
// FTP server to be misclassified as SMTP. "esmtp" alone is sufficient: any server
// that announces itself as ESMTP-capable is an SMTP server.
func parseFTPSMTPBanner(banner string) (name, version string) {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "postfix"), strings.Contains(lower, "sendmail"),
		strings.Contains(lower, "esmtp"):
		name = "smtp"
	case strings.Contains(lower, "proftpd"), strings.Contains(lower, "vsftpd"),
		strings.Contains(lower, "pure-ftpd"), strings.Contains(lower, "ftp"):
		name = "ftp"
	default:
		// 220 is used by several other protocols too; leave name empty
		// rather than misclassify.
	}
	return
}
