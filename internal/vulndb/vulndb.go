// Package vulndb maps known-vulnerable service versions to CVE records.
//
// Its single responsibility is answering "given a service name and version
// string, which known vulnerabilities apply?" The check is local — no network
// calls, no external files — so it adds zero latency to the scan pipeline.
//
// Why hardcoded data rather than an external JSON file?
// A CLI tool used for external recon should have no external dependencies at
// runtime beyond the network itself. A JSON file adds file-system I/O, error
// handling, a new flag, and a deployment artefact. The hardcoded map is a
// single Go file — trivially auditable, trivially updatable, always available.
// When the CVE list grows large enough to justify a database, the
// VulnerabilityChecker interface makes swapping the implementation a one-line
// change in main.go.
//
// Why does this package import pkg/models rather than define its own types?
// models.Vulnerability must be assignable to models.Service.Vulnerabilities,
// and pkg/models cannot import internal packages. Defining the type here and
// also in models would create two incompatible types for the same concept.
// The solution is to own the type in models (the shared vocabulary layer) and
// have this package import it — a legitimate dependency direction.
package vulndb

import (
	"strconv"
	"strings"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// VulnerabilityChecker is the interface consumed by cmd/asm/main.go.
//
// The narrow interface means main.go is decoupled from the VulnDB
// implementation — tests can inject a stub that returns pre-canned results
// without loading the full CVE dataset.
type VulnerabilityChecker interface {
	// Check returns all known vulnerabilities for the given service name and
	// version string. Returns nil when no vulnerabilities are known, when name
	// is unrecognised, or when version is empty and the rule requires a version.
	Check(name, version string) []models.Vulnerability
}

// vulnRule defines a version range for a single CVE.
type vulnRule struct {
	// minVersion is the first affected version (inclusive). An empty string
	// means all versions up to maxVersion are affected.
	minVersion string

	// maxVersion is the last affected version (inclusive). The version reported
	// by the fingerprinter must be ≤ maxVersion for the rule to fire.
	maxVersion string

	vuln models.Vulnerability
}

// VulnDB implements VulnerabilityChecker against a hardcoded CVE dataset.
//
// The dataset is intentionally curated rather than exhaustive — it covers the
// highest-impact, most commonly encountered vulnerabilities in external attack
// surface assessments. Each entry was selected because it is: (a) remotely
// exploitable without authentication, or (b) widely present on forgotten
// infrastructure, or (c) directly relevant to the protocols the ASM engine
// fingerprints.
type VulnDB struct {
	// rules maps lowercase service names to their vulnerability rules.
	// The service name must match the Name field produced by the fingerprinter.
	rules map[string][]vulnRule
}

// New constructs a VulnDB loaded with the built-in CVE dataset.
func New() *VulnDB {
	db := &VulnDB{rules: make(map[string][]vulnRule)}
	db.load()
	return db
}

// load populates the rules map with the built-in CVE entries.
//
// Version ranges are specified as the last known-vulnerable version. When a
// minimum version exists (e.g. regreSSHion only affects 8.5p1 and later), both
// bounds are set. When all versions up to the maximum are affected, minVersion
// is left empty.
func (v *VulnDB) load() {
	// --- OpenSSH ---
	v.add("openssh", vulnRule{
		// regreSSHion: signal handler race condition in sshd.
		// Introduced in OpenSSH 8.5p1 when a fix for CVE-2006-5051 was
		// accidentally reverted. Allows unauthenticated RCE as root on
		// glibc-based Linux systems. Patched in 9.8p1.
		minVersion: "8.5p1",
		maxVersion: "9.7p1",
		vuln: models.Vulnerability{
			CVE:      "CVE-2024-6387",
			Severity: models.Critical,
			Description: "regreSSHion — unauthenticated RCE via signal handler race " +
				"in sshd (affects 8.5p1–9.7p1, patched in 9.8p1)",
		},
	})
	v.add("openssh", vulnRule{
		// Username enumeration: timing side-channel in the authentication
		// failure path leaks whether an account exists.
		maxVersion: "7.6",
		vuln: models.Vulnerability{
			CVE:         "CVE-2018-15473",
			Severity:    models.Medium,
			Description: "username enumeration via timing side-channel in authentication failure path",
		},
	})

	// --- Apache httpd ---
	v.add("apache", vulnRule{
		// Path traversal: %2e%2e%2f sequences bypass access controls, allowing
		// unauthenticated read of arbitrary files and, with mod_cgi enabled, RCE.
		// Only affects 2.4.49. A variant (CVE-2021-42013) extends to 2.4.50.
		minVersion: "2.4.49",
		maxVersion: "2.4.50",
		vuln: models.Vulnerability{
			CVE:         "CVE-2021-41773",
			Severity:    models.Critical,
			Description: "path traversal + unauthenticated RCE via %2e%2e%2f sequences (2.4.49–2.4.50 only)",
		},
	})
	v.add("apache", vulnRule{
		// Buffer overflow: a crafted request body triggers a heap buffer overflow
		// in mod_lua, crashing the worker process. Affects all 2.4.x before 2.4.52.
		maxVersion: "2.4.51",
		vuln: models.Vulnerability{
			CVE:         "CVE-2021-44790",
			Severity:    models.High,
			Description: "mod_lua buffer overflow via crafted request body (pre-2.4.52)",
		},
	})

	// --- nginx ---
	v.add("nginx", vulnRule{
		// Off-by-one write in the DNS resolver: a specially crafted DNS CNAME
		// response can corrupt one byte of heap memory. Exploitable for code
		// execution in specific configurations.
		maxVersion: "1.20.0",
		vuln: models.Vulnerability{
			CVE:         "CVE-2021-23017",
			Severity:    models.High,
			Description: "off-by-one write in DNS resolver via crafted CNAME response (pre-1.20.1)",
		},
	})

	// --- SMTP / Postfix ---
	v.add("smtp", vulnRule{
		// SMTP smuggling: inconsistent line-ending handling allows injecting
		// commands into an SMTP session, enabling spoofed email from trusted domains.
		// Affects Postfix < 3.5.23, 3.6.x < 3.6.17, 3.7.x < 3.7.17, etc.
		// Reported version from the fingerprinter is the Postfix version.
		maxVersion: "3.5.22",
		vuln: models.Vulnerability{
			CVE:         "CVE-2023-51764",
			Severity:    models.High,
			Description: "SMTP smuggling allows spoofed email from trusted domains (Postfix < 3.5.23)",
		},
	})

	// --- FTP / ProFTPD ---
	v.add("ftp", vulnRule{
		// Terrapin attack: prefix truncation in the SSH handshake allows
		// downgrading negotiated algorithms. ProFTPD uses embedded SSH-like
		// mechanisms in SFTP mode — older builds share the vulnerability.
		maxVersion: "1.3.7",
		vuln: models.Vulnerability{
			CVE:         "CVE-2023-48795",
			Severity:    models.High,
			Description: "Terrapin SSH prefix truncation attack affects SFTP mode (pre-1.3.8)",
		},
	})

	// --- IMAP / POP3 (Dovecot) ---
	// The fingerprinter does not extract a version for IMAP/POP3 banners, so
	// version-gated rules would never fire. These entries use an empty maxVersion
	// to match any version — they serve as informational notes rather than
	// precise version checks.
	v.add("imap", vulnRule{
		maxVersion: "",
		vuln: models.Vulnerability{
			CVE:         "CVE-2024-23184",
			Severity:    models.High,
			Description: "excessive resource allocation via malformed address headers in Dovecot (pre-2.3.21)",
		},
	})
	v.add("pop3", vulnRule{
		maxVersion: "",
		vuln: models.Vulnerability{
			CVE:         "CVE-2024-23184",
			Severity:    models.High,
			Description: "excessive resource allocation via malformed address headers in Dovecot (pre-2.3.21)",
		},
	})

	// --- Generic HTTP (informational) ---
	v.add("http", vulnRule{
		// Not a CVE — a configuration note. Plain HTTP transmits credentials and
		// session tokens in clear text; any network observer can intercept them.
		maxVersion: "",
		vuln: models.Vulnerability{
			CVE:      "",
			Severity: models.Low,
			Description: "plain HTTP — credentials and session tokens transmitted in clear text; " +
				"consider enforcing HTTPS",
		},
	})
}

// add appends a rule for the given service name.
func (v *VulnDB) add(service string, r vulnRule) {
	v.rules[service] = append(v.rules[service], r)
}

// Check returns all known vulnerabilities for the given service name and
// version string. It is safe to call with an empty version — the call returns
// nil rather than matching rules that require version comparison.
//
// Version comparison is performed with compareVersions, which handles both
// dotted-decimal (nginx "1.18.0", Apache "2.4.41") and OpenSSH-style
// "major.minor.patchpN" strings.
func (v *VulnDB) Check(name, version string) []models.Vulnerability {
	rules, ok := v.rules[strings.ToLower(name)]
	if !ok {
		return nil
	}

	var matches []models.Vulnerability
	for _, r := range rules {
		// When maxVersion is empty the rule is an unconditional note — it fires
		// regardless of version (used for IMAP/POP3/HTTP informational entries).
		if r.maxVersion == "" {
			matches = append(matches, r.vuln)
			continue
		}
		// Skip if we have no version string to compare against.
		if version == "" {
			continue
		}
		// The reported version must be ≤ maxVersion.
		if compareVersions(version, r.maxVersion) > 0 {
			continue
		}
		// If a minimum version is set, the reported version must be ≥ minVersion.
		if r.minVersion != "" && compareVersions(version, r.minVersion) < 0 {
			continue
		}
		matches = append(matches, r.vuln)
	}
	return matches
}

// compareVersions compares two version strings and returns:
//
//	-1 if a < b
//	 0 if a == b
//	+1 if a > b
//
// The comparison handles two formats:
//
//   - Dotted decimal: "1.18.0", "2.4.41"
//   - OpenSSH style:  "8.4p1" (patch level follows the letter 'p')
//
// Comparison is numeric component by component. The 'p' suffix is treated as
// a sub-patch component: "8.4p1" is parsed as [8, 4, 1] for comparison
// purposes. This approximation is correct for all OpenSSH versions in the CVE
// dataset — no OpenSSH release changes meaning between dotted-decimal and 'p'
// notation.
func compareVersions(a, b string) int {
	partsA := splitVersion(a)
	partsB := splitVersion(b)

	// Compare component by component; the shorter one is padded with zeros.
	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}
	for i := range maxLen {
		va, vb := 0, 0
		if i < len(partsA) {
			va = partsA[i]
		}
		if i < len(partsB) {
			vb = partsB[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}

// splitVersion converts a version string into a slice of integer components.
//
// "1.18.0"  → [1, 18, 0]
// "8.4p1"   → [8, 4, 1]   (the 'p' is treated as a component separator)
// "2.4.41"  → [2, 4, 41]
//
// Non-numeric components are treated as zero to avoid panics on unexpected
// version formats from fingerprinted banners.
func splitVersion(v string) []int {
	// Replace 'p' (OpenSSH patch separator) with '.' so all formats are uniform.
	v = strings.ReplaceAll(v, "p", ".")
	raw := strings.Split(v, ".")
	parts := make([]int, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			// Non-numeric component — treat as zero rather than failing the whole
			// comparison. This handles unusual suffixes like "1.18.0-ubuntu1".
			n = 0
		}
		parts = append(parts, n)
	}
	return parts
}
