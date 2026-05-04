package discovery

import (
	"net"
	"testing"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// hasService returns true if any indicator in the slice has the given service name.
func hasService(indicators []models.ServiceIndicator, service string) bool {
	for _, ind := range indicators {
		if ind.Service == service {
			return true
		}
	}
	return false
}

// mockDNSIntelResolver is a test double for DNSIntelResolver.
type mockDNSIntelResolver struct {
	txts   []string
	mxs    []*net.MX
	txtErr error
	mxErr  error
}

func (m *mockDNSIntelResolver) LookupTXT(_ string) ([]string, error) {
	return m.txts, m.txtErr
}

func (m *mockDNSIntelResolver) LookupMX(_ string) ([]*net.MX, error) {
	return m.mxs, m.mxErr
}

func TestDNSIntelligenceScanner_Scan(t *testing.T) {
	tests := []struct {
		name         string
		resolver     *mockDNSIntelResolver
		wantCount    int
		wantServices []string // service names that must appear in results
		wantRecords  []string // record type (TXT/MX) for each wantServices entry
	}{
		{
			name: "Mailgun detected via SPF include",
			resolver: &mockDNSIntelResolver{
				txts: []string{"v=spf1 include:mailgun.org ~all"},
			},
			wantCount:    1,
			wantServices: []string{"Mailgun"},
			wantRecords:  []string{"TXT"},
		},
		{
			name: "Microsoft 365 detected via MX record",
			resolver: &mockDNSIntelResolver{
				mxs: []*net.MX{{Host: "example-org.mail.protection.outlook.com."}},
			},
			wantCount:    1,
			wantServices: []string{"Microsoft 365"},
			wantRecords:  []string{"MX"},
		},
		{
			name: "multiple services detected from one SPF record",
			resolver: &mockDNSIntelResolver{
				txts: []string{"v=spf1 include:mailgun.org include:_spf.google.com ~all"},
			},
			wantCount:    2,
			wantServices: []string{"Mailgun", "Google Workspace"},
		},
		{
			name: "non-SPF TXT records are ignored",
			resolver: &mockDNSIntelResolver{
				txts: []string{"google-site-verification=abc123", "MS=ms12345678"},
			},
			wantCount: 0,
		},
		{
			// Google Workspace can match both "_spf.google.com" and "google.com"
			// patterns in the same SPF string. It should only be reported once.
			name: "same service matched by multiple SPF patterns reported once",
			resolver: &mockDNSIntelResolver{
				txts: []string{"v=spf1 include:_spf.google.com include:google.com ~all"},
			},
			wantCount:    1,
			wantServices: []string{"Google Workspace"},
		},
		{
			// Google Workspace appears in both SPF (TXT) and MX — these are two
			// distinct indicators with different record types and evidence, so
			// both should be reported.
			name: "same service from TXT and MX produces two separate indicators",
			resolver: &mockDNSIntelResolver{
				txts: []string{"v=spf1 include:_spf.google.com ~all"},
				mxs:  []*net.MX{{Host: "aspmx.l.google.com."}},
			},
			wantCount: 2,
		},
		{
			// When the TXT lookup fails, MX results should still be returned.
			name: "TXT lookup failure does not block MX results",
			resolver: &mockDNSIntelResolver{
				txtErr: &net.DNSError{Err: "no such host"},
				mxs:    []*net.MX{{Host: "mail.protection.outlook.com."}},
			},
			wantCount:    1,
			wantServices: []string{"Microsoft 365"},
		},
		{
			// When the MX lookup fails, TXT results should still be returned.
			name: "MX lookup failure does not block TXT results",
			resolver: &mockDNSIntelResolver{
				txts:  []string{"v=spf1 include:sendgrid.net ~all"},
				mxErr: &net.DNSError{Err: "no such host"},
			},
			wantCount:    1,
			wantServices: []string{"SendGrid"},
		},
		{
			name: "domain with no DNS records returns empty slice without error",
			resolver: &mockDNSIntelResolver{
				txtErr: &net.DNSError{Err: "no such host"},
				mxErr:  &net.DNSError{Err: "no such host"},
			},
			wantCount: 0,
		},
		{
			// Multiple MX records for the same provider should be reported once.
			name: "multiple MX records for the same provider deduplicated",
			resolver: &mockDNSIntelResolver{
				mxs: []*net.MX{
					{Host: "aspmx.l.google.com."},
					{Host: "alt1.aspmx.l.google.com."},
					{Host: "alt2.aspmx.l.google.com."},
				},
			},
			wantCount:    1,
			wantServices: []string{"Google Workspace"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewDNSIntelligenceScanner(tt.resolver)
			got, err := scanner.Scan("example.com")

			if err != nil {
				t.Fatalf("Scan returned unexpected error: %v", err)
			}
			if len(got) != tt.wantCount {
				t.Errorf("got %d indicator(s), want %d; results: %v", len(got), tt.wantCount, got)
			}

			gotServices := make(map[string]string, len(got)) // service → record type
			for _, ind := range got {
				gotServices[ind.Service] = ind.Record
			}

			for i, svc := range tt.wantServices {
				if _, ok := gotServices[svc]; !ok {
					t.Errorf("missing expected service %q; got %v", svc, got)
					continue
				}
				if len(tt.wantRecords) > i && tt.wantRecords[i] != "" {
					if gotServices[svc] != tt.wantRecords[i] {
						t.Errorf("service %q: Record = %q, want %q", svc, gotServices[svc], tt.wantRecords[i])
					}
				}
			}
		})
	}
}

// TestParseSPF directly exercises the SPF helper, focusing on cases that the
// higher-level Scan tests do not reach — in particular the suffix-match branch
// (e.g. "eu.mailgun.org" matching the "mailgun.org" pattern).
func TestParseSPF(t *testing.T) {
	tests := []struct {
		name         string
		txts         []string
		wantServices []string
		wantCount    int
	}{
		{
			name:         "empty TXT records return no indicators",
			txts:         nil,
			wantCount:    0,
		},
		{
			name:         "non-SPF TXT record is ignored",
			txts:         []string{"google-site-verification=abc123"},
			wantCount:    0,
		},
		{
			// Exact match: include target equals the pattern key directly.
			name:         "exact include match detects Mailgun",
			txts:         []string{"v=spf1 include:mailgun.org ~all"},
			wantServices: []string{"Mailgun"},
			wantCount:    1,
		},
		{
			// Suffix match: "eu.mailgun.org" ends with ".mailgun.org".
			// This branch is never exercised by the Scan-level tests, which only
			// use exact include targets.
			name:         "subdomain include target matches via suffix rule",
			txts:         []string{"v=spf1 include:eu.mailgun.org ~all"},
			wantServices: []string{"Mailgun"},
			wantCount:    1,
		},
		{
			// Two patterns map to the same service — dedup must fire.
			name:         "same service from two patterns reported once",
			txts:         []string{"v=spf1 include:_spf.google.com include:google.com ~all"},
			wantServices: []string{"Google Workspace"},
			wantCount:    1,
		},
		{
			// Token without "include:" prefix must be silently ignored.
			name:         "non-include token does not produce an indicator",
			txts:         []string{"v=spf1 ip4:192.0.2.0/24 ~all"},
			wantCount:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSPF(tt.txts)
			if len(got) != tt.wantCount {
				t.Errorf("parseSPF: got %d indicator(s), want %d; results: %v",
					len(got), tt.wantCount, got)
			}
			for _, svc := range tt.wantServices {
				if !hasService(got, svc) {
					t.Errorf("parseSPF: expected service %q not found in %v", svc, got)
				}
			}
		})
	}
}

// TestParseMX directly exercises the MX helper, verifying trailing-dot stripping
// and deduplication. The Scan tests confirm overall behaviour but never assert
// that the dot-strip step specifically causes the match to succeed.
func TestParseMX(t *testing.T) {
	tests := []struct {
		name         string
		mxs          []*net.MX
		wantServices []string
		wantCount    int
	}{
		{
			name:      "nil MX slice returns no indicators",
			mxs:       nil,
			wantCount: 0,
		},
		{
			name:      "unrecognised MX host returns no indicators",
			mxs:       []*net.MX{{Host: "mail.unknown-provider.example."}},
			wantCount: 0,
		},
		{
			// The trailing FQDN dot must be stripped before matching.
			// Without stripping, "aspmx.l.google.com." would not end with
			// ".google.com" and the match would silently fail.
			name:         "trailing dot is stripped before matching",
			mxs:          []*net.MX{{Host: "aspmx.l.google.com."}},
			wantServices: []string{"Google Workspace"},
			wantCount:    1,
		},
		{
			// The same result must be produced when there is no trailing dot,
			// confirming the strip is safe to apply unconditionally.
			name:         "host without trailing dot also matches",
			mxs:          []*net.MX{{Host: "aspmx.l.google.com"}},
			wantServices: []string{"Google Workspace"},
			wantCount:    1,
		},
		{
			// Three failover MX records for the same provider must be deduplicated
			// to a single indicator.
			name: "multiple failover records for same provider deduplicated",
			mxs: []*net.MX{
				{Host: "aspmx.l.google.com."},
				{Host: "alt1.aspmx.l.google.com."},
				{Host: "alt2.aspmx.l.google.com."},
			},
			wantServices: []string{"Google Workspace"},
			wantCount:    1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMX(tt.mxs)
			if len(got) != tt.wantCount {
				t.Errorf("parseMX: got %d indicator(s), want %d; results: %v",
					len(got), tt.wantCount, got)
			}
			for _, svc := range tt.wantServices {
				if !hasService(got, svc) {
					t.Errorf("parseMX: expected service %q not found in %v", svc, got)
				}
			}
		})
	}
}
