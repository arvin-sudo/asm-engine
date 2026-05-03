package discovery

import (
	"net"
	"strings"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// DNSIntelResolver is the interface for TXT and MX record lookups used by
// DNSIntelligenceScanner.
//
// A dedicated interface rather than direct calls to net.LookupTXT and
// net.LookupMX keeps the scanner fully testable without a live DNS resolver.
// Both methods are grouped into one interface because they are always queried
// together during an intelligence scan — splitting them into two interfaces
// would provide no practical benefit here.
type DNSIntelResolver interface {
	LookupTXT(domain string) ([]string, error)
	LookupMX(domain string) ([]*net.MX, error)
}

// netDNSIntelResolver is the production DNSIntelResolver backed by the system
// resolver.
type netDNSIntelResolver struct{}

func (r *netDNSIntelResolver) LookupTXT(domain string) ([]string, error) {
	return net.LookupTXT(domain)
}

func (r *netDNSIntelResolver) LookupMX(domain string) ([]*net.MX, error) {
	return net.LookupMX(domain)
}

// NewNetDNSIntelResolver returns a DNSIntelResolver backed by the system DNS
// configuration. Pass this to NewDNSIntelligenceScanner in production; inject
// a mockDNSIntelResolver in tests.
func NewNetDNSIntelResolver() DNSIntelResolver {
	return &netDNSIntelResolver{}
}

// spfIncludes maps SPF include: targets to known third-party service names.
//
// SPF records expose which email and identity services an organisation has
// authorised to send on its behalf. Services like Mailgun or Zendesk that
// appear here may represent shadow IT assets — infrastructure integrated by
// one team without a full security review of the third party's own attack
// surface.
var spfIncludes = map[string]string{
	"mailgun.org":                 "Mailgun",
	"_spf.google.com":             "Google Workspace",
	"google.com":                  "Google Workspace",
	"spf.protection.outlook.com":  "Microsoft 365",
	"outlook.com":                 "Microsoft 365",
	"sendgrid.net":                "SendGrid",
	"amazonses.com":               "Amazon SES",
	"mandrillapp.com":             "Mandrill (Mailchimp)",
	"zendesk.com":                 "Zendesk",
	"salesforce.com":              "Salesforce",
	"_spf.salesforce.com":         "Salesforce",
	"mailchimp.com":               "Mailchimp",
	"postmarkapp.com":             "Postmark",
	"sparkpostmail.com":           "SparkPost",
}

// mxHosts maps substrings of MX record hostnames to known email providers.
//
// MX records directly reveal the email infrastructure in use, which is
// relevant for phishing risk assessment and for mapping third-party
// dependencies that sit at the boundary of the organisation's attack surface.
// Matching by substring rather than exact hostname means any subdomain variant
// of a provider's mail exchange is caught without maintaining an exhaustive list.
var mxHosts = map[string]string{
	"google.com":              "Google Workspace",
	"googlemail.com":          "Google Workspace",
	"outlook.com":             "Microsoft 365",
	"protection.outlook.com":  "Microsoft 365",
	"mailgun.org":             "Mailgun",
	"amazonses.com":           "Amazon SES",
	"zoho.com":                "Zoho Mail",
	"zohomail.com":            "Zoho Mail",
	"protonmail.ch":           "ProtonMail",
	"sendgrid.net":            "SendGrid",
	"messagingengine.com":     "FastMail",
	"mxrecord.io":             "Mailchimp",
}

// DNSIntelligenceScanner discovers third-party service integrations from a
// target domain's TXT and MX DNS records.
//
// TXT records often contain SPF policy strings that list every email and
// identity service the organisation has authorised — revealing integrations
// that may not be obvious from the public web presence. MX records identify
// the email provider, which is relevant for phishing risk and third-party
// dependency mapping. Together they paint a picture of the organisation's
// indirect attack surface that no amount of subdomain enumeration can reveal.
type DNSIntelligenceScanner struct {
	resolver DNSIntelResolver
}

// NewDNSIntelligenceScanner constructs a DNSIntelligenceScanner backed by the
// provided resolver.
func NewDNSIntelligenceScanner(r DNSIntelResolver) *DNSIntelligenceScanner {
	return &DNSIntelligenceScanner{resolver: r}
}

// Scan queries TXT and MX records for domain and returns a ServiceIndicator
// for each recognised third-party integration found.
//
// Both record types are queried independently. A failure on one (e.g. the
// domain has no TXT records or the resolver returns NXDOMAIN for MX) does not
// prevent the other from contributing results — the scan is best-effort and
// always returns whatever it can find. The error return is always nil; it
// exists only to satisfy a consistent interface pattern.
func (s *DNSIntelligenceScanner) Scan(domain string) ([]models.ServiceIndicator, error) {
	var indicators []models.ServiceIndicator

	if txts, err := s.resolver.LookupTXT(domain); err == nil {
		indicators = append(indicators, parseSPF(txts)...)
	}
	if mxs, err := s.resolver.LookupMX(domain); err == nil {
		indicators = append(indicators, parseMX(mxs)...)
	}

	return indicators, nil
}

// parseSPF scans TXT records for SPF policy strings and extracts service
// indicators from include: tokens.
//
// An SPF record looks like: "v=spf1 include:mailgun.org include:_spf.google.com ~all"
// Each include: target is matched against spfIncludes to identify the service.
// The same service name is reported at most once per call even if multiple
// include: targets match the same provider (e.g. both "google.com" and
// "_spf.google.com" resolve to "Google Workspace").
func parseSPF(txts []string) []models.ServiceIndicator {
	seen := make(map[string]struct{})
	var indicators []models.ServiceIndicator

	for _, txt := range txts {
		if !strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			continue
		}
		for _, token := range strings.Fields(txt) {
			token = strings.ToLower(token)
			if !strings.HasPrefix(token, "include:") {
				continue
			}
			target := strings.TrimPrefix(token, "include:")
			for pattern, service := range spfIncludes {
				if strings.Contains(target, pattern) {
					if _, ok := seen[service]; ok {
						continue
					}
					seen[service] = struct{}{}
					indicators = append(indicators, models.ServiceIndicator{
						Service:  service,
						Record:   "TXT",
						Evidence: txt,
					})
				}
			}
		}
	}
	return indicators
}

// parseMX matches MX record hostnames against mxHosts to identify the email
// provider in use.
//
// MX hostnames frequently contain vendor-specific substrings
// (e.g. "aspmx.l.google.com" → Google Workspace). The same provider is
// reported at most once even if multiple MX records match the same pattern —
// a domain may have several MX records for failover, but the provider is the
// same for all of them.
func parseMX(mxs []*net.MX) []models.ServiceIndicator {
	seen := make(map[string]struct{})
	var indicators []models.ServiceIndicator

	for _, mx := range mxs {
		host := strings.ToLower(strings.TrimRight(mx.Host, "."))
		for pattern, service := range mxHosts {
			if strings.Contains(host, pattern) {
				if _, ok := seen[service]; ok {
					continue
				}
				seen[service] = struct{}{}
				indicators = append(indicators, models.ServiceIndicator{
					Service:  service,
					Record:   "MX",
					Evidence: mx.Host,
				})
			}
		}
	}
	return indicators
}
