package pipeline

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/arvin-sudo/asm-engine/internal/analysis"
	"github.com/arvin-sudo/asm-engine/internal/cloudscan"
	"github.com/arvin-sudo/asm-engine/internal/discovery"
	"github.com/arvin-sudo/asm-engine/internal/fingerprint"
	"github.com/arvin-sudo/asm-engine/internal/scanner"
	"github.com/arvin-sudo/asm-engine/internal/storage"
	"github.com/arvin-sudo/asm-engine/internal/vulndb"
	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// Config holds every parameter needed to execute one scan run.
// It mirrors the flags parsed in cmd/asm/main.go and is passed unchanged to
// both the CLI consumer and the SSE handler so neither has to re-parse flags.
type Config struct {
	// Domain is the normalised scan target (lowercase, no trailing dot).
	Domain string

	// Ports is the deduplicated list of TCP ports to probe in Phase 2.
	Ports []int

	// Workers is the goroutine pool size for the TCP port scanner.
	Workers int

	// ScanTimeout is the per-connection deadline for scanning and fingerprinting.
	ScanTimeout time.Duration

	// RateLimit is the maximum TCP connection attempts per second (0 = unlimited).
	RateLimit int

	// DSN is the PostgreSQL connection string. Empty disables persistence.
	DSN string

	// IsLocal skips the CT log / OSINT phases (Phase 1a–1d) and builds a
	// synthetic Asset directly from the target. Set for IP addresses and bare
	// hostnames that have no public DNS history (e.g. Docker service names).
	IsLocal bool
}

// Runner executes the ASM scan pipeline and emits typed ScanEvents on a
// channel. It holds references to every concrete implementation so NewRunner
// instantiates them once — the Run method can be called multiple times on the
// same Runner without re-dialling DNS or re-reading the vulndb dataset.
type Runner struct {
	subdiscoverer discovery.SubdomainDiscoverer
	resolver      discovery.Discoverer
	ptrEnricher   *discovery.PTREnricher
	intelScanner  *discovery.DNSIntelligenceScanner
	tcpScanner    scanner.Scanner
	bannerFP      fingerprint.Fingerprinter
	webFP         fingerprint.WebFingerprinter
	vulnChecker   vulndb.VulnerabilityChecker
	cloudScanner  cloudscan.CloudScanner
	store         storage.Store    // nil when Config.DSN == ""
	differ        *analysis.Differ // nil when store == nil
}

// DefaultPorts is the set of TCP ports probed when the caller does not specify
// a custom port list. It is defined here — rather than in cmd/ or web/ — so
// both consumers share a single source of truth without importing each other.
//
// The selection covers services most commonly exposed on an external attack
// surface: web servers, SSH, database engines, remote desktop, and popular
// NoSQL stores. Deliberately narrower than nmap's top-1000 list; the goal is
// fast, signal-rich output rather than exhaustive enumeration.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017,
}

// webServiceNames is the set of service names for which web technology
// fingerprinting is attempted. Duplicated from main.go so the Runner is
// self-contained and main.go can delegate completely.
var webServiceNames = map[string]bool{
	"http": true, "https": true, "nginx": true, "apache": true, "iis": true,
}

// HTTP client timeouts for OSINT sources — kept in sync with main.go values.
const (
	ctLogTimeout        = 30 * time.Second
	hackerTargetTimeout = 10 * time.Second
	waybackTimeout      = 60 * time.Second

	// eventChannelBufferSize is the capacity of the ScanEvent channel returned
	// by Run. A buffer of 64 gives the pipeline goroutine enough headroom during
	// the Phase 1b subdomain burst so it never blocks waiting for the consumer.
	// If the buffer overflows under extreme load, events are dropped gracefully
	// (progress updates, not findings) rather than stalling the scan goroutine.
	eventChannelBufferSize = 64
)

// NewRunner constructs a Runner by wiring every concrete implementation.
// This is the single instantiation point: cmd/asm/main.go and internal/web
// both call NewRunner and hand the result to Run. If DSN is set, a live
// PostgreSQL connection is opened; the caller must not call NewRunner when the
// DB is unreachable and DSN is set — NewPostgresStore returns an error.
func NewRunner(cfg Config) (*Runner, error) {
	r := &Runner{
		subdiscoverer: discovery.NewMultiSourceDiscoverer(
			discovery.NewCTDiscoverer(&http.Client{Timeout: ctLogTimeout}),
			discovery.NewHackerTargetDiscoverer(&http.Client{Timeout: hackerTargetTimeout}),
			discovery.NewWayBackDiscoverer(&http.Client{Timeout: waybackTimeout}),
		),
		resolver:     discovery.NewDNSResolver(discovery.NewNetResolver()),
		ptrEnricher:  discovery.NewPTREnricher(discovery.NewNetPTRResolver()),
		intelScanner: discovery.NewDNSIntelligenceScanner(discovery.NewNetDNSIntelResolver()),
		tcpScanner:   scanner.NewTCPScanner(cfg.Ports, cfg.ScanTimeout, cfg.Workers, cfg.RateLimit),
		bannerFP:     fingerprint.NewBannerFingerprinter(cfg.ScanTimeout+time.Second, 4096),
		webFP:        fingerprint.NewWebStackFingerprinter(cfg.ScanTimeout + time.Second),
		vulnChecker:  vulndb.New(),
		cloudScanner: cloudscan.NewBucketHunter(&http.Client{Timeout: 10 * time.Second}),
	}

	if cfg.DSN != "" {
		ps, err := storage.NewPostgresStore(cfg.DSN)
		if err != nil {
			return nil, fmt.Errorf("runner: store: %w", err)
		}
		r.store = ps
		r.differ = analysis.NewDiffer(ps)
	}

	return r, nil
}

// Close releases resources held by the Runner (primarily the DB connection
// pool). Must be called when the Runner is no longer needed.
func (r *Runner) Close() {
	if r.store != nil {
		r.store.Close()
	}
}

// Run executes the full scan pipeline for cfg.Domain and sends typed ScanEvents
// on the returned channel. The channel is closed when the pipeline completes or
// when ctx is cancelled — callers may range over it safely.
//
// Run spawns exactly one goroutine. If cfg.IsLocal is true the CT log / OSINT
// phases (1a–1d) are skipped and a synthetic Asset is built directly from the
// target so that IP addresses and Docker service names work without modification.
func (r *Runner) Run(ctx context.Context, cfg Config) <-chan ScanEvent {
	ch := make(chan ScanEvent, eventChannelBufferSize)
	go func() {
		defer close(ch)
		r.execute(ctx, cfg, ch)
	}()
	return ch
}

// execute is the private method that performs the pipeline. It is separated
// from Run so the goroutine wrapper stays trivial and the full logic is
// readable as a linear sequence of phases.
func (r *Runner) execute(ctx context.Context, cfg Config, ch chan<- ScanEvent) {
	domain := cfg.Domain

	// -------------------------------------------------------------------------
	// Persistence header
	// -------------------------------------------------------------------------
	if r.store != nil {
		emit(ch, newEvent(EventPhaseStart, PhasePayload{
			Phase:   "db",
			Message: "Persistence enabled — connected to database.",
		}))
	}

	// -------------------------------------------------------------------------
	// Phase 1 — asset discovery (skipped for local targets)
	// -------------------------------------------------------------------------
	var liveAssets []models.Asset

	if cfg.IsLocal {
		// Bypass all OSINT phases. Build one synthetic Asset so Phase 2 can run.
		// isLocalTarget already validated the domain; buildSyntheticAsset resolves
		// a bare hostname via the OS DNS (which works inside Docker bridge networks).
		synth := buildSyntheticAsset(domain)
		liveAssets = []models.Asset{synth}
		if r.store != nil {
			if err := r.store.SaveAsset(synth); err != nil {
				emit(ch, newEvent(EventError, ErrorPayload{
					Phase:   "1",
					Message: fmt.Sprintf("save asset %q: %v", synth.Domain, err),
				}))
			}
		}
		emit(ch, newEvent(EventPhaseComplete, PhasePayload{
			Phase:   "1a-1d",
			Message: fmt.Sprintf("OSINT phases skipped — local target detected (%s).", domain),
		}))
	} else {
		liveAssets = r.runPhase1(ctx, domain, ch)
	}

	if ctx.Err() != nil {
		return
	}

	// -------------------------------------------------------------------------
	// Phase 2 — TCP port scanning + fingerprinting
	// -------------------------------------------------------------------------
	if len(liveAssets) > 0 {
		r.runPhase2(ctx, cfg, liveAssets, ch)
	} else {
		emit(ch, newEvent(EventPhaseComplete, PhasePayload{
			Phase:   "2",
			Message: "Phase 2: skipped — no live assets to scan.",
		}))
	}

	if ctx.Err() != nil {
		return
	}

	// -------------------------------------------------------------------------
	// Phase 3 — cloud bucket hunting
	// -------------------------------------------------------------------------
	r.runPhase3(ctx, domain, ch)

	emit(ch, newEvent(EventDone, DonePayload{Summary: "Scan complete."}))
}

// runPhase1 runs phases 1a through 1d and returns the live assets found.
func (r *Runner) runPhase1(ctx context.Context, domain string, ch chan<- ScanEvent) []models.Asset {
	// --- Phase 1a: passive subdomain discovery ---
	emit(ch, newEvent(EventPhaseStart, PhasePayload{
		Phase:   "1a",
		Message: fmt.Sprintf("Phase 1a: passive recon for %s (CT logs, HackerTarget, WayBack)...", domain),
	}))

	subdomains, err := r.subdiscoverer.Discover(ctx, domain)
	if err != nil {
		emit(ch, newEvent(EventError, ErrorPayload{Phase: "1a", Message: err.Error()}))
		return nil
	}

	emit(ch, newEvent(EventPhaseComplete, PhasePayload{
		Phase:   "1a",
		Message: fmt.Sprintf("Found %d %s.", len(subdomains), pluralise(len(subdomains), "subdomain", "subdomains")),
	}))

	if ctx.Err() != nil {
		return nil
	}

	// --- Phase 1b: DNS resolution ---
	var liveAssets []models.Asset
	var wildcardCount int

	for _, s := range subdomains {
		if ctx.Err() != nil {
			return liveAssets
		}
		if s.IsWildcard() {
			emit(ch, newEvent(EventSubdomain, SubdomainPayload{
				Name:   s.Name,
				Source: s.Source,
				Status: "wildcard",
			}))
			wildcardCount++
			continue
		}

		asset, err := r.resolver.Discover(s.Name)
		if err != nil {
			emit(ch, newEvent(EventSubdomain, SubdomainPayload{
				Name:   s.Name,
				Source: s.Source,
				Status: "dead",
			}))
			continue
		}

		emit(ch, newEvent(EventSubdomain, SubdomainPayload{
			Name:   asset.Domain,
			Source: s.Source,
			Status: "live",
			IPs:    asset.IPs,
		}))
		liveAssets = append(liveAssets, asset)

		if r.store != nil {
			if err := r.store.SaveAsset(asset); err != nil {
				emit(ch, newEvent(EventError, ErrorPayload{Phase: "1b", Message: fmt.Sprintf("save asset %q: %v", asset.Domain, err)}))
			}
		}
	}

	deadCount := len(subdomains) - len(liveAssets) - wildcardCount
	emit(ch, newEvent(EventPhaseComplete, PhasePayload{
		Phase: "1b",
		Message: fmt.Sprintf("Phase 1b complete: %d live, %d wildcard, %d dead — %d total subdomains discovered.",
			len(liveAssets), wildcardCount, deadCount, len(subdomains)),
	}))

	if ctx.Err() != nil {
		return liveAssets
	}

	// --- Phase 1c: PTR reverse DNS enrichment ---
	if len(liveAssets) > 0 {
		emit(ch, newEvent(EventPhaseStart, PhasePayload{
			Phase:   "1c",
			Message: "Phase 1c: PTR enrichment on discovered IPs...",
		}))

		var allIPs []string
		for _, a := range liveAssets {
			allIPs = append(allIPs, a.IPs...)
		}

		knownDomains := make(map[string]struct{}, len(liveAssets))
		for _, a := range liveAssets {
			knownDomains[a.Domain] = struct{}{}
		}

		ptrSubs := r.ptrEnricher.Enrich(allIPs)
		ptrNew := 0

		for _, s := range ptrSubs {
			if ctx.Err() != nil {
				return liveAssets
			}
			if _, ok := knownDomains[s.Name]; ok {
				continue
			}
			if s.IsWildcard() {
				emit(ch, newEvent(EventSubdomain, SubdomainPayload{
					Name:   s.Name,
					Status: "ptr_wildcard",
				}))
				continue
			}

			asset, err := r.resolver.Discover(s.Name)
			if err != nil {
				emit(ch, newEvent(EventSubdomain, SubdomainPayload{
					Name:   s.Name,
					Status: "ptr_dead",
				}))
				continue
			}

			emit(ch, newEvent(EventSubdomain, SubdomainPayload{
				Name:   asset.Domain,
				Status: "ptr_live",
				IPs:    asset.IPs,
			}))
			liveAssets = append(liveAssets, asset)
			knownDomains[asset.Domain] = struct{}{}
			ptrNew++

			if r.store != nil {
				if err := r.store.SaveAsset(asset); err != nil {
					emit(ch, newEvent(EventError, ErrorPayload{Phase: "1c", Message: fmt.Sprintf("save asset %q: %v", asset.Domain, err)}))
				}
			}
		}

		emit(ch, newEvent(EventPhaseComplete, PhasePayload{
			Phase:   "1c",
			Message: fmt.Sprintf("Phase 1c complete: %d new asset(s) discovered via PTR.", ptrNew),
		}))
	} else {
		emit(ch, newEvent(EventPhaseComplete, PhasePayload{
			Phase:   "1c",
			Message: "Phase 1c: skipped — no live assets to enrich.",
		}))
	}

	if ctx.Err() != nil {
		return liveAssets
	}

	// --- Phase 1d: DNS intelligence (TXT/MX) ---
	emit(ch, newEvent(EventPhaseStart, PhasePayload{
		Phase:   "1d",
		Message: fmt.Sprintf("Phase 1d: DNS intelligence for %s...", domain),
	}))

	indicators, err := r.intelScanner.Scan(domain)
	if err != nil {
		emit(ch, newEvent(EventError, ErrorPayload{Phase: "1d", Message: err.Error()}))
	}

	for _, ind := range indicators {
		emit(ch, newEvent(EventDNSIndicator, DNSIndicatorPayload{
			Service:  ind.Service,
			Record:   ind.Record,
			Evidence: ind.Evidence,
		}))
	}

	emit(ch, newEvent(EventPhaseComplete, PhasePayload{
		Phase:   "1d",
		Message: fmt.Sprintf("Phase 1d complete: %d service indicator(s) found.", len(indicators)),
	}))

	return liveAssets
}

// runPhase2 runs TCP scanning, fingerprinting, vuln checking, and differential
// analysis for all live assets.
func (r *Runner) runPhase2(ctx context.Context, cfg Config, liveAssets []models.Asset, ch chan<- ScanEvent) {
	msg := fmt.Sprintf("Phase 2: scanning %d port(s) on %d live asset(s) — %d workers, %v timeout",
		len(cfg.Ports), len(liveAssets), cfg.Workers, cfg.ScanTimeout)
	if cfg.RateLimit > 0 {
		msg += fmt.Sprintf(", %d conn/s rate limit", cfg.RateLimit)
	}
	msg += "..."
	emit(ch, newEvent(EventPhaseStart, PhasePayload{Phase: "2", Message: msg}))

	// Snapshot assets BEFORE saving new ones so DiffAssets sees pre-scan state.
	var assetDiff *models.ScanDiff
	if r.differ != nil {
		var diffErr error
		assetDiff, diffErr = r.differ.DiffAssets(liveAssets)
		if diffErr != nil {
			emit(ch, newEvent(EventError, ErrorPayload{Phase: "2", Message: fmt.Sprintf("diff assets: %v", diffErr)}))
		}
	}

	// Build a set of new-asset domain names to annotate EventSubdomain events
	// with DiffKind == ChangeNewAsset so the UI shows the [NEW] badge.
	newAssets := make(map[string]struct{})
	if assetDiff != nil {
		for _, c := range assetDiff.AssetChanges {
			newAssets[c.Domain] = struct{}{}
		}
	}

	totalOpen := 0
	var allDiffs []*models.ScanDiff

	for _, asset := range liveAssets {
		if ctx.Err() != nil {
			return
		}

		openPorts, err := r.tcpScanner.Scan(ctx, asset)
		if err != nil {
			emit(ch, newEvent(EventError, ErrorPayload{
				Phase:   "2",
				Message: fmt.Sprintf("scan error %s: %v", asset.Domain, err),
			}))
			continue
		}

		// Load history BEFORE any writes for this asset so the diff compares
		// against the previous scan, not the rows we are about to write.
		var history *models.AssetHistory
		if r.differ != nil {
			h, histErr := r.differ.LoadAssetHistory(asset.Domain)
			if histErr != nil {
				emit(ch, newEvent(EventError, ErrorPayload{Phase: "2", Message: fmt.Sprintf("load history %q: %v", asset.Domain, histErr)}))
			} else {
				history = h
			}
		}

		if len(openPorts) == 0 {
			if r.differ != nil && history != nil {
				diff := r.differ.DiffAsset(asset.Domain, history, nil, nil)
				if !diff.IsEmpty() {
					allDiffs = append(allDiffs, diff)
				}
			}
			continue
		}

		sort.Slice(openPorts, func(i, j int) bool {
			if openPorts[i].IP != openPorts[j].IP {
				return openPorts[i].IP < openPorts[j].IP
			}
			return openPorts[i].Number < openPorts[j].Number
		})

		// Build a set of previously-open ports for the [OPENED] badge.
		prevPorts := make(map[string]struct{})
		if history != nil {
			for _, p := range history.Ports {
				prevPorts[fmt.Sprintf("%s:%d/%s", p.IP, p.Number, p.Proto)] = struct{}{}
			}
		}

		var scannedServices []models.Service

		for _, p := range openPorts {
			totalOpen++

			if r.store != nil {
				if err := r.store.SavePort(asset.Domain, p); err != nil {
					emit(ch, newEvent(EventError, ErrorPayload{Phase: "2", Message: fmt.Sprintf("save port %s:%d: %v", p.IP, p.Number, err)}))
				}
			}

			svc, err := r.bannerFP.Fingerprint(p)
			if err != nil {
				// Port is open but produced no banner — emit a minimal port event.
				diffKind := ""
				if _, seen := prevPorts[fmt.Sprintf("%s:%d/%s", p.IP, p.Number, p.Proto)]; !seen && history != nil {
					diffKind = string(models.ChangePortOpened)
				}
				emit(ch, newEvent(EventPort, PortPayload{
					Domain:   asset.Domain,
					IP:       p.IP,
					Port:     p.Number,
					Proto:    p.Proto,
					DiffKind: diffKind,
				}))
				continue
			}

			svc.Vulnerabilities = r.vulnChecker.Check(svc.Name, svc.Version)

			if r.store != nil && (svc.Name != "" || svc.Banner != "") {
				if err := r.store.SaveService(asset.Domain, svc); err != nil {
					emit(ch, newEvent(EventError, ErrorPayload{Phase: "2", Message: fmt.Sprintf("save service %s:%d: %v", svc.Port.IP, svc.Port.Number, err)}))
				}
			}
			if svc.Name != "" || svc.Banner != "" {
				scannedServices = append(scannedServices, svc)
			}

			// Web technology fingerprinting for HTTP/HTTPS ports.
			var techs []models.Technology
			if webServiceNames[svc.Name] || r.webFP.CanFingerprint(p.Number) {
				if t, err := r.webFP.FingerprintWeb(asset.Domain, p); err == nil {
					techs = t
				}
			}

			diffKind := ""
			if _, seen := prevPorts[fmt.Sprintf("%s:%d/%s", p.IP, p.Number, p.Proto)]; !seen && history != nil {
				diffKind = string(models.ChangePortOpened)
			}

			emit(ch, newEvent(EventPort, PortPayload{
				Domain:          asset.Domain,
				IP:              svc.Port.IP,
				Port:            svc.Port.Number,
				Proto:           svc.Port.Proto,
				ServiceName:     svc.Name,
				ServiceVersion:  svc.Version,
				Banner:          svc.Banner,
				Vulnerabilities: svc.Vulnerabilities,
				Technologies:    techs,
				DiffKind:        diffKind,
			}))
		}

		if r.differ != nil && history != nil {
			diff := r.differ.DiffAsset(asset.Domain, history, openPorts, scannedServices)
			if !diff.IsEmpty() {
				allDiffs = append(allDiffs, diff)
			}
		}
	}

	emit(ch, newEvent(EventPhaseComplete, PhasePayload{
		Phase:   "2",
		Message: fmt.Sprintf("Phase 2 complete: %d open port(s) across %d live asset(s).", totalOpen, len(liveAssets)),
	}))

	// Emit differential analysis events after Phase 2 output.
	if r.differ != nil {
		if assetDiff != nil {
			for _, c := range assetDiff.AssetChanges {
				emit(ch, newEvent(EventDiff, DiffPayload{
					Kind:   string(c.Kind),
					Domain: c.Domain,
				}))
			}
		}
		for _, d := range allDiffs {
			for _, pc := range d.PortChanges {
				emit(ch, newEvent(EventDiff, DiffPayload{
					Kind:   string(pc.Kind),
					Domain: d.Domain,
					IP:     pc.Port.IP,
					Port:   pc.Port.Number,
					Proto:  pc.Port.Proto,
				}))
			}
			for _, sc := range d.ServiceChanges {
				emit(ch, newEvent(EventDiff, DiffPayload{
					Kind:        string(models.ChangeVersionChange),
					Domain:      d.Domain,
					IP:          sc.Port.IP,
					Port:        sc.Port.Number,
					ServiceName: sc.ServiceName,
					OldVersion:  sc.OldVersion,
					NewVersion:  sc.NewVersion,
				}))
			}
		}
	}
}

// runPhase3 runs cloud storage bucket hunting.
func (r *Runner) runPhase3(ctx context.Context, domain string, ch chan<- ScanEvent) {
	if ctx.Err() != nil {
		return
	}

	emit(ch, newEvent(EventPhaseStart, PhasePayload{
		Phase:   "3",
		Message: fmt.Sprintf("Phase 3: cloud bucket scan for %s...", domain),
	}))

	buckets, err := r.cloudScanner.Scan(ctx, domain)
	if err != nil {
		emit(ch, newEvent(EventError, ErrorPayload{Phase: "3", Message: fmt.Sprintf("cloud bucket scan failed: %v", err)}))
		return
	}

	var publicCount, privateCount int
	for _, b := range buckets {
		if r.store != nil {
			if err := r.store.SaveBucket(domain, b); err != nil {
				emit(ch, newEvent(EventError, ErrorPayload{Phase: "3", Message: fmt.Sprintf("save bucket %q: %v", b.URL, err)}))
			}
		}

		emit(ch, newEvent(EventBucket, BucketPayload{
			URL:        b.URL,
			Provider:   b.Provider,
			Status:     b.Status,
			Accessible: b.Accessible,
		}))

		if b.Accessible {
			publicCount++
		} else {
			privateCount++
		}
	}

	msg := fmt.Sprintf("Phase 3 complete: %d public, %d private bucket(s) found.", publicCount, privateCount)
	if len(buckets) == 0 {
		msg = "Phase 3 complete: No cloud buckets found."
	}
	emit(ch, newEvent(EventPhaseComplete, PhasePayload{Phase: "3", Message: msg}))
}

// buildSyntheticAsset constructs a minimal Asset for a local target.
// For a bare IP address, Domain and IPs[0] are both the IP.
// For a hostname without dots (e.g. a Docker service name), OS DNS resolution
// is attempted; if it fails the name is used as-is so Docker bridge names
// that resolve only at scan time still work.
func buildSyntheticAsset(target string) models.Asset {
	if ip := net.ParseIP(target); ip != nil {
		return models.Asset{Domain: target, IPs: []string{target}}
	}
	ips, err := net.LookupHost(target)
	if err != nil || len(ips) == 0 {
		// Fallback: use the name itself. The TCP scanner will resolve it at
		// dial time via the OS resolver (works inside Docker bridge networks).
		return models.Asset{Domain: target, IPs: []string{target}}
	}
	return models.Asset{Domain: target, IPs: ips}
}

// IsLocalTarget reports whether target should bypass OSINT phases.
// An IP address (net.ParseIP succeeds) or a hostname without dots
// (e.g. "victim-container") cannot have public CT log history.
// Exported so cmd/asm/main.go can call it without re-implementing the logic.
//
// Security note: this function does not block private or link-local IP ranges
// (RFC 1918, 169.254.x.x, ::1). The scanner probes whatever address the target
// resolves to, which is the intended behaviour for authorised external recon.
// When running the web UI in a cloud environment, place a reverse proxy with
// authentication in front of the server to prevent unauthorised callers from
// directing the scanner at internal infrastructure.
func IsLocalTarget(target string) bool {
	return net.ParseIP(target) != nil || !strings.Contains(target, ".")
}

// NormalizeDomain trims whitespace, removes a trailing dot, and lowercases the
// result. Both the CLI (cmd/asm/main.go) and the web handler (internal/web)
// call this once at the entry point so every downstream package receives a
// consistent, well-formed domain string.
//
// Why three steps:
//   - TrimSpace: shells and HTTP clients can inject leading/trailing whitespace.
//   - TrimRight("."): FQDN notation ("example.com.") breaks the crt.sh scope
//     filter — the query becomes "%.example.com." and the parser computes
//     target = "example.com.", which never matches lowercase results like
//     "api.example.com", silently returning zero subdomains.
//   - ToLower: DNS names are case-insensitive (RFC 4343); normalising up front
//     prevents duplicate entries from mixed-case SAN values in CT log records.
func NormalizeDomain(target string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(target), "."))
}

// pluralise returns singular when n == 1, plural otherwise.
func pluralise(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
