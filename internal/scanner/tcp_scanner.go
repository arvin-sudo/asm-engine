package scanner

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

const (
	// defaultTimeout is the per-connection dial deadline.
	//
	// Two seconds balances speed against false negatives on slow or
	// geographically distant hosts. A firewall that silently drops packets
	// (a "filtered" port) will hold the connection open until this deadline
	// fires, so keeping it short matters when the value is multiplied across
	// thousands of (IP, port) pairs.
	defaultTimeout = 2 * time.Second

	// defaultWorkers bounds the goroutine pool size per Scan call.
	//
	// 100 concurrent dials is fast in practice while staying within typical
	// OS file-descriptor limits (ulimit -n is commonly 1 024 or higher). It
	// also keeps the outbound traffic rate well below the threshold that
	// network rate-limiting was designed to guard against.
	defaultWorkers = 100
)

// TCPScanner implements Scanner by probing a configurable list of TCP ports
// using a fixed-size goroutine worker pool.
//
// Why a fixed-size pool rather than one goroutine per port?
// Spawning one goroutine per probe is simple but unbounded. An asset with five
// IP addresses and 1 000 ports would produce 5 000 simultaneous dial attempts.
// Each consumes a file descriptor; most operating systems cap processes at
// ~1 024 open descriptors by default. The pool bounds concurrency to a
// predictable level regardless of how large the port list grows, trading a
// small amount of throughput for operational safety.
type TCPScanner struct {
	ports     []int
	timeout   time.Duration
	workers   int
	rateLimit int // max dial attempts per second; 0 = unlimited
}

// NewTCPScanner constructs a TCPScanner.
//
// ports is the list of port numbers to probe; callers choose the set relevant
// to their scan goal. A zero or negative timeout defaults to 2 s; a zero or
// negative workers count defaults to 100. A zero or negative rateLimit disables
// throttling — workers dial as fast as the OS and network allow.
func NewTCPScanner(ports []int, timeout time.Duration, workers, rateLimit int) *TCPScanner {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if workers <= 0 {
		workers = defaultWorkers
	}
	if rateLimit < 0 {
		rateLimit = 0
	}
	return &TCPScanner{ports: ports, timeout: timeout, workers: workers, rateLimit: rateLimit}
}

// Scan probes every (IP, port) combination in asset and returns one Port value
// for each combination that accepted a TCP connection.
//
// Work is distributed across s.workers goroutines via a buffered job channel.
// A successful net.DialTimeout confirms a port is open — the connection is
// closed immediately because we only need reachability here. Banner reading is
// the fingerprinter's responsibility and runs in a separate pipeline stage.
//
// Results arrive in non-deterministic order because goroutines finish
// independently. Callers must sort if a stable display order is required.
func (s *TCPScanner) Scan(asset models.Asset) ([]models.Port, error) {
	if !asset.IsValid() {
		return nil, fmt.Errorf("tcp_scanner: invalid asset %q", asset.Domain)
	}

	type job struct {
		ip   string
		port int
	}

	total := len(asset.IPs) * len(s.ports)

	// Nothing to probe — return early rather than creating channels and a
	// closer goroutine that would immediately terminate for zero work.
	if total == 0 {
		return nil, nil
	}

	jobs := make(chan job, total)
	results := make(chan models.Port, total)

	// Cap the pool to the actual number of jobs. With a small port list or a
	// single-IP asset, spawning all s.workers goroutines would mean most of
	// them start, range over an already-closed jobs channel, and exit without
	// doing any work — wasted initialisation cost for no benefit.
	poolSize := min(s.workers, total)

	// When rateLimit > 0, a ticker fires at 1/rateLimit intervals. Each worker
	// reads one tick before dialing, so at most rateLimit connection attempts
	// are initiated per second across the entire pool. This keeps the outbound
	// connection rate below thresholds that IDS/firewall systems flag as scanning.
	// time.NewTicker starts with an empty channel — the first tick (and therefore
	// the first dial) is delayed by one full interval. Every dial is rate-limited,
	// including the first.
	var tokens <-chan time.Time
	if s.rateLimit > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(s.rateLimit))
		defer ticker.Stop()
		tokens = ticker.C
	}

	var wg sync.WaitGroup
	for range poolSize {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if tokens != nil {
					<-tokens
				}
				// net.JoinHostPort handles bare IPv6 addresses correctly —
				// fmt.Sprintf("%s:%d", ip, port) would produce "::1:80" which
				// is ambiguous. JoinHostPort produces "[::1]:80" as required.
				addr := net.JoinHostPort(j.ip, strconv.Itoa(j.port))
				conn, err := net.DialTimeout("tcp", addr, s.timeout)
				if err != nil {
					// A refused or timed-out connection is not an error in the
					// domain sense — it simply means the port is closed or
					// filtered. Only open ports produce results.
					continue
				}
				conn.Close()
				results <- models.Port{IP: j.ip, Number: j.port, Proto: "tcp"}
			}
		}()
	}

	for _, ip := range asset.IPs {
		for _, port := range s.ports {
			jobs <- job{ip: ip, port: port}
		}
	}
	close(jobs)

	// Close results only after all workers finish. This must happen in a
	// dedicated goroutine because: (a) the main goroutine is blocked draining
	// results and cannot call close itself, and (b) any individual worker
	// finishing does not mean all workers are done — only the WaitGroup knows
	// when the last one exits. Closing results causes the for-range below to
	// terminate naturally.
	go func() {
		wg.Wait()
		close(results)
	}()

	var open []models.Port
	for p := range results {
		open = append(open, p)
	}
	return open, nil
}
