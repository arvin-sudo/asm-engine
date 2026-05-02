package scanner

import (
	"net"
	"testing"
	"time"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// startAcceptServer binds a local TCP listener on a random port and accepts
// connections in a background goroutine, closing each one immediately. It
// returns the listener (caller must defer Close) and the port number.
//
// Using a real listener avoids mocking net.Conn and ensures the test exercises
// the actual dial path through the OS network stack.
func startAcceptServer(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startAcceptServer: Listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener was closed by test cleanup
			}
			conn.Close()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func TestTCPScanner_Scan_OpenPort(t *testing.T) {
	ln, port := startAcceptServer(t)
	defer ln.Close()

	s := NewTCPScanner([]int{port}, time.Second, 1)
	asset := models.Asset{Domain: "localhost", IPs: []string{"127.0.0.1"}}

	got, err := s.Scan(asset)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Scan() returned %d open ports, want 1", len(got))
	}
	if got[0].Number != port || got[0].IP != "127.0.0.1" || got[0].Proto != "tcp" {
		t.Errorf("Scan() got %+v, want port %d on 127.0.0.1/tcp", got[0], port)
	}
}

func TestTCPScanner_Scan_ClosedPort(t *testing.T) {
	// Port 1 (tcpmux) is not bound on any developer machine. On localhost, a
	// refused connection returns immediately (RST), so the short timeout still
	// completes quickly without risking a flaky slow test.
	s := NewTCPScanner([]int{1}, 200*time.Millisecond, 1)
	asset := models.Asset{Domain: "localhost", IPs: []string{"127.0.0.1"}}

	got, err := s.Scan(asset)
	if err != nil {
		t.Fatalf("Scan() unexpected error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Scan() returned %d ports for a closed port, want 0", len(got))
	}
}

func TestTCPScanner_Scan_InvalidAsset(t *testing.T) {
	s := NewTCPScanner([]int{80}, time.Second, 1)
	_, err := s.Scan(models.Asset{})
	if err == nil {
		t.Fatal("Scan() expected error for invalid asset, got nil")
	}
}

func TestTCPScanner_Scan_MultiplePorts(t *testing.T) {
	ln1, port1 := startAcceptServer(t)
	ln2, port2 := startAcceptServer(t)
	defer ln1.Close()
	defer ln2.Close()

	s := NewTCPScanner([]int{port1, port2}, time.Second, 10)
	asset := models.Asset{Domain: "localhost", IPs: []string{"127.0.0.1"}}

	got, err := s.Scan(asset)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 2 {
		t.Errorf("Scan() returned %d open ports, want 2", len(got))
	}
}

func TestTCPScanner_Scan_MultipleIPs(t *testing.T) {
	// The scanner itself does not deduplicate IPs — that is the DNS resolver's
	// responsibility. This test verifies that the scanner faithfully probes
	// every (IP, port) pair it is given, even when the IP list contains the
	// same address twice. Passing "127.0.0.1" twice produces 4 dial attempts
	// (2 ports × 2 IP entries) and therefore 4 open-port results.
	ln1, port1 := startAcceptServer(t)
	ln2, port2 := startAcceptServer(t)
	defer ln1.Close()
	defer ln2.Close()

	s := NewTCPScanner([]int{port1, port2}, time.Second, 10)
	asset := models.Asset{
		Domain: "localhost",
		IPs:    []string{"127.0.0.1", "127.0.0.1"},
	}

	got, err := s.Scan(asset)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 4 {
		t.Errorf("Scan() returned %d open ports, want 4 (2 ports × 2 IP entries)", len(got))
	}
}

func TestNewTCPScanner_Defaults(t *testing.T) {
	s := NewTCPScanner([]int{80}, 0, 0)
	if s.timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", s.timeout, defaultTimeout)
	}
	if s.workers != defaultWorkers {
		t.Errorf("workers = %d, want %d", s.workers, defaultWorkers)
	}
}
