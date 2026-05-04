package fingerprint

// defaultHTTPPorts lists the TCP port numbers expected to speak plain HTTP.
//
// Both BannerFingerprinter and WebStackFingerprinter classify ports against
// this list. Keeping it here means adding a non-standard HTTP port requires
// editing one line in one file rather than hunting two constructors.
var defaultHTTPPorts = []int{80, 8080, 8888}

// defaultHTTPSPorts lists the TCP port numbers expected to speak HTTPS.
var defaultHTTPSPorts = []int{443, 8443}

// buildPortMap converts a slice of port numbers into a boolean membership map
// for O(1) classification. Only membership matters — the bool value is unused.
func buildPortMap(ports []int) map[int]bool {
	m := make(map[int]bool, len(ports))
	for _, p := range ports {
		m[p] = true
	}
	return m
}
