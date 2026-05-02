package models

// Asset is a discovered external asset belonging to a target domain.
type Asset struct {
	Domain string
	IPs    []string
}

// IsValid reports whether the asset has a non-empty domain.
func (a Asset) IsValid() bool {
	return a.Domain != ""
}

// Port represents an open port discovered on an asset.
type Port struct {
	IP     string
	Number int
	Proto  string // "tcp" or "udp"
}

// Service describes the software identified on an open port.
type Service struct {
	Port    Port
	Name    string // e.g. "nginx", "openssh"
	Version string // e.g. "1.18.0"
	Banner  string // raw banner grabbed from the port
}
