package models

import "testing"

func TestAsset_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		asset Asset
		want  bool
	}{
		{"valid domain", Asset{Domain: "example.com"}, true},
		{"empty domain", Asset{Domain: ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.asset.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubdomain_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		subdomain Subdomain
		want      bool
	}{
		{"valid name", Subdomain{Name: "api.example.com"}, true},
		{"empty name", Subdomain{Name: ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.subdomain.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubdomain_IsWildcard(t *testing.T) {
	tests := []struct {
		name      string
		subdomain Subdomain
		want      bool
	}{
		{"wildcard entry", Subdomain{Name: "*.example.com"}, true},
		{"regular subdomain", Subdomain{Name: "api.example.com"}, false},
		{"apex domain", Subdomain{Name: "example.com"}, false},
		{"empty name", Subdomain{Name: ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.subdomain.IsWildcard(); got != tt.want {
				t.Errorf("IsWildcard() = %v, want %v", got, tt.want)
			}
		})
	}
}
