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
