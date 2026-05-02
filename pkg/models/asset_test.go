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
