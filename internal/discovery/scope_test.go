package discovery

import "testing"

func TestInScope(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		target string
		want   bool
	}{
		{
			name:   "apex match",
			input:  "example.com",
			target: "example.com",
			want:   true,
		},
		{
			name:   "direct subdomain",
			input:  "api.example.com",
			target: "example.com",
			want:   true,
		},
		{
			name:   "nested subdomain",
			input:  "v2.api.example.com",
			target: "example.com",
			want:   true,
		},
		{
			name:   "wildcard entry from CT log",
			input:  "*.example.com",
			target: "example.com",
			want:   true,
		},
		{
			name:   "unrelated domain",
			input:  "evil.com",
			target: "example.com",
			want:   false,
		},
		{
			name:   "similar prefix without dot boundary",
			input:  "notexample.com",
			target: "example.com",
			want:   false,
		},
		{
			name:   "subdomain of similarly-named domain",
			input:  "api.notexample.com",
			target: "example.com",
			want:   false,
		},
		{
			name:   "empty input name",
			input:  "",
			target: "example.com",
			want:   false,
		},
		{
			name:   "empty target",
			input:  "example.com",
			target: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inScope(tt.input, tt.target)
			if got != tt.want {
				t.Errorf("inScope(%q, %q) = %v, want %v", tt.input, tt.target, got, tt.want)
			}
		})
	}
}
