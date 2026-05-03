package vulndb

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"equal dotted", "1.18.0", "1.18.0", 0},
		{"a less than b", "1.18.0", "1.20.1", -1},
		{"a greater than b", "2.4.52", "2.4.41", 1},
		{"openssh equal", "8.4p1", "8.4p1", 0},
		{"openssh a less", "8.4p1", "9.7p1", -1},
		{"openssh a greater", "9.8p1", "9.7p1", 1},
		{"different depths equal", "1.18", "1.18.0", 0},
		{"different depths less", "1.18", "1.18.1", -1},
		{"patch boundary", "2.4.50", "2.4.50", 0},
		{"major version dominates", "3.0.0", "2.99.99", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestVulnDB_Check(t *testing.T) {
	db := New()

	tests := []struct {
		name        string
		service     string
		version     string
		wantCVEs    []string // subset of CVEs that must appear; order ignored
		wantNone    bool     // true if no matches expected
	}{
		{
			name:     "openssh regreSSHion in range",
			service:  "openssh",
			version:  "8.4p1",
			wantNone: true, // 8.4p1 is BELOW the min 8.5p1 for CVE-2024-6387
		},
		{
			name:     "openssh regreSSHion at min",
			service:  "openssh",
			version:  "8.5p1",
			wantCVEs: []string{"CVE-2024-6387"},
		},
		{
			name:     "openssh regreSSHion at max",
			service:  "openssh",
			version:  "9.7p1",
			wantCVEs: []string{"CVE-2024-6387"},
		},
		{
			name:     "openssh patched version",
			service:  "openssh",
			version:  "9.8p1",
			wantNone: true,
		},
		{
			name:     "openssh enumeration only (old version)",
			service:  "openssh",
			version:  "7.5",
			wantCVEs: []string{"CVE-2018-15473"},
		},
		{
			name:     "apache path traversal at 2.4.49",
			service:  "apache",
			version:  "2.4.49",
			wantCVEs: []string{"CVE-2021-41773"},
		},
		{
			name:     "apache version predating traversal range",
			service:  "apache",
			version:  "2.4.41",
			wantNone: false, // 2.4.41 < 2.4.49 so traversal rule should NOT fire
		},
		{
			name:     "apache patched past 2.4.52",
			service:  "apache",
			version:  "2.4.58",
			wantNone: true,
		},
		{
			name:     "nginx pre-1.20.1",
			service:  "nginx",
			version:  "1.18.0",
			wantCVEs: []string{"CVE-2021-23017"},
		},
		{
			name:     "nginx patched at 1.20.1",
			service:  "nginx",
			version:  "1.20.1",
			wantNone: true,
		},
		{
			name:     "http always gets informational note",
			service:  "http",
			version:  "",
			wantCVEs: []string{""},
		},
		{
			name:     "empty version skips version-gated rules",
			service:  "nginx",
			version:  "",
			wantNone: true,
		},
		{
			name:     "unknown service",
			service:  "foobar",
			version:  "1.0.0",
			wantNone: true,
		},
		{
			name:     "imap fires unconditionally",
			service:  "imap",
			version:  "",
			wantCVEs: []string{"CVE-2024-23184"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db.Check(tt.service, tt.version)

			if tt.wantNone && len(got) != 0 {
				t.Errorf("Check(%q, %q): expected no results, got %v", tt.service, tt.version, got)
				return
			}

			for _, wantCVE := range tt.wantCVEs {
				found := false
				for _, v := range got {
					if v.CVE == wantCVE {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Check(%q, %q): CVE %q not found in results %v",
						tt.service, tt.version, wantCVE, got)
				}
			}
		})
	}
}

func TestVulnDB_Check_CaseInsensitive(t *testing.T) {
	db := New()
	// Service names from the fingerprinter are already lowercase, but the
	// interface contract should be robust to callers passing uppercase.
	got := db.Check("NGINX", "1.18.0")
	if len(got) == 0 {
		t.Error("Check(NGINX) must match lowercase nginx rules")
	}
}
