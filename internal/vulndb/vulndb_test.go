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
		// Distribution suffixes like "-ubuntu1" are non-numeric: Atoi fails and
		// the component is treated as zero. "1.18.0-ubuntu1" → [1, 18, 0] which
		// equals [1, 18, 0], so the two versions compare as equal.
		{"distro suffix treated as zero component", "1.18.0-ubuntu1", "1.18.0", 0},
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
			// 2.4.41 is below the path-traversal minVersion (2.4.49) so
			// CVE-2021-41773 does NOT fire. However, the mod_lua buffer-overflow
			// rule (CVE-2021-44790, maxVersion 2.4.51, no minVersion) does fire —
			// 2.4.41 ≤ 2.4.51. Expect exactly one result (the buffer-overflow).
			name:     "apache version predating traversal range",
			service:  "apache",
			version:  "2.4.41",
			wantNone: false,
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
		{
			name:     "pop3 fires unconditionally",
			service:  "pop3",
			version:  "",
			wantCVEs: []string{"CVE-2024-23184"},
		},
		{
			name:     "smtp at max boundary 3.5.22 matches",
			service:  "smtp",
			version:  "3.5.22",
			wantCVEs: []string{"CVE-2023-51764"},
		},
		{
			name:     "smtp patched at 3.5.23 does not match",
			service:  "smtp",
			version:  "3.5.23",
			wantNone: true,
		},
		{
			name:     "ftp at max boundary 1.3.7 matches",
			service:  "ftp",
			version:  "1.3.7",
			wantCVEs: []string{"CVE-2023-48795"},
		},
		{
			name:     "ftp patched at 1.3.8 does not match",
			service:  "ftp",
			version:  "1.3.8",
			wantNone: true,
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

// TestSplitVersion directly exercises the version-string parser that underpins
// all CVE range checks. compareVersions tests cover the comparison logic but
// not the parsing rules — a change to the 'p'-separator handling or the
// distro-suffix treatment would pass compareVersions tests while silently
// breaking the parser.
func TestSplitVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		// Empty string: Split produces [""], the empty component is skipped,
		// result is an empty slice rather than a panic.
		{"empty string", "", []int{}},
		{"single component", "5", []int{5}},
		{"dotted decimal", "1.18.0", []int{1, 18, 0}},
		// OpenSSH 'p' separator: "8.4p1" → "8.4.1" after replacement.
		{"openssh p-notation", "8.4p1", []int{8, 4, 1}},
		{"openssh high version", "9.8p1", []int{9, 8, 1}},
		// Short p-notation with no minor: "8p1" → "8.1".
		{"short p-notation no minor", "8p1", []int{8, 1}},
		// Distribution suffixes such as "-ubuntu1" make the component
		// non-numeric; Atoi fails and the component is treated as zero.
		// "1.18.0-ubuntu1" splits as ["1", "18", "0-ubuntu1"] → [1, 18, 0].
		{"distro suffix treated as zero", "1.18.0-ubuntu1", []int{1, 18, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitVersion(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("splitVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("splitVersion(%q)[%d] = %d, want %d", tt.input, i, v, tt.want[i])
				}
			}
		})
	}
}
