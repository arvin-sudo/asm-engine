package analysis

import (
	"errors"
	"testing"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// mockHistoryReader is an in-memory HistoryReader for unit tests.
// It returns only the data configured per-test — no database required.
type mockHistoryReader struct {
	assets   []models.AssetRecord
	ports    map[string][]models.Port
	services map[string][]models.Service
	err      error // when non-nil, all calls return this error
}

func (m *mockHistoryReader) FindAssets() ([]models.AssetRecord, error) {
	return m.assets, m.err
}

func (m *mockHistoryReader) FindPorts(domain string) ([]models.Port, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.ports[domain], nil
}

func (m *mockHistoryReader) FindServices(domain string) ([]models.Service, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.services[domain], nil
}

func TestDiffer_DiffAssets(t *testing.T) {
	tests := []struct {
		name           string
		historical     []models.AssetRecord
		current        []models.Asset
		wantNewDomains []string
	}{
		{
			name:           "empty history means all assets are new",
			historical:     nil,
			current:        []models.Asset{{Domain: "api.example.com"}, {Domain: "www.example.com"}},
			wantNewDomains: []string{"api.example.com", "www.example.com"},
		},
		{
			name:           "all assets already known — no changes",
			historical:     []models.AssetRecord{{Asset: models.Asset{Domain: "api.example.com"}}},
			current:        []models.Asset{{Domain: "api.example.com"}},
			wantNewDomains: nil,
		},
		{
			name: "one existing one new",
			historical: []models.AssetRecord{
				{Asset: models.Asset{Domain: "api.example.com"}},
			},
			current: []models.Asset{
				{Domain: "api.example.com"},
				{Domain: "dev.example.com"}, // new
			},
			wantNewDomains: []string{"dev.example.com"},
		},
		{
			name:           "empty current scan — no diff output",
			historical:     []models.AssetRecord{{Asset: models.Asset{Domain: "api.example.com"}}},
			current:        nil,
			wantNewDomains: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &mockHistoryReader{assets: tt.historical}
			d := NewDiffer(reader)

			diff, err := d.DiffAssets(tt.current)
			if err != nil {
				t.Fatalf("DiffAssets() error = %v", err)
			}

			got := make(map[string]bool)
			for _, c := range diff.AssetChanges {
				if c.Kind != models.ChangeNewAsset {
					t.Errorf("unexpected ChangeKind %q for domain %q", c.Kind, c.Domain)
				}
				got[c.Domain] = true
			}

			for _, want := range tt.wantNewDomains {
				if !got[want] {
					t.Errorf("expected NEW ASSET %q not found in diff", want)
				}
			}
			if len(diff.AssetChanges) != len(tt.wantNewDomains) {
				t.Errorf("got %d asset changes, want %d", len(diff.AssetChanges), len(tt.wantNewDomains))
			}
		})
	}
}

func TestDiffer_DiffAsset_Ports(t *testing.T) {
	tcp80 := models.Port{IP: "1.2.3.4", Number: 80, Proto: "tcp"}
	tcp443 := models.Port{IP: "1.2.3.4", Number: 443, Proto: "tcp"}
	tcp5432 := models.Port{IP: "1.2.3.4", Number: 5432, Proto: "tcp"}

	tests := []struct {
		name       string
		histPorts  []models.Port
		currPorts  []models.Port
		wantOpened []models.Port
		wantClosed []models.Port
	}{
		{
			name:       "no history means all ports are opened",
			histPorts:  nil,
			currPorts:  []models.Port{tcp80, tcp443},
			wantOpened: []models.Port{tcp80, tcp443},
		},
		{
			name:      "same ports as history — no changes",
			histPorts: []models.Port{tcp80, tcp443},
			currPorts: []models.Port{tcp80, tcp443},
		},
		{
			name:       "new port opened since last scan",
			histPorts:  []models.Port{tcp80},
			currPorts:  []models.Port{tcp80, tcp5432},
			wantOpened: []models.Port{tcp5432},
		},
		{
			name:       "port closed since last scan",
			histPorts:  []models.Port{tcp80, tcp443},
			currPorts:  []models.Port{tcp80},
			wantClosed: []models.Port{tcp443},
		},
		{
			name:       "port swap: one closed, one opened",
			histPorts:  []models.Port{tcp80},
			currPorts:  []models.Port{tcp443},
			wantOpened: []models.Port{tcp443},
			wantClosed: []models.Port{tcp80},
		},
		{
			name:       "all ports closed — history had ports, current is empty",
			histPorts:  []models.Port{tcp80, tcp443},
			currPorts:  nil,
			wantClosed: []models.Port{tcp80, tcp443},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// DiffAsset is pure — no reader calls. Use an empty mock for safety.
			d := NewDiffer(&mockHistoryReader{})
			history := &models.AssetHistory{Ports: tt.histPorts}

			diff := d.DiffAsset("example.com", history, tt.currPorts, nil)

			var opened, closed []models.Port
			for _, c := range diff.PortChanges {
				switch c.Kind {
				case models.ChangePortOpened:
					opened = append(opened, c.Port)
				case models.ChangePortClosed:
					closed = append(closed, c.Port)
				}
			}

			if len(opened) != len(tt.wantOpened) {
				t.Errorf("opened ports: got %d, want %d", len(opened), len(tt.wantOpened))
			}
			if len(closed) != len(tt.wantClosed) {
				t.Errorf("closed ports: got %d, want %d", len(closed), len(tt.wantClosed))
			}
		})
	}
}

func TestDiffer_DiffAsset_ServiceVersionChange(t *testing.T) {
	port443 := models.Port{IP: "1.2.3.4", Number: 443, Proto: "tcp"}
	port80 := models.Port{IP: "1.2.3.4", Number: 80, Proto: "tcp"}

	tests := []struct {
		name         string
		histServices []models.Service
		currServices []models.Service
		wantChanges  int
		wantOld      string
		wantNew      string
	}{
		{
			name: "version upgraded",
			histServices: []models.Service{
				{Port: port443, Name: "nginx", Version: "1.18.0"},
			},
			currServices: []models.Service{
				{Port: port443, Name: "nginx", Version: "1.24.0"},
			},
			wantChanges: 1,
			wantOld:     "1.18.0",
			wantNew:     "1.24.0",
		},
		{
			name: "same version — no change",
			histServices: []models.Service{
				{Port: port443, Name: "nginx", Version: "1.18.0"},
			},
			currServices: []models.Service{
				{Port: port443, Name: "nginx", Version: "1.18.0"},
			},
			wantChanges: 0,
		},
		{
			name: "empty old version — not reported as change",
			histServices: []models.Service{
				{Port: port443, Name: "nginx", Version: ""},
			},
			currServices: []models.Service{
				{Port: port443, Name: "nginx", Version: "1.18.0"},
			},
			wantChanges: 0,
		},
		{
			name: "empty new version — not reported as change",
			histServices: []models.Service{
				{Port: port443, Name: "nginx", Version: "1.18.0"},
			},
			currServices: []models.Service{
				{Port: port443, Name: "nginx", Version: ""},
			},
			wantChanges: 0,
		},
		{
			name: "multiple ports — only changed one reported",
			histServices: []models.Service{
				{Port: port443, Name: "nginx", Version: "1.18.0"},
				{Port: port80, Name: "apache", Version: "2.4.41"},
			},
			currServices: []models.Service{
				{Port: port443, Name: "nginx", Version: "1.24.0"}, // changed
				{Port: port80, Name: "apache", Version: "2.4.41"}, // unchanged
			},
			wantChanges: 1,
			wantOld:     "1.18.0",
			wantNew:     "1.24.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// DiffAsset is pure — no reader calls. Use an empty mock for safety.
			d := NewDiffer(&mockHistoryReader{})
			history := &models.AssetHistory{Services: tt.histServices}

			diff := d.DiffAsset("example.com", history, nil, tt.currServices)

			if len(diff.ServiceChanges) != tt.wantChanges {
				t.Fatalf("ServiceChanges: got %d, want %d — changes: %v",
					len(diff.ServiceChanges), tt.wantChanges, diff.ServiceChanges)
			}
			if tt.wantChanges > 0 {
				c := diff.ServiceChanges[0]
				if c.OldVersion != tt.wantOld || c.NewVersion != tt.wantNew {
					t.Errorf("version change: got %q→%q, want %q→%q",
						c.OldVersion, c.NewVersion, tt.wantOld, tt.wantNew)
				}
			}
		})
	}
}

func TestDiffer_LoadAssetHistory(t *testing.T) {
	tcp80 := models.Port{IP: "1.2.3.4", Number: 80, Proto: "tcp"}
	svc := models.Service{Port: tcp80, Name: "nginx", Version: "1.18.0"}

	tests := []struct {
		name            string
		domain          string
		readerPorts     []models.Port
		readerServices  []models.Service
		readerErr       error
		wantErr         bool
		wantPortCount   int
		wantServiceCount int
	}{
		{
			name:             "returns ports and services for domain",
			domain:           "example.com",
			readerPorts:      []models.Port{tcp80},
			readerServices:   []models.Service{svc},
			wantPortCount:    1,
			wantServiceCount: 1,
		},
		{
			name:      "reader error is propagated",
			domain:    "example.com",
			readerErr: errors.New("db down"),
			wantErr:   true,
		},
		{
			name:             "empty history for unknown domain",
			domain:           "unknown.example.com",
			wantPortCount:    0,
			wantServiceCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &mockHistoryReader{
				ports:    map[string][]models.Port{tt.domain: tt.readerPorts},
				services: map[string][]models.Service{tt.domain: tt.readerServices},
				err:      tt.readerErr,
			}
			d := NewDiffer(reader)

			history, err := d.LoadAssetHistory(tt.domain)
			if tt.wantErr {
				if err == nil {
					t.Fatal("LoadAssetHistory() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadAssetHistory() unexpected error: %v", err)
			}
			if len(history.Ports) != tt.wantPortCount {
				t.Errorf("Ports: got %d, want %d", len(history.Ports), tt.wantPortCount)
			}
			if len(history.Services) != tt.wantServiceCount {
				t.Errorf("Services: got %d, want %d", len(history.Services), tt.wantServiceCount)
			}
		})
	}
}

func TestDiffer_DiffAssets_Error(t *testing.T) {
	reader := &mockHistoryReader{err: errors.New("db unavailable")}
	d := NewDiffer(reader)

	diff, err := d.DiffAssets([]models.Asset{{Domain: "api.example.com"}})
	if err == nil {
		t.Fatal("DiffAssets() expected error when reader fails, got nil")
	}
	if diff != nil {
		t.Errorf("DiffAssets() expected nil diff on reader error, got %v", diff)
	}
}

func TestDiffer_DiffAsset_CombinedPortAndServiceChange(t *testing.T) {
	port80 := models.Port{IP: "1.2.3.4", Number: 80, Proto: "tcp"}
	port443 := models.Port{IP: "1.2.3.4", Number: 443, Proto: "tcp"}

	// History: only port 443, nginx 1.18.0.
	history := &models.AssetHistory{
		Ports: []models.Port{port443},
		Services: []models.Service{
			{Port: port443, Name: "nginx", Version: "1.18.0"},
		},
	}
	// Current: port 443 (nginx upgraded) + port 80 (newly opened).
	currentPorts := []models.Port{port443, port80}
	currentServices := []models.Service{
		{Port: port443, Name: "nginx", Version: "1.24.0"},
	}

	d := NewDiffer(&mockHistoryReader{})
	diff := d.DiffAsset("example.com", history, currentPorts, currentServices)

	if len(diff.PortChanges) != 1 {
		t.Fatalf("PortChanges: got %d, want 1 — %v", len(diff.PortChanges), diff.PortChanges)
	}
	if diff.PortChanges[0].Kind != models.ChangePortOpened {
		t.Errorf("PortChange kind: got %q, want %q", diff.PortChanges[0].Kind, models.ChangePortOpened)
	}
	if diff.PortChanges[0].Port.Number != 80 {
		t.Errorf("opened port number: got %d, want 80", diff.PortChanges[0].Port.Number)
	}

	if len(diff.ServiceChanges) != 1 {
		t.Fatalf("ServiceChanges: got %d, want 1 — %v", len(diff.ServiceChanges), diff.ServiceChanges)
	}
	sc := diff.ServiceChanges[0]
	if sc.OldVersion != "1.18.0" || sc.NewVersion != "1.24.0" {
		t.Errorf("version change: got %q→%q, want 1.18.0→1.24.0", sc.OldVersion, sc.NewVersion)
	}
}

func TestScanDiff_IsEmpty(t *testing.T) {
	empty := &models.ScanDiff{}
	if !empty.IsEmpty() {
		t.Error("IsEmpty() on zero-value ScanDiff should be true")
	}

	withAsset := &models.ScanDiff{
		AssetChanges: []models.AssetChange{{Domain: "x.com", Kind: models.ChangeNewAsset}},
	}
	if withAsset.IsEmpty() {
		t.Error("IsEmpty() on ScanDiff with asset changes should be false")
	}
}
