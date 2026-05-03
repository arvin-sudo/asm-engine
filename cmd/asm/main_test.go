package main

import (
	"testing"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

func TestParsePorts_DefaultsOnEmpty(t *testing.T) {
	ports, err := parsePorts("")
	if err != nil {
		t.Fatalf("parsePorts(\"\") error = %v", err)
	}
	if len(ports) != len(defaultPorts) {
		t.Errorf("got %d ports, want %d (default list)", len(ports), len(defaultPorts))
	}
}

func TestParsePorts_DefaultsOnWhitespace(t *testing.T) {
	ports, err := parsePorts("   ")
	if err != nil {
		t.Fatalf("parsePorts(whitespace) error = %v", err)
	}
	if len(ports) != len(defaultPorts) {
		t.Errorf("got %d ports, want %d (default list)", len(ports), len(defaultPorts))
	}
}

func TestParsePorts_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"80", []int{80}},
		{"80,443", []int{80, 443}},
		{"80, 443", []int{80, 443}},          // whitespace around values is trimmed
		{"1,65535", []int{1, 65535}},         // boundary values are accepted
		{"80,80,443", []int{80, 443}},        // duplicate port is dropped
		{"80,443,80,8080,443", []int{80, 443, 8080}}, // multiple duplicates, order preserved
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePorts(tt.input)
			if err != nil {
				t.Fatalf("parsePorts(%q) error = %v", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d ports, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ports[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParsePorts_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"non-integer token", "abc"},
		{"mixed valid and invalid", "80,abc"},
		{"zero is out of range", "0"},
		{"65536 is out of range", "65536"},
		{"negative is out of range", "-1"},
		{"empty token from double comma", "80,,443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePorts(tt.input)
			if err == nil {
				t.Errorf("parsePorts(%q) expected error, got nil", tt.input)
			}
		})
	}
}

func TestFilterByIP(t *testing.T) {
	ports := []models.Port{
		{IP: "1.2.3.4", Number: 80, Proto: "tcp"},
		{IP: "5.6.7.8", Number: 443, Proto: "tcp"},
		{IP: "1.2.3.4", Number: 443, Proto: "tcp"},
	}

	tests := []struct {
		ip        string
		wantCount int
	}{
		{"1.2.3.4", 2},
		{"5.6.7.8", 1},
		{"9.9.9.9", 0},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := filterByIP(ports, tt.ip)
			if len(got) != tt.wantCount {
				t.Errorf("filterByIP(%q) returned %d ports, want %d", tt.ip, len(got), tt.wantCount)
			}
		})
	}
}
