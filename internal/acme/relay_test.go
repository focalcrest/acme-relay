package acme

import (
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"  example.com  ", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"  https://www.example.com  ", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestContainsString(t *testing.T) {
	tests := []struct {
		list     []string
		s        string
		expected bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{[]string{}, "a", false},
		{[]string{""}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			result := containsString(tt.list, tt.s)
			if result != tt.expected {
				t.Errorf("containsString(%v, %q) = %v, want %v", tt.list, tt.s, result, tt.expected)
			}
		})
	}
}

func TestDecodeCSR(t *testing.T) {
	// Invalid base64 should fail
	_, err := DecodeCSR("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestGetDomainsFromCSR_InvalidBase64(t *testing.T) {
	_, err := GetDomainsFromCSR("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}
