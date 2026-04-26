package acme

import (
	"testing"
)

func TestProblem_Error(t *testing.T) {
	p := &Problem{Type: "urn:ietf:params:acme:error:badNonce", Detail: "invalid nonce"}
	if got := p.Error(); got != "invalid nonce" {
		t.Errorf("Error() = %q, want %q", got, "invalid nonce")
	}

	p2 := &Problem{Type: "urn:ietf:params:acme:error:malformed"}
	if got := p2.Error(); got != "urn:ietf:params:acme:error:malformed" {
		t.Errorf("Error() with no detail = %q, want type", got)
	}
}

func TestNewDirectory(t *testing.T) {
	dir := NewDirectory("https://acme.example.com")
	if dir.NewNonce != "https://acme.example.com/acme/newnonce" {
		t.Errorf("NewNonce = %q", dir.NewNonce)
	}
	if dir.NewAccount != "https://acme.example.com/acme/new-account" {
		t.Errorf("NewAccount = %q", dir.NewAccount)
	}
	if dir.NewOrder != "https://acme.example.com/acme/new-order" {
		t.Errorf("NewOrder = %q", dir.NewOrder)
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}
	if n1 == "" {
		t.Fatal("nonce should not be empty")
	}
	n2, _ := GenerateNonce()
	if n1 == n2 {
		t.Error("two nonces should differ")
	}
}

func TestGenerateToken(t *testing.T) {
	t1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}
	if t1 == "" {
		t.Fatal("token should not be empty")
	}
	t2, _ := GenerateToken()
	if t1 == t2 {
		t.Error("two tokens should differ")
	}
}

func TestComputeKeyAuthorization(t *testing.T) {
	result := ComputeKeyAuthorization("token123", "thumbprint456")
	if result != "token123.thumbprint456" {
		t.Errorf("ComputeKeyAuthorization = %q, want token123.thumbprint456", result)
	}
}

func TestComputeDNSKeyAuthorization(t *testing.T) {
	result := ComputeDNSKeyAuthorization("token123", "thumbprint456")
	if result != "token123.thumbprint456" {
		t.Errorf("ComputeDNSKeyAuthorization = %q", result)
	}
}

func TestComputeThumbprint(t *testing.T) {
	result := ComputeThumbprint([]byte("test-data"))
	if result == "" {
		t.Fatal("thumbprint should not be empty")
	}
	// Same input must produce same output
	result2 := ComputeThumbprint([]byte("test-data"))
	if result != result2 {
		t.Error("same input should produce same thumbprint")
	}
	// Different input should produce different output
	result3 := ComputeThumbprint([]byte("other-data"))
	if result == result3 {
		t.Error("different inputs should produce different thumbprints")
	}
}

func TestParseIdentifiers(t *testing.T) {
	tests := []struct {
		name    string
		input   []Identifier
		want    int
		wantErr bool
	}{
		{
			name:  "valid dns identifier",
			input: []Identifier{{Type: "dns", Value: "example.com"}},
			want:  1,
		},
		{
			name:  "multiple valid identifiers",
			input: []Identifier{{Type: "dns", Value: "a.com"}, {Type: "dns", Value: "b.com"}},
			want:  2,
		},
		{
			name:    "unsupported type",
			input:   []Identifier{{Type: "ip", Value: "1.2.3.4"}},
			wantErr: true,
		},
		{
			name:    "invalid domain - no dot",
			input:   []Identifier{{Type: "dns", Value: "localhost"}},
			wantErr: true,
		},
		{
			name:    "invalid domain - empty",
			input:   []Identifier{{Type: "dns", Value: ""}},
			wantErr: true,
		},
		{
			name:    "invalid domain - too long",
			input:   []Identifier{{Type: "dns", Value: string(make([]byte, 254))}},
			wantErr: true,
		},
		{
			name:    "invalid domain - uppercase",
			input:   []Identifier{{Type: "dns", Value: "EXAMPLE.COM"}},
			wantErr: true,
		},
		{
			name:  "empty identifiers list",
			input: []Identifier{},
			want:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIdentifiers(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIdentifiers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.want {
				t.Errorf("ParseIdentifiers() returned %d identifiers, want %d", len(got), tt.want)
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a-b.example.com", true},
		{"", false},
		{"localhost", false},
		{"EXAMPLE.COM", false},
		{"example.com/path", false},
		{"valid-domain.org", true},
		{"123.example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := isValidDomain(tt.domain); got != tt.want {
				t.Errorf("isValidDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}
